"""Direct endpoint handler tests for CodeLeak Patrol FastAPI app."""

from pathlib import Path
import pytest
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.main import (
    AuditRequest,
    LoginRequest,
    RemediationUpdateRequest,
    audit_statistics,
    create_audit,
    download_audit_report,
    download_git_hook,
    download_history_csv,
    download_project_zip,
    get_audit,
    get_current_user_profile,
    health_check,
    list_audits,
    list_policies,
    login,
    logout,
    toggle_remediation,
)


def test_api_health_handler():
    data = health_check()
    assert data["status"] == "healthy"
    assert "chroma_db" in data
    assert "ollama" in data


def test_create_audit_handler_with_secret():
    req = AuditRequest(
        diff="""
+++ b/config.py
+AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
""",
        source="sandbox",
    )
    data = create_audit(req)
    assert data["commit_blocked"] is True
    assert data["risk_level"] in {"CRITICAL", "HIGH"}
    assert data["total_secrets"] >= 1
    assert len(data["remediation_items"]) > 0

    audit_id = data["id"]

    # Test toggling remediation checklist item
    rem_id = data["remediation_items"][0]["id"]
    patch_req = RemediationUpdateRequest(completed=True)
    updated = toggle_remediation(audit_id, rem_id, patch_req)
    assert any(it["id"] == rem_id and it["completed"] is True for it in updated["remediation_items"])

    # Test get single audit
    single = get_audit(audit_id)
    assert single["id"] == audit_id


def test_create_audit_handler_with_clean_code():
    req = AuditRequest(
        diff="""
+++ b/math_helper.py
+def add(a, b):
+    return a + b
""",
        source="sandbox",
    )
    data = create_audit(req)
    assert data["commit_blocked"] is False
    assert data["risk_level"] == "SAFE"


def test_list_audits_handler():
    audits = list_audits(limit=10, offset=0)
    assert isinstance(audits, list)


def test_stats_handler():
    stats = audit_statistics()
    assert "total_scans" in stats
    assert "blocked_commits" in stats
    assert "total_secrets_detected" in stats


def test_policies_handler():
    policies = list_policies()
    assert len(policies) >= 5


def test_download_endpoints():
    # 1. Test project zip packaging
    zip_resp = download_project_zip()
    assert zip_resp.media_type == "application/zip"
    assert "attachment; filename=\"airgap-sentinel.zip\"" in zip_resp.headers["Content-Disposition"]

    # 2. Test git hook download
    hook_resp = download_git_hook()
    assert hook_resp.media_type == "text/x-python"
    assert len(hook_resp.body) > 50

    # 3. Test history CSV download
    csv_resp = download_history_csv()
    assert csv_resp.media_type == "text/csv"
    assert "airgap_audit_history.csv" in csv_resp.headers["Content-Disposition"]

    # 4. Test audit report download (JSON & Markdown)
    req = AuditRequest(diff="+++ b/demo.py\n+print('hello')", source="test")
    audit = create_audit(req)
    audit_id = audit["id"]

    json_resp = download_audit_report(audit_id, format="json")
    assert json_resp.media_type == "application/json"
    assert audit_id.encode("utf-8") in json_resp.body

    md_resp = download_audit_report(audit_id, format="markdown")
    assert "text/markdown" in md_resp.media_type
    assert b"AirGap Sentinel Security Audit Report" in md_resp.body


def test_email_login_handler():
    # Test valid email login
    login_req = LoginRequest(
        email="developer@company.local",
        password="SecurePass123!",
        role="Lead Auditor",
    )
    auth_resp = login(login_req)
    assert auth_resp["status"] == "authenticated"
    assert "token" in auth_resp
    assert auth_resp["user"]["email"] == "developer@company.local"
    assert auth_resp["user"]["role"] == "Lead Auditor"

    # Test profile retrieval
    profile = get_current_user_profile(email="developer@company.local")
    assert profile["email"] == "developer@company.local"

    # Test logout
    logout_resp = logout()
    assert logout_resp["status"] == "logged_out"

    # Test invalid email validation error
    with pytest.raises(Exception):
        login(LoginRequest(email="invalid_email_no_at"))


