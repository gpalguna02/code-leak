"""Automated test suite for CodeLeak Patrol scanner, RAG engine, and database."""

import json
from pathlib import Path
import pytest
import sys

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.database import (
    get_audit_by_id,
    get_audit_stats,
    get_audits,
    init_db,
    save_audit,
    update_remediation_task,
)
from app.ollama_client import run_heuristic_analysis
from app.rag_engine import retrieve_policies_for_findings
from app.scanner import (
    calculate_entropy,
    mask_secret,
    parse_git_diff_lines,
    scan_content,
)


# 1. Entropy & Masking Tests
def test_calculate_entropy():
    # Identical repeating characters have 0 entropy
    assert calculate_entropy("AAAAAA") == 0.0
    assert calculate_entropy("") == 0.0

    # Low entropy natural English text
    low_ent = calculate_entropy("hello world")
    assert low_ent < 3.2

    # High entropy base64 / hex cryptographic strings
    high_ent = calculate_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert high_ent > 4.0


def test_mask_secret():
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"
    assert mask_secret("ghp_1234567890abcdef") == "ghp_************cdef"
    assert mask_secret("short") == "*****"


# 2. Secret Detection Tests
def test_detect_aws_access_key():
    diff = """
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 import os
+AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
"""
    result = scan_content(diff)
    assert result["total_secrets"] >= 1
    aws_findings = [f for f in result["findings"] if f["rule_id"] == "SEC-AWS-KEY"]
    assert len(aws_findings) == 1
    assert aws_findings[0]["cwe"] == "CWE-798"
    assert aws_findings[0]["severity"] == "CRITICAL"
    assert "AKIA************MPLE" in aws_findings[0]["masked_value"]


def test_detect_github_token():
    raw_code = 'GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"\n'
    result = scan_content(raw_code)
    gh_findings = [f for f in result["findings"] if f["rule_id"] == "SEC-GH-TOKEN"]
    assert len(gh_findings) == 1
    assert gh_findings[0]["severity"] == "CRITICAL"


def test_detect_private_rsa_key():
    raw_code = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA04m...
-----END RSA PRIVATE KEY-----
"""
    result = scan_content(raw_code)
    priv_findings = [f for f in result["findings"] if f["rule_id"] == "SEC-PRIV-KEY"]
    assert len(priv_findings) == 1


def test_detect_database_connection_uri():
    diff = """
+DATABASE_URL = "postgres://admin:superSecretP@ssword123@db.prod.internal:5432/production"
"""
    result = scan_content(diff)
    db_findings = [f for f in result["findings"] if f["rule_id"] == "SEC-DB-URI"]
    assert len(db_findings) == 1
    assert db_findings[0]["cwe"] == "CWE-798"


# 3. CWE Vulnerability Pattern Tests
def test_detect_sql_injection():
    diff = """
+++ b/app/users.py
@@ -10,3 +10,4 @@
 def get_user(user_id):
-    return db.query(user_id)
+    query = f"SELECT * FROM users WHERE id = {user_id}"
+    return cursor.execute(query)
"""
    result = scan_content(diff)
    assert "CWE-89" in result["cwe_hits"]
    sql_findings = [f for f in result["findings"] if f["cwe"] == "CWE-89"]
    assert len(sql_findings) >= 1
    assert sql_findings[0]["severity"] == "CRITICAL"


def test_detect_broken_crypto_md5():
    diff = """
+import hashlib
+def hash_password(pwd):
+    return hashlib.md5(pwd.encode()).hexdigest()
"""
    result = scan_content(diff)
    assert "CWE-327" in result["cwe_hits"]
    crypto_findings = [f for f in result["findings"] if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) >= 1
    assert crypto_findings[0]["severity"] in {"HIGH", "CRITICAL"}


def test_detect_path_traversal():
    diff = """
+def download_file(user_file):
+    return open(os.path.join('/static/files', request.args.get('path'))).read()
"""
    result = scan_content(diff)
    assert "CWE-22" in result["cwe_hits"]


def test_clean_diff_passes():
    diff = """
diff --git a/safe_file.py b/safe_file.py
--- a/safe_file.py
+++ b/safe_file.py
@@ -1,2 +1,5 @@
+import os
+def get_user_param():
+    return os.environ.get("SAFE_USER_ID", "default")
"""
    result = scan_content(diff)
    assert result["total_secrets"] == 0
    assert result["total_vulnerabilities"] == 0
    assert result["max_severity"] == "SAFE"


# 4. Git Diff Parser Tests
def test_diff_parser_ignores_deletions():
    diff = """
diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -1,2 +1,2 @@
-AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
+AWS_KEY = os.environ.get("AWS_KEY")
"""
    result = scan_content(diff)
    # The removed line (-) contains the key, but the added line (+) uses os.environ.
    # Therefore, no secrets should be flagged!
    assert result["total_secrets"] == 0


# 5. RAG Engine Policy Retrieval Tests
def test_retrieve_policies():
    policies = retrieve_policies_for_findings(["CWE-798"], ["AWS Access Key ID"], top_k=2)
    assert len(policies) > 0
    cwe_ids = [p["cwe_id"] for p in policies]
    assert "CWE-798" in cwe_ids


# 6. Heuristic Fallback Analysis Tests
def test_heuristic_blocks_critical_secret():
    scan_results = {
        "findings": [
            {
                "type": "secret",
                "title": "AWS Access Key",
                "cwe": "CWE-798",
                "severity": "CRITICAL",
                "file": "config.py",
                "line": 12,
            }
        ],
        "total_secrets": 1,
        "total_vulnerabilities": 0,
        "max_severity": "CRITICAL",
    }
    analysis = run_heuristic_analysis(scan_results, [])
    assert analysis["commit_blocked"] is True
    assert analysis["risk_level"] == "CRITICAL"
    assert len(analysis["remediation_checklist"]) > 0


def test_heuristic_passes_clean_code():
    scan_results = {
        "findings": [],
        "total_secrets": 0,
        "total_vulnerabilities": 0,
        "max_severity": "SAFE",
    }
    analysis = run_heuristic_analysis(scan_results, [])
    assert analysis["commit_blocked"] is False
    assert analysis["risk_level"] == "SAFE"


# 7. Database CRUD & Stats Tests
def test_database_crud(tmp_path):
    test_db = tmp_path / "test_audits.db"
    init_db(test_db)

    audit = save_audit(
        source="unit_test",
        commit_blocked=True,
        risk_level="CRITICAL",
        summary="Test blocked secret commit",
        total_secrets=1,
        total_vulnerabilities=1,
        raw_input="+AWS_KEY = 'AKIA...'",
        llm_engine="heuristic-fallback",
        remediation_items=[{"id": "rem-1", "task": "Rotate key", "completed": False}],
        findings=[{"type": "secret", "title": "AWS Key", "cwe": "CWE-798", "severity": "CRITICAL"}],
        policies=[{"id": "CWE-798", "title": "Hardcoded credentials"}],
        db_path=test_db,
    )
    assert audit["id"] is not None
    assert audit["commit_blocked"] is True

    # Test retrieval
    fetched = get_audit_by_id(audit["id"], db_path=test_db)
    assert fetched is not None
    assert fetched["id"] == audit["id"]

    # Test remediation toggle
    updated = update_remediation_task(audit["id"], "rem-1", True, db_path=test_db)
    assert updated["remediation_items"][0]["completed"] is True

    # Test stats
    stats = get_audit_stats(db_path=test_db)
    assert stats["total_scans"] == 1
    assert stats["blocked_commits"] == 1
    assert stats["total_secrets_detected"] == 1

