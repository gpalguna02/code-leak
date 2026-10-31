"""FastAPI REST API router and application entry point for CodeLeak Patrol."""

import csv
import io
import json
import os
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.config import API_HOST, API_PORT, OLLAMA_MODEL, PROJECT_ROOT
from app.database import (
    delete_audit,
    get_audit_by_id,
    get_audit_stats,
    get_audits,
    get_or_create_user,
    get_user_by_email,
    init_db,
    save_audit,
    update_remediation_task,
)
from app.ollama_client import analyze_diff_with_llm, check_ollama_health
from app.rag_engine import get_vector_collection, retrieve_policies_for_findings
from app.scanner import scan_content


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes SQLite and ChromaDB on startup."""
    try:
        init_db()
    except Exception as e:
        print(f"Notice: init_db startup note: {e}")
    try:
        get_vector_collection()
    except Exception as e:
        print(f"Notice: get_vector_collection startup note: {e}")
    yield


app = FastAPI(
    title="AirGap Sentinel API",
    description="Zero-Exfiltration Local Code Defense",
    version="1.0.0",
    lifespan=lifespan,
)

# Decoupled SPA dashboard CORS enablement
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic Schemas
class AuditRequest(BaseModel):
    diff: str = Field(..., description="Unified git diff or raw source code to analyze")
    source: str = Field(default="sandbox", description="Origin of audit: git_hook, sandbox, cli")
    model: Optional[str] = Field(default=None, description="Optional local LLM model name (default: gemma3:1b)")


class RemediationUpdateRequest(BaseModel):
    completed: bool = Field(..., description="New completion status of the remediation checklist task")


class LoginRequest(BaseModel):
    email: str = Field(..., description="Developer or company email address")
    password: Optional[str] = Field(default=None, description="Optional password or security access PIN")
    role: Optional[str] = Field(default="SecOps Auditor", description="User role")


# ---------------------------------------------------------
# Authentication Endpoints (Using Our Own Email)
# ---------------------------------------------------------
@app.post("/api/auth/login")
def login(payload: LoginRequest) -> Dict[str, Any]:
    """
    Authenticates a user using their own email address.
    Zero external exfiltration: accounts and credentials are saved locally in SQLite.
    """
    email = payload.email.strip()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid email address (e.g. yourname@company.com).",
        )

    try:
        user = get_or_create_user(
            email=email,
            password=payload.password,
            role=payload.role or "SecOps Auditor",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

    session_token = f"cp_sess_{user['id'][:8]}_{int(datetime.now(timezone.utc).timestamp())}"
    return {
        "status": "authenticated",
        "token": session_token,
        "user": user,
    }


@app.get("/api/auth/me")
def get_current_user_profile(email: str = Query(..., description="User email")) -> Dict[str, Any]:
    """Retrieves user profile for the current session."""
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")
    return user


@app.post("/api/auth/logout")
def logout() -> Dict[str, str]:
    """Terminates session."""
    return {"status": "logged_out"}



@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    """Health status check for backend components."""
    ollama_status = check_ollama_health()
    vector_store = get_vector_collection()
    policy_count = len(vector_store.get_all()) if hasattr(vector_store, "get_all") else vector_store.count()

    return {
        "status": "healthy",
        "service": "AirGap Sentinel Backend",
        "version": "1.0.0",
        "database": "sqlite_ready",
        "chroma_db": {
            "status": "ready",
            "indexed_policies": policy_count,
        },
        "ollama": ollama_status,
    }


@app.post("/api/audit")
def create_audit(payload: AuditRequest) -> Dict[str, Any]:
    """
    Core security audit pipeline:
    1. Parse and scan diff for high-entropy secrets and CWE vulnerability patterns.
    2. Retrieve relevant CWE definitions and company security policies from ChromaDB.
    3. Run local LLM reasoning (Ollama gemma3:1b) with graceful heuristic fallback.
    4. Store audit record and remediation checklist in SQLite.
    5. Return complete audit report.
    """
    diff_text = payload.diff.strip()
    if not diff_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Diff or source code input cannot be empty.",
        )

    # 1. Regex & Shannon entropy scan
    scan_results = scan_content(diff_text)

    # 2. Vector retrieval from ChromaDB
    finding_titles = [f["title"] for f in scan_results["findings"]]
    cwe_hits = scan_results["cwe_hits"]
    policies = retrieve_policies_for_findings(cwe_hits, finding_titles, top_k=3)

    # 3. Local LLM analysis with fallback
    analysis = analyze_diff_with_llm(
        diff_text=diff_text,
        scan_results=scan_results,
        policies=policies,
        model=payload.model or OLLAMA_MODEL,
    )

    # 4. Save to SQLite database
    saved_audit = save_audit(
        source=payload.source,
        commit_blocked=analysis["commit_blocked"],
        risk_level=analysis["risk_level"],
        summary=analysis["summary"],
        total_secrets=scan_results["total_secrets"],
        total_vulnerabilities=scan_results["total_vulnerabilities"],
        raw_input=diff_text,
        llm_engine=analysis["engine_used"],
        remediation_items=analysis["remediation_checklist"],
        findings=scan_results["findings"],
        policies=policies,
    )

    return saved_audit


@app.get("/api/audits")
def list_audits(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    source: Optional[str] = Query(default=None),
    risk_level: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """Retrieves paginated audit history."""
    return get_audits(limit=limit, offset=offset, source=source, risk_level=risk_level)


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str) -> Dict[str, Any]:
    """Retrieves a single audit report by UUID."""
    record = get_audit_by_id(audit_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit record not found.")
    return record


@app.patch("/api/audits/{audit_id}/remediation/{task_id}")
def toggle_remediation(
    audit_id: str,
    task_id: str,
    payload: RemediationUpdateRequest,
) -> Dict[str, Any]:
    """Updates the status of a remediation checklist task."""
    updated = update_remediation_task(audit_id, task_id, payload.completed)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit or remediation task not found.",
        )
    return updated


@app.delete("/api/audits/{audit_id}")
def remove_audit(audit_id: str) -> Dict[str, Any]:
    """Deletes an audit record."""
    success = delete_audit(audit_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit record not found.")
    return {"status": "deleted", "id": audit_id}


@app.get("/api/stats")
def audit_statistics() -> Dict[str, Any]:
    """Returns aggregated metrics for dashboard counters."""
    return get_audit_stats()


@app.get("/api/policies")
def list_policies() -> List[Dict[str, Any]]:
    """Returns all pre-seeded security policies and CWE standards from ChromaDB."""
    vector_store = get_vector_collection()
    if hasattr(vector_store, "get_all"):
        raw_items = vector_store.get_all()
        return [
            {
                "id": item["id"],
                "document": item["document"],
                "metadata": item["metadata"],
            }
            for item in raw_items
        ]
    else:
        # ChromaDB standard collection
        data = vector_store.get()
        results = []
        ids = data.get("ids", [])
        docs = data.get("documents", [])
        metas = data.get("metadatas", [])
        for p_id, doc, meta in zip(ids, docs, metas):
            results.append({"id": p_id, "document": doc, "metadata": meta})
        return results


# ---------------------------------------------------------
# Download & Export Endpoints
# ---------------------------------------------------------
@app.get("/api/download/project-zip")
def download_project_zip() -> StreamingResponse:
    """Creates and streams an in-memory zip archive of the complete AirGap Sentinel application."""
    zip_buffer = io.BytesIO()
    exclude_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules", ".idea", ".vscode"}
    exclude_files = {".DS_Store", "audits.db-journal"}

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(PROJECT_ROOT):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if file in exclude_files or file.endswith(".pyc"):
                    continue
                file_path = Path(root) / file
                try:
                    arcname = file_path.relative_to(PROJECT_ROOT)
                    zip_file.write(file_path, arcname=str(arcname))
                except Exception:
                    continue

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="airgap-sentinel.zip"'
        },
    )


@app.get("/api/download/hook")
def download_git_hook() -> Response:
    """Downloads the standalone pre-commit git hook script."""
    hook_path = PROJECT_ROOT / "backend" / "scripts" / "pre_commit_scanner.py"
    if not hook_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hook script not found.")

    content = hook_path.read_text(encoding="utf-8")
    return Response(
        content=content,
        media_type="text/x-python",
        headers={
            "Content-Disposition": 'attachment; filename="pre-commit"'
        },
    )


@app.get("/api/download/history-csv")
def download_history_csv() -> StreamingResponse:
    """Streams the complete audit history log as a CSV spreadsheet."""
    audits = get_audits(limit=1000, offset=0)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Audit ID",
        "Timestamp",
        "Source",
        "Risk Level",
        "Commit Blocked",
        "Total Secrets",
        "Total Vulnerabilities",
        "LLM Engine",
        "Summary",
    ])

    for a in audits:
        writer.writerow([
            a.get("id"),
            a.get("timestamp"),
            a.get("source"),
            a.get("risk_level"),
            "BLOCKED" if a.get("commit_blocked") else "PASSED",
            a.get("total_secrets", 0),
            a.get("total_vulnerabilities", 0),
            a.get("llm_engine"),
            (a.get("summary") or "").replace("\n", " "),
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="airgap_audit_history.csv"'
        },
    )


@app.get("/api/download/audit/{audit_id}")
def download_audit_report(audit_id: str, format: str = Query(default="json")) -> Response:
    """Downloads an individual security audit report formatted as JSON or Markdown."""
    audit = get_audit_by_id(audit_id)
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit record not found.")

    short_id = audit_id[:8]
    if format.lower() in ("markdown", "md"):
        lines = [
            "# AirGap Sentinel Security Audit Report",
            f"**Audit ID:** `{audit['id']}`  ",
            f"**Timestamp:** {audit.get('timestamp')}  ",
            f"**Source:** {audit.get('source')}  ",
            f"**Risk Level:** `{audit.get('risk_level')}`  ",
            f"**Status:** {'⛔ BLOCKED' if audit.get('commit_blocked') else '✔ PASSED'}  ",
            f"**Analysis Engine:** `{audit.get('llm_engine')}`  ",
            "",
            "## Executive Summary",
            audit.get("summary") or "No summary provided.",
            "",
            "## Findings Overview",
            f"- **Secrets Detected:** {audit.get('total_secrets', 0)}",
            f"- **CWE Vulnerabilities:** {audit.get('total_vulnerabilities', 0)}",
            "",
        ]

        findings = audit.get("findings", [])
        if findings:
            lines.append("### Detailed Security Findings")
            for f in findings:
                f_type = f.get("type", "finding").upper()
                lines.append(f"#### [{f_type}] {f.get('title')}")
                lines.append(f"- **Severity:** {f.get('severity')} | **File:** `{f.get('file')}:{f.get('line')}`")
                if f.get("masked_value"):
                    lines.append(f"- **Masked Value:** `{f.get('masked_value')}`")
                if f.get("cwe"):
                    lines.append(f"- **CWE Standard:** {f.get('cwe')}")
                if f.get("description"):
                    lines.append(f"- **Description:** {f.get('description')}")
                if f.get("remediation"):
                    lines.append(f"- **Remediation:** {f.get('remediation')}")
                lines.append("")

        items = audit.get("remediation_items", [])
        if items:
            lines.append("## Actionable Remediation Checklist")
            for item in items:
                status_box = "[x]" if item.get("completed") else "[ ]"
                lines.append(f"- {status_box} **{item.get('task')}** ({item.get('priority')})")
                lines.append(f"  {item.get('description')}")
            lines.append("")

        md_content = "\n".join(lines)
        return Response(
            content=md_content,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="audit_{short_id}.md"'
            },
        )
    else:
        json_content = json.dumps(audit, indent=2)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="audit_{short_id}.json"'
            },
        )


# Mount Frontend Static Assets
try:
    from fastapi.staticfiles import StaticFiles
    _frontend_path = PROJECT_ROOT / "frontend"
    if _frontend_path.exists():
        app.mount("/", StaticFiles(directory=str(_frontend_path), html=True), name="frontend")
except Exception:
    pass



if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=API_HOST, port=API_PORT, reload=True)

