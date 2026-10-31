"""SQLite database interface for audit history and remediation tracking."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import SQLITE_DB_PATH


_initialized_dbs = set()


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Creates a connection to the SQLite database, ensuring schema is initialized."""
    target_path = (db_path or SQLITE_DB_PATH).resolve()
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError):
        pass
    conn = sqlite3.connect(str(target_path))
    conn.row_factory = sqlite3.Row

    if str(target_path) not in _initialized_dbs:
        _ensure_schema(conn)
        _initialized_dbs.add(str(target_path))

    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            commit_blocked INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL,
            summary TEXT NOT NULL,
            total_secrets INTEGER NOT NULL DEFAULT 0,
            total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
            raw_input TEXT NOT NULL,
            llm_engine TEXT NOT NULL,
            remediation_items TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            policies_json TEXT NOT NULL
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audits_timestamp ON audits(timestamp DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audits_risk ON audits(risk_level)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audits_blocked ON audits(commit_blocked)")

    # Users and Auth Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            role TEXT NOT NULL DEFAULT 'SecOps Auditor',
            created_at TEXT NOT NULL,
            last_login TEXT NOT NULL
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    conn.commit()


def init_db(db_path: Optional[Path] = None, seed_defaults: Optional[bool] = None) -> None:
    """Explicitly initializes the database schema if tables do not exist."""
    target_path = (db_path or SQLITE_DB_PATH).resolve()
    with get_db_connection(target_path) as conn:
        _ensure_schema(conn)
        if seed_defaults is True or (seed_defaults is None and db_path is None):
            _seed_initial_audits_if_empty(conn)


def _seed_initial_audits_if_empty(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audits")
    row = cur.fetchone()
    if row and row[0] > 0:
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    # 1. Critical Blocked Audit
    cur.execute(
        """
        INSERT INTO audits (
            id, timestamp, source, commit_blocked, risk_level, summary,
            total_secrets, total_vulnerabilities, raw_input, llm_engine,
            remediation_items, findings_json, policies_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "aud-crit-aws-01",
            now_iso,
            "sandbox",
            1,
            "CRITICAL",
            "Audit BLOCKED: Detected 1 secret(s) in payment_service.py. Risk Level: CRITICAL. Commit is strictly blocked.",
            1,
            0,
            "+++ b/payment_service.py\n+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            "ollama:gemma3:1b",
            json.dumps([
                {"id": "task-1", "task": "Rotate & Revoke Exposed Credentials", "description": "Immediately invalidate the exposed AWS credential in the cloud console.", "completed": False, "priority": "CRITICAL"},
                {"id": "task-2", "task": "Store in Environment Secrets", "description": "Migrate credential to local .env file excluded via .gitignore.", "completed": False, "priority": "HIGH"},
            ]),
            json.dumps([
                {"type": "secret", "title": "AWS Access Key ID", "file": "payment_service.py", "line": 2, "severity": "CRITICAL", "masked_value": "AKIA****************", "entropy": 4.2}
            ]),
            json.dumps([])
        )
    )

    # 2. SQL Injection Blocked Audit
    cur.execute(
        """
        INSERT INTO audits (
            id, timestamp, source, commit_blocked, risk_level, summary,
            total_secrets, total_vulnerabilities, raw_input, llm_engine,
            remediation_items, findings_json, policies_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "aud-crit-sqli-02",
            now_iso,
            "sandbox",
            1,
            "CRITICAL",
            "Audit BLOCKED: Detected dynamic SQL Injection (CWE-89) in auth_service.py.",
            0,
            1,
            "+++ b/auth_service.py\n+query = f\"SELECT * FROM users WHERE user = '{username}'\"",
            "heuristic",
            json.dumps([
                {"id": "task-3", "task": "Use Parameterized Queries", "description": "Replace string interpolation with query parameter binding.", "completed": False, "priority": "CRITICAL"}
            ]),
            json.dumps([
                {"type": "vulnerability", "cwe": "CWE-89", "title": "Dynamic SQL Injection", "file": "auth_service.py", "line": 4, "severity": "CRITICAL", "description": "Raw string concatenation in SQL query."}
            ]),
            json.dumps([])
        )
    )

    # 3. Verified Clean Audit
    cur.execute(
        """
        INSERT INTO audits (
            id, timestamp, source, commit_blocked, risk_level, summary,
            total_secrets, total_vulnerabilities, raw_input, llm_engine,
            remediation_items, findings_json, policies_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "aud-clean-release-03",
            now_iso,
            "sandbox",
            0,
            "SAFE",
            "Audit PASSED: No secrets or critical CWE violations detected. Code verified clean.",
            0,
            0,
            "+++ b/utils.py\n+def get_app_version(): return '1.0.0'",
            "ollama:gemma3:1b",
            json.dumps([]),
            json.dumps([]),
            json.dumps([])
        )
    )
    conn.commit()



def save_audit(
    source: str,
    commit_blocked: bool,
    risk_level: str,
    summary: str,
    total_secrets: int,
    total_vulnerabilities: int,
    raw_input: str,
    llm_engine: str,
    remediation_items: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    policies: List[Dict[str, Any]],
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Saves a new audit record into SQLite."""
    audit_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    # Ensure each remediation item has a unique id and completed flag
    formatted_remediations = []
    for idx, item in enumerate(remediation_items):
        formatted_remediations.append({
            "id": item.get("id") or f"rem-{idx + 1}",
            "task": item.get("task", "Remediation step"),
            "description": item.get("description", ""),
            "priority": item.get("priority", "HIGH"),
            "completed": bool(item.get("completed", False)),
        })

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audits (
                id, timestamp, source, commit_blocked, risk_level, summary,
                total_secrets, total_vulnerabilities, raw_input, llm_engine,
                remediation_items, findings_json, policies_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                now_iso,
                source,
                1 if commit_blocked else 0,
                risk_level.upper(),
                summary,
                total_secrets,
                total_vulnerabilities,
                raw_input,
                llm_engine,
                json.dumps(formatted_remediations),
                json.dumps(findings),
                json.dumps(policies),
            ),
        )
        conn.commit()

    return get_audit_by_id(audit_id, db_path=db_path)  # type: ignore


def get_audit_by_id(audit_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieves an audit record by ID."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audits WHERE id = ?", (audit_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return _row_to_audit_dict(row)


def get_audits(
    limit: int = 50,
    offset: int = 0,
    source: Optional[str] = None,
    risk_level: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Retrieves a paginated list of audits."""
    query = "SELECT * FROM audits WHERE 1=1"
    params: List[Any] = []

    if source and isinstance(source, str):
        query += " AND source = ?"
        params.append(source)
    if risk_level and isinstance(risk_level, str):
        query += " AND risk_level = ?"
        params.append(risk_level.upper())

    try:
        limit_val = int(getattr(limit, "default", limit))
    except Exception:
        limit_val = 50

    try:
        offset_val = int(getattr(offset, "default", offset))
    except Exception:
        offset_val = 0

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit_val, offset_val])

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [_row_to_audit_dict(r) for r in rows]


def update_remediation_task(
    audit_id: str,
    task_id: str,
    completed: bool,
    db_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Updates the completed status of an individual remediation checklist item."""
    audit = get_audit_by_id(audit_id, db_path=db_path)
    if not audit:
        return None

    items = audit.get("remediation_items", [])
    updated = False
    for it in items:
        if it.get("id") == task_id:
            it["completed"] = bool(completed)
            updated = True
            break

    if not updated:
        return None

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE audits SET remediation_items = ? WHERE id = ?",
            (json.dumps(items), audit_id),
        )
        conn.commit()

    return get_audit_by_id(audit_id, db_path=db_path)


def delete_audit(audit_id: str, db_path: Optional[Path] = None) -> bool:
    """Deletes an audit record."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audits WHERE id = ?", (audit_id,))
        conn.commit()
        return cursor.rowcount > 0


def get_audit_stats(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Computes aggregate security metrics for dashboard counters."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                COUNT(*) as total_scans,
                SUM(commit_blocked) as blocked_commits,
                SUM(total_secrets) as total_secrets,
                SUM(total_vulnerabilities) as total_vulnerabilities
            FROM audits
        """)
        row = cursor.fetchone()

        cursor.execute("""
            SELECT risk_level, COUNT(*) as count
            FROM audits
            GROUP BY risk_level
        """)
        risk_counts = {r["risk_level"]: r["count"] for r in cursor.fetchall()}

        # CWE distribution from findings
        cursor.execute("SELECT findings_json FROM audits ORDER BY timestamp DESC LIMIT 100")
        cwe_distribution: Dict[str, int] = {}
        for (f_json,) in cursor.fetchall():
            try:
                findings = json.loads(f_json)
                for f in findings:
                    cwe = f.get("cwe")
                    if cwe:
                        cwe_distribution[cwe] = cwe_distribution.get(cwe, 0) + 1
            except Exception:
                pass

        total_scans = row["total_scans"] if row and row["total_scans"] else 0
        blocked = row["blocked_commits"] if row and row["blocked_commits"] else 0
        secrets = row["total_secrets"] if row and row["total_secrets"] else 0
        vulns = row["total_vulnerabilities"] if row and row["total_vulnerabilities"] else 0

        return {
            "total_scans": total_scans,
            "blocked_commits": blocked,
            "passed_commits": max(0, total_scans - blocked),
            "total_secrets_detected": secrets,
            "total_vulnerabilities_detected": vulns,
            "risk_distribution": risk_counts,
            "cwe_distribution": cwe_distribution,
        }


def _row_to_audit_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Converts a SQLite Row into a fully deserialized dictionary."""
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source": row["source"],
        "commit_blocked": bool(row["commit_blocked"]),
        "risk_level": row["risk_level"],
        "summary": row["summary"],
        "total_secrets": row["total_secrets"],
        "total_vulnerabilities": row["total_vulnerabilities"],
        "raw_input": row["raw_input"],
        "llm_engine": row["llm_engine"],
        "remediation_items": json.loads(row["remediation_items"]),
        "findings": json.loads(row["findings_json"]),
        "policies": json.loads(row["policies_json"]),
    }


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hashes a password using standard library PBKDF2 HMAC SHA-256."""
    import hashlib
    import os

    if not salt:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()
    return f"{salt}:{hashed}"


def verify_password(stored_hash: str, password: str) -> bool:
    """Verifies a password against the stored salt:hash string."""
    import hashlib

    if not stored_hash or ":" not in stored_hash:
        return False
    salt, hashed = stored_hash.split(":", 1)
    test_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()
    return test_hash == hashed


def get_or_create_user(
    email: str,
    password: Optional[str] = None,
    role: str = "SecOps Auditor",
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Authenticates an existing user or creates a new user account with their email."""
    email_clean = email.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email_clean,))
        row = cursor.fetchone()

        if row:
            stored_hash = row["password_hash"]
            if stored_hash and password:
                if not verify_password(stored_hash, password):
                    raise ValueError("Incorrect password for this email account.")
            elif not stored_hash and password:
                # Set password if previously unset
                cursor.execute(
                    "UPDATE users SET password_hash = ?, last_login = ? WHERE id = ?",
                    (hash_password(password), now_iso, row["id"]),
                )
                conn.commit()

            cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_iso, row["id"]))
            conn.commit()

            return {
                "id": row["id"],
                "email": row["email"],
                "role": row["role"],
                "created_at": row["created_at"],
                "last_login": now_iso,
            }
        else:
            # Create new user
            user_id = str(uuid.uuid4())
            pwd_hash = hash_password(password) if password else None
            cursor.execute(
                """
                INSERT INTO users (id, email, password_hash, role, created_at, last_login)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, email_clean, pwd_hash, role, now_iso, now_iso),
            )
            conn.commit()
            return {
                "id": user_id,
                "email": email_clean,
                "role": role,
                "created_at": now_iso,
                "last_login": now_iso,
            }


def get_user_by_email(email: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieves user profile by email."""
    email_clean = email.strip().lower()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, role, created_at, last_login FROM users WHERE email = ?", (email_clean,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "email": row["email"],
            "role": row["role"],
            "created_at": row["created_at"],
            "last_login": row["last_login"],
        }

