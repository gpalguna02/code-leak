"""High-entropy secret scanner and CWE vulnerability pattern detector for Git diffs."""

import fnmatch
import math
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from app.config import DEFAULT_IGNORED_PATH_PATTERNS
except ImportError:
    DEFAULT_IGNORED_PATH_PATTERNS = ["*.md", "tests/*", "*/tests/*", "*test_*.py"]


def calculate_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    for count in char_counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def mask_secret(secret: str) -> str:
    """Masks a secret for safe display in UI, CLI, and audit records."""
    if not secret:
        return ""
    length = len(secret)
    if length <= 6:
        return "*" * length
    if length <= 12:
        return secret[:2] + ("*" * (length - 4)) + secret[-2:]
    return secret[:4] + ("*" * (length - 8)) + secret[-4:]


# Regex pattern definitions for known secret signatures
SECRET_PATTERNS = [
    {
        "id": "SEC-AWS-KEY",
        "name": "AWS Access Key ID",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        "min_entropy": 2.5,
    },
    {
        "id": "SEC-AWS-SECRET",
        "name": "AWS Secret Access Key",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "min_entropy": 3.8,
    },
    {
        "id": "SEC-GH-TOKEN",
        "name": "GitHub Personal Access Token",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"),
        "min_entropy": 3.0,
    },
    {
        "id": "SEC-GCP-KEY",
        "name": "Google Cloud API Key",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "min_entropy": 3.4,
    },
    {
        "id": "SEC-SLACK-TOKEN",
        "name": "Slack API Token",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
        "min_entropy": 3.0,
    },
    {
        "id": "SEC-STRIPE-KEY",
        "name": "Stripe API Key",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b((?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b"),
        "min_entropy": 3.2,
    },
    {
        "id": "SEC-JWT-TOKEN",
        "name": "JSON Web Token (JWT)",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "min_entropy": 3.8,
    },
    {
        "id": "SEC-PRIV-KEY",
        "name": "Private Cryptographic Key",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "min_entropy": 0.0,
    },
    {
        "id": "SEC-DB-URI",
        "name": "Database Connection String with Credentials",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^\s:@]+:[^\s:@]+@[^\s\/]+)\b"),
        "min_entropy": 2.8,
    },
    {
        "id": "SEC-OPENAI-KEY",
        "name": "OpenAI / HuggingFace API Key",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|hf_[a-zA-Z0-9]{34})\b"),
        "min_entropy": 3.2,
    },
    {
        "id": "SEC-GENERIC-SECRET",
        "name": "Generic High-Entropy Credential Assignment",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "pattern": re.compile(r"(?i)\b(?:api[_-]?key|auth[_-]?token|secret[_-]?key|client[_-]?secret|access[_-]?token|password|passwd|db_password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.\/+=]{16,})['\"]"),
        "min_entropy": 3.6,
    },
]

# Vulnerability pattern definitions matching common CWEs
VULNERABILITY_PATTERNS = [
    {
        "id": "VULN-CWE-89-CONCAT",
        "cwe": "CWE-89",
        "name": "SQL Injection via String Concatenation / Interpolation",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"""(?i)(?:cursor\.execute|conn\.execute|execute_query|db\.query)\s*\(\s*(?:f['"].*SELECT.*\{|['"].*SELECT.*\+|(?:f['"].*(?:INSERT|UPDATE|DELETE).*\{))""",
        ),
        "description": "SQL statement dynamically formed using string formatting or variable concatenation without parameter bindings.",
        "remediation": "Use parameterized queries (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) or ORM binding.",
    },
    {
        "id": "VULN-CWE-89-RAW",
        "cwe": "CWE-89",
        "name": "SQL Injection Raw Formatted Query",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"""(?i)(?:query|sql)\s*=\s*(?:f['"].*(?:SELECT|UPDATE|DELETE|INSERT).*\{|['"].*(?:SELECT|UPDATE|DELETE)\s+.*['"]\s*\+)""",
        ),
        "description": "Direct construction of SQL query string via interpolated expressions or concatenation.",
        "remediation": "Never format untrusted parameters directly into SQL text; utilize bind parameters.",
    },
    {
        "id": "VULN-CWE-327-MD5",
        "cwe": "CWE-327",
        "name": "Use of Broken Cryptographic Hash (MD5)",
        "severity": "HIGH",
        "pattern": re.compile(r"""(?i)(?:hashlib\.md5\(|crypto\.createHash\(['"]md5['"]\)|MD5\.new\()"""),
        "description": "MD5 suffers from known cryptographic collision weaknesses and is insecure for security functions.",
        "remediation": "Upgrade to SHA-256 (hashlib.sha256) for integrity or Argon2/bcrypt/PBKDF2 for password hashing.",
    },
    {
        "id": "VULN-CWE-327-SHA1",
        "cwe": "CWE-327",
        "name": "Use of Deprecated Cryptographic Hash (SHA-1)",
        "severity": "MEDIUM",
        "pattern": re.compile(r"""(?i)(?:hashlib\.sha1\(|crypto\.createHash\(['"]sha1['"]\)|SHA1\.new\()"""),
        "description": "SHA-1 has theoretical and practical collision attacks.",
        "remediation": "Replace with SHA-256 or SHA-3 algorithms.",
    },
    {
        "id": "VULN-CWE-327-DES",
        "cwe": "CWE-327",
        "name": "Use of Weak Block Cipher (DES / RC4 / ECB mode)",
        "severity": "CRITICAL",
        "pattern": re.compile(r"""(?i)(?:DES\.new|ARC4\.new|AES\.MODE_ECB|Blowfish\.new)"""),
        "description": "DES has inadequate key length (56 bits); ECB mode reveals plaintext patterns.",
        "remediation": "Use AES-GCM (AES.MODE_GCM) or ChaCha20-Poly1305 with authenticated encryption.",
    },
    {
        "id": "VULN-CWE-22-TRAVERSAL",
        "cwe": "CWE-22",
        "name": "Path Traversal via Unvalidated File Path",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"""(?i)(?:open\s*\(\s*(?:os\.path\.join\(.*request\.|request\.(?:args|form|params)|f['"].*\{user|.*(?:\.\./|\.\.\\)))"""
        ),
        "description": "Direct file system access using untrusted user input without path normalization and bounds checking.",
        "remediation": "Validate input using os.path.abspath and ensure the canonical path starts with the trusted base directory.",
    },
    {
        "id": "VULN-CWE-312-LEAK-LOG",
        "cwe": "CWE-312",
        "name": "Cleartext Storage / Transmission of Sensitive Data (Logging)",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)(?:logging\.(?:info|debug|warn|error)|print|console\.log)\s*\(\s*(?:f['"].*\{(?:password|passwd|auth_token|secret_key|api_key|token|access_token|credit_card)\}|.*,\s*(?:password|passwd|auth_token|secret_key|api_key|token)\b|['"].*(?:password|secret|token)\s*[:=]\s*['"]\s*\+)"""
        ),
        "description": "Writing sensitive authentication credentials or private data to application logs or standard output.",
        "remediation": "Redact or mask sensitive fields prior to logging, and exclude authentication headers.",
    },
    {
        "id": "VULN-CWE-78-CMD-INJ",
        "cwe": "CWE-78",
        "name": "OS Command Injection via Shell Execution",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"""(?i)(?:os\.system\s*\(|subprocess\.(?:call|Popen|run)\s*\(.*shell\s*=\s*True)"""
        ),
        "description": "Invoking system shell with dynamic strings risks arbitrary command injection.",
        "remediation": "Avoid shell=True; pass commands as a sanitized arguments list to subprocess.run(..., shell=False).",
    },
]


def parse_git_diff_lines(diff_text: str) -> List[Tuple[str, int, str]]:
    """
    Parses a unified git diff into added lines with their target file and line number.
    Returns list of tuples: (filename, line_number, added_line_content)
    """
    lines = diff_text.splitlines()
    results: List[Tuple[str, int, str]] = []

    current_file = "staged_changes.txt"
    current_line_no = 0
    is_unified_diff = False

    # Check if input resembles a git unified diff
    for line in lines[:20]:
        if line.startswith("diff --git") or line.startswith("--- ") or line.startswith("+++ "):
            is_unified_diff = True
            break

    if not is_unified_diff:
        # Treat as raw code paste (e.g. from Manual Code Paste Sandbox)
        for idx, line in enumerate(lines, start=1):
            results.append(("manual_input.txt", idx, line))
        return results

    # Unified diff parser
    for line in lines:
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
        elif line.startswith("+++ "):
            current_file = line[4:].strip()
        elif line.startswith("@@"):
            # @@ -a,b +c,d @@
            match = re.search(r"\+(\d+)", line)
            if match:
                current_line_no = int(match.group(1)) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            current_line_no += 1
            added_content = line[1:]  # strip leading '+'
            results.append((current_file, current_line_no, added_content))
        elif not line.startswith("-"):
            current_line_no += 1

    return results


def scan_content(
    text: str,
    ignore_patterns: Optional[List[str]] = None,
    filter_test_paths: bool = True,
) -> Dict[str, Any]:
    """
    Scans a diff or raw code content for secrets and CWE vulnerabilities.
    Returns:
        {
            "total_secrets": int,
            "total_vulnerabilities": int,
            "findings": list of finding objects,
            "cwe_hits": list of unique CWE IDs encountered,
            "max_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE"
        }
    """
    diff_lines = parse_git_diff_lines(text)
    findings: List[Dict[str, Any]] = []
    seen_finding_signatures = set()
    cwe_hits = set()

    patterns = ignore_patterns if ignore_patterns is not None else DEFAULT_IGNORED_PATH_PATTERNS

    for file_path, line_no, line_content in diff_lines:
        # Check path exclusions (e.g. tests, documentation)
        if filter_test_paths and file_path != "manual_input.txt":
            norm_path = file_path.replace("\\", "/").lower()
            file_name = norm_path.split("/")[-1]
            if any(fnmatch.fnmatch(norm_path, pat.lower()) or fnmatch.fnmatch(file_name, pat.lower()) for pat in patterns):
                continue
        line_stripped = line_content.strip()
        if not line_stripped or line_stripped.startswith(("#", "//", "/*", "*")):
            # Ignore pure comment lines to avoid false alarms on documentation examples
            # unless an actual high-entropy AWS or private key is in the comment
            is_key_in_comment = False
            for priv_check in ("AKIA", "-----BEGIN"):
                if priv_check in line_stripped:
                    is_key_in_comment = True
                    break
            if not is_key_in_comment and line_stripped.startswith(("#", "//")):
                continue

        # 1. Scan for Secrets
        for sec_rule in SECRET_PATTERNS:
            matches = sec_rule["pattern"].findall(line_content)
            for raw_match in matches:
                secret_str = raw_match if isinstance(raw_match, str) else raw_match[0]
                secret_str = secret_str.strip("'\"")
                entropy = calculate_entropy(secret_str)

                # Skip obvious generic dummy placeholders (e.g. "your_api_key_here")
                lower_val = secret_str.lower()
                if lower_val in {"your_api_key", "your_secret_key", "placeholder_token", "dummy_secret", "xxxxxxxxxxxxxxxx"}:
                    continue

                if entropy >= sec_rule["min_entropy"]:
                    masked = mask_secret(secret_str)
                    sig = f"SECRET:{sec_rule['id']}:{file_path}:{line_no}:{masked}"
                    if sig not in seen_finding_signatures:
                        seen_finding_signatures.add(sig)
                        cwe_hits.add(sec_rule["cwe"])
                        findings.append({
                            "type": "secret",
                            "rule_id": sec_rule["id"],
                            "title": sec_rule["name"],
                            "cwe": sec_rule["cwe"],
                            "severity": sec_rule["severity"],
                            "file": file_path,
                            "line": line_no,
                            "masked_value": masked,
                            "entropy": entropy,
                            "snippet": line_stripped[:120],
                            "description": f"Detected high-entropy secret ({sec_rule['name']}) with Shannon entropy score of {entropy}.",
                            "remediation": "Revoke the exposed key immediately and inject the credential via environment variables or secret store.",
                        })

        # 2. Scan for Vulnerabilities (CWEs)
        for vuln_rule in VULNERABILITY_PATTERNS:
            if vuln_rule["pattern"].search(line_content):
                sig = f"VULN:{vuln_rule['id']}:{file_path}:{line_no}"
                if sig not in seen_finding_signatures:
                    seen_finding_signatures.add(sig)
                    cwe_hits.add(vuln_rule["cwe"])
                    findings.append({
                        "type": "vulnerability",
                        "rule_id": vuln_rule["id"],
                        "title": vuln_rule["name"],
                        "cwe": vuln_rule["cwe"],
                        "severity": vuln_rule["severity"],
                        "file": file_path,
                        "line": line_no,
                        "masked_value": None,
                        "entropy": None,
                        "snippet": line_stripped[:120],
                        "description": vuln_rule["description"],
                        "remediation": vuln_rule["remediation"],
                    })

    # Determine overall maximum severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]
    max_severity = "SAFE"
    for sev in severity_order:
        if any(f["severity"] == sev for f in findings):
            max_severity = sev
            break

    total_secrets = sum(1 for f in findings if f["type"] == "secret")
    total_vulns = sum(1 for f in findings if f["type"] == "vulnerability")

    return {
        "total_secrets": total_secrets,
        "total_vulnerabilities": total_vulns,
        "findings": findings,
        "cwe_hits": list(cwe_hits),
        "max_severity": max_severity,
    }
