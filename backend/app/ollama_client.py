"""Local Ollama client (gemma3:1b) with structured JSON parsing and graceful heuristic fallback."""

import json
import logging
import re
from typing import Any, Dict, List, Optional
import requests

from app.config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are CodeLeak Patrol, an expert local DevSecOps security auditor.
Analyze the provided code diff, detected secrets, and retrieved CWE policies.
Assess whether the git commit must be BLOCKED or ALLOWED.
Any exposed secret (API key, private key, token, cloud credential) or critical vulnerability (SQL Injection, Path Traversal, Command Injection) MUST have "commit_blocked": true and risk_level "CRITICAL" or "HIGH".

You must respond ONLY with a valid JSON object strictly matching this schema:
{
  "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE",
  "commit_blocked": true | false,
  "summary": "Concise 1-3 sentence summary of security findings and commit recommendation.",
  "remediation_checklist": [
    {
      "id": "rem-1",
      "task": "Action title",
      "description": "Specific remediation instructions.",
      "priority": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    }
  ]
}
"""


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """Extracts and parses JSON from raw LLM output."""
    if not text:
        return None
    text = text.strip()

    # Try direct parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # Try extracting from ```json ... ``` code fence
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fence_match:
        try:
            return json.loads(fence_match.group(1).strip())
        except Exception:
            pass

    # Try finding outermost { ... }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except Exception:
            pass

    return None


def run_heuristic_analysis(
    scan_results: Dict[str, Any],
    policies: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Graceful heuristic fallback engine when Ollama is unavailable.
    Provides deterministic, high-fidelity security analysis and actionable checklists.
    """
    findings = scan_results.get("findings", [])
    secrets = [f for f in findings if f.get("type") == "secret"]
    vulns = [f for f in findings if f.get("type") == "vulnerability"]

    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    remediation_checklist: List[Dict[str, Any]] = []
    task_idx = 1

    if critical_count > 0:
        risk_level = "CRITICAL"
        commit_blocked = True
    elif high_count > 0:
        risk_level = "HIGH"
        commit_blocked = True
    elif medium_count > 0:
        risk_level = "MEDIUM"
        commit_blocked = False
    elif findings:
        risk_level = "LOW"
        commit_blocked = False
    else:
        risk_level = "SAFE"
        commit_blocked = False

    # Build contextual remediation tasks for secrets
    if secrets:
        remediation_checklist.append({
            "id": f"rem-{task_idx}",
            "task": "Rotate & Revoke Exposed Credentials",
            "description": f"Immediately invalidate the {len(secrets)} leaked credential(s) in the respective service console (AWS, GitHub, Stripe, DB).",
            "priority": "CRITICAL",
        })
        task_idx += 1
        remediation_checklist.append({
            "id": f"rem-{task_idx}",
            "task": "Move Credentials to Local Environment (.env)",
            "description": "Store secrets in environment variables or a local secret store. Ensure .env is listed in .gitignore.",
            "priority": "CRITICAL",
        })
        task_idx += 1
        remediation_checklist.append({
            "id": f"rem-{task_idx}",
            "task": "Purge Secret from Local Git History",
            "description": "If staged or committed, use 'git reset' or 'git-filter-repo' to prevent history contamination.",
            "priority": "HIGH",
        })
        task_idx += 1

    # Build contextual remediation tasks for CWE vulnerabilities
    for v in vulns:
        cwe = v.get("cwe")
        title = v.get("title", "")
        if cwe == "CWE-89":
            remediation_checklist.append({
                "id": f"rem-{task_idx}",
                "task": "Refactor Dynamic SQL to Parameterized Queries",
                "description": f"Address SQL injection at {v.get('file')}:{v.get('line')}. Replace string concatenation with prepared statement placeholders.",
                "priority": "CRITICAL",
            })
            task_idx += 1
        elif cwe == "CWE-327":
            remediation_checklist.append({
                "id": f"rem-{task_idx}",
                "task": "Upgrade Broken Cryptographic Algorithm",
                "description": f"Replace weak crypto pattern ({title}) at {v.get('file')}:{v.get('line')} with SHA-256 or AES-GCM.",
                "priority": "HIGH",
            })
            task_idx += 1
        elif cwe == "CWE-22":
            remediation_checklist.append({
                "id": f"rem-{task_idx}",
                "task": "Sanitize Path Traversal Vectors",
                "description": f"Validate file path at {v.get('file')}:{v.get('line')} using os.path.abspath and common directory root verification.",
                "priority": "CRITICAL",
            })
            task_idx += 1
        elif cwe == "CWE-312":
            remediation_checklist.append({
                "id": f"rem-{task_idx}",
                "task": "Remove Sensitive Data from Logs",
                "description": f"Eliminate plain logging of credentials at {v.get('file')}:{v.get('line')}.",
                "priority": "HIGH",
            })
            task_idx += 1
        elif cwe == "CWE-78":
            remediation_checklist.append({
                "id": f"rem-{task_idx}",
                "task": "Eliminate Shell Execution Command Injection",
                "description": f"Avoid shell=True in subprocess call at {v.get('file')}:{v.get('line')}. Use sanitized argument lists.",
                "priority": "CRITICAL",
            })
            task_idx += 1

    # In case no findings were present
    if not findings:
        remediation_checklist.append({
            "id": f"rem-{task_idx}",
            "task": "Pre-commit Security Check Passed",
            "description": "No hardcoded secrets or CWE vulnerability patterns detected in the analyzed diff.",
            "priority": "LOW",
        })
        summary = "Audit PASSED: No secrets or critical CWE violations detected. Code is safe to commit."
    else:
        status_str = "BLOCKED" if commit_blocked else "WARNING"
        summary = (
            f"Audit {status_str}: Detected {len(secrets)} secret(s) and {len(vulns)} vulnerability pattern(s). "
            f"Risk Level: {risk_level}. Commit is {'strictly blocked' if commit_blocked else 'allowed with warnings'}."
        )

    return {
        "risk_level": risk_level,
        "commit_blocked": commit_blocked,
        "summary": summary,
        "remediation_checklist": remediation_checklist,
        "engine_used": "heuristic-fallback",
    }


def analyze_diff_with_llm(
    diff_text: str,
    scan_results: Dict[str, Any],
    policies: List[Dict[str, Any]],
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Sends diff and scan context to Ollama (gemma3:1b).
    Gracefully falls back to heuristic engine if Ollama is offline or fails.
    """
    selected_model = model or OLLAMA_MODEL
    url = f"{OLLAMA_BASE_URL}/api/generate"

    # Format context for LLM
    findings_summary = []
    for f in scan_results.get("findings", []):
        if f.get("type") == "secret":
            findings_summary.append(
                f"- [SECRET] {f.get('title')} in {f.get('file')}:{f.get('line')} (Masked: {f.get('masked_value')}, Entropy: {f.get('entropy')})"
            )
        else:
            findings_summary.append(
                f"- [VULN] {f.get('title')} ({f.get('cwe')}) in {f.get('file')}:{f.get('line')} -> {f.get('snippet')}"
            )

    policies_summary = []
    for p in policies:
        policies_summary.append(f"- {p.get('title')} [{p.get('severity')}]: {p.get('document')[:160]}...")

    prompt = f"""AUDIT REQUEST:
Diff Snippet (first 1500 chars):
{diff_text[:1500]}

Detected High-Entropy Secrets & Vulnerabilities:
{chr(10).join(findings_summary) if findings_summary else "No automated pattern matches."}

Retrieved Company Policies & CWE Rules:
{chr(10).join(policies_summary) if policies_summary else "No specific policies matched."}

Evaluate the risk and provide the required JSON response.
"""

    payload = {
        "model": selected_model,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "format": "json",
    }

    try:
        response = requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT_SECONDS)
        if response.status_code == 200:
            resp_data = response.json()
            raw_response_text = resp_data.get("response", "")
            parsed = extract_json_from_text(raw_response_text)
            if parsed and isinstance(parsed, dict) and "risk_level" in parsed:
                # Validate and ensure required fields
                risk = str(parsed.get("risk_level", "HIGH")).upper()
                blocked = bool(parsed.get("commit_blocked", risk in {"CRITICAL", "HIGH"}))

                # Safety check: if scanner found critical secrets, force commit_blocked
                if scan_results.get("total_secrets", 0) > 0 or scan_results.get("max_severity") == "CRITICAL":
                    blocked = True
                    if risk not in {"CRITICAL", "HIGH"}:
                        risk = "CRITICAL"

                remediations = parsed.get("remediation_checklist", [])
                if not isinstance(remediations, list) or len(remediations) == 0:
                    heuristic = run_heuristic_analysis(scan_results, policies)
                    remediations = heuristic["remediation_checklist"]

                return {
                    "risk_level": risk,
                    "commit_blocked": blocked,
                    "summary": parsed.get("summary", "Audit completed via Ollama gemma3:1b."),
                    "remediation_checklist": remediations,
                    "engine_used": f"ollama:{selected_model}",
                }
    except Exception as exc:
        logger.debug("Ollama offline (%s). Falling back to heuristic engine.", exc)

    # Fallback to local heuristic engine
    return run_heuristic_analysis(scan_results, policies)


def check_ollama_health() -> Dict[str, Any]:
    """Checks whether local Ollama service is reachable and lists available models."""
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=1.5)
        if resp.status_code == 200:
            models_info = resp.json().get("models", [])
            model_names = [m.get("name", "") for m in models_info]
            return {
                "available": True,
                "url": OLLAMA_BASE_URL,
                "models": model_names,
                "target_model": OLLAMA_MODEL,
                "target_model_installed": any(OLLAMA_MODEL in m for m in model_names),
            }
    except Exception:
        pass

    return {
        "available": False,
        "url": OLLAMA_BASE_URL,
        "target_model": OLLAMA_MODEL,
        "message": "Ollama service offline or unreachable. Heuristic engine active as fallback.",
    }
