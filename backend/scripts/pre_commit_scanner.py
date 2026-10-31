"""Local CLI pre-commit scanner invoked by .git/hooks/pre-commit to audit staged diffs."""

import subprocess
import sys
from pathlib import Path

# Add backend directory to path
BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.database import init_db, save_audit
from app.ollama_client import analyze_diff_with_llm
from app.rag_engine import retrieve_policies_for_findings
from app.scanner import scan_content

# ANSI Terminal Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def get_staged_diff() -> str:
    """Retrieves staged changes using git diff --cached from project root."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--no-color"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout
    except Exception as exc:
        print(f"{YELLOW}[CodeLeak Patrol] Warning: Unable to read git staged diff: {exc}{RESET}")
        return ""


def main():
    print(f"\n{CYAN}{BOLD}------------------------------------------------------------{RESET}")
    print(f"{CYAN}{BOLD}   CodeLeak Patrol - Local Pre-Commit Security Auditor       {RESET}")
    print(f"{CYAN}{BOLD}------------------------------------------------------------{RESET}")

    diff_text = get_staged_diff()

    if not diff_text.strip():
        print(f"{YELLOW}No staged changes detected. Skipping audit.{RESET}\n")
        sys.exit(0)

    print(f"{CYAN}[*] Auditing staged git diff ({len(diff_text)} bytes)...{RESET}")

    # 1. Run secret & vulnerability scan
    scan_results = scan_content(diff_text)
    findings = scan_results["findings"]
    cwe_hits = scan_results["cwe_hits"]

    # 2. Vector policy retrieval
    finding_titles = [f["title"] for f in findings]
    policies = retrieve_policies_for_findings(cwe_hits, finding_titles, top_k=2)

    # 3. LLM / Heuristic Reasoning
    analysis = analyze_diff_with_llm(diff_text, scan_results, policies)

    # 4. Save audit to local SQLite history
    try:
        init_db()
        save_audit(
            source="git_hook",
            commit_blocked=analysis["commit_blocked"],
            risk_level=analysis["risk_level"],
            summary=analysis["summary"],
            total_secrets=scan_results["total_secrets"],
            total_vulnerabilities=scan_results["total_vulnerabilities"],
            raw_input=diff_text,
            llm_engine=analysis["engine_used"],
            remediation_items=analysis["remediation_checklist"],
            findings=findings,
            policies=policies,
        )
    except Exception as db_exc:
        # Non-blocking if DB write encounters file lock
        pass

    # 5. Output results to developer console
    if analysis["commit_blocked"]:
        print(f"\n{RED}{BOLD}============================================================{RESET}")
        print(f"{RED}{BOLD} [BLOCKED] COMMIT REJECTED: HIGH-RISK SECURITY VIOLATIONS   {RESET}")
        print(f"{RED}{BOLD}============================================================{RESET}")
        print(f"{RED}Risk Level:{RESET} {BOLD}{analysis['risk_level']}{RESET}")
        print(f"{RED}Summary:{RESET}    {analysis['summary']}\n")

        print(f"{BOLD}Detected Security Findings:{RESET}")
        for idx, f in enumerate(findings, start=1):
            if f["type"] == "secret":
                print(f"  {RED}{BOLD}[{idx}] EXPOSED SECRET:{RESET} {f['title']}")
                print(f"      File:    {f['file']}:{f['line']}")
                print(f"      Masked:  {f['masked_value']} (Shannon Entropy: {f['entropy']})")
                print(f"      Snippet: {f['snippet']}")
            else:
                print(f"  {YELLOW}{BOLD}[{idx}] VULNERABILITY:{RESET} {f['title']} ({f['cwe']})")
                print(f"      File:    {f['file']}:{f['line']}")
                print(f"      Snippet: {f['snippet']}")

        print(f"\n{BOLD}Actionable Remediation Checklist:{RESET}")
        for rem in analysis.get("remediation_checklist", []):
            print(f"  {RED}[ ]{RESET} {BOLD}{rem['task']}{RESET}: {rem['description']}")

        print(f"\n{YELLOW}Tip: View the interactive dashboard at http://127.0.0.1:8080 (or port 8000){RESET}")
        print(f"{RED}{BOLD}Aborting commit. Please resolve the security findings above.{RESET}\n")
        sys.exit(1)
    else:
        print(f"\n{GREEN}{BOLD}============================================================{RESET}")
        print(f"{GREEN}{BOLD} [PASSED] CodeLeak Patrol: Staged diff verified. Clean!     {RESET}")
        print(f"{GREEN}{BOLD}============================================================{RESET}")
        print(f"{GREEN}Risk Level:{RESET} {analysis['risk_level']}")
        print(f"{GREEN}Summary:{RESET}    {analysis['summary']}")
        print(f"{GREEN}Allowing commit to proceed.{RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
