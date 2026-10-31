"""Automatically configures .git/hooks/pre-commit to enforce local secret and vulnerability auditing."""

import os
import stat
import sys
from pathlib import Path

# Locate project root
SCRIPTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPTS_DIR.parent.parent
GIT_DIR = PROJECT_ROOT / ".git"
HOOKS_DIR = GIT_DIR / "hooks"
PRE_COMMIT_HOOK = HOOKS_DIR / "pre-commit"

HOOK_BASH_TEMPLATE = """#!/bin/sh
# ==============================================================================
# CodeLeak Patrol - Local Pre-Commit Security Hook
# Automatically installed by backend/scripts/install_hook.py
# Zero external network exfiltration - 100% Local CI/CD Guard
# ==============================================================================

# Locate Python binary
if command -v python3 >/dev/null 2>&1; then
    PY_BIN=python3
elif command -v python >/dev/null 2>&1; then
    PY_BIN=python
else
    echo "[CodeLeak Patrol] Error: Python binary not found in PATH."
    exit 1
fi

# Locate repository root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "$REPO_ROOT" ]; then
    echo "[CodeLeak Patrol] Error: Cannot determine repository root."
    exit 1
fi

SCANNER_SCRIPT="$REPO_ROOT/backend/scripts/pre_commit_scanner.py"

if [ ! -f "$SCANNER_SCRIPT" ]; then
    echo "[CodeLeak Patrol] Warning: Scanner script not found at $SCANNER_SCRIPT"
    exit 0
fi

# Run the local scanner against staged changes
"$PY_BIN" "$SCANNER_SCRIPT"
HOOK_EXIT_CODE=$?

exit $HOOK_EXIT_CODE
"""


def install():
    print("=" * 60)
    print(" CodeLeak Patrol - Pre-Commit Hook Installer")
    print("=" * 60)
    print(f"Project root: {PROJECT_ROOT}")

    if not GIT_DIR.exists():
        print(f"[!] .git directory not found at {GIT_DIR}. Initializing git repository...")
        import subprocess

        subprocess.run(["git", "init", str(PROJECT_ROOT)], check=True)

    HOOKS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Writing hook to: {PRE_COMMIT_HOOK}")
    with open(PRE_COMMIT_HOOK, "w", encoding="utf-8", newline="\n") as f:
        f.write(HOOK_BASH_TEMPLATE)

    # Set executable permissions (0o755)
    try:
        current_perms = os.stat(PRE_COMMIT_HOOK).st_mode
        os.chmod(PRE_COMMIT_HOOK, current_perms | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception as perm_err:
        print(f"[Note] Note on permissions: {perm_err}")

    print("\n[SUCCESS] Pre-commit hook installed successfully!")
    print(f"Path: {PRE_COMMIT_HOOK}")
    print("Every 'git commit' will now automatically audit staged changes for:")
    print("  - Leaked API keys, JWT, SSH/RSA keys, cloud credentials, tokens")
    print("  - CWE vulnerabilities (CWE-89, CWE-327, CWE-22, CWE-312, CWE-78)")
    print("  - Zero external network exfiltration.")


if __name__ == "__main__":
    install()
