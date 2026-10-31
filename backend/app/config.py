"""Configuration settings for AirGap Sentinel."""

import os
import shutil
import tempfile
from pathlib import Path

# Paths
APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

# Detect serverless / cloud read-only environments (Vercel, AWS Lambda, Render)
IS_SERVERLESS = bool(
    os.environ.get("VERCEL")
    or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    or os.environ.get("LAMBDA_TASK_ROOT")
)

TEMP_DATA_DIR = Path(tempfile.gettempdir()) / "airgap_data"

if IS_SERVERLESS:
    DATA_DIR = TEMP_DATA_DIR
else:
    DATA_DIR = BACKEND_DIR / "data"

try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except (OSError, PermissionError):
    DATA_DIR = TEMP_DATA_DIR
    DATA_DIR.mkdir(parents=True, exist_ok=True)

SQLITE_DB_PATH = DATA_DIR / "audits.db"
CHROMA_DB_PATH = DATA_DIR / "chroma_db"

try:
    CHROMA_DB_PATH.mkdir(parents=True, exist_ok=True)
except (OSError, PermissionError):
    pass

# When running in serverless environment (e.g. Vercel), copy pre-seeded database & policies to writable temp
if IS_SERVERLESS:
    src_data = BACKEND_DIR / "data"
    if src_data.exists():
        src_db = src_data / "audits.db"
        if src_db.exists() and not SQLITE_DB_PATH.exists():
            try:
                shutil.copy2(src_db, SQLITE_DB_PATH)
            except Exception:
                pass
        src_chroma = src_data / "chroma_db"
        if src_chroma.exists():
            for p in src_chroma.glob("*.json"):
                dst_p = CHROMA_DB_PATH / p.name
                if not dst_p.exists():
                    try:
                        shutil.copy2(p, dst_p)
                    except Exception:
                        pass



# Local Network / API settings
API_HOST = os.environ.get("CODELEAK_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("CODELEAK_PORT", "8000"))

# Local LLM settings (Ollama)
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma3:1b")
OLLAMA_TIMEOUT_SECONDS = float(os.environ.get("OLLAMA_TIMEOUT", "6.0"))

# Scanner thresholds
ENTROPY_THRESHOLD_STRICT = 3.6
ENTROPY_THRESHOLD_TOKEN = 3.2
MAX_DIFF_SIZE_BYTES = 5 * 1024 * 1024  # 5MB diff safety limit

# Files and paths excluded from pre-commit blocking (e.g. documentation, test fixtures)
DEFAULT_IGNORED_PATH_PATTERNS = [
    "*.md",
    "tests/*",
    "*/tests/*",
    "*test_*.py",
    "*.test.*",
    "*.spec.*",
]

# Blocking policy: CRITICAL and HIGH findings block git commit by default
BLOCKING_RISK_LEVELS = {"CRITICAL", "HIGH"}
