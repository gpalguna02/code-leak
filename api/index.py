import os
import sys
from pathlib import Path

# Add backend directory to sys.path so that 'app.main' and relative imports resolve
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Ensure Vercel serverless flag is active
os.environ["VERCEL"] = "1"

# Import FastAPI application instance
from app.main import app

