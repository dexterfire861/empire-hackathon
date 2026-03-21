import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root or specter/ directory
_config_dir = Path(__file__).resolve().parent
load_dotenv(_config_dir.parent / ".env")
load_dotenv(_config_dir / ".env")

# API Keys
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
GOOGLE_CSE_API_KEY = os.getenv("GOOGLE_CSE_API_KEY", "")
GOOGLE_CSE_CX = os.getenv("GOOGLE_CSE_CX", "")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
BREACHDIRECTORY_RAPIDAPI_KEY = os.getenv("BREACHDIRECTORY_RAPIDAPI_KEY", "")
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")

# Agent settings
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
MAX_SCAN_ROUNDS = 5
SUBPROCESS_TIMEOUT = 120  # seconds
MAX_GOOGLE_QUERIES_PER_SCAN = 10
API_TIMEOUT = 15  # seconds for HTTP API calls
