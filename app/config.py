import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Detect operating system
IS_LINUX = platform.system().lower() == "linux"

# Directory for panel data (DB, backups)
DATA_DIR = Path(os.getenv("AWG_PANEL_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# AmneziaWG config root directory
if IS_LINUX:
    DEFAULT_AWG_DIR = Path("/etc/amnezia/amneziawg")
else:
    DEFAULT_AWG_DIR = DATA_DIR / "amneziawg"

AWG_DIR = Path(os.getenv("AWG_DIR", DEFAULT_AWG_DIR))
AWG_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "awg_panel.db"

HOST = os.getenv("PANEL_HOST", "0.0.0.0")
PORT = int(os.getenv("PANEL_PORT", "8088"))

SECRET_KEY = os.getenv("SECRET_KEY", "awg-secret-key-change-in-production")

DEFAULT_DNS = os.getenv("DEFAULT_DNS", "1.1.1.1, 8.8.8.8")
DEFAULT_MTU = int(os.getenv("DEFAULT_MTU", "1200"))
