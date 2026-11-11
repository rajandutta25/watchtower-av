"""Paths and tunables for Watchtower AV."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "Watchtower AV"
VERSION = "0.1.0"

IS_WINDOWS = sys.platform.startswith("win")


def _data_root() -> Path:
    override = os.environ.get("WATCHTOWER_HOME")
    if override:
        return Path(override)
    if IS_WINDOWS:
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "WatchtowerAV"
    return Path.home() / ".watchtower"


def _bundle_dir() -> Path:
    # Works both from source and from a PyInstaller one-file build.
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


DATA_DIR = _data_root()
QUARANTINE_DIR = DATA_DIR / "quarantine"
LOG_DIR = DATA_DIR / "logs"
SIG_DB = DATA_DIR / "signatures.db"
USER_RULES_DIR = DATA_DIR / "rules"            # drop extra .yar files here
BUNDLED_RULES_DIR = _bundle_dir() / "rules"

# Scanning limits
MAX_FILE_SIZE = 100 * 1024 * 1024              # skip files over 100 MB
READ_CHUNK = 1024 * 1024
SCAN_THREADS = max(2, (os.cpu_count() or 4))

# Verdict thresholds (score 0-100)
MALICIOUS_SCORE = 70
SUSPICIOUS_SCORE = 40

# File types worth scanning in quick / real-time mode
RISKY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".msi", ".msp",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".bat", ".cmd", ".lnk", ".jar", ".docm", ".xlsm", ".pptm", ".iso", ".img",
    ".zip", ".rar", ".7z", ".com", ".pif", ".reg", ".txt",
}

SKIP_DIRS_WINDOWS = {
    r"c:\windows\winsxs", r"c:\windows\installer", r"c:\$recycle.bin",
    r"c:\system volume information",
}


def quick_scan_targets() -> list[Path]:
    home = Path.home()
    targets = [home / "Downloads", home / "Desktop", home / "Documents"]
    if IS_WINDOWS:
        env = os.environ
        for var in ("TEMP", "APPDATA", "LOCALAPPDATA"):
            if env.get(var):
                targets.append(Path(env[var]))
        targets.append(Path(env.get("PROGRAMDATA", r"C:\ProgramData")) /
                       r"Microsoft\Windows\Start Menu\Programs\Startup")
        targets.append(Path(env.get("APPDATA", "")) /
                       r"Microsoft\Windows\Start Menu\Programs\Startup")
    else:
        targets.append(Path("/tmp"))
    return [t for t in targets if t.exists()]


def realtime_targets() -> list[Path]:
    home = Path.home()
    targets = [home / "Downloads", home / "Desktop"]
    if IS_WINDOWS and os.environ.get("TEMP"):
        targets.append(Path(os.environ["TEMP"]))
    return [t for t in targets if t.exists()]


def full_scan_targets() -> list[Path]:
    if IS_WINDOWS:
        import string
        return [Path(f"{d}:\\") for d in string.ascii_uppercase if Path(f"{d}:\\").exists()]
    return [Path("/")]


def ensure_dirs() -> None:
    for d in (DATA_DIR, QUARANTINE_DIR, LOG_DIR, USER_RULES_DIR):
        d.mkdir(parents=True, exist_ok=True)
