"""SHA-256 signature database (SQLite).

Import community hash feeds (e.g. MalwareBazaar's SHA-256 export) with
`watchtower update-sigs <file>`; one hash per line, optional ",name" suffix.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from . import config

# EICAR standard antivirus test file (harmless). Lets users verify detection.
BUILTIN = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
    "8b3f191819931d1f2cef7289239b5f77c00b079847b9c2636e56854d1e5eff71": "EICAR-Test-File (crlf)",
}


class SignatureDB:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or config.SIG_DB)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS sigs (sha256 TEXT PRIMARY KEY, name TEXT, source TEXT)"
        )
        self._conn.commit()

    def lookup(self, sha256: str) -> str | None:
        sha256 = sha256.lower()
        if sha256 in BUILTIN:
            return BUILTIN[sha256]
        with self._lock:
            row = self._conn.execute(
                "SELECT name FROM sigs WHERE sha256=?", (sha256,)
            ).fetchone()
        return row[0] if row else None

    def add(self, sha256: str, name: str = "Malware.Generic", source: str = "user") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO sigs VALUES (?,?,?)", (sha256.lower(), name, source)
            )
            self._conn.commit()

    def import_file(self, file: Path, source: str | None = None) -> int:
        """Import hashes from a text/CSV file. Lines starting with # are ignored."""
        source = source or Path(file).name
        rows = []
        with open(file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip().strip('"')
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip().strip('"') for p in line.split(",")]
                h = parts[0].lower()
                if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                    name = parts[1] if len(parts) > 1 and parts[1] else "Malware.Generic"
                    rows.append((h, name, source))
        with self._lock:
            self._conn.executemany("INSERT OR REPLACE INTO sigs VALUES (?,?,?)", rows)
            self._conn.commit()
        return len(rows)

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM sigs").fetchone()[0] + len(BUILTIN)
