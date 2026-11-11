"""Quarantine vault.

Files are XOR-obfuscated so they can't be executed or re-detected by other
AV products, and stored with a JSON sidecar recording where they came from.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from . import config

log = logging.getLogger("watchtower.quarantine")
KEY = 0xA7


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    threat: str
    sha256: str
    quarantined_at: float

    @property
    def when(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(self.quarantined_at))


def _xor(data: bytes) -> bytes:
    return bytes(b ^ KEY for b in data)


class Quarantine:
    def __init__(self, root: Path | None = None):
        self.root = Path(root or config.QUARANTINE_DIR)
        self.root.mkdir(parents=True, exist_ok=True)

    def add(self, path: str, threat: str = "Unknown", sha256: str = "") -> QuarantineItem:
        src = Path(path)
        qid = uuid.uuid4().hex
        data = src.read_bytes()
        (self.root / f"{qid}.bin").write_bytes(_xor(data))
        item = QuarantineItem(qid, str(src.resolve()), threat, sha256, time.time())
        (self.root / f"{qid}.json").write_text(json.dumps(asdict(item), indent=2))
        try:
            src.unlink()
        except PermissionError:
            # File is locked (e.g. running). Schedule deletion at next reboot on Windows.
            if config.IS_WINDOWS:
                import ctypes
                ctypes.windll.kernel32.MoveFileExW(str(src), None, 0x4)  # DELAY_UNTIL_REBOOT
                log.warning("%s locked; will be removed at reboot", src)
            else:
                raise
        log.info("Quarantined %s as %s (%s)", src, qid, threat)
        return item

    def list(self) -> list[QuarantineItem]:
        items = []
        for meta in self.root.glob("*.json"):
            try:
                items.append(QuarantineItem(**json.loads(meta.read_text())))
            except Exception:
                continue
        return sorted(items, key=lambda i: i.quarantined_at, reverse=True)

    def restore(self, qid: str, dest: str | None = None) -> Path:
        meta = self.root / f"{qid}.json"
        item = QuarantineItem(**json.loads(meta.read_text()))
        target = Path(dest or item.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_xor((self.root / f"{qid}.bin").read_bytes()))
        self.delete(qid)
        log.info("Restored %s to %s", qid, target)
        return target

    def delete(self, qid: str) -> None:
        for ext in (".bin", ".json"):
            f = self.root / f"{qid}{ext}"
            if f.exists():
                os.remove(f)
