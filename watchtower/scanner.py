"""Core scan engine: signatures -> YARA -> heuristics -> verdict."""
from __future__ import annotations

import hashlib
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

from . import config, heuristics
from .signatures import SignatureDB
from .yara_engine import YaraEngine

log = logging.getLogger("watchtower.scanner")

CLEAN, SUSPICIOUS, MALICIOUS, ERROR, SKIPPED = "clean", "suspicious", "malicious", "error", "skipped"
CONTENT_READ_LIMIT = 8 * 1024 * 1024  # bytes passed to YARA / script heuristics


@dataclass
class ScanResult:
    path: str
    verdict: str = CLEAN
    score: int = 0
    threat: str | None = None
    sha256: str | None = None
    reasons: list[str] = field(default_factory=list)

    @property
    def is_threat(self) -> bool:
        return self.verdict in (MALICIOUS, SUSPICIOUS)


@dataclass
class ScanStats:
    scanned: int = 0
    skipped: int = 0
    errors: int = 0
    threats: list[ScanResult] = field(default_factory=list)


class Scanner:
    def __init__(self, sigdb: SignatureDB | None = None, yara_engine: YaraEngine | None = None):
        config.ensure_dirs()
        self.sigdb = sigdb or SignatureDB()
        self.yara = yara_engine or YaraEngine()
        self._cancel = threading.Event()

    # ------------------------------------------------------------------ file
    def scan_file(self, path: str | os.PathLike) -> ScanResult:
        p = Path(path)
        res = ScanResult(path=str(p))
        try:
            st = p.stat()
            if not p.is_file():
                res.verdict = SKIPPED
                return res
            if st.st_size > config.MAX_FILE_SIZE:
                res.verdict = SKIPPED
                res.reasons.append("file too large")
                return res

            h = hashlib.sha256()
            head = bytearray()
            with open(p, "rb") as fh:
                while chunk := fh.read(config.READ_CHUNK):
                    h.update(chunk)
                    if len(head) < CONTENT_READ_LIMIT:
                        head += chunk[: CONTENT_READ_LIMIT - len(head)]
            res.sha256 = h.hexdigest()
            data = bytes(head)

            # 1. exact signature
            name = self.sigdb.lookup(res.sha256)
            if name:
                res.verdict, res.score, res.threat = MALICIOUS, 100, name
                res.reasons.append(f"known malware hash ({name})")
                return res

            # 2. YARA + 3. heuristics
            score = 0
            for s, reason, family in self.yara.match(data):
                score += s
                res.reasons.append(reason)
                if family and (res.threat is None or s >= 70):
                    res.threat = family
            for s, reason in heuristics.analyze(p, data):
                score += s
                res.reasons.append(reason)

            res.score = max(0, min(100, score))
            if res.score >= config.MALICIOUS_SCORE:
                res.verdict = MALICIOUS
                res.threat = res.threat or "Heur.Malicious"
            elif res.score >= config.SUSPICIOUS_SCORE:
                res.verdict = SUSPICIOUS
                res.threat = res.threat or "Heur.Suspicious"
        except (PermissionError, FileNotFoundError, OSError) as exc:
            res.verdict = ERROR
            res.reasons.append(str(exc))
        return res

    # ------------------------------------------------------------------ tree
    def cancel(self) -> None:
        self._cancel.set()

    def iter_files(self, roots: Iterable[Path], risky_only: bool = False) -> Iterator[Path]:
        skip = {s.lower() for s in config.SKIP_DIRS_WINDOWS}
        for root in roots:
            root = Path(root)
            if root.is_file():
                yield root
                continue
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                if self._cancel.is_set():
                    return
                dirnames[:] = [d for d in dirnames
                               if os.path.join(dirpath, d).lower() not in skip
                               and not os.path.islink(os.path.join(dirpath, d))]
                for fn in filenames:
                    if risky_only and Path(fn).suffix.lower() not in config.RISKY_EXTENSIONS:
                        continue
                    yield Path(dirpath) / fn

    def scan_paths(
        self,
        roots: Iterable[Path],
        risky_only: bool = False,
        on_result: Callable[[ScanResult], None] | None = None,
        threads: int | None = None,
    ) -> ScanStats:
        self._cancel.clear()
        stats = ScanStats()
        lock = threading.Lock()

        def work(path: Path) -> None:
            if self._cancel.is_set():
                return
            r = self.scan_file(path)
            with lock:
                if r.verdict == SKIPPED:
                    stats.skipped += 1
                elif r.verdict == ERROR:
                    stats.errors += 1
                else:
                    stats.scanned += 1
                    if r.is_threat:
                        stats.threats.append(r)
                        log.warning("%s %s [%s] score=%d %s", r.verdict.upper(), r.path,
                                    r.threat, r.score, "; ".join(r.reasons))
            if on_result:
                on_result(r)

        with ThreadPoolExecutor(max_workers=threads or config.SCAN_THREADS) as pool:
            for _ in pool.map(work, self.iter_files(roots, risky_only)):
                pass
        return stats
