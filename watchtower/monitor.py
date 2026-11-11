"""Real-time protection: watches folders and scans files as they land."""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import config
from .quarantine import Quarantine
from .scanner import MALICIOUS, ScanResult, Scanner

log = logging.getLogger("watchtower.monitor")


class _Handler(FileSystemEventHandler):
    def __init__(self, guard: "RealTimeGuard"):
        self.guard = guard

    def on_created(self, event):
        if not event.is_directory:
            self.guard.enqueue(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.guard.enqueue(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.guard.enqueue(event.dest_path)


class RealTimeGuard:
    """Debounces events (browsers write files in pieces), then scans."""

    SETTLE_SECONDS = 1.5

    def __init__(self, scanner: Scanner, quarantine: Quarantine | None = None,
                 auto_quarantine: bool = True,
                 on_threat: Callable[[ScanResult], None] | None = None,
                 paths: list[Path] | None = None):
        self.scanner = scanner
        self.quarantine = quarantine or Quarantine()
        self.auto_quarantine = auto_quarantine
        self.on_threat = on_threat
        self.paths = paths or config.realtime_targets()
        self._pending: dict[str, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._observer: Observer | None = None
        self._worker: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._observer is not None

    def enqueue(self, path: str) -> None:
        if Path(path).suffix.lower() in (".crdownload", ".part", ".tmp", ".partial"):
            return
        with self._lock:
            self._pending[path] = time.time()

    def _loop(self) -> None:
        while not self._stop.wait(0.5):
            now = time.time()
            with self._lock:
                ready = [p for p, t in self._pending.items() if now - t >= self.SETTLE_SECONDS]
                for p in ready:
                    del self._pending[p]
            for p in ready:
                self._handle(p)

    def _handle(self, path: str) -> None:
        if str(config.QUARANTINE_DIR) in path:
            return
        res = self.scanner.scan_file(path)
        if not res.is_threat:
            return
        log.warning("Real-time: %s %s (%s)", res.verdict, path, res.threat)
        if self.auto_quarantine and res.verdict == MALICIOUS:
            try:
                self.quarantine.add(path, res.threat or "Unknown", res.sha256 or "")
                res.reasons.append("auto-quarantined")
            except Exception as exc:
                log.error("Quarantine failed for %s: %s", path, exc)
        if self.on_threat:
            self.on_threat(res)

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._observer = Observer()
        handler = _Handler(self)
        for p in self.paths:
            self._observer.schedule(handler, str(p), recursive=True)
            log.info("Real-time protection watching %s", p)
        self._observer.start()
        self._worker = threading.Thread(target=self._loop, daemon=True)
        self._worker.start()

    def stop(self) -> None:
        if not self.running:
            return
        self._stop.set()
        self._observer.stop()
        self._observer.join(timeout=5)
        self._observer = None
