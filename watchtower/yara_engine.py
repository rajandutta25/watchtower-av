"""Compiles bundled + user YARA rules once and matches file content."""
from __future__ import annotations

import logging
from pathlib import Path

from . import config

log = logging.getLogger("watchtower.yara")

try:
    import yara
except ImportError:
    yara = None


class YaraEngine:
    def __init__(self, extra_dirs: list[Path] | None = None):
        self.rules = None
        self.rule_count = 0
        if yara is None:
            log.warning("yara-python not installed; YARA scanning disabled")
            return
        dirs = [config.BUNDLED_RULES_DIR, config.USER_RULES_DIR] + list(extra_dirs or [])
        sources: dict[str, str] = {}
        for d in dirs:
            if not d.exists():
                continue
            for f in sorted(list(d.glob("*.yar")) + list(d.glob("*.yara"))):
                try:
                    yara.compile(filepath=str(f))  # validate individually
                    sources[f"{d.name}_{f.stem}"] = str(f)
                except yara.Error as exc:
                    log.error("Skipping bad rule file %s: %s", f, exc)
        if sources:
            self.rules = yara.compile(filepaths=sources)
            self.rule_count = sum(1 for _ in self.rules)

    def match(self, data: bytes) -> list[tuple[int, str, str | None]]:
        """Returns [(score, reason, family)]."""
        if not self.rules:
            return []
        try:
            matches = self.rules.match(data=data, timeout=30)
        except Exception as exc:
            log.debug("yara error: %s", exc)
            return []
        out = []
        for m in matches:
            score = int(m.meta.get("score", 50))
            desc = m.meta.get("description", m.rule)
            out.append((score, f"YARA {m.rule}: {desc}", m.meta.get("family")))
        return out
