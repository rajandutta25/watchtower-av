"""Scan running processes: their executables plus behavioural red flags."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import psutil

from . import config
from .scanner import Scanner

log = logging.getLogger("watchtower.process")

USER_WRITABLE_HINTS = ("\\appdata\\local\\temp\\", "\\users\\public\\", "\\downloads\\",
                       "\\appdata\\roaming\\", "\\programdata\\", "/tmp/")
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
          "mshta.exe", "rundll32.exe", "regsvr32.exe"}
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
                "smss.exe", "explorer.exe"}


@dataclass
class ProcessFinding:
    pid: int
    name: str
    exe: str
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    threat: str | None = None


def scan_processes(scanner: Scanner) -> list[ProcessFinding]:
    findings: list[ProcessFinding] = []
    seen_exe: dict[str, object] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
        try:
            info = proc.info
            exe = info.get("exe") or ""
            name = (info.get("name") or "").lower()
            f = ProcessFinding(info["pid"], name, exe)
            low = exe.lower()

            if exe:
                if exe not in seen_exe:
                    seen_exe[exe] = scanner.scan_file(exe)
                r = seen_exe[exe]
                if r.is_threat:
                    f.score += r.score
                    f.threat = r.threat
                    f.reasons += r.reasons

            if any(h in low for h in USER_WRITABLE_HINTS) and low.endswith(".exe"):
                f.score += 10
                f.reasons.append("running from user-writable folder")

            if config.IS_WINDOWS and name in SYSTEM_NAMES and low and \
                    not low.startswith(("c:\\windows\\system32", "c:\\windows\\syswow64",
                                        "c:\\windows\\explorer.exe")):
                f.score += 60
                f.reasons.append("system process name from wrong location (masquerading)")

            try:
                parent = proc.parent()
                pname = (parent.name() if parent else "").lower()
            except psutil.Error:
                pname = ""
            if pname in OFFICE_PARENTS and name in SHELLS:
                f.score += 50
                f.reasons.append(f"Office app {pname} spawned {name}")

            cmd = " ".join(info.get("cmdline") or []).lower()
            if name in ("powershell.exe", "pwsh.exe") and (" -enc" in cmd or "-encodedcommand" in cmd):
                f.score += 35
                f.reasons.append("PowerShell running encoded command")
            if "downloadstring" in cmd or "-urlcache" in cmd:
                f.score += 30
                f.reasons.append("command line downloads remote content")

            if f.score >= config.SUSPICIOUS_SCORE:
                f.score = min(100, f.score)
                f.threat = f.threat or "Behavior.Suspicious"
                findings.append(f)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return findings


def kill(pid: int) -> None:
    psutil.Process(pid).kill()
