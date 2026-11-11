"""Static heuristics: PE structure, script content and filename tricks.

Each check returns (score, reason). Scores add up and are capped at 100.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

try:
    import pefile
except ImportError:  # heuristics still work for scripts without pefile
    pefile = None

PACKER_SECTIONS = {
    b"UPX0", b"UPX1", b"UPX2", b".aspack", b".adata", b"MPRESS1", b"MPRESS2",
    b".petite", b".themida", b".vmp0", b".vmp1", b".nsp0", b".nsp1",
}

# Import combinations typical of process injection / credential theft / keylogging
SUSPICIOUS_IMPORT_SETS = [
    ({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, 35, "process injection APIs"),
    ({"NtUnmapViewOfSection", "SetThreadContext", "ResumeThread"}, 35, "process hollowing APIs"),
    ({"SetWindowsHookExA", "GetAsyncKeyState"}, 20, "keylogging APIs"),
    ({"SetWindowsHookExW", "GetAsyncKeyState"}, 20, "keylogging APIs"),
    ({"MiniDumpWriteDump", "OpenProcess"}, 25, "process memory dumping (credential theft)"),
    ({"CryptEncrypt", "FindFirstFileW", "MoveFileExW"}, 20, "bulk file encryption pattern"),
    ({"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}, 10, "anti-debugging"),
    ({"URLDownloadToFileA", "WinExec"}, 25, "download-and-execute"),
    ({"URLDownloadToFileW", "ShellExecuteW"}, 20, "download-and-execute"),
]

SCRIPT_PATTERNS = [
    (re.compile(rb"(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}"), 35, "PowerShell encoded command"),
    (re.compile(rb"(?i)(iex|invoke-expression)\s*\(?\s*\(?\s*new-object\s+net\.webclient"), 40, "PowerShell download cradle"),
    (re.compile(rb"(?i)downloadstring\s*\(|downloadfile\s*\("), 20, "remote download in script"),
    (re.compile(rb"(?i)vssadmin(\.exe)?\s+delete\s+shadows"), 50, "shadow copy deletion (ransomware)"),
    (re.compile(rb"(?i)wmic\s+shadowcopy\s+delete"), 50, "shadow copy deletion (ransomware)"),
    (re.compile(rb"(?i)bcdedit.{0,40}recoveryenabled\s+no"), 40, "disables Windows recovery"),
    (re.compile(rb"(?i)set-mppreference\s+-disable(realtimemonitoring|ioavprotection)"), 45, "disables Microsoft Defender"),
    (re.compile(rb"(?i)amsiutils|amsiinitfailed"), 45, "AMSI bypass"),
    (re.compile(rb"(?i)frombase64string\s*\("), 10, "base64 decoding in script"),
    (re.compile(rb"(?i)wscript\.shell.{0,80}\.run"), 15, "script spawns commands"),
    (re.compile(rb"(?i)reg(\.exe)?\s+add\s+.{0,60}\\currentversion\\run"), 25, "adds autorun persistence"),
    (re.compile(rb"(?i)schtasks(\.exe)?\s+/create"), 15, "creates scheduled task"),
    (re.compile(rb"(?i)certutil(\.exe)?\s+.{0,30}-urlcache"), 35, "certutil download (LOLBin)"),
    (re.compile(rb"(?i)mshta(\.exe)?\s+(http|vbscript|javascript)"), 35, "mshta remote execution (LOLBin)"),
]

SCRIPT_EXTS = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".txt"}
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".mp3"}
EXEC_EXTS = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".vbs", ".hta", ".lnk"}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def check_filename(path: Path) -> list[tuple[int, str]]:
    hits = []
    name = path.name.lower()
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in EXEC_EXTS and suffixes[-2] in DOC_EXTS:
        hits.append((30, f"double extension disguise ({''.join(suffixes[-2:])})"))
    if "‮" in path.name:
        hits.append((50, "right-to-left override character in filename"))
    if re.search(r"\s{5,}\.\w+$", name):
        hits.append((20, "padded filename hides real extension"))
    return hits


def check_pe(path: Path, head: bytes) -> list[tuple[int, str]]:
    if pefile is None or not head.startswith(b"MZ"):
        return []
    hits: list[tuple[int, str]] = []
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
    except Exception:
        return [(15, "malformed PE header")]

    try:
        names = {s.Name.rstrip(b"\x00") for s in pe.sections}
        packers = names & PACKER_SECTIONS
        if packers:
            hits.append((20, f"packed/protected ({b', '.join(packers).decode(errors='ignore')})"))

        high_entropy = [s for s in pe.sections if s.SizeOfRawData > 4096 and s.get_entropy() > 7.2]
        if high_entropy:
            hits.append((15, f"{len(high_entropy)} high-entropy section(s) (encrypted/packed code)"))

        for s in pe.sections:
            ch = s.Characteristics
            if ch & 0x20000000 and ch & 0x80000000:  # EXECUTE + WRITE
                sname = s.Name.rstrip(b"\x00").decode(errors="ignore")
                hits.append((15, f"writable+executable section {sname}"))
                break

        imports: set[str] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    imports.add(imp.name.decode(errors="ignore"))
        for needed, score, reason in SUSPICIOUS_IMPORT_SETS:
            if needed <= imports:
                hits.append((score, reason))
        if len(imports) < 5 and pe.FILE_HEADER.Characteristics & 0x2:
            hits.append((10, "very few imports (likely resolves APIs at runtime)"))

        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if sec_dir.VirtualAddress == 0:
            hits.append((5, "not digitally signed"))
        else:
            hits.append((-15, "has Authenticode signature block"))
    finally:
        pe.close()
    return hits


def check_script(path: Path, data: bytes) -> list[tuple[int, str]]:
    if path.suffix.lower() not in SCRIPT_EXTS:
        return []
    hits = []
    seen = set()
    for rx, score, reason in SCRIPT_PATTERNS:
        if reason not in seen and rx.search(data):
            hits.append((score, reason))
            seen.add(reason)
    return hits


def analyze(path: Path, data: bytes) -> list[tuple[int, str]]:
    """`data` is the first few MB of the file."""
    return check_filename(path) + check_pe(path, data[:2]) + check_script(path, data)
