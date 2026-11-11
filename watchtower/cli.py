"""Command-line interface.

    watchtower scan <path...> [--quarantine]
    watchtower quick | full
    watchtower processes [--kill]
    watchtower monitor
    watchtower quarantine list | restore <id> | delete <id>
    watchtower update-sigs <hashfile>
    watchtower info
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import config, setup_logging
from .quarantine import Quarantine
from .scanner import MALICIOUS, ScanResult, Scanner

RED, YEL, GRN, DIM, RST = "\033[91m", "\033[93m", "\033[92m", "\033[2m", "\033[0m"
if config.IS_WINDOWS:
    import os
    os.system("")  # enable ANSI colours in Windows 10+ console


def _print_threat(r: ScanResult) -> None:
    c = RED if r.verdict == MALICIOUS else YEL
    print(f"{c}[{r.verdict.upper()}]{RST} {r.path}")
    print(f"    threat: {r.threat}  score: {r.score}")
    for reason in r.reasons:
        print(f"    - {reason}")


def _run_scan(scanner: Scanner, roots, risky_only: bool, do_quarantine: bool) -> int:
    start = time.time()
    count = [0]

    def progress(r: ScanResult):
        count[0] += 1
        if count[0] % 200 == 0:
            print(f"{DIM}  ...{count[0]} files{RST}", file=sys.stderr)

    print(f"Scanning: {', '.join(str(r) for r in roots)}")
    try:
        stats = scanner.scan_paths(roots, risky_only=risky_only, on_result=progress)
    except KeyboardInterrupt:
        scanner.cancel()
        print("Cancelled.")
        return 130
    for t in stats.threats:
        _print_threat(t)
    q = Quarantine()
    if do_quarantine:
        for t in stats.threats:
            if t.verdict == MALICIOUS:
                try:
                    item = q.add(t.path, t.threat or "Unknown", t.sha256 or "")
                    print(f"{GRN}  quarantined{RST} {t.path} -> {item.id}")
                except Exception as exc:
                    print(f"{RED}  could not quarantine{RST} {t.path}: {exc}")
    dur = time.time() - start
    colour = RED if stats.threats else GRN
    print(f"\n{colour}{len(stats.threats)} threat(s){RST} | {stats.scanned} scanned, "
          f"{stats.skipped} skipped, {stats.errors} unreadable | {dur:.1f}s")
    return 1 if stats.threats else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="watchtower", description=f"{config.APP_NAME} {config.VERSION}")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files or folders")
    s.add_argument("paths", nargs="+")
    s.add_argument("-q", "--quarantine", action="store_true", help="quarantine malicious files")
    s.add_argument("--risky-only", action="store_true", help="only executable/script types")
    s.add_argument("--pause", action="store_true", help="wait for Enter before exiting (Explorer menu)")

    for name, hlp in (("quick", "scan Downloads, Desktop, Temp, Startup"),
                      ("full", "scan all drives")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("-q", "--quarantine", action="store_true")

    p = sub.add_parser("processes", help="scan running processes")
    p.add_argument("--kill", action="store_true", help="terminate flagged processes")

    sub.add_parser("monitor", help="run real-time protection in the foreground")

    qp = sub.add_parser("quarantine", help="manage quarantine")
    qs = qp.add_subparsers(dest="qcmd", required=True)
    qs.add_parser("list")
    r = qs.add_parser("restore"); r.add_argument("id"); r.add_argument("--to")
    d = qs.add_parser("delete"); d.add_argument("id")

    u = sub.add_parser("update-sigs", help="import SHA-256 hash list")
    u.add_argument("file")

    sub.add_parser("info", help="show engine status")

    a = ap.parse_args(argv)
    setup_logging(a.verbose)

    if a.cmd == "quarantine":
        q = Quarantine()
        if a.qcmd == "list":
            items = q.list()
            if not items:
                print("Quarantine is empty.")
            for i in items:
                print(f"{i.id}  {i.when}  {i.threat:<28} {i.original_path}")
        elif a.qcmd == "restore":
            print(f"Restored to {q.restore(a.id, a.to)}")
        else:
            q.delete(a.id); print("Deleted.")
        return 0

    scanner = Scanner()

    if a.cmd == "info":
        print(f"{config.APP_NAME} {config.VERSION}")
        print(f"  data dir      : {config.DATA_DIR}")
        print(f"  hash sigs     : {scanner.sigdb.count()}")
        print(f"  YARA rules    : {scanner.yara.rule_count}")
        print(f"  quarantined   : {len(Quarantine().list())}")
        return 0
    if a.cmd == "update-sigs":
        n = scanner.sigdb.import_file(Path(a.file))
        print(f"Imported {n} signatures. Total: {scanner.sigdb.count()}")
        return 0
    if a.cmd == "scan":
        rc = _run_scan(scanner, [Path(p) for p in a.paths], a.risky_only, a.quarantine)
        if a.pause:
            if rc == 1 and input("Quarantine malicious files? [y/N] ").strip().lower() == "y":
                _run_scan(scanner, [Path(p) for p in a.paths], a.risky_only, True)
            input("Press Enter to close...")
        return rc
    if a.cmd == "quick":
        return _run_scan(scanner, config.quick_scan_targets(), True, a.quarantine)
    if a.cmd == "full":
        return _run_scan(scanner, config.full_scan_targets(), False, a.quarantine)
    if a.cmd == "processes":
        from .process_scan import kill, scan_processes
        found = scan_processes(scanner)
        for f in found:
            print(f"{YEL}[PID {f.pid}]{RST} {f.name} {f.exe}  score={f.score} {f.threat}")
            for reason in f.reasons:
                print(f"    - {reason}")
            if a.kill:
                try:
                    kill(f.pid); print(f"    {GRN}terminated{RST}")
                except Exception as exc:
                    print(f"    {RED}kill failed: {exc}{RST}")
        print(f"{len(found)} suspicious process(es).")
        return 1 if found else 0
    if a.cmd == "monitor":
        from .monitor import RealTimeGuard
        guard = RealTimeGuard(scanner, on_threat=_print_threat)
        guard.start()
        print("Real-time protection on:", ", ".join(map(str, guard.paths)), "(Ctrl+C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            guard.stop()
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
