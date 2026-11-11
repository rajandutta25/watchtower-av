# 🛡 Watchtower AV

Free, open-source antivirus for Windows (GPL-3.0). Non-commercial community project — no paid tiers, no ads, no data selling. Stage 1 of a next-generation open EDR.

## Features (v0.1)

| Layer | What it does |
|---|---|
| **Hash signatures** | SHA-256 lookups in a local SQLite DB. Import any hash feed (e.g. MalwareBazaar SHA-256 export). |
| **YARA engine** | Bundled rules (EICAR, Mimikatz, Cobalt Strike, ransomware, PowerShell loaders, Office macro droppers) + your own `.yar` files. |
| **PE heuristics** | Packers (UPX/Themida/VMProtect), high-entropy sections, W+X sections, injection / hollowing / keylogger / credential-dump import sets, missing signature. |
| **Script heuristics** | Encoded PowerShell, download cradles, AMSI bypass, Defender tampering, shadow-copy deletion, LOLBins (certutil, mshta), Run-key persistence. |
| **Filename tricks** | Double extensions (`invoice.pdf.exe`), RTL-override, padded names. |
| **Real-time protection** | Watches Downloads, Desktop and %TEMP%; auto-quarantines malicious files as they land. |
| **Process scan** | Flags masquerading system binaries, Office → shell child processes, encoded PowerShell, binaries running from user-writable paths. Optional kill. |
| **Quarantine** | XOR-obfuscated vault with metadata; restore or delete. Locked files are removed at reboot. |
| **GUI + CLI** | Tkinter desktop app and a scriptable `watchtower` command. |

Scoring: each finding adds points; ≥70 = **malicious**, ≥40 = **suspicious**, signature hit = 100.

## Install (end users — no Python needed)

1. Download **`WatchtowerAV-Setup-x.y.z.exe`** from the Releases page.
2. Run it → Next → Install. It asks for admin rights (needed to scan the whole PC).
3. Done. You get:
   - Start menu + desktop shortcut
   - Real-time protection that starts automatically when you sign in
   - **Right-click → "Scan with Watchtower AV"** on any file or folder
   - `watchtower` command in any terminal (`watchtower quick`, `watchtower processes`, ...)
   - A normal uninstaller in *Settings → Apps*

Silent install for admins/IT: `WatchtowerAV-Setup-0.1.0.exe /VERYSILENT /TASKS=autostart`

## Building the installer

**Option A — automatic (recommended):** push this folder to a GitHub repo. The workflow in
`.github/workflows/build.yml` builds on a Windows machine, runs the tests, test-installs the
setup, and uploads `WatchtowerAV-Setup.exe` under *Actions → latest run → Artifacts*.
Push a tag (`git tag v0.1.0 && git push --tags`) to publish it as a Release.

**Option B — on your own Windows PC:** install Python 3.12 and Inno Setup 6 once, then run
`build_windows.bat`. Output: `dist\WatchtowerAV-Setup-0.1.0.exe`.

## Developers: run from source

```powershell
py -m pip install -r requirements.txt
py -m watchtower                 # GUI
py -m watchtower quick           # CLI quick scan
py -m watchtower scan C:\Users\me\Downloads --quarantine
py -m pytest tests
```

## Test it safely

Download the EICAR test file from https://www.eicar.org/download-anti-malware-testfile/ into Downloads. With real-time protection on, it is quarantined within ~2 seconds. (Windows Defender may grab it first. Add a Defender exclusion for a test folder if needed.)

## Data locations

`%PROGRAMDATA%\WatchtowerAV\` → `signatures.db`, `rules\` (custom YARA), `quarantine\`, `logs\watchtower.log`. Override with the `WATCHTOWER_HOME` environment variable.

## Roadmap to EDR

1. **Now:** on-demand + real-time file scanning, process triage (user mode).
2. **Next:** run as a Windows service; AMSI provider (script content scanning); ETW consumer (process/network/registry telemetry via `Microsoft-Windows-Kernel-Process`, `Threat-Intelligence`); Sigma rule engine on events.
3. **Then:** minifilter driver for true pre-execution blocking; ransomware canary files + rollback via VSS; network isolation via WFP.
4. **Fleet:** agent → central server (events, rule push, remote response), MITRE ATT&CK mapping.

## Limitations

This is a user-mode scanner: it scans files after they are written, not before they execute, and it can be terminated by malware running as admin. Use it alongside Microsoft Defender, not instead of it, until the service/driver stages land.

## License

Watchtower AV is free software, licensed under the **GNU General Public License v3.0** (see `LICENSE`).
You may use, study, share and modify it. If you distribute a modified version, you must publish its
source code under the same license, so Watchtower and its derivatives stay open source forever.

Copyright (C) 2026 Rajan (@rajandutta25) and contributors.

## Supporting the project

Watchtower AV is a non-commercial community project. There will never be a paid edition, ads or data collection.
Optional donations (the **Sponsor** button on GitHub) go only toward running costs, mainly the
EV certificate needed for Microsoft to sign the future kernel driver. Spending will be published.
