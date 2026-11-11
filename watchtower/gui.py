"""Tkinter desktop UI (ships with Python, no extra deps)."""
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import config, setup_logging
from .monitor import RealTimeGuard
from .quarantine import Quarantine
from .scanner import MALICIOUS, ScanResult, Scanner

BG, CARD, FG, ACCENT, OK, WARN, BAD = "#0f172a", "#1e293b", "#e2e8f0", "#38bdf8", "#22c55e", "#f59e0b", "#ef4444"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        setup_logging()
        self.title(f"{config.APP_NAME} {config.VERSION}")
        self.geometry("980x640")
        self.minsize(820, 520)
        self.configure(bg=BG)

        self.scanner = Scanner()
        self.quarantine = Quarantine()
        self.events: queue.Queue = queue.Queue()
        self.guard = RealTimeGuard(self.scanner, self.quarantine,
                                   on_threat=lambda r: self.events.put(("rt", r)))
        self.scan_thread: threading.Thread | None = None
        self.threats: dict[str, ScanResult] = {}

        self._style()
        self._build()
        self.after(150, self._pump)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.toggle_realtime(force=True)

    # ----------------------------------------------------------- layout
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, fieldbackground=CARD, font=("Segoe UI", 10))
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=CARD, foreground=FG, padding=(16, 8))
        s.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", BG)])
        s.configure("Accent.TButton", background=ACCENT, foreground=BG, padding=(14, 8),
                    font=("Segoe UI", 10, "bold"))
        s.map("Accent.TButton", background=[("active", "#7dd3fc")])
        s.configure("TButton", background=CARD, foreground=FG, padding=(12, 7))
        s.map("TButton", background=[("active", "#334155")])
        s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=FG, rowheight=26)
        s.configure("Treeview.Heading", background="#334155", foreground=FG)
        s.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=CARD)

    def _build(self):
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=20, pady=(16, 6))
        tk.Label(head, text="🛡  " + config.APP_NAME, bg=BG, fg=FG,
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        self.status = tk.Label(head, text="", bg=BG, font=("Segoe UI", 11, "bold"))
        self.status.pack(side="right")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=20, pady=10)
        self._build_scan_tab(nb)
        self._build_quarantine_tab(nb)
        self._build_about_tab(nb)

    def _build_scan_tab(self, nb):
        tab = tk.Frame(nb, bg=BG)
        nb.add(tab, text="Scan")
        bar = tk.Frame(tab, bg=BG)
        bar.pack(fill="x", pady=10)
        ttk.Button(bar, text="Quick scan", style="Accent.TButton",
                   command=lambda: self.start_scan(config.quick_scan_targets(), True)).pack(side="left", padx=4)
        ttk.Button(bar, text="Full scan",
                   command=lambda: self.start_scan(config.full_scan_targets(), False)).pack(side="left", padx=4)
        ttk.Button(bar, text="Scan folder…", command=self.pick_folder).pack(side="left", padx=4)
        ttk.Button(bar, text="Scan file…", command=self.pick_file).pack(side="left", padx=4)
        ttk.Button(bar, text="Processes", command=self.scan_processes).pack(side="left", padx=4)
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.scanner.cancel, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        self.rt_btn = ttk.Button(bar, text="", command=self.toggle_realtime)
        self.rt_btn.pack(side="right", padx=4)

        self.progress = ttk.Progressbar(tab, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 4))
        self.scan_label = tk.Label(tab, text="Ready.", bg=BG, fg="#94a3b8", anchor="w")
        self.scan_label.pack(fill="x")

        cols = ("verdict", "threat", "score", "path")
        self.tree = ttk.Treeview(tab, columns=cols, show="headings", selectmode="extended")
        for c, w in zip(cols, (100, 200, 60, 560)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w, anchor="w")
        self.tree.tag_configure(MALICIOUS, foreground=BAD)
        self.tree.tag_configure("suspicious", foreground=WARN)
        self.tree.pack(fill="both", expand=True, pady=6)
        self.tree.bind("<Double-1>", self.show_details)

        act = tk.Frame(tab, bg=BG)
        act.pack(fill="x")
        ttk.Button(act, text="Quarantine selected", style="Accent.TButton",
                   command=self.quarantine_selected).pack(side="left", padx=4)
        ttk.Button(act, text="Details", command=self.show_details).pack(side="left", padx=4)
        ttk.Button(act, text="Ignore", command=self.ignore_selected).pack(side="left", padx=4)

    def _build_quarantine_tab(self, nb):
        tab = tk.Frame(nb, bg=BG)
        nb.add(tab, text="Quarantine")
        cols = ("when", "threat", "path", "id")
        self.qtree = ttk.Treeview(tab, columns=cols, show="headings")
        for c, w in zip(cols, (140, 200, 480, 0)):
            self.qtree.heading(c, text=c.title())
            self.qtree.column(c, width=w, anchor="w", stretch=c != "id")
        self.qtree.pack(fill="both", expand=True, pady=10)
        bar = tk.Frame(tab, bg=BG)
        bar.pack(fill="x")
        ttk.Button(bar, text="Refresh", command=self.refresh_quarantine).pack(side="left", padx=4)
        ttk.Button(bar, text="Restore", command=self.restore_selected).pack(side="left", padx=4)
        ttk.Button(bar, text="Delete permanently", command=self.delete_selected).pack(side="left", padx=4)
        self.refresh_quarantine()

    def _build_about_tab(self, nb):
        tab = tk.Frame(nb, bg=BG)
        nb.add(tab, text="Engine")
        self.info = tk.Label(tab, bg=BG, fg=FG, justify="left", anchor="nw", font=("Consolas", 10))
        self.info.pack(fill="both", expand=True, padx=10, pady=10)
        bar = tk.Frame(tab, bg=BG)
        bar.pack(fill="x")
        ttk.Button(bar, text="Import hash list…", command=self.import_sigs).pack(side="left", padx=4)
        ttk.Button(bar, text="Open rules folder", command=self.open_rules).pack(side="left", padx=4)
        self.refresh_info()

    # ----------------------------------------------------------- actions
    def refresh_info(self):
        self.info.config(text=(
            f"{config.APP_NAME} {config.VERSION}  —  free & open source (MIT)\n\n"
            f"Hash signatures : {self.scanner.sigdb.count():,}\n"
            f"YARA rules      : {self.scanner.yara.rule_count}\n"
            f"Data folder     : {config.DATA_DIR}\n"
            f"Custom rules    : {config.USER_RULES_DIR}\n"
            f"Real-time paths : {', '.join(map(str, self.guard.paths)) or '-'}\n\n"
            "Test detection safely with the EICAR test file from eicar.org."))

    def _set_status(self):
        if self.guard.running:
            self.status.config(text="● Protected", fg=OK)
            self.rt_btn.config(text="Turn real-time OFF")
        else:
            self.status.config(text="● Real-time protection off", fg=BAD)
            self.rt_btn.config(text="Turn real-time ON")

    def toggle_realtime(self, force: bool = False):
        try:
            if self.guard.running and not force:
                self.guard.stop()
            else:
                self.guard.start()
        except Exception as exc:
            messagebox.showerror(config.APP_NAME, f"Real-time protection failed: {exc}")
        self._set_status()

    def pick_folder(self):
        d = filedialog.askdirectory()
        if d:
            self.start_scan([Path(d)], False)

    def pick_file(self):
        f = filedialog.askopenfilename()
        if f:
            self.start_scan([Path(f)], False)

    def start_scan(self, roots, risky_only):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo(config.APP_NAME, "A scan is already running.")
            return
        self.tree.delete(*self.tree.get_children())
        self.threats.clear()
        self.progress.start(12)
        self.stop_btn.config(state="normal")
        self.counter = 0
        self.t0 = time.time()

        def cb(r: ScanResult):
            self.events.put(("result", r))

        def run():
            stats = self.scanner.scan_paths(roots, risky_only=risky_only, on_result=cb)
            self.events.put(("done", stats))

        self.scan_thread = threading.Thread(target=run, daemon=True)
        self.scan_thread.start()

    def scan_processes(self):
        from .process_scan import scan_processes

        def run():
            for f in scan_processes(self.scanner):
                r = ScanResult(path=f"[PID {f.pid}] {f.exe or f.name}", verdict="suspicious",
                               score=f.score, threat=f.threat, reasons=f.reasons)
                self.events.put(("result", r))
            self.events.put(("procdone", None))
        self.tree.delete(*self.tree.get_children())
        self.scan_label.config(text="Checking running processes…")
        threading.Thread(target=run, daemon=True).start()

    def _add_threat_row(self, r: ScanResult):
        iid = self.tree.insert("", "end", values=(r.verdict.upper(), r.threat, r.score, r.path),
                               tags=(r.verdict,))
        self.threats[iid] = r

    def _pump(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "result":
                    self.counter = getattr(self, "counter", 0) + 1
                    if payload.is_threat:
                        self._add_threat_row(payload)
                    if self.counter % 25 == 0:
                        self.scan_label.config(text=f"{self.counter:,} files — {payload.path[-90:]}")
                elif kind == "done":
                    self.progress.stop()
                    self.stop_btn.config(state="disabled")
                    n = len(payload.threats)
                    self.scan_label.config(
                        text=f"Finished in {time.time() - self.t0:.0f}s — {payload.scanned:,} scanned, "
                             f"{n} threat(s) found.", fg=BAD if n else OK)
                elif kind == "procdone":
                    self.scan_label.config(text=f"Process check done — {len(self.threats)} flagged.")
                elif kind == "rt":
                    self._add_threat_row(payload)
                    self.refresh_quarantine()
                    messagebox.showwarning(
                        config.APP_NAME,
                        f"Threat blocked!\n\n{payload.threat}\n{payload.path}\n\n"
                        + ("Moved to quarantine." if "auto-quarantined" in payload.reasons
                           else "Review it in the Scan tab."))
        except queue.Empty:
            pass
        self.after(150, self._pump)

    def _selected(self):
        return [(iid, self.threats[iid]) for iid in self.tree.selection() if iid in self.threats]

    def quarantine_selected(self):
        for iid, r in self._selected():
            if r.path.startswith("[PID"):
                continue
            try:
                self.quarantine.add(r.path, r.threat or "Unknown", r.sha256 or "")
                self.tree.delete(iid)
            except Exception as exc:
                messagebox.showerror(config.APP_NAME, f"{r.path}\n{exc}")
        self.refresh_quarantine()

    def ignore_selected(self):
        for iid, _ in self._selected():
            self.tree.delete(iid)

    def show_details(self, _evt=None):
        sel = self._selected()
        if sel:
            r = sel[0][1]
            messagebox.showinfo("Details", f"{r.path}\n\nThreat: {r.threat}\nScore: {r.score}\n"
                                f"SHA-256: {r.sha256}\n\n" + "\n".join("• " + x for x in r.reasons))

    def refresh_quarantine(self):
        self.qtree.delete(*self.qtree.get_children())
        for i in self.quarantine.list():
            self.qtree.insert("", "end", iid=i.id, values=(i.when, i.threat, i.original_path, i.id))

    def restore_selected(self):
        for qid in self.qtree.selection():
            if messagebox.askyesno(config.APP_NAME, "Restore this file? Only do this if you're sure it is safe."):
                self.quarantine.restore(qid)
        self.refresh_quarantine()

    def delete_selected(self):
        sel = self.qtree.selection()
        if sel and messagebox.askyesno(config.APP_NAME, f"Permanently delete {len(sel)} item(s)?"):
            for qid in sel:
                self.quarantine.delete(qid)
        self.refresh_quarantine()

    def import_sigs(self):
        f = filedialog.askopenfilename(filetypes=[("Hash lists", "*.txt *.csv"), ("All", "*.*")])
        if f:
            n = self.scanner.sigdb.import_file(Path(f))
            messagebox.showinfo(config.APP_NAME, f"Imported {n:,} signatures.")
            self.refresh_info()

    def open_rules(self):
        import os, subprocess
        config.USER_RULES_DIR.mkdir(parents=True, exist_ok=True)
        if config.IS_WINDOWS:
            os.startfile(config.USER_RULES_DIR)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(config.USER_RULES_DIR)])

    def _on_close(self):
        self.scanner.cancel()
        self.guard.stop()
        self.destroy()


def main():
    import sys
    app = App()
    ico = config.BUNDLED_RULES_DIR.parent / "assets" / "watchtower.ico"
    if config.IS_WINDOWS and ico.exists():
        try:
            app.iconbitmap(str(ico))
        except tk.TclError:
            pass
    if "--minimized" in sys.argv:   # used by the login autostart entry
        app.iconify()
    app.mainloop()


if __name__ == "__main__":
    main()
