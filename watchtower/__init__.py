"""Watchtower AV - free, open-source antivirus for Windows."""
import logging
import logging.handlers

from . import config

__version__ = config.VERSION


def setup_logging(verbose: bool = False) -> None:
    config.ensure_dirs()
    root = logging.getLogger("watchtower")
    if root.handlers:
        return
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh = logging.handlers.RotatingFileHandler(
        config.LOG_DIR / "watchtower.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(fh)
