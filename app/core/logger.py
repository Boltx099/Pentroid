"""
app.core.logger
================

Application-wide logging setup.

Every module obtains a logger via ``get_logger(__name__)`` rather than
calling ``logging.getLogger`` directly, so log format / handlers stay
centrally controlled and the eventual GUI "Live Logs & Terminal" panel
and the database ``Logs`` table can both tap into the same stream via
``QtSignalLogHandler`` and ``DatabaseLogHandler`` (registered by the
GUI and Database modules respectively at startup).

Log files are rotated to keep ``logs/`` bounded in size, since analysis
runs (Frida hooks, logcat capture, network capture) can be very chatty.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional

from app.core.config import get_settings

_CONFIGURED = False

_FILE_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)-28s | %(message)s"
)
_CONSOLE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class _LevelColorFormatter(logging.Formatter):
    """Adds ANSI color to console output based on level (cyber/dark theme)."""

    _COLORS = {
        logging.DEBUG: "\x1b[38;5;244m",     # grey
        logging.INFO: "\x1b[38;5;39m",       # cyan/blue
        logging.WARNING: "\x1b[38;5;214m",   # amber
        logging.ERROR: "\x1b[38;5;196m",     # red
        logging.CRITICAL: "\x1b[48;5;196m\x1b[97m",  # white on red
    }
    _RESET = "\x1b[0m"

    def __init__(self, use_color: bool) -> None:
        super().__init__(fmt=_CONSOLE_FORMAT, datefmt=_DATE_FORMAT)
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if not self._use_color:
            return message
        color = self._COLORS.get(record.levelno, "")
        return f"{color}{message}{self._RESET}" if color else message


class QtSignalLogHandler(logging.Handler):
    """
    Handler that forwards formatted log records to a callback.

    The GUI's Live Logs & Terminal panel registers a callback here
    (typically a Qt Signal's ``.emit``) so every log line the backend
    produces streams into the dockable log panel in real time, without
    the core/business logic importing PySide6 anywhere.
    """

    def __init__(self, callback) -> None:
        super().__init__()
        self._callback = callback
        self.setFormatter(logging.Formatter(_CONSOLE_FORMAT, datefmt=_DATE_FORMAT))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._callback(self.format(record), record.levelname)
        except Exception:  # pragma: no cover - never let logging crash the app
            self.handleError(record)


def setup_logging(force: bool = False) -> None:
    """
    Configure the root logger once per process.

    Adds:
    * RotatingFileHandler -> logs/pentroid.log
    * StreamHandler -> stdout (colorized), if ``logging.console_output``
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    settings = get_settings()
    root = logging.getLogger("pentroid")
    root.setLevel(getattr(logging, settings.logging.level))
    root.handlers.clear()

    file_handler = RotatingFileHandler(
        filename=settings.paths.logs_dir / "pentroid.log",
        maxBytes=settings.logging.max_bytes,
        backupCount=settings.logging.backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(_FILE_FORMAT, datefmt=_DATE_FORMAT))
    root.addHandler(file_handler)

    if settings.logging.console_output:
        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setFormatter(
            _LevelColorFormatter(use_color=sys.stdout.isatty())
        )
        root.addHandler(console_handler)

    root.propagate = False
    _CONFIGURED = True
    root.info(
        "Logging initialized (level=%s, file=%s)",
        settings.logging.level,
        settings.paths.logs_dir / "pentroid.log",
    )


def get_logger(name: str) -> logging.Logger:
    """
    Return a namespaced child logger, e.g. ``get_logger(__name__)`` from
    ``app.core.workflow_engine`` yields logger ``pentroid.app.core.workflow_engine``.
    """
    if not _CONFIGURED:
        setup_logging()
    qualified = name if name.startswith("pentroid") else f"pentroid.{name}"
    return logging.getLogger(qualified)


def attach_gui_handler(callback) -> QtSignalLogHandler:
    """Attach (and return) a GUI signal handler to the root pentroid logger."""
    handler = QtSignalLogHandler(callback)
    logging.getLogger("pentroid").addHandler(handler)
    return handler


def detach_handler(handler: Optional[logging.Handler]) -> None:
    """Remove a previously attached handler (used when a panel closes)."""
    if handler is not None:
        logging.getLogger("pentroid").removeHandler(handler)
