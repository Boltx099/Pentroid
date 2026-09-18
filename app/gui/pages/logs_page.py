"""
app.gui.pages.logs_page
==========================

Log viewer over ``logs/pentroid.log``: level filter, substring search,
adjustable tail length and optional auto-refresh.

Reads the tail of the file rather than the whole thing -- a long-lived
install's log grows without bound and loading all of it into a
QPlainTextEdit on every refresh would make the page progressively
slower. The Dashboard's LIVE LOGS panel shows the last 12 lines; this
page is for actually reading them.
"""

from __future__ import annotations

from collections import deque

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLineEdit, QPlainTextEdit, QPushButton, QWidget,
)

from app.core.config import get_settings
from app.gui.pages.common import BasePage, card, kv_row, label
from app.gui.pages.reverse_engineering_page import open_in_file_manager
from app.gui.theme import Colors

_LEVELS = ["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
_TAIL_CHOICES = [200, 500, 2000, 10000]
_REFRESH_MS = 3000


def read_tail(path, max_lines: int) -> list[str]:
    """Last ``max_lines`` lines of a text file, streamed through a bounded
    deque so memory stays proportional to the tail, not to the file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return list(deque(handle, maxlen=max_lines))
    except OSError:
        return []


class LogsPage(BasePage):
    title_text = "Logs"
    subtitle_text = (
        "Everything Pentroid writes to logs/pentroid.log \u2014 tool invocations, plugin "
        "results, workflow steps and errors."
    )

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._log_file = get_settings().paths.logs_dir / "pentroid.log"

        self._build_controls()
        self._build_viewer()

        self._timer = QTimer(self)
        self._timer.setInterval(_REFRESH_MS)
        self._timer.timeout.connect(self.refresh)

        self.refresh()

    def _build_controls(self) -> None:
        frame, layout = card("FILTER")
        layout.addWidget(kv_row("File", str(self._log_file)))

        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(10)

        row_layout.addWidget(label("Level", size=11, color=Colors.TEXT_SECONDARY))
        self._level_combo = QComboBox()
        self._level_combo.addItems(_LEVELS)
        self._level_combo.currentIndexChanged.connect(self.refresh)
        row_layout.addWidget(self._level_combo)

        row_layout.addWidget(label("Show last", size=11, color=Colors.TEXT_SECONDARY))
        self._tail_combo = QComboBox()
        for count in _TAIL_CHOICES:
            self._tail_combo.addItem(f"{count:,} lines", count)
        self._tail_combo.setCurrentIndex(1)
        self._tail_combo.currentIndexChanged.connect(self.refresh)
        row_layout.addWidget(self._tail_combo)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search text...")
        self._search.textChanged.connect(self.refresh)
        row_layout.addWidget(self._search, stretch=1)

        self._auto = QCheckBox("Auto-refresh")
        self._auto.toggled.connect(self._on_auto_toggled)
        row_layout.addWidget(self._auto)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        row_layout.addWidget(refresh_btn)

        open_btn = QPushButton("Open folder")
        open_btn.clicked.connect(self._on_open_folder)
        row_layout.addWidget(open_btn)

        layout.addWidget(row)
        self.body.addWidget(frame)

    def _build_viewer(self) -> None:
        frame, layout = card("LOG OUTPUT")
        self._viewer = QPlainTextEdit()
        self._viewer.setReadOnly(True)
        self._viewer.setMinimumHeight(420)
        self._viewer.setLineWrapMode(QPlainTextEdit.NoWrap)
        self._viewer.setStyleSheet(
            f"background-color: {Colors.BG_INPUT}; color: {Colors.TEXT_SECONDARY}; "
            f"font-family: Consolas, 'DejaVu Sans Mono', monospace; font-size: 11px; "
            f"border: 1px solid {Colors.BORDER}; border-radius: 8px; padding: 8px;"
        )
        layout.addWidget(self._viewer)
        self.body.addWidget(frame)

    def _on_auto_toggled(self, checked: bool) -> None:
        if checked:
            self._timer.start()
        else:
            self._timer.stop()

    def _on_open_folder(self) -> None:
        folder = self._log_file.parent
        error = open_in_file_manager(folder)
        self.set_status(
            f"Opened {folder}" if not error else f"Could not open {folder}: {error}",
            Colors.ACCENT_GREEN if not error else Colors.STATUS_ERROR,
        )

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt override
        # Don't keep re-reading the log once the user navigates elsewhere.
        self._timer.stop()
        super().hideEvent(event)

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        if getattr(self, "_auto", None) is not None and self._auto.isChecked():
            self._timer.start()

    def refresh(self) -> None:
        if not hasattr(self, "_viewer"):
            return

        if not self._log_file.exists():
            self._viewer.setPlainText("")
            self.set_status(
                f"No log file at {self._log_file} yet \u2014 it's created on first write.",
                Colors.TEXT_MUTED,
            )
            return

        lines = read_tail(self._log_file, self._tail_combo.currentData() or 500)
        level = self._level_combo.currentText()
        needle = self._search.text().strip().lower()

        if level != "ALL":
            # The logger writes "[LEVEL]" into each line, so matching that token
            # avoids false positives from the word appearing in a message body.
            token = f"[{level}]"
            lines = [line for line in lines if token in line]
        if needle:
            lines = [line for line in lines if needle in line.lower()]

        at_bottom = (
            self._viewer.verticalScrollBar().value()
            >= self._viewer.verticalScrollBar().maximum() - 4
        )
        self._viewer.setPlainText("".join(lines).rstrip("\n"))
        if at_bottom:
            # Only follow the tail if the user was already at the bottom;
            # otherwise auto-refresh would yank them away from what they're reading.
            bar = self._viewer.verticalScrollBar()
            bar.setValue(bar.maximum())

        self.set_status(
            f"{len(lines)} line(s) shown"
            + (f", filtered to {level}" if level != "ALL" else "")
            + (f", matching '{needle}'" if needle else ""),
            Colors.TEXT_MUTED,
        )
