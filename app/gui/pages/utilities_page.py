"""
app.gui.pages.utilities_page
===============================

Small self-contained helpers that don't belong to a pipeline: a file
hash calculator, the resolved on-disk locations Pentroid is using, and
live row counts for the local database.

Everything here is pure Python or a read-only database query. The hash
calculator uses ``hashlib`` directly rather than reaching into the
``file_hashing`` plugin: that plugin exists to attach hashes to an
analysis as evidence, and importing a Plugin from the GUI layer would
break the rule that only the workflow engine instantiates plugins.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QPushButton, QWidget

from app.core.config import get_settings
from app.database.database import session_scope
from app.database.models import Analysis, Device, Finding, Log, Plugin, Project, Report
from app.gui.controllers.background_task_runner import get_background_task_runner
from app.gui.pages.common import BasePage, card, clear_layout, empty_state, kv_row, label
from app.gui.pages.reverse_engineering_page import open_in_file_manager
from app.gui.theme import Colors

_CHUNK = 1024 * 1024


def hash_file(path: str) -> dict[str, str]:
    """Stream the file once, feeding all three digests, so a 300 MB APK never
    gets loaded into memory and is only read from disk a single time."""
    digests = {"MD5": hashlib.md5(), "SHA-1": hashlib.sha1(), "SHA-256": hashlib.sha256()}
    size = 0
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK):
            size += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
    result = {name: digest.hexdigest() for name, digest in digests.items()}
    result["Size"] = f"{size:,} bytes"
    return result


class UtilitiesPage(BasePage):
    title_text = "Utilities"
    subtitle_text = (
        "Standalone helpers: hash a file, see where Pentroid keeps things on disk, and "
        "check what's actually in the local database."
    )

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._task_runner = get_background_task_runner()
        self._task_runner.finished.connect(self._on_finished)
        self._task_runner.failed.connect(self._on_failed)
        self._hash_job: str | None = None
        self._file_path: str | None = None

        self._build_hash_card()
        self._build_paths_card()
        self._build_db_card()
        self.refresh()

    def _build_hash_card(self) -> None:
        frame, layout = card(
            "FILE HASHES",
            "MD5, SHA-1 and SHA-256 for any file \u2014 useful for VirusTotal lookups and for "
            "recording sample identity in a report.",
        )
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(10)
        self._file_label = label("No file selected", size=11, color=Colors.TEXT_MUTED, wrap=True)
        row_layout.addWidget(self._file_label, stretch=1)
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._on_browse)
        row_layout.addWidget(browse)
        compute = QPushButton("Compute hashes")
        compute.setProperty("class", "Primary")
        compute.clicked.connect(self._on_compute)
        row_layout.addWidget(compute)
        layout.addWidget(row)

        self._hash_layout = layout
        self._hash_anchor = layout.count()
        self.body.addWidget(frame)

    def _build_paths_card(self) -> None:
        frame, layout = card(
            "STORAGE LOCATIONS",
            "Resolved at startup; every directory listed is created if missing.",
        )
        settings = get_settings()
        paths = settings.paths
        self._paths = {
            "Projects": paths.projects_dir,
            "Reports": paths.reports_dir,
            "Tools": paths.tools_dir,
            "Logs": paths.logs_dir,
            "Plugins": paths.plugins_dir,
            "Database": paths.database_dir,
            "Config": paths.config_dir,
        }
        for name, path in self._paths.items():
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(10)
            row_layout.addWidget(kv_row(name, str(path)), stretch=1)
            open_btn = QPushButton("Open")
            open_btn.clicked.connect(lambda _=False, p=path: self._on_open(p))
            row_layout.addWidget(open_btn)
            layout.addWidget(row)
        self.body.addWidget(frame)

    def _build_db_card(self) -> None:
        frame, layout = card(
            "DATABASE",
            "Row counts straight from the local SQLite database Pentroid is using.",
        )
        self._db_layout = layout
        self._db_anchor = layout.count()
        self.body.addWidget(frame)

    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        if not hasattr(self, "_db_layout"):
            return
        clear_layout(self._db_layout, keep=self._db_anchor)

        settings = get_settings()
        db_file = settings.paths.database_file
        try:
            with session_scope() as session:
                counts = [
                    ("Projects", session.query(Project).count()),
                    ("Analyses", session.query(Analysis).count()),
                    ("Findings", session.query(Finding).count()),
                    ("Devices", session.query(Device).count()),
                    ("Reports", session.query(Report).count()),
                    ("Registered plugins", session.query(Plugin).count()),
                    ("Log rows", session.query(Log).count()),
                ]
        except Exception as exc:  # noqa: BLE001 - a broken DB is worth showing, not crashing on
            self._db_layout.addWidget(label(
                f"Could not read the database: {exc}", size=11,
                color=Colors.STATUS_ERROR, wrap=True,
            ))
            return

        self._db_layout.addWidget(kv_row("File", str(db_file)))
        if db_file.exists():
            self._db_layout.addWidget(
                kv_row("On-disk size", f"{db_file.stat().st_size / 1024:.1f} KB")
            )
        for name, count in counts:
            self._db_layout.addWidget(kv_row(name, f"{count:,}"))

    def _on_open(self, path: Path) -> None:
        error = open_in_file_manager(path)
        self.set_status(
            f"Opened {path}" if not error else f"Could not open {path}: {error}",
            Colors.ACCENT_GREEN if not error else Colors.STATUS_ERROR,
        )

    def _on_browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to hash", "", "All Files (*)")
        if path:
            self._file_path = path
            self._file_label.setText(path)
            self._file_label.setStyleSheet(
                f"color: {Colors.TEXT_PRIMARY}; font-size: 11px; font-weight: 400;"
            )

    def _on_compute(self) -> None:
        if not self._file_path:
            self.set_status("Select a file first.", Colors.STATUS_WARNING)
            return
        if self._hash_job is not None:
            return
        clear_layout(self._hash_layout, keep=self._hash_anchor)
        self.set_status("Hashing...", Colors.STATUS_RUNNING)
        # Backgrounded: hashing a multi-hundred-megabyte APK on the GUI thread
        # would freeze the window for the duration.
        self._hash_job = self._task_runner.run(hash_file, self._file_path)

    def _on_finished(self, job_id: str, result) -> None:
        if job_id != self._hash_job:
            return
        self._hash_job = None
        clear_layout(self._hash_layout, keep=self._hash_anchor)
        for name, value in (result or {}).items():
            self._hash_layout.addWidget(kv_row(name, value))
        self.set_status("Hashes computed. Click a value to select and copy it.",
                        Colors.ACCENT_GREEN)

    def _on_failed(self, job_id: str, error_message: str) -> None:
        if job_id != self._hash_job:
            return
        self._hash_job = None
        clear_layout(self._hash_layout, keep=self._hash_anchor)
        self._hash_layout.addWidget(empty_state(f"Hashing failed: {error_message}"))
        self.set_status(f"Hashing failed: {error_message}", Colors.STATUS_ERROR)
