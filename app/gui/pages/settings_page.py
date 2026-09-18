"""
app.gui.pages.settings_page
==============================

Two real sections:

1. **Dependency Manager** -- lists every tool in ``TOOL_REGISTRY`` with
   live install status, and an "Install" button that actually
   downloads/installs it (through ``BackgroundTaskRunner`` so the
   blocking network/subprocess work never freezes the GUI thread).
   This is the first GUI surface for the Dependency Manager, which
   until now only had two hardcoded rows on the Dashboard.

2. **Service API Keys** -- VirusTotal / MobSF / Burp Suite config,
   persisted via the existing ``Setting`` key-value table
   (``get_setting``/``set_setting`` from Module 1). Honest limitation
   surfaced directly in the UI: these are stored in plaintext in the
   local SQLite database -- there's no secrets-encryption layer (e.g.
   OS keychain integration) yet.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from app.core.dependency_manager import TOOL_REGISTRY, InstallMethod, get_dependency_manager
from app.database.database import get_setting, set_setting
from app.gui.controllers.background_task_runner import get_background_task_runner
from app.gui.theme import Colors

_SERVICE_KEYS = [
    ("VirusTotal API Key", "virustotal_api_key", False),
    ("MobSF Base URL", "mobsf_base_url", False),
    ("MobSF API Key", "mobsf_api_key", False),
    ("Burp Suite API Base URL", "burp_api_base_url", False),
    ("Burp Suite API Key", "burp_api_key", False),
    ("GitHub Token (raises tool-download rate limit 60/hr \u2192 5000/hr)", "github_token", True),
]


class _ToolRow(QFrame):
    def __init__(self, tool_name: str, on_install, parent=None):
        super().__init__(parent)
        self.tool_name = tool_name
        self.setProperty("class", "Card")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        spec = TOOL_REGISTRY[tool_name]
        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        name_lbl = QLabel(spec.name)
        name_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 13px; font-weight: 700;")
        text_col.addWidget(name_lbl)
        desc_lbl = QLabel(spec.description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        text_col.addWidget(desc_lbl)
        layout.addLayout(text_col, stretch=1)

        self._status_lbl = QLabel("Checking...")
        self._status_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 11px; font-weight: 600;")
        layout.addWidget(self._status_lbl)

        self._action_btn = QPushButton()
        if spec.install_method == InstallMethod.SERVICE:
            self._action_btn.setText("Service (no install)")
            self._action_btn.setEnabled(False)
        elif spec.install_method == InstallMethod.SYSTEM:
            self._action_btn.setText("System ($PATH)")
            self._action_btn.setEnabled(False)
        else:
            self._action_btn.setText("Install")
            self._action_btn.clicked.connect(lambda: on_install(self))
        layout.addWidget(self._action_btn)

    def set_status(self, installed: bool, version: str | None) -> None:
        if installed:
            self._status_lbl.setText(f"Installed{f' ({version})' if version else ''}")
            self._status_lbl.setStyleSheet(f"color: {Colors.ACCENT_GREEN}; font-size: 11px; font-weight: 600;")
        else:
            self._status_lbl.setText("Not installed")
            self._status_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 11px; font-weight: 600;")

    def set_installing(self) -> None:
        self._action_btn.setEnabled(False)
        self._action_btn.setText("Installing...")
        self._status_lbl.setText("Working...")
        self._status_lbl.setStyleSheet(f"color: {Colors.STATUS_RUNNING}; font-size: 11px; font-weight: 600;")

    def set_install_failed(self, message: str) -> None:
        self._action_btn.setEnabled(True)
        self._action_btn.setText("Retry Install")
        self._status_lbl.setText("Failed")
        self._status_lbl.setStyleSheet(f"color: {Colors.STATUS_ERROR}; font-size: 11px; font-weight: 600;")
        self._status_lbl.setToolTip(message)


def _card(title: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setProperty("class", "Card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    header = QLabel(title)
    header.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 14px; font-weight: 700;")
    layout.addWidget(header)
    return frame, layout


class SettingsPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._deps = get_dependency_manager()
        self._task_runner = get_background_task_runner()
        self._task_runner.finished.connect(self._on_install_finished)
        self._task_runner.failed.connect(self._on_install_failed)
        self._pending_installs: dict[str, _ToolRow] = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(14)
        scroll.setWidget(content)

        title = QLabel("Settings")
        title.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        layout.addWidget(title)

        dep_card, self._dep_layout = _card("DEPENDENCY MANAGER")
        self._tool_rows: dict[str, _ToolRow] = {}
        for tool_name in sorted(TOOL_REGISTRY):
            row = _ToolRow(tool_name, on_install=self._on_install_clicked)
            self._tool_rows[tool_name] = row
            self._dep_layout.addWidget(row)
        layout.addWidget(dep_card)

        api_card, api_layout = _card("SERVICE API KEYS")
        note = QLabel(
            "\u26A0 Stored in plaintext in the local database -- no OS-keychain/encryption layer yet. "
            "Don't use these fields for anything you wouldn't want readable from the SQLite file directly."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {Colors.STATUS_WARNING}; font-size: 10px;")
        api_layout.addWidget(note)

        self._api_fields: dict[str, QLineEdit] = {}
        for label, key, is_password in _SERVICE_KEYS:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(180)
            lbl.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px;")
            row.addWidget(lbl)
            field = QLineEdit()
            field.setText(get_setting(key, default="") or "")
            if is_password:
                field.setEchoMode(QLineEdit.Password)
            self._api_fields[key] = field
            row.addWidget(field)
            row_widget = QWidget()
            row_widget.setLayout(row)
            api_layout.addWidget(row_widget)

        save_btn = QPushButton("Save API Keys")
        save_btn.setProperty("class", "Primary")
        save_btn.clicked.connect(self._on_save_api_keys)
        api_layout.addWidget(save_btn)
        layout.addWidget(api_card)

        layout.addStretch()
        self.refresh_status()

    def _on_install_clicked(self, row: "_ToolRow") -> None:
        row.set_installing()
        job_id = self._task_runner.run(self._deps.install, row.tool_name)
        self._pending_installs[job_id] = row

    def _on_install_finished(self, job_id: str, result) -> None:
        row = self._pending_installs.pop(job_id, None)
        if row is None:
            return
        row.set_status(result.installed, result.version)
        row._action_btn.setEnabled(True)
        row._action_btn.setText("Reinstall" if result.installed else "Install")
        self._main_window.set_status(f"{row.tool_name}: {'installed' if result.installed else 'install failed'}",
                                      Colors.ACCENT_GREEN if result.installed else Colors.STATUS_ERROR)

    def _on_install_failed(self, job_id: str, error_message: str) -> None:
        row = self._pending_installs.pop(job_id, None)
        if row is None:
            return
        row.set_install_failed(error_message)
        self._main_window.set_status(f"{row.tool_name} install failed: {error_message}", Colors.STATUS_ERROR)

    def _on_save_api_keys(self) -> None:
        for key, field in self._api_fields.items():
            set_setting(key, field.text())
        self._main_window.set_status("API keys saved", Colors.ACCENT_GREEN)

    def refresh_status(self) -> None:
        for tool_name, row in self._tool_rows.items():
            status = self._deps.status(tool_name)
            row.set_status(status.installed, status.version)
