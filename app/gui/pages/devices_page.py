"""
app.gui.pages.devices_page
=============================

Lists real ``Device`` rows from the database, lets the user trigger a
real ADB scan (``DeviceConnectionManager.scan_and_sync``), and run the
real ``DeviceSetupWizard`` against a specific device -- all through
``BackgroundTaskRunner`` so the blocking ADB subprocess calls never
freeze the GUI thread.

Per architecture rule, this page never calls ``adb``/``ToolManager``
directly -- only through ``DeviceConnectionManager`` /
``DeviceSetupWizard``.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from app.core.device.connection_manager import get_connection_manager
from app.core.device.setup_wizard import DeviceSetupWizard
from app.database.database import session_scope
from app.database.models import Device
from app.gui.controllers.background_task_runner import get_background_task_runner
from app.gui.dialogs.setup_wizard_dialog import SetupWizardDialog
from app.gui.icon_provider import get_icon, icon_label
from app.gui.theme import Colors


class _DeviceRow(QFrame):
    def __init__(self, identifier: str, name: str, platform: str, conn_type: str,
                 status: str, is_rooted: bool, on_run_wizard, parent=None):
        super().__init__(parent)
        self.identifier = identifier
        self.setProperty("class", "Card")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        icon = icon_label("android_apk" if platform == "android" else "ios_analysis", size=20)
        layout.addWidget(icon)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 13px; font-weight: 700;")
        text_col.addWidget(name_lbl)
        detail = f"{identifier} \u2022 {conn_type}" + (" \u2022 rooted" if is_rooted else "")
        detail_lbl = QLabel(detail)
        detail_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        text_col.addWidget(detail_lbl)
        layout.addLayout(text_col, stretch=1)

        status_color = {
            "ready": Colors.ACCENT_GREEN, "unauthorized": Colors.STATUS_WARNING,
            "busy": Colors.STATUS_RUNNING,
        }.get(status, Colors.TEXT_MUTED)
        status_lbl = QLabel(status.upper())
        status_lbl.setStyleSheet(
            f"color: {status_color}; font-size: 10px; font-weight: 700; "
            f"border: 1px solid {status_color}; border-radius: 6px; padding: 2px 8px;"
        )
        layout.addWidget(status_lbl)

        wizard_btn = QPushButton("Run Setup Wizard")
        wizard_btn.clicked.connect(lambda: on_run_wizard(identifier))
        layout.addWidget(wizard_btn)


class DevicesPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._connection_manager = get_connection_manager()
        self._task_runner = get_background_task_runner()
        self._task_runner.finished.connect(self._on_task_finished)
        self._task_runner.failed.connect(self._on_task_failed)
        self._pending_kind: dict[str, str] = {}  # job_id -> "scan" | "wizard"
        self._wizard_dialog: SetupWizardDialog | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(14)

        header = QHBoxLayout()
        title = QLabel("Devices")
        title.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()
        self._wireless_btn = QPushButton("Connect Wirelessly")
        self._wireless_btn.clicked.connect(self._on_connect_wireless)
        header.addWidget(self._wireless_btn)
        self._scan_btn = QPushButton("Scan for Devices")
        self._scan_btn.setIcon(get_icon("refresh", "#06110a", 14))
        self._scan_btn.setProperty("class", "Primary")
        self._scan_btn.clicked.connect(self._on_scan)
        header.addWidget(self._scan_btn)
        outer.addLayout(header)

        self._note_label = QLabel("")
        self._note_label.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 11px;")
        self._note_label.setWordWrap(True)
        outer.addWidget(self._note_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        list_container = QWidget()
        self._list_layout = QVBoxLayout(list_container)
        self._list_layout.setSpacing(8)
        self._list_layout.setAlignment(Qt.AlignTop)
        scroll.setWidget(list_container)
        outer.addWidget(scroll, stretch=1)

        self.refresh()

    def _on_connect_wireless(self) -> None:
        from app.gui.dialogs.wireless_connect_dialog import WirelessConnectDialog

        dialog = WirelessConnectDialog(self, connection_manager=self._connection_manager)
        dialog.exec()
        if dialog.connected:
            # A newly connected wireless device only shows up after a rescan.
            self._on_scan()

    def _on_scan(self) -> None:
        self._scan_btn.setEnabled(False)
        self._note_label.setText("Scanning for devices via ADB...")
        self._note_label.setStyleSheet(f"color: {Colors.STATUS_RUNNING}; font-size: 11px;")
        job_id = self._task_runner.run(self._connection_manager.scan_and_sync)
        self._pending_kind[job_id] = "scan"

    def _on_run_wizard(self, serial: str) -> None:
        dialog = SetupWizardDialog(self)
        self._wizard_dialog = dialog
        wizard = DeviceSetupWizard(connection_manager=self._connection_manager)
        job_id = self._task_runner.run(wizard.run, serial=serial)
        self._pending_kind[job_id] = "wizard"
        dialog.exec()

    def _on_task_finished(self, job_id: str, result) -> None:
        kind = self._pending_kind.pop(job_id, None)
        if kind == "scan":
            self._scan_btn.setEnabled(True)
            count = len(result) if result else 0
            self._note_label.setText(f"Scan complete -- {count} device(s) found.")
            self._note_label.setStyleSheet(f"color: {Colors.ACCENT_GREEN}; font-size: 11px;")
            self.refresh()
        elif kind == "wizard" and self._wizard_dialog is not None:
            self._wizard_dialog.show_results(result)

    def _on_task_failed(self, job_id: str, error_message: str) -> None:
        kind = self._pending_kind.pop(job_id, None)
        if kind == "scan":
            self._scan_btn.setEnabled(True)
            self._note_label.setText(f"Scan failed: {error_message}")
            self._note_label.setStyleSheet(f"color: {Colors.STATUS_ERROR}; font-size: 11px;")
        elif kind == "wizard" and self._wizard_dialog is not None:
            self._wizard_dialog.show_error(error_message)

    def refresh(self) -> None:
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        with session_scope() as session:
            devices = session.query(Device).order_by(Device.last_connected_at.desc().nullslast()).all()
            rows_data = [
                (d.identifier, d.display_name, d.platform.value, d.connection_type.value,
                 d.status.value, d.is_rooted)
                for d in devices
            ]

        if not rows_data:
            empty = QLabel(
                "No devices detected yet. Connect a device or start an emulator, "
                "then click \u201cScan for Devices\u201d."
            )
            empty.setAlignment(Qt.AlignCenter)
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 12px; padding: 40px;")
            self._list_layout.addWidget(empty)
            return

        for row_data in rows_data:
            self._list_layout.addWidget(_DeviceRow(*row_data, on_run_wizard=self._on_run_wizard))
