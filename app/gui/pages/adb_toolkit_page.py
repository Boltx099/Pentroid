"""
app.gui.pages.adb_toolkit_page
=================================

Day-to-day ADB operations against a selected device: server lifecycle,
device properties, installed third-party packages, and install /
launch / force-stop / uninstall for a chosen package.

Every operation is a method on ``DeviceConnectionManager``, which runs
adb through ``ToolManager`` with ``shell=False`` and a timeout. This
page deliberately offers no free-text "run any adb command" box: that
would hand arbitrary argv to a subprocess from the GUI layer and
bypass the single enforcement point the architecture puts in
ToolManager.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QComboBox, QFileDialog, QHBoxLayout, QPushButton, QWidget

from app.core.device.connection_manager import get_connection_manager
from app.database.database import session_scope
from app.database.models import Device, Platform
from app.gui.controllers.background_task_runner import get_background_task_runner
from app.gui.pages.common import (
    ActionRow, BasePage, card, clear_layout, empty_state, kv_row, label,
)
from app.gui.theme import Colors

# getprop returns several hundred keys; these are the ones that actually
# matter when deciding whether a device can run a given workflow.
_INTERESTING_PROPS = [
    ("ro.product.manufacturer", "Manufacturer"),
    ("ro.product.model", "Model"),
    ("ro.build.version.release", "Android version"),
    ("ro.build.version.sdk", "API level"),
    ("ro.product.cpu.abi", "CPU ABI"),
    ("ro.build.type", "Build type"),
    ("ro.debuggable", "Debuggable build"),
    ("ro.secure", "ro.secure"),
]


class AdbToolkitPage(BasePage):
    title_text = "ADB Toolkit"
    subtitle_text = (
        "Inspect and drive a connected Android device. Commands run through the same "
        "sandboxed ToolManager the analysis plugins use."
    )

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._devices = get_connection_manager()
        self._task_runner = get_background_task_runner()
        self._task_runner.finished.connect(self._on_finished)
        self._task_runner.failed.connect(self._on_failed)
        self._jobs: dict[str, str] = {}
        self._apk_path: str | None = None

        self._build_device_card()
        self._build_properties_card()
        self._build_packages_card()
        self._build_install_card()
        self.refresh()

    # ------------------------------------------------------------------ #
    def _build_device_card(self) -> None:
        frame, layout = card("DEVICE", "Pick the target for every action on this page.")
        self._device_combo = QComboBox()
        layout.addWidget(self._device_combo)

        row = ActionRow("ADB server", "Start the local adb daemon if it isn't already running.")
        row.add_button("Start server", self._on_start_server)
        row.add_button("Rescan devices", self._on_rescan, primary=True)
        layout.addWidget(row)
        self.body.addWidget(frame)

    def _build_properties_card(self) -> None:
        frame, layout = card("DEVICE PROPERTIES", "Read live from `adb shell getprop`.")
        self._props_layout = layout
        self._props_anchor = layout.count()
        load = QPushButton("Read properties")
        load.clicked.connect(self._on_read_props)
        layout.addWidget(load)
        self._props_anchor = layout.count()
        layout.addWidget(empty_state("Click 'Read properties' to query the device."))
        self.body.addWidget(frame)

    def _build_packages_card(self) -> None:
        frame, layout = card(
            "INSTALLED PACKAGES",
            "Third-party packages only \u2014 the several hundred system packages on a stock "
            "image are noise when you're testing an app.",
        )
        self._package_combo = QComboBox()
        self._package_combo.setEnabled(False)
        layout.addWidget(self._package_combo)

        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(10)
        for text, handler, primary in [
            ("List packages", self._on_list_packages, True),
            ("Launch", self._on_launch, False),
            ("Force stop", self._on_force_stop, False),
            ("Uninstall", self._on_uninstall, False),
        ]:
            btn = QPushButton(text)
            if primary:
                btn.setProperty("class", "Primary")
            btn.clicked.connect(handler)
            row_layout.addWidget(btn)
        row_layout.addStretch()
        layout.addWidget(row)
        self.body.addWidget(frame)

    def _build_install_card(self) -> None:
        frame, layout = card(
            "INSTALL AN APK",
            "Runs `adb install -r`, which reinstalls over an existing copy and keeps its data.",
        )
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(10)
        self._apk_label = label("No APK selected", size=11, color=Colors.TEXT_MUTED, wrap=True)
        row_layout.addWidget(self._apk_label, stretch=1)
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._on_browse_apk)
        row_layout.addWidget(browse)
        install = QPushButton("Install on device")
        install.setProperty("class", "Primary")
        install.clicked.connect(self._on_install_apk)
        row_layout.addWidget(install)
        layout.addWidget(row)
        self.body.addWidget(frame)

    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        if not hasattr(self, "_device_combo"):
            return
        with session_scope() as session:
            rows = [
                (d.identifier, d.display_name, d.status.value)
                for d in session.query(Device)
                .filter(Device.platform == Platform.ANDROID)
                .order_by(Device.last_connected_at.desc().nullslast())
                .all()
            ]
        previous = self._device_combo.currentData()
        self._device_combo.blockSignals(True)
        self._device_combo.clear()
        if not rows:
            self._device_combo.addItem("No devices \u2014 click Rescan devices", None)
            self._device_combo.setEnabled(False)
        else:
            self._device_combo.setEnabled(True)
            for identifier, name, status in rows:
                self._device_combo.addItem(f"{name}  \u2014  {identifier}  ({status})", identifier)
            if previous:
                index = self._device_combo.findData(previous)
                if index >= 0:
                    self._device_combo.setCurrentIndex(index)
        self._device_combo.blockSignals(False)

    def _serial(self) -> str | None:
        serial = self._device_combo.currentData()
        if not serial:
            self.set_status("Select a device first.", Colors.STATUS_WARNING)
        return serial

    def _package(self) -> str | None:
        package = self._package_combo.currentData()
        if not package:
            self.set_status("List packages and pick one first.", Colors.STATUS_WARNING)
        return package

    # ------------------------------------------------------------------ #
    def _on_start_server(self) -> None:
        self.set_status("Starting the ADB server...", Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._devices.start_adb_server)] = "start_server"

    def _on_rescan(self) -> None:
        self.set_status("Scanning for devices over ADB...", Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._devices.scan_and_sync)] = "scan"

    def _on_read_props(self) -> None:
        serial = self._serial()
        if not serial:
            return
        self.set_status(f"Reading properties from {serial}...", Colors.STATUS_RUNNING)
        self._jobs[
            self._task_runner.run(self._devices.get_device_properties, serial)
        ] = "props"

    def _on_list_packages(self) -> None:
        serial = self._serial()
        if not serial:
            return
        self.set_status(f"Listing third-party packages on {serial}...", Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._devices.list_packages, serial)] = "packages"

    def _on_launch(self) -> None:
        serial, package = self._serial(), self._package()
        if not serial or not package:
            return
        self._jobs[
            self._task_runner.run(self._devices.launch_app, serial, package)
        ] = f"launch:{package}"

    def _on_force_stop(self) -> None:
        serial, package = self._serial(), self._package()
        if not serial or not package:
            return
        self._jobs[
            self._task_runner.run(self._devices.force_stop_app, serial, package)
        ] = f"stop:{package}"

    def _on_uninstall(self) -> None:
        serial, package = self._serial(), self._package()
        if not serial or not package:
            return
        self._jobs[
            self._task_runner.run(self._devices.uninstall_app, serial, package)
        ] = f"uninstall:{package}"

    def _on_browse_apk(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select an APK", "", "APK Files (*.apk)")
        if path:
            self._apk_path = path
            self._apk_label.setText(Path(path).name)
            self._apk_label.setStyleSheet(
                f"color: {Colors.TEXT_PRIMARY}; font-size: 11px; font-weight: 400;"
            )

    def _on_install_apk(self) -> None:
        serial = self._serial()
        if not serial:
            return
        if not self._apk_path:
            self.set_status("Select an APK first.", Colors.STATUS_WARNING)
            return
        self.set_status(f"Installing {Path(self._apk_path).name}...", Colors.STATUS_RUNNING)
        self._jobs[
            self._task_runner.run(self._devices.install_apk, serial, self._apk_path)
        ] = "install_apk"

    # ------------------------------------------------------------------ #
    def _on_finished(self, job_id: str, result) -> None:
        kind = self._jobs.pop(job_id, None)
        if kind is None:
            return

        if kind == "start_server":
            self.set_status("ADB server is running.", Colors.ACCENT_GREEN)
        elif kind == "scan":
            count = len(result) if result else 0
            self.set_status(f"Scan complete \u2014 {count} device(s).", Colors.ACCENT_GREEN)
            self.refresh()
        elif kind == "props":
            self._render_props(result or {})
        elif kind == "packages":
            self._render_packages(result or [])
        elif kind == "install_apk":
            ok = bool(result)
            self.set_status(
                "APK installed." if ok else
                "Install did not report success \u2014 check signature conflicts or free space.",
                Colors.ACCENT_GREEN if ok else Colors.STATUS_ERROR,
            )
        elif kind.startswith("launch:"):
            ok = bool(result)
            package = kind.split(":", 1)[1]
            self.set_status(
                f"Launched {package}." if ok else
                f"Could not launch {package} \u2014 it may have no launcher activity.",
                Colors.ACCENT_GREEN if ok else Colors.STATUS_WARNING,
            )
        elif kind.startswith("stop:"):
            self.set_status(f"Force-stopped {kind.split(':', 1)[1]}.", Colors.TEXT_SECONDARY)
        elif kind.startswith("uninstall:"):
            ok = bool(result)
            package = kind.split(":", 1)[1]
            self.set_status(
                f"Uninstalled {package}." if ok else f"Could not uninstall {package}.",
                Colors.ACCENT_GREEN if ok else Colors.STATUS_ERROR,
            )
            if ok:
                self._on_list_packages()

    def _on_failed(self, job_id: str, error_message: str) -> None:
        self._jobs.pop(job_id, None)
        self.set_status(error_message, Colors.STATUS_ERROR)

    def _render_props(self, props: dict[str, str]) -> None:
        clear_layout(self._props_layout, keep=self._props_anchor)
        if not props:
            self._props_layout.addWidget(empty_state("The device returned no properties."))
            return
        for key, display in _INTERESTING_PROPS:
            if key in props:
                self._props_layout.addWidget(kv_row(display, props[key]))
        self._props_layout.addWidget(label(
            f"{len(props)} properties read in total; the rest are omitted as noise.",
            size=10, color=Colors.TEXT_MUTED,
        ))

    def _render_packages(self, packages: list[str]) -> None:
        self._package_combo.clear()
        if not packages:
            self._package_combo.addItem("No third-party packages installed", None)
            self._package_combo.setEnabled(False)
            self.set_status("No third-party packages on that device.", Colors.TEXT_MUTED)
            return
        self._package_combo.setEnabled(True)
        for package in packages:
            self._package_combo.addItem(package, package)
        self.set_status(f"{len(packages)} third-party package(s) found.", Colors.ACCENT_GREEN)
