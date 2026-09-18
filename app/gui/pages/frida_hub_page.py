"""
app.gui.pages.frida_hub_page
===============================

Frida control surface: host CLI status, the two on-device frida-server
binaries, and start/stop/status for the server on a selected device.

Every action is a real call into ``DeviceConnectionManager`` (which
pushes the matching frida-server build to the device, chmods it and
launches it) or ``DependencyManager``. The GUI never runs adb or frida
itself -- see the architecture rule.

What this page does *not* do is run scripts. ``frida_instrumentation``
is a workflow plugin, so hooking a running app happens through the
Dynamic Analysis pipeline where its output can be aggregated into
findings; this page exists to get the device into a state where that
pipeline will succeed.
"""

from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QWidget

from app.core.dependency_manager import get_dependency_manager
from app.core.device.connection_manager import get_connection_manager
from app.database.database import session_scope
from app.database.models import Device, Platform
from app.gui.controllers.background_task_runner import get_background_task_runner
from app.gui.pages.common import ActionRow, BasePage, card, clear_layout, empty_state, kv_row, label
from app.gui.pages.workflow_page import invalidate_health_cache
from app.gui.theme import Colors


class FridaHubPage(BasePage):
    title_text = "Frida Hub"
    subtitle_text = (
        "Get a device ready for runtime instrumentation: install the Frida CLI on this "
        "machine, push the matching frida-server build to the device, and start it."
    )

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._deps = get_dependency_manager()
        self._devices = get_connection_manager()
        self._task_runner = get_background_task_runner()
        self._task_runner.finished.connect(self._on_finished)
        self._task_runner.failed.connect(self._on_failed)
        self._jobs: dict[str, str] = {}

        self._build_host_card()
        self._build_device_card()
        self.refresh()

    def _build_host_card(self) -> None:
        frame, layout = card(
            "HOST COMPONENTS",
            "frida-tools runs on this machine. The frida-server binaries are pushed to the "
            "device and must match its CPU architecture.",
        )
        self._tool_rows: dict[str, ActionRow] = {}
        for tool_name, description in [
            ("frida", "Frida CLI and Python bindings, installed into an isolated virtualenv."),
            ("frida_server_arm64", "On-device server for arm64 physical devices."),
            ("frida_server_x86_64", "On-device server for x86_64 emulators."),
            ("objection", "Runtime mobile exploration toolkit built on Frida."),
        ]:
            row = ActionRow(tool_name, description)
            row.add_button("Install", lambda _=False, n=tool_name: self._on_install(n))
            self._tool_rows[tool_name] = row
            layout.addWidget(row)
        self.body.addWidget(frame)

    def _build_device_card(self) -> None:
        frame, layout = card(
            "FRIDA SERVER ON DEVICE",
            "Starting frida-server needs root on the device. On a non-rooted device this "
            "will fail, and that is a property of the device, not a bug here.",
        )
        self._device_combo = QComboBox()
        self._device_combo.currentIndexChanged.connect(self._on_device_changed)
        layout.addWidget(self._device_combo)

        actions = ActionRow("frida-server", "Select a device to see its current state.")
        actions.add_button("Check status", self._on_check, primary=False)
        actions.add_button("Start", self._on_start, primary=True)
        actions.add_button("Stop", self._on_stop)
        self._actions = actions
        layout.addWidget(actions)

        self._detail_layout = layout
        self._detail_anchor = layout.count()
        self.body.addWidget(frame)

    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        if not hasattr(self, "_device_combo"):
            return
        self._reload_devices()
        self._jobs[self._task_runner.run(self._deps.status_all)] = "status_all"

    def _reload_devices(self) -> None:
        with session_scope() as session:
            rows = [
                (d.identifier, d.display_name, d.status.value, d.is_rooted)
                for d in session.query(Device)
                .filter(Device.platform == Platform.ANDROID)
                .order_by(Device.last_connected_at.desc().nullslast())
                .all()
            ]
        previous = self._device_combo.currentData()
        self._device_combo.blockSignals(True)
        self._device_combo.clear()
        if not rows:
            self._device_combo.addItem("No devices \u2014 scan on the Devices page", None)
            self._device_combo.setEnabled(False)
        else:
            self._device_combo.setEnabled(True)
            for identifier, name, status, rooted in rows:
                suffix = "  \u2022  rooted" if rooted else ""
                self._device_combo.addItem(f"{name}  \u2014  {identifier}  ({status}){suffix}",
                                           identifier)
            if previous:
                index = self._device_combo.findData(previous)
                if index >= 0:
                    self._device_combo.setCurrentIndex(index)
        self._device_combo.blockSignals(False)
        self._on_device_changed()

    def _serial(self) -> str | None:
        return self._device_combo.currentData()

    def _on_device_changed(self) -> None:
        serial = self._serial()
        self._actions.set_description(
            f"Target: {serial}" if serial
            else "No device selected. Scan for devices on the Devices page first."
        )

    # ------------------------------------------------------------------ #
    def _on_install(self, tool_name: str) -> None:
        self.set_status(f"Installing {tool_name}...", Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._deps.install, tool_name)] = f"install:{tool_name}"

    def _on_check(self) -> None:
        serial = self._serial()
        if not serial:
            return
        self.set_status(f"Querying {serial}...", Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._devices.get_readiness, serial)] = "readiness"

    def _on_start(self) -> None:
        serial = self._serial()
        if not serial:
            return
        self.set_status(
            f"Pushing and starting frida-server on {serial} (needs root)...",
            Colors.STATUS_RUNNING,
        )
        self._jobs[
            self._task_runner.run(self._devices.start_frida_server, serial)
        ] = "start"

    def _on_stop(self) -> None:
        serial = self._serial()
        if not serial:
            return
        self._jobs[self._task_runner.run(self._devices.stop_frida_server, serial)] = "stop"

    # ------------------------------------------------------------------ #
    def _on_finished(self, job_id: str, result) -> None:
        kind = self._jobs.pop(job_id, None)
        if kind is None:
            return

        if kind == "status_all":
            for tool_name, row in self._tool_rows.items():
                status = (result or {}).get(tool_name)
                if status is None:
                    continue
                if status.installed:
                    row.set_status("INSTALLED", Colors.ACCENT_GREEN)
                else:
                    row.set_status("NOT INSTALLED", Colors.TEXT_MUTED)
        elif kind.startswith("install:"):
            invalidate_health_cache()
            tool_name = kind.split(":", 1)[1]
            row = self._tool_rows.get(tool_name)
            if row is not None:
                row.set_status(
                    "INSTALLED" if result.installed else "FAILED",
                    Colors.ACCENT_GREEN if result.installed else Colors.STATUS_ERROR,
                )
            self.set_status(
                f"{tool_name}: {'installed' if result.installed else 'install failed'}",
                Colors.ACCENT_GREEN if result.installed else Colors.STATUS_ERROR,
            )
        elif kind == "readiness":
            self._render_readiness(result)
        elif kind == "start":
            started = bool(result)
            self.set_status(
                "frida-server is running on the device."
                if started else
                "frida-server did not start. The usual cause is no root shell on the device.",
                Colors.ACCENT_GREEN if started else Colors.STATUS_ERROR,
            )
            self._on_check()
        elif kind == "stop":
            self.set_status("Stop signal sent to frida-server.", Colors.TEXT_SECONDARY)
            self._on_check()

    def _on_failed(self, job_id: str, error_message: str) -> None:
        kind = self._jobs.pop(job_id, None)
        self.set_status(f"{kind or 'Task'} failed: {error_message}", Colors.STATUS_ERROR)

    def _render_readiness(self, readiness) -> None:
        clear_layout(self._detail_layout, keep=self._detail_anchor)
        if readiness is None:
            self._detail_layout.addWidget(empty_state("No readiness data returned."))
            return

        self._detail_layout.addWidget(kv_row(
            "Root shell", "yes" if readiness.is_rooted else "no",
            Colors.ACCENT_GREEN if readiness.is_rooted else Colors.STATUS_WARNING,
        ))
        self._detail_layout.addWidget(kv_row(
            "frida-server", "running" if readiness.frida_server_running else "not running",
            Colors.ACCENT_GREEN if readiness.frida_server_running else Colors.TEXT_MUTED,
        ))
        self._detail_layout.addWidget(kv_row(
            "Proxy configured", "yes" if readiness.proxy_configured else "no"
        ))
        self._detail_layout.addWidget(kv_row(
            "User CA certificates", str(len(readiness.user_certs_installed))
        ))
        if not readiness.frida_server_running:
            self._detail_layout.addWidget(label(
                "Dynamic Analysis will skip its Frida step until the server is running.",
                size=10, color=Colors.STATUS_WARNING, wrap=True,
            ))
