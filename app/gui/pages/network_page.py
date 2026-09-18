"""
app.gui.pages.network_page
=============================

Interception setup for device traffic: install mitmproxy, point the
device's global HTTP proxy at this machine, and check which user CA
certificates the device trusts.

Boundary, stated plainly: there is no traffic-capture *plugin*, so
there is no network workflow that produces findings. Everything the
Workflow Engine can aggregate comes from a Plugin, and none of the
nineteen installed plugins parses a flow file. What this page does is
the setup work that has to happen first, and every button on it is a
real call into ``DeviceConnectionManager`` or ``DependencyManager``.

The static pipeline already covers a good part of the network story
without any capture at all -- the Network Security Config plugin
reports cleartext-traffic policy and certificate pinning, and Tracker
Detection reports the third-party endpoints an app ships with.
"""

from __future__ import annotations

import socket

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QPushButton, QWidget

from app.core.dependency_manager import get_dependency_manager
from app.core.device.connection_manager import get_connection_manager
from app.database.database import session_scope
from app.database.models import Device, Platform
from app.gui.controllers.background_task_runner import get_background_task_runner
from app.gui.pages.common import (
    ActionRow, BasePage, NoticeCard, card, clear_layout, empty_state, kv_row, label,
)
from app.gui.theme import Colors

_DEFAULT_PROXY_PORT = 8080


def local_ip() -> str:
    """
    Best guess at the LAN address a device should send traffic to.

    Opens a UDP socket toward a public address and reads back the local
    endpoint the OS chose. No packet is actually sent -- ``connect`` on a UDP
    socket only fixes the route -- so this works offline and never reaches the
    internet. It beats ``gethostbyname(gethostname())``, which returns
    127.0.1.1 on most Linux distributions and would be useless to a phone.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


class NetworkAnalysisPage(BasePage):
    title_text = "Network Analysis"
    subtitle_text = (
        "Set a device up to route its traffic through an intercepting proxy on this machine."
    )

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._devices = get_connection_manager()
        self._deps = get_dependency_manager()
        self._task_runner = get_background_task_runner()
        self._task_runner.finished.connect(self._on_finished)
        self._task_runner.failed.connect(self._on_failed)
        self._jobs: dict[str, str] = {}

        self.body.addWidget(NoticeCard(
            "Traffic capture isn't wired into a workflow yet",
            "Findings in Pentroid are produced by plugins, and none of the installed plugins "
            "parses a captured flow, so there is no network workflow to run and no network "
            "findings to score. This page does the setup that has to happen first \u2014 proxy, "
            "certificate trust \u2014 after which you read the traffic in mitmproxy or Burp "
            "directly.",
            bullets=[
                "Already covered without capture: Network Security Config reports "
                "cleartext-traffic policy and pinning; Tracker Detection reports the "
                "third-party endpoints baked into the app.",
                "Apps that pin certificates will not appear in the proxy at all until the "
                "pinning is bypassed \u2014 use Dynamic Analysis with Frida for that.",
            ],
        ))

        self._build_proxy_tool_card()
        self._build_device_card()
        self.refresh()

    def _build_proxy_tool_card(self) -> None:
        frame, layout = card(
            "PROXY", "mitmproxy runs on this machine and terminates the device's TLS."
        )
        self._mitm_row = ActionRow(
            "mitmproxy",
            "Intercepting proxy. Its CA certificate is generated on first run at "
            "~/.mitmproxy/mitmproxy-ca-cert.cer and must be trusted by the device.",
        )
        self._mitm_row.add_button("Install", lambda: self._on_install("mitmproxy"))
        layout.addWidget(self._mitm_row)

        self._burp_row = ActionRow(
            "Burp Suite",
            "Configured as a service under Settings rather than installed here.",
        )
        layout.addWidget(self._burp_row)

        layout.addWidget(kv_row("This machine's LAN address", local_ip()))
        self.body.addWidget(frame)

    def _build_device_card(self) -> None:
        frame, layout = card(
            "DEVICE PROXY",
            "Writes the device's global HTTP proxy setting over ADB. Apps using the platform "
            "HTTP stack will follow it; apps opening raw sockets will not.",
        )
        self._device_combo = QComboBox()
        layout.addWidget(self._device_combo)

        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(10)
        row_layout.addWidget(label("Proxy", size=11, color=Colors.TEXT_SECONDARY))
        self._host_edit = QLineEdit(local_ip())
        row_layout.addWidget(self._host_edit, stretch=1)
        self._port_edit = QLineEdit(str(_DEFAULT_PROXY_PORT))
        self._port_edit.setFixedWidth(80)
        row_layout.addWidget(self._port_edit)

        set_btn = QPushButton("Set proxy")
        set_btn.setProperty("class", "Primary")
        set_btn.clicked.connect(self._on_set_proxy)
        row_layout.addWidget(set_btn)

        clear_btn = QPushButton("Clear proxy")
        clear_btn.clicked.connect(self._on_clear_proxy)
        row_layout.addWidget(clear_btn)

        check_btn = QPushButton("Check state")
        check_btn.clicked.connect(self._on_check)
        row_layout.addWidget(check_btn)
        layout.addWidget(row)

        self._state_layout = layout
        self._state_anchor = layout.count()
        layout.addWidget(empty_state("Select a device and click 'Check state'."))
        self.body.addWidget(frame)

    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        if not hasattr(self, "_device_combo"):
            return

        status = self._deps.status("mitmproxy")
        self._mitm_row.set_status(
            "INSTALLED" if status.installed else "NOT INSTALLED",
            Colors.ACCENT_GREEN if status.installed else Colors.TEXT_MUTED,
        )
        self._burp_row.set_status("SERVICE", Colors.ACCENT_CYAN)

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
            self._device_combo.addItem("No devices \u2014 scan on the Devices page", None)
            self._device_combo.setEnabled(False)
        else:
            self._device_combo.setEnabled(True)
            for identifier, name, status_value in rows:
                self._device_combo.addItem(
                    f"{name}  \u2014  {identifier}  ({status_value})", identifier
                )
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

    def _on_install(self, tool_name: str) -> None:
        self.set_status(f"Installing {tool_name}...", Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._deps.install, tool_name)] = "install"

    def _on_set_proxy(self) -> None:
        serial = self._serial()
        if not serial:
            return
        host = self._host_edit.text().strip()
        try:
            port = int(self._port_edit.text().strip())
        except ValueError:
            self.set_status("Port must be a number.", Colors.STATUS_ERROR)
            return
        self.set_status(f"Setting proxy to {host}:{port} on {serial}...", Colors.STATUS_RUNNING)
        self._jobs[
            self._task_runner.run(self._devices.set_proxy, serial, host, port)
        ] = "set_proxy"

    def _on_clear_proxy(self) -> None:
        serial = self._serial()
        if not serial:
            return
        self._jobs[self._task_runner.run(self._devices.clear_proxy, serial)] = "clear_proxy"

    def _on_check(self) -> None:
        serial = self._serial()
        if not serial:
            return
        self.set_status(f"Reading proxy and certificate state from {serial}...",
                        Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._collect_state, serial)] = "state"

    def _collect_state(self, serial: str) -> dict:
        return {
            "proxy": self._devices.get_proxy_settings(serial),
            "certs": self._devices.list_user_certificates(serial),
        }

    # ------------------------------------------------------------------ #
    def _on_finished(self, job_id: str, result) -> None:
        kind = self._jobs.pop(job_id, None)
        if kind == "install":
            self.refresh()
            self.set_status(
                "mitmproxy installed." if result.installed else "Install failed.",
                Colors.ACCENT_GREEN if result.installed else Colors.STATUS_ERROR,
            )
        elif kind == "set_proxy":
            self.set_status(f"Device now reports http_proxy = {result}", Colors.ACCENT_GREEN)
            self._on_check()
        elif kind == "clear_proxy":
            self.set_status("Proxy cleared.", Colors.TEXT_SECONDARY)
            self._on_check()
        elif kind == "state":
            self._render_state(result or {})

    def _on_failed(self, job_id: str, error_message: str) -> None:
        self._jobs.pop(job_id, None)
        self.set_status(error_message, Colors.STATUS_ERROR)

    def _render_state(self, state: dict) -> None:
        clear_layout(self._state_layout, keep=self._state_anchor)
        proxy = state.get("proxy")
        certs = state.get("certs") or []

        self._state_layout.addWidget(kv_row(
            "http_proxy", proxy or "not set",
            Colors.ACCENT_GREEN if proxy else Colors.TEXT_MUTED,
        ))
        self._state_layout.addWidget(kv_row(
            "User CA certificates", str(len(certs)),
            Colors.ACCENT_GREEN if certs else Colors.STATUS_WARNING,
        ))
        for name in certs[:10]:
            self._state_layout.addWidget(kv_row(f"  {name}", "trusted"))

        if not certs:
            self._state_layout.addWidget(label(
                "No user CA certificate is installed, so TLS interception will fail with a "
                "certificate error inside the app. Install the proxy's CA on the device "
                "first. Note that on Android 7+ apps only trust user CAs if their network "
                "security config opts in, which most release builds don't \u2014 that usually "
                "means a rooted device with the CA in the system store.",
                size=10, color=Colors.STATUS_WARNING, wrap=True,
            ))
        self.set_status("Device state read.", Colors.ACCENT_GREEN)
