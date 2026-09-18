"""
app.gui.pages.ios_page
=========================

iOS support, stated accurately.

``IOSConnectionManager`` is real and works: it enumerates simulators
and physical devices, reads device info over lockdown, and assesses a
jailbroken device over SSH. This page drives all of that.

What does **not** exist is an IPA analysis pipeline. Every plugin under
``app/plugins/installed`` parses Android artefacts -- APK signing
blocks, AndroidManifest.xml, dex, smali -- and none of them can read a
Mach-O binary, an ``Info.plist`` or an embedded mobileprovision. Rather
than render an empty "run analysis" button that would imply the
capability exists and is merely misconfigured, the page says so and
lists exactly what is wired up today.
"""

from __future__ import annotations

from PySide6.QtWidgets import QLineEdit, QPushButton, QWidget

from app.core.dependency_manager import get_dependency_manager
from app.core.device.ios_connection_manager import get_ios_connection_manager
from app.gui.controllers.background_task_runner import get_background_task_runner
from app.gui.pages.common import (
    ActionRow, BasePage, NoticeCard, card, clear_layout, empty_state, kv_row, label,
)
from app.gui.theme import Colors


class IOSAnalysisPage(BasePage):
    title_text = "iOS Analysis"
    subtitle_text = (
        "Discover iOS simulators and devices, read device info, and assess a jailbroken "
        "device's instrumentation surface."
    )

    def __init__(self, main_window, parent=None):
        super().__init__(main_window, parent)
        self._ios = get_ios_connection_manager()
        self._deps = get_dependency_manager()
        self._task_runner = get_background_task_runner()
        self._task_runner.finished.connect(self._on_finished)
        self._task_runner.failed.connect(self._on_failed)
        self._jobs: dict[str, str] = {}

        self.body.addWidget(NoticeCard(
            "No IPA analysis pipeline exists yet",
            "Pentroid's nineteen analysis plugins all parse Android artefacts. There is no "
            "plugin that reads a Mach-O binary, Info.plist or embedded mobileprovision, so "
            "there is no iOS static workflow to run \u2014 pointing this page at an .ipa would "
            "produce nothing. The iOS device tooling below is real and working.",
            bullets=[
                "Working: simulator and physical-device discovery, lockdown device info, "
                "SSH reachability and jailbreak assessment.",
                "Not built: IPA unpacking, binary analysis, entitlement and ATS review, "
                "iOS findings and risk scoring.",
                "Android targets are fully supported \u2014 see Android APK, Malware, Dynamic "
                "and Privacy Analysis.",
            ],
        ))

        self._build_tool_card()
        self._build_discovery_card()
        self._build_jailbreak_card()
        self.refresh()

    def _build_tool_card(self) -> None:
        frame, layout = card(
            "HOST TOOLING",
            "pymobiledevice3 talks to iOS devices over usbmux/lockdown without requiring Xcode.",
        )
        self._tool_row = ActionRow(
            "pymobiledevice3", "Required for physical-device discovery and device info."
        )
        self._tool_row.add_button("Install", self._on_install)
        layout.addWidget(self._tool_row)
        self.body.addWidget(frame)

    def _build_discovery_card(self) -> None:
        frame, layout = card(
            "DEVICES & SIMULATORS",
            "Simulators come from `simctl` (macOS only); physical devices from "
            "pymobiledevice3.",
        )
        scan = QPushButton("Scan for iOS devices")
        scan.setProperty("class", "Primary")
        scan.clicked.connect(self._on_scan)
        layout.addWidget(scan)
        self._discovery_layout = layout
        self._discovery_anchor = layout.count()
        layout.addWidget(empty_state("Click scan to enumerate simulators and devices."))
        self.body.addWidget(frame)

    def _build_jailbreak_card(self) -> None:
        frame, layout = card(
            "JAILBROKEN DEVICE ASSESSMENT",
            "Checks SSH reachability on a jailbroken device and reports what instrumentation "
            "surface it exposes. Enter the device's IP address on your network.",
        )
        self._host_edit = QLineEdit()
        self._host_edit.setPlaceholderText("e.g. 192.168.1.42")
        layout.addWidget(self._host_edit)

        assess = QPushButton("Assess device")
        assess.clicked.connect(self._on_assess)
        layout.addWidget(assess)

        self._assess_layout = layout
        self._assess_anchor = layout.count()
        self.body.addWidget(frame)

    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        if not hasattr(self, "_tool_row"):
            return
        status = self._deps.status("pymobiledevice3")
        if status.installed:
            self._tool_row.set_status("INSTALLED", Colors.ACCENT_GREEN)
        else:
            self._tool_row.set_status("NOT INSTALLED", Colors.TEXT_MUTED)

    def _on_install(self) -> None:
        self.set_status("Installing pymobiledevice3...", Colors.STATUS_RUNNING)
        self._jobs[
            self._task_runner.run(self._deps.install, "pymobiledevice3")
        ] = "install"

    def _on_scan(self) -> None:
        self.set_status("Enumerating iOS simulators and devices...", Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._collect_devices)] = "scan"

    def _collect_devices(self) -> dict:
        """Runs on a worker thread; both calls shell out and can be slow."""
        result: dict = {"simulators": [], "physical": [], "errors": []}
        try:
            result["simulators"] = self._ios.list_simulators()
        except Exception as exc:  # noqa: BLE001 - one source failing shouldn't hide the other
            result["errors"].append(f"Simulators: {exc}")
        try:
            result["physical"] = self._ios.list_physical_devices()
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"Physical devices: {exc}")
        return result

    def _on_assess(self) -> None:
        host = self._host_edit.text().strip()
        if not host:
            self.set_status("Enter the device's IP address first.", Colors.STATUS_WARNING)
            return
        self.set_status(f"Assessing {host} over SSH...", Colors.STATUS_RUNNING)
        self._jobs[self._task_runner.run(self._ios.assess_jailbreak, host)] = "assess"

    # ------------------------------------------------------------------ #
    def _on_finished(self, job_id: str, result) -> None:
        kind = self._jobs.pop(job_id, None)
        if kind == "install":
            self.refresh()
            self.set_status(
                "pymobiledevice3 installed." if result.installed else "Install failed.",
                Colors.ACCENT_GREEN if result.installed else Colors.STATUS_ERROR,
            )
        elif kind == "scan":
            self._render_devices(result or {})
        elif kind == "assess":
            self._render_assessment(result)

    def _on_failed(self, job_id: str, error_message: str) -> None:
        self._jobs.pop(job_id, None)
        self.set_status(error_message, Colors.STATUS_ERROR)

    def _render_devices(self, data: dict) -> None:
        clear_layout(self._discovery_layout, keep=self._discovery_anchor)
        simulators = data.get("simulators") or []
        physical = data.get("physical") or []

        if simulators:
            self._discovery_layout.addWidget(
                label("Simulators", size=11, bold=True, color=Colors.TEXT_SECONDARY)
            )
            for sim in simulators:
                name = getattr(sim, "name", str(sim))
                udid = getattr(sim, "udid", "")
                state = getattr(sim, "state", "")
                self._discovery_layout.addWidget(kv_row(name, f"{state}  \u2022  {udid}"))

        if physical:
            self._discovery_layout.addWidget(
                label("Physical devices", size=11, bold=True, color=Colors.TEXT_SECONDARY)
            )
            for device in physical:
                name = getattr(device, "name", str(device))
                udid = getattr(device, "udid", "")
                self._discovery_layout.addWidget(kv_row(name, udid))

        for error in data.get("errors") or []:
            self._discovery_layout.addWidget(
                label(error, size=10, color=Colors.STATUS_WARNING, wrap=True)
            )

        if not simulators and not physical:
            self._discovery_layout.addWidget(empty_state(
                "No iOS simulators or devices found. Simulators need macOS with Xcode "
                "command-line tools; physical devices need pymobiledevice3 installed and "
                "the device unlocked and trusted."
            ))
            self.set_status("No iOS devices found.", Colors.TEXT_MUTED)
        else:
            self.set_status(
                f"{len(simulators)} simulator(s), {len(physical)} device(s).",
                Colors.ACCENT_GREEN,
            )

    def _render_assessment(self, assessment) -> None:
        clear_layout(self._assess_layout, keep=self._assess_anchor)
        if assessment is None:
            self._assess_layout.addWidget(empty_state("No assessment returned."))
            return
        for field in ("host", "ssh_reachable", "ssh_port", "jailbroken", "detail", "notes"):
            if hasattr(assessment, field):
                value = getattr(assessment, field)
                if value in (None, ""):
                    continue
                self._assess_layout.addWidget(
                    kv_row(field.replace("_", " ").title(), str(value))
                )
        self.set_status("Assessment complete.", Colors.ACCENT_GREEN)
