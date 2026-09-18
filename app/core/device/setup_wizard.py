"""
app.core.device.setup_wizard
===============================

Implements the "DEVICE SETUP WIZARD" flow from the architecture:

    Check ADB -> Detect Device -> Enable USB Debugging -> Accept RSA
    -> Root Check -> Start Frida -> Install Burp Certificate -> Ready

A few of these steps are things the *user* does on the physical device
(enabling USB debugging in Developer Options, tapping "Allow" on the
RSA fingerprint prompt, installing a certificate via a browser URL) --
the wizard's job for those is to verify completion and give clear
guidance, not to pretend it can automate a tap on someone else's
screen. "Enable USB Debugging" specifically has no separate check: ADB
literally cannot see a device until that setting is on, so it's folded
into the device-detection step rather than asked twice.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.device.connection_manager import DeviceConnectionManager, get_connection_manager
from app.core.exceptions import ADBNotFoundError, DeviceAuthorizationError, DeviceConnectionError, NoDeviceFoundError, ToolNotFoundError
from app.core.logger import get_logger

logger = get_logger(__name__)

_BURP_CERT_URL = "http://burp/cert"  # Burp's well-known cert URL when its proxy is the device's active proxy


@dataclass
class WizardStepResult:
    step: str
    passed: bool
    message: str
    guidance: str | None = None


class DeviceSetupWizard:
    """Runs the guided device-readiness sequence, stopping at the first hard blocker."""

    def __init__(self, connection_manager: DeviceConnectionManager | None = None) -> None:
        self._conn = connection_manager or get_connection_manager()

    def run(self, serial: str | None = None) -> list[WizardStepResult]:
        results: list[WizardStepResult] = []

        adb_result = self._check_adb()
        results.append(adb_result)
        if not adb_result.passed:
            return results

        device_result, resolved_serial = self._check_device_detected(serial)
        results.append(device_result)
        if not device_result.passed or resolved_serial is None:
            return results

        auth_result = self._check_authorized(resolved_serial)
        results.append(auth_result)
        if not auth_result.passed:
            return results

        results.append(self._check_root(resolved_serial))
        results.append(self._check_frida(resolved_serial))
        results.append(self._check_certificate(resolved_serial))
        results.append(self._final_ready(resolved_serial, results))
        return results

    # ------------------------------------------------------------------ #
    # Step 1: ADB
    # ------------------------------------------------------------------ #
    def _check_adb(self) -> WizardStepResult:
        try:
            self._conn.start_adb_server()
            return WizardStepResult("Check ADB", True, "ADB server is running.")
        except ADBNotFoundError as exc:
            return WizardStepResult(
                "Check ADB", False, f"ADB unavailable: {exc.message}",
                guidance="Install ADB via Settings > Dependency Manager, then retry.",
            )

    # ------------------------------------------------------------------ #
    # Step 2: Detect device (also covers "USB debugging enabled" implicitly)
    # ------------------------------------------------------------------ #
    def _check_device_detected(self, serial: str | None) -> tuple[WizardStepResult, str | None]:
        try:
            entries = self._conn.list_devices()
        except ADBNotFoundError as exc:
            return WizardStepResult("Detect Device", False, str(exc)), None

        if not entries:
            return (
                WizardStepResult(
                    "Detect Device", False, "No device detected.",
                    guidance=(
                        "Connect the device via USB (or start an emulator/Genymotion/Waydroid "
                        "instance) and enable Developer Options > USB Debugging."
                    ),
                ),
                None,
            )

        target = next((e for e in entries if e.serial == serial), entries[0]) if serial else entries[0]
        return (
            WizardStepResult("Detect Device", True, f"Detected device: {target.serial}"),
            target.serial,
        )

    # ------------------------------------------------------------------ #
    # Step 3: Accept RSA / authorization
    # ------------------------------------------------------------------ #
    def _check_authorized(self, serial: str) -> WizardStepResult:
        try:
            self._conn.require_authorized(serial)
            return WizardStepResult("Accept RSA", True, "Device is authorized.")
        except DeviceAuthorizationError:
            return WizardStepResult(
                "Accept RSA", False, "Device is not yet authorized.",
                guidance="On the device, accept the 'Allow USB debugging?' RSA fingerprint prompt.",
            )
        except NoDeviceFoundError:
            return WizardStepResult("Accept RSA", False, "Device disconnected during authorization check.")

    # ------------------------------------------------------------------ #
    # Step 4: Root check (informational -- not a hard gate)
    # ------------------------------------------------------------------ #
    def _check_root(self, serial: str) -> WizardStepResult:
        is_rooted = self._conn.check_root(serial)
        if is_rooted:
            return WizardStepResult("Root Check", True, "Device is rooted.")
        return WizardStepResult(
            "Root Check", True, "Device is not rooted.",
            guidance=(
                "Some dynamic-analysis checks (frida-server, direct filesystem access) need "
                "root. Non-root workflows (Objection app repackaging, Frida gadget injection) "
                "are still available."
            ),
        )

    # ------------------------------------------------------------------ #
    # Step 5: Start Frida
    # ------------------------------------------------------------------ #
    def _check_frida(self, serial: str) -> WizardStepResult:
        if self._conn.check_frida_server_running(serial):
            return WizardStepResult("Start Frida", True, "frida-server is already running.")

        try:
            started = self._conn.start_frida_server(serial)
        except (ToolNotFoundError, DeviceConnectionError) as exc:
            return WizardStepResult(
                "Start Frida", False, f"Could not start frida-server: {exc}",
                guidance="Install the matching frida_server_<abi> tool via the Dependency Manager.",
            )

        if started:
            return WizardStepResult("Start Frida", True, "frida-server started successfully.")
        return WizardStepResult(
            "Start Frida", False, "frida-server was pushed but is not running.",
            guidance="Check device root access -- frida-server needs root to bind its control port.",
        )

    # ------------------------------------------------------------------ #
    # Step 6: Install Burp certificate (user action, we can only verify)
    # ------------------------------------------------------------------ #
    def _check_certificate(self, serial: str) -> WizardStepResult:
        certs = self._conn.list_user_certificates(serial)
        if certs:
            return WizardStepResult("Install Burp Certificate", True, f"{len(certs)} user certificate(s) installed.")
        return WizardStepResult(
            "Install Burp Certificate", False, "No user CA certificates found on device.",
            guidance=(
                f"With the device's proxy pointed at Burp/mitmproxy, open {_BURP_CERT_URL} "
                "in the device browser and install the downloaded certificate under "
                "Settings > Security > Install from storage."
            ),
        )

    # ------------------------------------------------------------------ #
    # Step 7: Ready
    # ------------------------------------------------------------------ #
    def _final_ready(self, serial: str, prior_results: list[WizardStepResult]) -> WizardStepResult:
        readiness = self._conn.get_readiness(serial)
        if readiness.ready:
            return WizardStepResult("Ready", True, "Device is ready for dynamic analysis.")
        missing = []
        if not readiness.frida_server_running:
            missing.append("frida-server running")
        if not readiness.user_certs_installed:
            missing.append("CA certificate installed")
        return WizardStepResult(
            "Ready", False, "Device setup incomplete.",
            guidance=f"Still needed: {', '.join(missing)}.",
        )
