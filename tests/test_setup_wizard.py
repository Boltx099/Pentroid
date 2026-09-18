"""
Tests for Module 3e: Device Setup Wizard.

Uses a fake DeviceConnectionManager exposing the exact methods the
wizard calls, so each step's branching logic (hard blocker vs.
informational vs. pass) is verified in isolation without needing a
real device or the full ADB stack underneath.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from app.core.device.adb_parser import RawDeviceEntry
from app.core.exceptions import ADBNotFoundError, DeviceAuthorizationError, DeviceConnectionError, NoDeviceFoundError, ToolNotFoundError


@dataclass
class _FakeReadiness:
    frida_server_running: bool
    user_certs_installed: list
    ready: bool


class _FakeConnectionManager:
    """Configurable stand-in for DeviceConnectionManager, one flag per wizard step."""

    def __init__(
        self,
        adb_ok: bool = True,
        devices: list | None = None,
        authorized: bool = True,
        rooted: bool = False,
        frida_running: bool = False,
        frida_start_succeeds: bool = True,
        certs: list | None = None,
    ):
        self.adb_ok = adb_ok
        self.devices = devices if devices is not None else [RawDeviceEntry(serial="ABC123", state="device")]
        self.authorized = authorized
        self.rooted = rooted
        self.frida_running = frida_running
        self.frida_start_succeeds = frida_start_succeeds
        self.certs = certs if certs is not None else []

    def start_adb_server(self):
        if not self.adb_ok:
            raise ADBNotFoundError("adb not found")

    def list_devices(self):
        if not self.adb_ok:
            raise ADBNotFoundError("adb not found")
        return self.devices

    def require_authorized(self, serial):
        if not self.authorized:
            raise DeviceAuthorizationError("not authorized")

    def check_root(self, serial):
        return self.rooted

    def check_frida_server_running(self, serial):
        return self.frida_running

    def start_frida_server(self, serial):
        if not self.frida_start_succeeds:
            raise DeviceConnectionError("push failed")
        self.frida_running = True
        return True

    def list_user_certificates(self, serial):
        return self.certs

    def get_readiness(self, serial):
        return _FakeReadiness(
            frida_server_running=self.frida_running,
            user_certs_installed=self.certs,
            ready=self.frida_running and bool(self.certs),
        )


def test_full_success_path_reaches_ready():
    from app.core.device.setup_wizard import DeviceSetupWizard

    fake = _FakeConnectionManager(rooted=True, certs=["9a5ba575.0"])
    wizard = DeviceSetupWizard(connection_manager=fake)
    results = wizard.run()

    step_names = [r.step for r in results]
    assert step_names == [
        "Check ADB", "Detect Device", "Accept RSA",
        "Root Check", "Start Frida", "Install Burp Certificate", "Ready",
    ]
    assert all(r.passed for r in results)


def test_stops_at_adb_missing():
    from app.core.device.setup_wizard import DeviceSetupWizard

    fake = _FakeConnectionManager(adb_ok=False)
    wizard = DeviceSetupWizard(connection_manager=fake)
    results = wizard.run()

    assert len(results) == 1
    assert results[0].step == "Check ADB"
    assert results[0].passed is False
    assert results[0].guidance is not None


def test_stops_at_no_device_detected():
    from app.core.device.setup_wizard import DeviceSetupWizard

    fake = _FakeConnectionManager(devices=[])
    wizard = DeviceSetupWizard(connection_manager=fake)
    results = wizard.run()

    assert [r.step for r in results] == ["Check ADB", "Detect Device"]
    assert results[-1].passed is False


def test_stops_at_unauthorized_device():
    from app.core.device.setup_wizard import DeviceSetupWizard

    fake = _FakeConnectionManager(authorized=False)
    wizard = DeviceSetupWizard(connection_manager=fake)
    results = wizard.run()

    assert [r.step for r in results] == ["Check ADB", "Detect Device", "Accept RSA"]
    assert results[-1].passed is False
    assert "RSA fingerprint" in results[-1].guidance


def test_root_check_is_informational_not_blocking():
    from app.core.device.setup_wizard import DeviceSetupWizard

    fake = _FakeConnectionManager(rooted=False, certs=["9a5ba575.0"])
    wizard = DeviceSetupWizard(connection_manager=fake)
    results = wizard.run()

    root_step = next(r for r in results if r.step == "Root Check")
    assert root_step.passed is True  # not rooted, but doesn't block the wizard
    assert "not rooted" in root_step.message.lower()
    # wizard continues past root check
    assert "Start Frida" in [r.step for r in results]


def test_frida_start_failure_reports_but_continues_to_cert_check():
    from app.core.device.setup_wizard import DeviceSetupWizard

    fake = _FakeConnectionManager(frida_start_succeeds=False, certs=["hash.0"])
    wizard = DeviceSetupWizard(connection_manager=fake)
    results = wizard.run()

    frida_step = next(r for r in results if r.step == "Start Frida")
    assert frida_step.passed is False
    # wizard doesn't hard-stop on a failed frida start -- still runs remaining steps
    assert "Install Burp Certificate" in [r.step for r in results]
    assert "Ready" in [r.step for r in results]


def test_final_ready_false_when_certs_missing():
    from app.core.device.setup_wizard import DeviceSetupWizard

    fake = _FakeConnectionManager(rooted=True, frida_running=True, certs=[])
    wizard = DeviceSetupWizard(connection_manager=fake)
    results = wizard.run()

    ready_step = results[-1]
    assert ready_step.step == "Ready"
    assert ready_step.passed is False
    assert "CA certificate installed" in ready_step.guidance


def test_picks_requested_serial_when_multiple_devices_present():
    from app.core.device.setup_wizard import DeviceSetupWizard

    fake = _FakeConnectionManager(
        devices=[
            RawDeviceEntry(serial="FIRST", state="device"),
            RawDeviceEntry(serial="SECOND", state="device"),
        ],
        rooted=True, certs=["hash.0"],
    )
    wizard = DeviceSetupWizard(connection_manager=fake)
    results = wizard.run(serial="SECOND")

    detect_step = next(r for r in results if r.step == "Detect Device")
    assert "SECOND" in detect_step.message
