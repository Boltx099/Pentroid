"""
Tests for Module 3d: iOS Device Connection Manager.

``check_ssh_reachable`` is tested against a real local TCP listener
(genuine socket I/O, not mocked) -- this is the one piece of the iOS
manager fully verifiable without real hardware. Everything else uses
canned pymobiledevice3/simctl-shaped output via a fake ToolManager.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest


# --------------------------------------------------------------------------- #
# ios_parser -- pure functions
# --------------------------------------------------------------------------- #
def test_parse_simctl_list_real_apple_json_shape():
    from app.core.device.ios_parser import parse_simctl_list

    raw = """
    {
      "devices": {
        "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
          {"udid": "AAAA-1111", "name": "iPhone 15 Pro", "state": "Booted", "isAvailable": true},
          {"udid": "BBBB-2222", "name": "iPhone SE (3rd generation)", "state": "Shutdown", "isAvailable": true},
          {"udid": "CCCC-3333", "name": "Old Unavailable Device", "state": "Shutdown", "isAvailable": false}
        ]
      }
    }
    """
    entries = parse_simctl_list(raw)
    assert len(entries) == 2  # unavailable device excluded
    booted = next(e for e in entries if e.state == "Booted")
    assert booted.name == "iPhone 15 Pro"
    assert booted.runtime == "iOS 17.4"


def test_parse_simctl_list_handles_malformed_json():
    from app.core.device.ios_parser import parse_simctl_list

    assert parse_simctl_list("not json at all") == []


def test_parse_usbmux_list_tolerates_bare_list_and_wrapped():
    from app.core.device.ios_parser import parse_usbmux_list

    bare = '[{"Identifier": "00008030-ABC123", "ConnectionType": "USB"}]'
    entries = parse_usbmux_list(bare)
    assert entries[0].udid == "00008030-ABC123"
    assert entries[0].connection_type == "usb"

    wrapped = '{"devices": [{"udid": "XYZ", "connection_type": "network-wifi"}]}'
    entries2 = parse_usbmux_list(wrapped)
    assert entries2[0].udid == "XYZ"
    assert entries2[0].connection_type == "network"


def test_parse_usbmux_list_skips_entries_without_identifier():
    from app.core.device.ios_parser import parse_usbmux_list

    raw = '[{"SomeOtherField": "no id here"}]'
    assert parse_usbmux_list(raw) == []


def test_parse_lockdown_info_flattens_scalars_only():
    from app.core.device.ios_parser import parse_lockdown_info

    raw = '{"ProductVersion": "17.4", "DeviceClass": "iPhone", "NestedThing": {"a": 1}, "ListThing": [1,2]}'
    info = parse_lockdown_info(raw)
    assert info == {"ProductVersion": "17.4", "DeviceClass": "iPhone"}


# --------------------------------------------------------------------------- #
# SSH reachability -- real socket I/O against a local mock listener
# --------------------------------------------------------------------------- #
@pytest.fixture
def mock_ssh_server():
    """Spin up a real local TCP server that sends an SSH-like banner, like a jailbroken device would."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]
    server_sock.listen(1)
    stop_flag = threading.Event()

    def _serve():
        server_sock.settimeout(0.5)
        while not stop_flag.is_set():
            try:
                conn, _ = server_sock.accept()
            except socket.timeout:
                continue
            conn.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
            conn.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    yield port
    stop_flag.set()
    thread.join(timeout=2)
    server_sock.close()


def test_check_ssh_reachable_true_with_real_banner(mock_ssh_server):
    from app.core.device.ios_connection_manager import IOSConnectionManager

    manager = IOSConnectionManager(tool_manager=None)
    reachable, banner = manager.check_ssh_reachable("127.0.0.1", port=mock_ssh_server, timeout=2.0)
    assert reachable is True
    assert "SSH-2.0-OpenSSH" in banner


def test_check_ssh_reachable_false_for_closed_port():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    manager = IOSConnectionManager(tool_manager=None)
    # Port 1 is a reserved/unlikely-bound port; connection should be refused
    reachable, banner = manager.check_ssh_reachable("127.0.0.1", port=1, timeout=1.0)
    assert reachable is False
    assert banner is None


def test_assess_jailbreak_medium_confidence_with_ssh_banner(mock_ssh_server, monkeypatch):
    from app.core.device.ios_connection_manager import IOSConnectionManager
    import app.core.device.ios_connection_manager as mod

    manager = IOSConnectionManager(tool_manager=None)
    # Point the jailbreak port list at our mock server's port for this test
    monkeypatch.setattr(mod, "_JAILBREAK_SSH_PORTS", (mock_ssh_server,))

    assessment = manager.assess_jailbreak("127.0.0.1")
    assert assessment.ssh_reachable is True
    assert assessment.likely_jailbroken is True
    assert assessment.confidence == "medium"


def test_assess_jailbreak_not_reachable_returns_low_confidence_false():
    from app.core.device.ios_connection_manager import IOSConnectionManager
    import app.core.device.ios_connection_manager as mod

    manager = IOSConnectionManager(tool_manager=None)
    # Use a port almost certainly closed on localhost in the test sandbox
    assessment = manager.assess_jailbreak("127.0.0.1")
    assert assessment.likely_jailbroken is False
    assert assessment.confidence == "low"


# --------------------------------------------------------------------------- #
# Simulator listing -- platform gating
# --------------------------------------------------------------------------- #
def test_list_simulators_returns_empty_on_non_macos(monkeypatch):
    from app.core.device.ios_connection_manager import IOSConnectionManager
    import app.core.device.ios_connection_manager as mod

    monkeypatch.setattr(mod.platform, "system", lambda: "Linux")
    manager = IOSConnectionManager(tool_manager=None)
    assert manager.list_simulators() == []


# --------------------------------------------------------------------------- #
# Physical device listing -- fake ToolManager with pymobiledevice3-shaped output
# --------------------------------------------------------------------------- #
class _FakeToolManager:
    def __init__(self, stdout: str, exit_code: int = 0):
        self._stdout = stdout
        self._exit_code = exit_code

    def run(self, tool_name, args, timeout=300, cwd=None, env=None):
        from app.core.tool_manager import ToolExecutionResult
        return ToolExecutionResult(
            tool=tool_name, command=[tool_name, *args], exit_code=self._exit_code,
            stdout=self._stdout, stderr="" if self._exit_code == 0 else "error", duration=0.01,
        )


def test_list_physical_devices_parses_fake_pymobiledevice3_output():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    fake = _FakeToolManager('[{"Identifier": "00008030-ABC", "ConnectionType": "USB"}]')
    manager = IOSConnectionManager(tool_manager=fake)
    devices = manager.list_physical_devices()
    assert len(devices) == 1
    assert devices[0].udid == "00008030-ABC"


def test_list_physical_devices_returns_empty_on_tool_failure():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    fake = _FakeToolManager("", exit_code=1)
    manager = IOSConnectionManager(tool_manager=fake)
    assert manager.list_physical_devices() == []
