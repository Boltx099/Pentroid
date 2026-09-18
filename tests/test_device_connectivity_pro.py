"""
Tests for the professional device-connectivity additions:
wireless ADB (Android) and pymobiledevice3 parity features (iOS).
"""
from __future__ import annotations
import pytest


class _FakeToolManager:
    """Returns scripted results keyed by a substring of the joined args."""

    def __init__(self, responses, exit_codes=None):
        self._responses = responses
        self._exit_codes = exit_codes or {}
        self.calls = []

    def run(self, tool_name, args, timeout=300, cwd=None, env=None):
        from app.core.tool_manager import ToolExecutionResult
        self.calls.append(args)
        key = " ".join(args)
        for pattern, output in self._responses.items():
            if pattern in key:
                return ToolExecutionResult(
                    tool=tool_name, command=[tool_name, *args],
                    exit_code=self._exit_codes.get(pattern, 0),
                    stdout=output, stderr="", duration=0.01,
                )
        return ToolExecutionResult(
            tool=tool_name, command=[tool_name, *args], exit_code=0,
            stdout="", stderr="", duration=0.01,
        )


# --------------------------------------------------------------------------- #
# Wireless ADB
# --------------------------------------------------------------------------- #
def test_connect_wireless_success():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"connect": "connected to 192.168.1.50:5555\n"})
    assert DeviceConnectionManager(tool_manager=fake).connect_wireless("192.168.1.50") is True


def test_connect_wireless_failure_despite_exit_code_zero():
    """adb exits 0 even when the connection fails -- output text is the real signal."""
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"connect": "failed to connect to 192.168.1.99:5555\n"})
    assert DeviceConnectionManager(tool_manager=fake).connect_wireless("192.168.1.99") is False


def test_connect_wireless_uses_custom_port():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"connect": "connected to 10.0.0.5:37000\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    manager.connect_wireless("10.0.0.5", port=37000)
    assert any("10.0.0.5:37000" in " ".join(c) for c in fake.calls)


def test_enable_tcpip_targets_correct_serial_and_port():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"tcpip": "restarting in TCP mode port: 5555\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    assert manager.enable_tcpip("R3CN90ABCDE", port=5555) is True
    joined = [" ".join(c) for c in fake.calls]
    assert any("-s R3CN90ABCDE tcpip 5555" in c for c in joined)


def test_pair_wireless_success():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"pair": "Successfully paired to 192.168.1.50:41234 [guid=adb-XXX]\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    assert manager.pair_wireless("192.168.1.50", 41234, "123456") is True


def test_pair_wireless_wrong_code_fails():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"pair": "Failed: Wrong password\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    assert manager.pair_wireless("192.168.1.50", 41234, "000000") is False


def test_pair_uses_pairing_port_not_connect_port():
    """Regression guard for the classic Android 11+ mistake of reusing the connect port."""
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"pair": "Successfully paired\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    manager.pair_wireless("192.168.1.50", 41234, "123456")
    joined = " ".join(" ".join(c) for c in fake.calls)
    assert "192.168.1.50:41234" in joined
    assert "5555" not in joined


def test_disconnect_all_when_no_host_given():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"disconnect": ""})
    manager = DeviceConnectionManager(tool_manager=fake)
    manager.disconnect_wireless()
    assert fake.calls[-1] == ["disconnect"]


# --------------------------------------------------------------------------- #
# iOS parity
# --------------------------------------------------------------------------- #
def test_ios_list_installed_apps():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    fake = _FakeToolManager({"apps list": '{"com.apple.Maps": {}, "com.target.App": {}}'})
    apps = IOSConnectionManager(tool_manager=fake).list_installed_apps("UDID123")
    assert "com.target.App" in apps


def test_ios_list_apps_returns_empty_on_failure():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    fake = _FakeToolManager({"apps list": ""}, exit_codes={"apps list": 1})
    assert IOSConnectionManager(tool_manager=fake).list_installed_apps("UDID123") == []


def test_ios_install_ipa_passes_path_and_udid():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    fake = _FakeToolManager({"apps install": "installed"})
    manager = IOSConnectionManager(tool_manager=fake)
    assert manager.install_ipa("UDID123", "/tmp/app.ipa") is True
    joined = " ".join(" ".join(c) for c in fake.calls)
    assert "/tmp/app.ipa" in joined and "UDID123" in joined


def test_ios_developer_mode_status_true_false_and_unknown():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    assert IOSConnectionManager(
        tool_manager=_FakeToolManager({"developer-mode-status": "true"})
    ).get_developer_mode_status("U") is True

    assert IOSConnectionManager(
        tool_manager=_FakeToolManager({"developer-mode-status": "Developer mode is disabled"})
    ).get_developer_mode_status("U") is False

    # A failed query must be None ("unknown"), NOT False ("confirmed disabled")
    assert IOSConnectionManager(
        tool_manager=_FakeToolManager({"developer-mode-status": ""}, exit_codes={"developer-mode-status": 1})
    ).get_developer_mode_status("U") is None


def test_ios_list_profiles_parses_ordered_identifiers():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    fake = _FakeToolManager({"profile list": '{"OrderedIdentifiers": ["com.portswigger.burp.ca"]}'})
    profiles = IOSConnectionManager(tool_manager=fake).list_profiles("UDID123")
    assert profiles == ["com.portswigger.burp.ca"]


def test_ios_is_paired_reflects_lockdown_info_exit_code():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    assert IOSConnectionManager(
        tool_manager=_FakeToolManager({"lockdown info": '{"ProductVersion": "17.4"}'})
    ).is_paired("U") is True

    assert IOSConnectionManager(
        tool_manager=_FakeToolManager({"lockdown info": ""}, exit_codes={"lockdown info": 1})
    ).is_paired("U") is False


def test_ios_readiness_ready_when_paired_devmode_and_profile_present():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    fake = _FakeToolManager({
        "lockdown info": '{"ProductVersion": "17.4"}',
        "developer-mode-status": "true",
        "profile list": '{"OrderedIdentifiers": ["com.burp.ca"]}',
    })
    readiness = IOSConnectionManager(tool_manager=fake).get_readiness("UDID123")
    assert readiness.paired is True
    assert readiness.developer_mode_enabled is True
    assert readiness.ready is True


def test_ios_readiness_not_ready_without_developer_mode():
    from app.core.device.ios_connection_manager import IOSConnectionManager

    fake = _FakeToolManager({
        "lockdown info": '{"ProductVersion": "17.4"}',
        "developer-mode-status": "false",
        "profile list": '{"OrderedIdentifiers": ["com.burp.ca"]}',
    })
    readiness = IOSConnectionManager(tool_manager=fake).get_readiness("UDID123")
    assert readiness.ready is False


# --------------------------------------------------------------------------- #
# Wireless connect dialog (GUI)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


class _FakeConn:
    def __init__(self, pair_ok=True, connect_ok=True):
        self.pair_ok = pair_ok
        self.connect_ok = connect_ok
        self.pair_calls = []
        self.connect_calls = []

    def pair_wireless(self, host, port, code):
        self.pair_calls.append((host, port, code))
        return self.pair_ok

    def connect_wireless(self, host, port=5555):
        self.connect_calls.append((host, port))
        return self.connect_ok


def test_dialog_rejects_pair_without_code(qapp):
    from app.gui.dialogs.wireless_connect_dialog import WirelessConnectDialog

    conn = _FakeConn()
    dialog = WirelessConnectDialog(connection_manager=conn)
    dialog._pair_host.setText("192.168.1.50")
    dialog._pair_code.setText("")
    dialog._on_pair()
    assert conn.pair_calls == []  # never reached the backend
    assert "6-digit" in dialog._status.text()


def test_dialog_pair_success_autofills_connect_host(qapp):
    from app.gui.dialogs.wireless_connect_dialog import WirelessConnectDialog

    conn = _FakeConn(pair_ok=True)
    dialog = WirelessConnectDialog(connection_manager=conn)
    dialog._pair_host.setText("192.168.1.50")
    dialog._pair_code.setText("123456")
    dialog._on_pair()
    assert conn.pair_calls == [("192.168.1.50", 37000, "123456")]
    assert dialog._connect_host.text() == "192.168.1.50"


def test_dialog_connect_success_sets_connected_flag(qapp):
    from app.gui.dialogs.wireless_connect_dialog import WirelessConnectDialog

    conn = _FakeConn(connect_ok=True)
    dialog = WirelessConnectDialog(connection_manager=conn)
    dialog._connect_host.setText("192.168.1.50")
    dialog._on_connect()
    assert dialog.connected is True
    assert conn.connect_calls == [("192.168.1.50", 5555)]


def test_dialog_connect_failure_explains_both_flows(qapp):
    from app.gui.dialogs.wireless_connect_dialog import WirelessConnectDialog

    conn = _FakeConn(connect_ok=False)
    dialog = WirelessConnectDialog(connection_manager=conn)
    dialog._connect_host.setText("192.168.1.99")
    dialog._on_connect()
    assert dialog.connected is False
    text = dialog._status.text().lower()
    assert "pair first" in text and "tcpip" in text


def test_dialog_backend_exception_does_not_crash_dialog(qapp):
    from app.gui.dialogs.wireless_connect_dialog import WirelessConnectDialog

    class _Boom:
        def connect_wireless(self, host, port=5555):
            raise RuntimeError("adb exploded")

    dialog = WirelessConnectDialog(connection_manager=_Boom())
    dialog._connect_host.setText("1.2.3.4")
    dialog._on_connect()  # must not raise
    assert "adb exploded" in dialog._status.text()
