"""
Tests for Module 3c: Device Connection Manager (Android/ADB side).

``adb_parser`` tests use real-world-shaped ``adb`` output samples.
``DeviceConnectionManager`` tests inject a fake ``ToolManager`` that
returns those same canned outputs -- so the manager's orchestration
logic (which command to run, how to interpret exit codes, how to
upsert into the DB) is genuinely exercised without needing physical
hardware.
"""

from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# adb_parser -- pure functions
# --------------------------------------------------------------------------- #
def test_parse_devices_output_handles_usb_emulator_and_unauthorized():
    from app.core.device.adb_parser import parse_devices_output

    raw = (
        "List of devices attached\n"
        "0123456789ABCDEF       device usb:1-1 product:sunfish model:Pixel_4a device:sunfish transport_id:1\n"
        "emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emulator64_x86_64 transport_id:2\n"
        "R3CN90ABCDE            unauthorized usb:1-2 transport_id:3\n"
        "\n"
    )
    entries = parse_devices_output(raw)
    assert len(entries) == 3

    usb = entries[0]
    assert usb.serial == "0123456789ABCDEF"
    assert usb.state == "device"
    assert usb.model == "Pixel_4a"

    emulator = entries[1]
    assert emulator.serial == "emulator-5554"
    assert emulator.product == "sdk_gphone64_x86_64"

    unauthorized = entries[2]
    assert unauthorized.state == "unauthorized"


def test_parse_devices_output_ignores_header_and_blank_lines():
    from app.core.device.adb_parser import parse_devices_output

    assert parse_devices_output("List of devices attached\n\n\n") == []


def test_classify_connection_type_emulator():
    from app.core.device.adb_parser import RawDeviceEntry, classify_connection_type
    from app.database.models import ConnectionType

    entry = RawDeviceEntry(serial="emulator-5554", state="device", product="sdk_gphone64_x86_64")
    assert classify_connection_type(entry) == ConnectionType.ANDROID_EMULATOR


def test_classify_connection_type_genymotion():
    from app.core.device.adb_parser import RawDeviceEntry, classify_connection_type
    from app.database.models import ConnectionType

    entry = RawDeviceEntry(serial="192.168.56.101:5555", state="device", product="vbox86p")
    assert classify_connection_type(entry) == ConnectionType.GENYMOTION


def test_classify_connection_type_waydroid():
    from app.core.device.adb_parser import RawDeviceEntry, classify_connection_type
    from app.database.models import ConnectionType

    entry = RawDeviceEntry(serial="127.0.0.1:38897", state="device", product="waydroid_x86_64")
    assert classify_connection_type(entry) == ConnectionType.WAYDROID


def test_classify_connection_type_generic_network_fallback():
    from app.core.device.adb_parser import RawDeviceEntry, classify_connection_type
    from app.database.models import ConnectionType

    entry = RawDeviceEntry(serial="10.0.0.5:5555", state="device", product="unknown_thing")
    assert classify_connection_type(entry) == ConnectionType.NETWORK


def test_classify_connection_type_usb_default():
    from app.core.device.adb_parser import RawDeviceEntry, classify_connection_type
    from app.database.models import ConnectionType

    entry = RawDeviceEntry(serial="ABC123", state="device", product="sunfish")
    assert classify_connection_type(entry) == ConnectionType.USB


def test_parse_getprop_output():
    from app.core.device.adb_parser import parse_getprop_output

    raw = "[ro.build.version.release]: [14]\n[ro.build.version.sdk]: [34]\n[ro.product.model]: [Pixel 7 Pro]\n"
    props = parse_getprop_output(raw)
    assert props["ro.build.version.sdk"] == "34"
    assert props["ro.product.model"] == "Pixel 7 Pro"


def test_is_root_shell_output():
    from app.core.device.adb_parser import is_root_shell_output

    assert is_root_shell_output("uid=0(root) gid=0(root)") is True
    assert is_root_shell_output("not-rooted") is False


def test_parse_ps_for_process():
    from app.core.device.adb_parser import parse_ps_for_process

    raw = "USER  PID  PPID\nshell 1234 1 frida-server\nroot  1 0 init\n"
    assert parse_ps_for_process(raw, "frida-server") is True
    assert parse_ps_for_process(raw, "objection-agent") is False


def test_parse_cert_listing_filters_ls_errors():
    from app.core.device.adb_parser import parse_cert_listing

    raw = "9a5ba575.0\nab1234ff.0\n"
    assert parse_cert_listing(raw) == ["9a5ba575.0", "ab1234ff.0"]
    assert parse_cert_listing("ls: No such file or directory\n") == []


# --------------------------------------------------------------------------- #
# DeviceConnectionManager -- fake ToolManager, real adb-shaped output
# --------------------------------------------------------------------------- #
class _FakeToolManager:
    """Returns pre-scripted ToolExecutionResult-like objects keyed by the args passed."""

    def __init__(self, responses: dict[str, str], exit_codes: dict[str, int] | None = None):
        self._responses = responses
        self._exit_codes = exit_codes or {}
        self.calls: list[list[str]] = []

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
            tool=tool_name, command=[tool_name, *args],
            exit_code=0, stdout="", stderr="", duration=0.01,
        )


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))
    import app.core.config as config_module
    config_module.get_settings.cache_clear()
    import app.database.database as db_module
    db_module._engine = None
    db_module._SessionFactory = None
    from app.database.database import init_db
    init_db()
    yield
    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None


def test_list_devices_parses_real_shaped_output():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({
        "devices -l": (
            "List of devices attached\n"
            "R3CN90ABCDE            device usb:1-1 product:sunfish model:Pixel_4a device:sunfish transport_id:1\n"
        ),
    })
    manager = DeviceConnectionManager(tool_manager=fake)
    devices = manager.list_devices()
    assert len(devices) == 1
    assert devices[0].serial == "R3CN90ABCDE"


def test_list_devices_raises_adb_not_found_when_tool_missing():
    from app.core.device.connection_manager import DeviceConnectionManager
    from app.core.exceptions import ADBNotFoundError, ToolNotFoundError

    class _MissingAdb:
        def run(self, *a, **kw):
            raise ToolNotFoundError("adb not installed")

    manager = DeviceConnectionManager(tool_manager=_MissingAdb())
    with pytest.raises(ADBNotFoundError):
        manager.list_devices()


def test_scan_and_sync_raises_when_no_devices():
    from app.core.device.connection_manager import DeviceConnectionManager
    from app.core.exceptions import NoDeviceFoundError

    fake = _FakeToolManager({"devices -l": "List of devices attached\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    with pytest.raises(NoDeviceFoundError):
        manager.scan_and_sync()


def test_scan_and_sync_upserts_device_row_and_reclassifies_on_rescan():
    from app.core.device.connection_manager import DeviceConnectionManager
    from app.database.database import session_scope
    from app.database.models import Device, DeviceStatus, ConnectionType

    fake = _FakeToolManager({
        "devices -l": (
            "List of devices attached\n"
            "emulator-5554   device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64\n"
        ),
    })
    manager = DeviceConnectionManager(tool_manager=fake)
    synced = manager.scan_and_sync()
    assert len(synced) == 1

    with session_scope() as session:
        row = session.query(Device).filter_by(identifier="emulator-5554").one()
        assert row.connection_type == ConnectionType.ANDROID_EMULATOR
        assert row.status == DeviceStatus.READY

    # Re-scan with the same device now unauthorized -> status should update, not duplicate
    fake._responses["devices -l"] = (
        "List of devices attached\nemulator-5554   unauthorized\n"
    )
    manager.scan_and_sync()
    with session_scope() as session:
        rows = session.query(Device).filter_by(identifier="emulator-5554").all()
        assert len(rows) == 1
        assert rows[0].status == DeviceStatus.UNAUTHORIZED


def test_require_authorized_raises_for_unauthorized_device():
    from app.core.device.connection_manager import DeviceConnectionManager
    from app.core.exceptions import DeviceAuthorizationError

    fake = _FakeToolManager({
        "devices -l": "List of devices attached\nABC123   unauthorized\n",
    })
    manager = DeviceConnectionManager(tool_manager=fake)
    with pytest.raises(DeviceAuthorizationError):
        manager.require_authorized("ABC123")


def test_check_root_true_and_false():
    from app.core.device.connection_manager import DeviceConnectionManager

    rooted = _FakeToolManager({"su -c id": "uid=0(root) gid=0(root)\n"})
    assert DeviceConnectionManager(tool_manager=rooted).check_root("ABC123") is True

    unrooted = _FakeToolManager({"su -c id": "not-rooted\n"})
    assert DeviceConnectionManager(tool_manager=unrooted).check_root("ABC123") is False


def test_check_frida_server_running():
    from app.core.device.connection_manager import DeviceConnectionManager

    running = _FakeToolManager({"ps -A": "shell 1234 1 frida-server\n"})
    assert DeviceConnectionManager(tool_manager=running).check_frida_server_running("ABC123") is True

    not_running = _FakeToolManager({"ps -A": "root 1 0 init\n"})
    assert DeviceConnectionManager(tool_manager=not_running).check_frida_server_running("ABC123") is False


def test_get_readiness_aggregates_all_checks():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({
        "su -c id": "uid=0(root)\n",
        "ps -A": "shell 1 1 frida-server\n",
        "settings get global http_proxy": "127.0.0.1:8080\n",
        "ls /data/misc/user/0/cacerts-added/": "9a5ba575.0\n",
    })
    manager = DeviceConnectionManager(tool_manager=fake)
    readiness = manager.get_readiness("ABC123")

    assert readiness.is_rooted is True
    assert readiness.frida_server_running is True
    assert readiness.proxy_configured is True
    assert readiness.user_certs_installed == ["9a5ba575.0"]
    assert readiness.ready is True


def test_get_readiness_not_ready_without_frida_or_certs():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({
        "su -c id": "not-rooted\n",
        "ps -A": "root 1 0 init\n",
        "settings get global http_proxy": "\n",
        "ls /data/misc/user/0/cacerts-added/": "ls: No such file or directory\n",
    })
    manager = DeviceConnectionManager(tool_manager=fake)
    readiness = manager.get_readiness("ABC123")
    assert readiness.ready is False


def test_start_frida_server_pushes_chmods_launches_and_verifies(tmp_path, monkeypatch):
    from app.core.device.connection_manager import DeviceConnectionManager

    fake_binary = tmp_path / "frida-server"
    fake_binary.write_bytes(b"\x7fELF-fake")

    class _FakeDeps:
        def get_binary_path(self, name):
            assert name == "frida_server_arm64"
            return fake_binary

    fake = _FakeToolManager({
        "getprop": "[ro.product.cpu.abi]: [arm64-v8a]\n",
        "push": "1 file pushed\n",
        "chmod 755": "",
        "nohup": "",
        "ps -A": "shell 1 1 frida-server\n",
    })
    manager = DeviceConnectionManager(tool_manager=fake)
    monkeypatch.setattr("time.sleep", lambda _s: None)  # skip the real 1s settle delay in tests

    running = manager.start_frida_server("ABC123", dependency_manager=_FakeDeps())
    assert running is True

    calls_joined = [" ".join(c) for c in fake.calls]
    assert any("push" in c and "frida-server" in c for c in calls_joined)
    assert any("chmod 755" in c for c in calls_joined)
    assert any("su -c" in c and "frida-server" in c for c in calls_joined)


def test_start_frida_server_raises_for_unsupported_abi():
    from app.core.device.connection_manager import DeviceConnectionManager
    from app.core.exceptions import DeviceConnectionError

    fake = _FakeToolManager({"getprop": "[ro.product.cpu.abi]: [armeabi-v7a]\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    with pytest.raises(DeviceConnectionError):
        manager.start_frida_server("ABC123", dependency_manager=object())


def test_start_frida_server_raises_when_push_fails(monkeypatch):
    from app.core.device.connection_manager import DeviceConnectionManager
    from app.core.exceptions import DeviceConnectionError

    class _FakeDeps:
        def get_binary_path(self, name):
            return "/fake/frida-server"

    fake = _FakeToolManager(
        {"getprop": "[ro.product.cpu.abi]: [arm64-v8a]\n", "push": "failed to push\n"},
        exit_codes={"push": 1},
    )
    manager = DeviceConnectionManager(tool_manager=fake)
    with pytest.raises(DeviceConnectionError):
        manager.start_frida_server("ABC123", dependency_manager=_FakeDeps())


def test_stop_frida_server_sends_pkill():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"pkill": ""})
    manager = DeviceConnectionManager(tool_manager=fake)
    manager.stop_frida_server("ABC123")
    calls_joined = [" ".join(c) for c in fake.calls]
    assert any("pkill" in c and "frida-server" in c for c in calls_joined)


def test_install_apk_success():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"install -r": "Performing Streamed Install\nSuccess\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    assert manager.install_apk("ABC123", "/tmp/app.apk") is True


def test_install_apk_failure():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager(
        {"install -r": "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]\n"},
        exit_codes={"install -r": 1},
    )
    manager = DeviceConnectionManager(tool_manager=fake)
    assert manager.install_apk("ABC123", "/tmp/app.apk") is False


def test_uninstall_app_success():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"uninstall": "Success\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    assert manager.uninstall_app("ABC123", "com.example.app") is True


def test_launch_app_success():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({
        "monkey": "Events injected: 1\n## Network stats: elapsed time=42ms\n",
    })
    manager = DeviceConnectionManager(tool_manager=fake)
    assert manager.launch_app("ABC123", "com.example.app") is True
    calls_joined = [" ".join(c) for c in fake.calls]
    assert any("com.example.app" in c and "LAUNCHER" in c for c in calls_joined)


def test_launch_app_failure_when_package_not_found():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"monkey": "** No activities found to run, monkey aborted.\n"})
    manager = DeviceConnectionManager(tool_manager=fake)
    assert manager.launch_app("ABC123", "com.nonexistent.app") is False


def test_force_stop_app_sends_correct_command():
    from app.core.device.connection_manager import DeviceConnectionManager

    fake = _FakeToolManager({"force-stop": ""})
    manager = DeviceConnectionManager(tool_manager=fake)
    manager.force_stop_app("ABC123", "com.example.app")
    calls_joined = [" ".join(c) for c in fake.calls]
    assert any("force-stop" in c and "com.example.app" in c for c in calls_joined)
