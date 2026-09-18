"""
Tests for Module 17b: logcat_capture plugin wrapper.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
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


def _make_context(tmp_path, device_id=None):
    from app.core.schemas import WorkflowStepContext
    return WorkflowStepContext(
        project_id=1, analysis_id=1, target_path=str(tmp_path / "x.apk"),
        workspace_path=str(tmp_path), device_id=device_id,
    )


def _seed_device(identifier="R3CN90ABCDE"):
    from app.database.database import session_scope
    from app.database.models import Device, Platform, ConnectionType, DeviceStatus

    with session_scope() as session:
        device = Device(
            identifier=identifier, display_name="Test Device", platform=Platform.ANDROID,
            connection_type=ConnectionType.USB, status=DeviceStatus.READY,
        )
        session.add(device)
        session.flush()
        return device.id


def test_logcat_plugin_skips_without_device_id(tmp_path):
    from app.plugins.installed.logcat_capture.plugin import LogcatCapturePlugin

    output = LogcatCapturePlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_logcat_plugin_skips_when_device_not_in_db(tmp_path):
    from app.plugins.installed.logcat_capture.plugin import LogcatCapturePlugin

    output = LogcatCapturePlugin().run(_make_context(tmp_path, device_id=999999))
    assert output.status.value == "skipped"


def test_logcat_plugin_timeout_is_treated_as_success(tmp_path, monkeypatch):
    """A bounded capture SHOULD end via timeout -- that's expected termination, not a failure."""
    from app.plugins.installed.logcat_capture.plugin import LogcatCapturePlugin
    import app.plugins.installed.logcat_capture.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    device_id = _seed_device()

    class _FakeToolManager:
        def run_streaming(self, tool_name, args, on_line, timeout=300):
            on_line("stdout", "I/ActivityManager( 1234): Displaying com.example.app/.MainActivity")
            return ToolExecutionResult(tool=tool_name, command=[tool_name, *args], exit_code=None,
                                        stdout="", stderr="", duration=15.0, timed_out=True)

    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())
    output = LogcatCapturePlugin().run(_make_context(tmp_path, device_id=device_id))
    assert output.status.value == "success"


def test_logcat_plugin_detects_crash_finding(tmp_path, monkeypatch):
    from app.plugins.installed.logcat_capture.plugin import LogcatCapturePlugin
    import app.plugins.installed.logcat_capture.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    device_id = _seed_device()

    class _FakeToolManager:
        def run_streaming(self, tool_name, args, on_line, timeout=300):
            on_line("stdout", "E/AndroidRuntime(5678): FATAL EXCEPTION: main")
            on_line("stdout", "E/AndroidRuntime(5678):     at com.example.app.MainActivity.onCreate(MainActivity.java:42)")
            return ToolExecutionResult(tool=tool_name, command=[tool_name, *args], exit_code=None,
                                        stdout="", stderr="", duration=15.0, timed_out=True)

    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())
    output = LogcatCapturePlugin().run(_make_context(tmp_path, device_id=device_id))
    assert output.status.value == "success"
    assert any("Crash" in f.title for f in output.findings)


def test_logcat_plugin_detects_runtime_secret(tmp_path, monkeypatch):
    from app.plugins.installed.logcat_capture.plugin import LogcatCapturePlugin
    import app.plugins.installed.logcat_capture.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    device_id = _seed_device()

    class _FakeToolManager:
        def run_streaming(self, tool_name, args, on_line, timeout=300):
            on_line("stdout", "D/ApiClient(1234): Using key AKIAIOSFODNN7EXAMPLE for request")
            return ToolExecutionResult(tool=tool_name, command=[tool_name, *args], exit_code=None,
                                        stdout="", stderr="", duration=15.0, timed_out=True)

    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())
    output = LogcatCapturePlugin().run(_make_context(tmp_path, device_id=device_id))
    assert output.status.value == "success"
    assert any("logged at runtime" in f.title for f in output.findings)
    assert output.findings[-1].severity.value == "high"


def test_logcat_plugin_real_failure_when_adb_errors_without_timeout(tmp_path, monkeypatch):
    """Distinguish a genuine failure (non-zero exit, NOT from our deliberate timeout) from expected termination."""
    from app.plugins.installed.logcat_capture.plugin import LogcatCapturePlugin
    import app.plugins.installed.logcat_capture.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    device_id = _seed_device()

    class _FakeToolManager:
        def run_streaming(self, tool_name, args, on_line, timeout=300):
            return ToolExecutionResult(tool=tool_name, command=[tool_name, *args], exit_code=1,
                                        stdout="", stderr="error: device offline", duration=0.2, timed_out=False)

    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())
    output = LogcatCapturePlugin().run(_make_context(tmp_path, device_id=device_id))
    assert output.status.value == "failed"
    assert "device offline" in output.errors[0]
