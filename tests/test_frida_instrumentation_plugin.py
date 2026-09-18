"""
Tests for Module 17c: frida_instrumentation plugin.

The fake ``frida`` module injected via ``sys.modules`` uses the exact
exception class names verified by installing real ``frida`` and
triggering them directly earlier this session (InvalidArgumentError,
ProcessNotFoundError, NotSupportedError, TimedOutError) -- not
guessed from documentation.
"""

from __future__ import annotations

import sys
import types

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))
    import app.core.config as config_module
    config_module.get_settings.cache_clear()
    import app.database.database as db_module
    db_module._engine = None
    db_module._SessionFactory = None
    import app.core.workflow.plugin_manager as pm_module
    pm_module.reset_plugin_manager()
    import app.core.workflow.workflow_manager as wf_module
    wf_module._workflow_manager = None
    from app.database.database import init_db
    init_db()
    yield
    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None
    pm_module.reset_plugin_manager()
    wf_module._workflow_manager = None


def _make_context(tmp_path, device_id=None, package_name=None):
    from app.core.schemas import WorkflowStepContext
    context = WorkflowStepContext(
        project_id=1, analysis_id=1, target_path=str(tmp_path / "x.apk"),
        workspace_path=str(tmp_path), device_id=device_id,
    )
    if package_name:
        context.shared_data["package_name"] = package_name
    return context


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


class _FakeScript:
    def __init__(self, messages):
        self._messages = messages
        self._callback = None

    def on(self, event_name, callback):
        self._callback = callback

    def load(self):
        for msg in self._messages:
            self._callback({"type": "send", "payload": msg}, None)


class _FakeSession:
    def __init__(self, messages):
        self._messages = messages
        self.detached = False

    def create_script(self, source):
        return _FakeScript(self._messages)

    def detach(self):
        self.detached = True


def _install_fake_frida(monkeypatch, messages=None, spawn_exc=None, attach_exc=None, get_device_exc=None):
    fake_frida = types.ModuleType("frida")

    class InvalidArgumentError(Exception):
        pass

    class ProcessNotFoundError(Exception):
        pass

    class NotSupportedError(Exception):
        pass

    class TimedOutError(Exception):
        pass

    fake_frida.InvalidArgumentError = InvalidArgumentError
    fake_frida.ProcessNotFoundError = ProcessNotFoundError
    fake_frida.NotSupportedError = NotSupportedError
    fake_frida.TimedOutError = TimedOutError

    sessions_created = []

    class _FakeDevice:
        def spawn(self, argv):
            if spawn_exc:
                raise spawn_exc
            return 4321

        def attach(self, pid):
            if attach_exc:
                raise attach_exc
            session = _FakeSession(messages or [])
            sessions_created.append(session)
            return session

        def resume(self, pid):
            pass

    def get_device(serial, timeout=10):
        if get_device_exc:
            raise get_device_exc
        return _FakeDevice()

    fake_frida.get_device = get_device
    monkeypatch.setitem(sys.modules, "frida", fake_frida)
    monkeypatch.setattr("time.sleep", lambda _s: None)  # skip the real monitoring-duration wait in tests
    return fake_frida, sessions_created


def test_skips_without_device_id(tmp_path):
    from app.plugins.installed.frida_instrumentation.plugin import FridaInstrumentationPlugin

    output = FridaInstrumentationPlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_skips_without_package_name(tmp_path, monkeypatch):
    from app.plugins.installed.frida_instrumentation.plugin import FridaInstrumentationPlugin
    import app.plugins.installed.frida_instrumentation.plugin as plugin_module

    device_id = _seed_device()
    monkeypatch.setattr(plugin_module, "get_connection_manager",
                         lambda: type("C", (), {"check_frida_server_running": lambda self, s: True})())
    _install_fake_frida(monkeypatch)

    output = FridaInstrumentationPlugin().run(_make_context(tmp_path, device_id=device_id))
    assert output.status.value == "skipped"
    assert "package name" in output.logs[0].lower()


def test_skips_when_frida_server_not_running(tmp_path, monkeypatch):
    from app.plugins.installed.frida_instrumentation.plugin import FridaInstrumentationPlugin
    import app.plugins.installed.frida_instrumentation.plugin as plugin_module

    device_id = _seed_device()
    monkeypatch.setattr(plugin_module, "get_connection_manager",
                         lambda: type("C", (), {"check_frida_server_running": lambda self, s: False})())
    _install_fake_frida(monkeypatch)

    output = FridaInstrumentationPlugin().run(
        _make_context(tmp_path, device_id=device_id, package_name="com.example.app")
    )
    assert output.status.value == "skipped"
    assert "frida-server" in output.logs[0].lower()


def test_successful_run_detects_ssl_pinning_bypass_and_root_checks(tmp_path, monkeypatch):
    from app.plugins.installed.frida_instrumentation.plugin import FridaInstrumentationPlugin
    import app.plugins.installed.frida_instrumentation.plugin as plugin_module

    device_id = _seed_device()
    monkeypatch.setattr(plugin_module, "get_connection_manager",
                         lambda: type("C", (), {"check_frida_server_running": lambda self, s: True})())

    messages = [
        {"hook": "instrumentation", "event": "hooks_installed"},
        {"hook": "ssl_pinning", "event": "checkServerTrusted_called_bypassed"},
        {"hook": "root_detection", "event": "su_path_check", "path": "/system/xbin/su"},
    ]
    fake_frida, sessions = _install_fake_frida(monkeypatch, messages=messages)

    output = FridaInstrumentationPlugin().run(
        _make_context(tmp_path, device_id=device_id, package_name="com.example.app")
    )
    assert output.status.value == "success"
    assert any("pinning" in f.title.lower() for f in output.findings)
    assert any("root-indicator" in f.title.lower() for f in output.findings)
    assert sessions[0].detached is True  # cleanup happened


def test_spawn_process_not_found_reports_failed(tmp_path, monkeypatch):
    from app.plugins.installed.frida_instrumentation.plugin import FridaInstrumentationPlugin
    import app.plugins.installed.frida_instrumentation.plugin as plugin_module

    device_id = _seed_device()
    monkeypatch.setattr(plugin_module, "get_connection_manager",
                         lambda: type("C", (), {"check_frida_server_running": lambda self, s: True})())

    fake_frida = types.ModuleType("frida")
    fake_frida.InvalidArgumentError = type("InvalidArgumentError", (Exception,), {})
    fake_frida.ProcessNotFoundError = type("ProcessNotFoundError", (Exception,), {})
    fake_frida.NotSupportedError = type("NotSupportedError", (Exception,), {})
    fake_frida.TimedOutError = type("TimedOutError", (Exception,), {})

    class _FakeDevice:
        def spawn(self, argv):
            raise fake_frida.ProcessNotFoundError("unable to find process with name 'com.example.app'")

    fake_frida.get_device = lambda serial, timeout=10: _FakeDevice()
    monkeypatch.setitem(sys.modules, "frida", fake_frida)
    monkeypatch.setattr("time.sleep", lambda _s: None)

    output = FridaInstrumentationPlugin().run(
        _make_context(tmp_path, device_id=device_id, package_name="com.example.app")
    )
    assert output.status.value == "failed"
    assert "not found" in output.errors[0].lower()


def test_device_not_found_by_frida_reports_failed(tmp_path, monkeypatch):
    from app.plugins.installed.frida_instrumentation.plugin import FridaInstrumentationPlugin
    import app.plugins.installed.frida_instrumentation.plugin as plugin_module

    device_id = _seed_device()
    monkeypatch.setattr(plugin_module, "get_connection_manager",
                         lambda: type("C", (), {"check_frida_server_running": lambda self, s: True})())

    fake_frida = types.ModuleType("frida")
    fake_frida.InvalidArgumentError = type("InvalidArgumentError", (Exception,), {})
    fake_frida.ProcessNotFoundError = type("ProcessNotFoundError", (Exception,), {})
    fake_frida.NotSupportedError = type("NotSupportedError", (Exception,), {})
    fake_frida.TimedOutError = type("TimedOutError", (Exception,), {})

    def _raise_invalid_arg(serial, timeout=10):
        raise fake_frida.InvalidArgumentError("device not found")

    fake_frida.get_device = _raise_invalid_arg
    monkeypatch.setitem(sys.modules, "frida", fake_frida)
    monkeypatch.setattr("time.sleep", lambda _s: None)

    output = FridaInstrumentationPlugin().run(
        _make_context(tmp_path, device_id=device_id, package_name="com.example.app")
    )
    assert output.status.value == "failed"
    assert "could not find device" in output.errors[0].lower()


def test_hook_script_is_valid_javascript_syntax():
    """Real syntax validation (matches the `node --check` verification done during development)."""
    import subprocess
    from app.plugins.installed.frida_instrumentation.plugin import _HOOK_SCRIPT_PATH

    result = subprocess.run(["node", "--check", str(_HOOK_SCRIPT_PATH)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_full_dynamic_workflow_completes_without_device(tmp_path):
    """
    Without a device_id, every device-dependent step (App Deployment,
    Frida Instrumentation, Logcat Capture) should gracefully SKIP --
    the workflow as a whole must still complete, not crash.
    """
    import zipfile
    from app.core.workflow.workflow_manager import get_workflow_manager, WORKFLOW_REGISTRY
    from app.database.database import session_scope
    from app.database.models import Analysis, Project, Platform, ProjectType, RunStatus

    assert "dynamic_analysis_default" in WORKFLOW_REGISTRY
    assert len(WORKFLOW_REGISTRY["dynamic_analysis_default"].steps) == 6

    apk_path = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"dex\n")

    with session_scope() as session:
        project = Project(
            name="DynamicTestApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_DYNAMIC,
            target_path=str(apk_path), workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        project_id = project.id

    wf = get_workflow_manager()
    # No device_id passed -- exactly the "no device selected" path every device-dependent step must handle
    analysis_id = wf.run_workflow_sync(
        "dynamic_analysis_default", project_id, str(apk_path), str(tmp_path / "ws")
    )

    with session_scope() as session:
        analysis = session.get(Analysis, analysis_id)
        assert analysis.status == RunStatus.COMPLETED
