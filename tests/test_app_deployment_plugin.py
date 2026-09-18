"""
Tests for Module 17d: app_deployment plugin.
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


def test_skips_without_device_id(tmp_path):
    from app.plugins.installed.app_deployment.plugin import AppDeploymentPlugin

    output = AppDeploymentPlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_skips_without_package_name(tmp_path):
    from app.plugins.installed.app_deployment.plugin import AppDeploymentPlugin

    device_id = _seed_device()
    output = AppDeploymentPlugin().run(_make_context(tmp_path, device_id=device_id))
    assert output.status.value == "skipped"


def test_successful_install_and_launch(tmp_path, monkeypatch):
    from app.plugins.installed.app_deployment.plugin import AppDeploymentPlugin
    import app.plugins.installed.app_deployment.plugin as plugin_module

    device_id = _seed_device()

    class _FakeConnManager:
        def install_apk(self, serial, apk_path):
            return True

        def launch_app(self, serial, package_name):
            return True

    monkeypatch.setattr(plugin_module, "get_connection_manager", lambda: _FakeConnManager())
    output = AppDeploymentPlugin().run(
        _make_context(tmp_path, device_id=device_id, package_name="com.example.app")
    )
    assert output.status.value == "success"
    assert "com.example.app" in output.findings[0].title


def test_install_failure_reports_failed(tmp_path, monkeypatch):
    from app.plugins.installed.app_deployment.plugin import AppDeploymentPlugin
    import app.plugins.installed.app_deployment.plugin as plugin_module

    device_id = _seed_device()

    class _FakeConnManager:
        def install_apk(self, serial, apk_path):
            return False

    monkeypatch.setattr(plugin_module, "get_connection_manager", lambda: _FakeConnManager())
    output = AppDeploymentPlugin().run(
        _make_context(tmp_path, device_id=device_id, package_name="com.example.app")
    )
    assert output.status.value == "failed"
    assert "install failed" in output.errors[0].lower()


def test_launch_failure_reports_failed_after_successful_install(tmp_path, monkeypatch):
    from app.plugins.installed.app_deployment.plugin import AppDeploymentPlugin
    import app.plugins.installed.app_deployment.plugin as plugin_module

    device_id = _seed_device()

    class _FakeConnManager:
        def install_apk(self, serial, apk_path):
            return True

        def launch_app(self, serial, package_name):
            return False

    monkeypatch.setattr(plugin_module, "get_connection_manager", lambda: _FakeConnManager())
    output = AppDeploymentPlugin().run(
        _make_context(tmp_path, device_id=device_id, package_name="com.example.app")
    )
    assert output.status.value == "failed"
    assert "launch" in output.errors[0].lower()
    assert "Install succeeded." in output.logs
