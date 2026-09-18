"""
Tests for Module 15: Settings page.
"""

from __future__ import annotations

import time

import pytest


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))
    import app.core.config as config_module
    config_module.get_settings.cache_clear()
    import app.database.database as db_module
    db_module._engine = None
    db_module._SessionFactory = None
    import app.core.dependency_manager as dep_module
    dep_module._manager = None
    import app.gui.controllers.background_task_runner as runner_module
    runner_module._runner = None
    from app.database.database import init_db
    init_db()
    yield
    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None
    dep_module._manager = None
    runner_module._runner = None


def test_settings_page_lists_every_registered_tool(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.settings_page import SettingsPage
    from app.core.dependency_manager import TOOL_REGISTRY

    window = MainWindow()
    page = SettingsPage(window)
    assert set(page._tool_rows.keys()) == set(TOOL_REGISTRY.keys())
    window.deleteLater()


def test_service_tools_show_disabled_install_button(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.settings_page import SettingsPage

    window = MainWindow()
    page = SettingsPage(window)
    row = page._tool_rows["virustotal"]
    assert row._action_btn.isEnabled() is False
    assert "Service" in row._action_btn.text()
    window.deleteLater()


def test_system_tools_show_disabled_install_button(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.settings_page import SettingsPage

    window = MainWindow()
    page = SettingsPage(window)
    row = page._tool_rows["keytool"]
    assert row._action_btn.isEnabled() is False
    assert "System" in row._action_btn.text()
    window.deleteLater()


def test_keytool_shows_installed_status_for_real(qapp):
    """keytool is genuinely on $PATH in this sandbox -- real status check, not mocked."""
    from app.gui.main_window import MainWindow
    from app.gui.pages.settings_page import SettingsPage

    window = MainWindow()
    page = SettingsPage(window)
    row = page._tool_rows["keytool"]
    assert "Installed" in row._status_lbl.text()
    window.deleteLater()


def test_downloadable_tool_shows_not_installed_initially(qapp, tmp_path):
    from app.gui.main_window import MainWindow
    from app.gui.pages.settings_page import SettingsPage

    window = MainWindow()
    page = SettingsPage(window)
    row = page._tool_rows["jadx"]
    assert row._status_lbl.text() == "Not installed"
    assert row._action_btn.isEnabled() is True
    window.deleteLater()


def test_api_key_save_and_reload_roundtrip(qapp, tmp_path):
    from app.gui.main_window import MainWindow
    from app.gui.pages.settings_page import SettingsPage
    from app.database.database import get_setting

    window = MainWindow()
    page = SettingsPage(window)
    page._api_fields["virustotal_api_key"].setText("test-vt-key-12345")
    page._on_save_api_keys()

    assert get_setting("virustotal_api_key") == "test-vt-key-12345"

    # A fresh page instance should load the persisted value back
    page2 = SettingsPage(window)
    assert page2._api_fields["virustotal_api_key"].text() == "test-vt-key-12345"
    window.deleteLater()


def test_install_flow_reaches_success_terminal_state(qapp, tmp_path, monkeypatch):
    """
    Verifies the GUI's install state machine end to end (button
    disables during install, re-enables on completion, status label
    updates) using a fake DependencyManager.install call for
    deterministic behavior. The real download mechanism itself
    (GitHub release fetch/extract, PIP_VENV) was already proven
    working against live GitHub/PyPI multiple times earlier this
    session (JADX, APKTool, frida-tools, frida-server) -- this test
    exercises the GUI wiring on top of it without depending on live
    network, which is more appropriate for a test that runs on every
    CI invocation.
    """
    from app.gui.main_window import MainWindow
    from app.gui.pages.settings_page import SettingsPage
    from app.core.dependency_manager import ToolStatus, InstallMethod
    from PySide6.QtWidgets import QApplication

    window = MainWindow()
    page = SettingsPage(window)
    row = page._tool_rows["bundletool"]

    def _fake_install(name):
        time.sleep(0.2)  # simulate real work briefly, still exercises the async path
        return ToolStatus(name=name, installed=True, version="1.18.1", binary_path=None,
                           install_method=InstallMethod.GITHUB_RELEASE)

    monkeypatch.setattr(page._deps, "install", _fake_install)

    assert row._action_btn.isEnabled() is True
    page._on_install_clicked(row)
    assert row._action_btn.isEnabled() is False

    for _ in range(50):
        QApplication.processEvents()
        time.sleep(0.05)
        if row._action_btn.isEnabled():
            break

    assert row._action_btn.isEnabled() is True
    assert "Installed" in row._status_lbl.text()
    assert "1.18.1" in row._status_lbl.text()
    window.deleteLater()
