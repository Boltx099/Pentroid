"""Tests for Module 18: theme toggle, notifications, and settings-icon wiring."""
from __future__ import annotations
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
    from app.database.database import init_db
    init_db()
    yield
    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None


@pytest.fixture(autouse=True)
def _reset_theme():
    from app.gui.theme import Colors
    yield
    Colors.set_theme("dark")


def test_set_theme_swaps_every_palette_key(qapp):
    from app.gui.theme import Colors, _DARK, _LIGHT
    assert Colors.current_theme == "dark"
    for key in _DARK:
        assert getattr(Colors, key) == _DARK[key]
    Colors.set_theme("light")
    assert Colors.current_theme == "light"
    for key in _LIGHT:
        assert getattr(Colors, key) == _LIGHT[key]


def test_set_theme_ignores_unknown_name(qapp):
    from app.gui.theme import Colors
    Colors.set_theme("dark")
    Colors.set_theme("nonexistent")
    assert Colors.current_theme == "dark"


def test_build_stylesheet_reflects_current_palette(qapp):
    from app.gui.theme import Colors, build_stylesheet
    Colors.set_theme("light")
    css = build_stylesheet()
    assert Colors.BG_APP in css
    assert "#080b12" not in css


def test_theme_toggle_button_actually_flips_palette(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.theme import Colors
    window = MainWindow()
    assert Colors.current_theme == "dark"
    window.top_bar.theme_toggled.emit()
    assert Colors.current_theme == "light"
    window.top_bar.theme_toggled.emit()
    assert Colors.current_theme == "dark"
    window.deleteLater()


def test_theme_toggle_updates_env_label(qapp):
    from app.gui.main_window import MainWindow
    window = MainWindow()
    assert "Theme: Dark" in window.env_label.text()
    window.top_bar.theme_toggled.emit()
    assert "Theme: Light" in window.env_label.text()
    window.deleteLater()


def test_notifications_button_gives_real_feedback(qapp):
    from app.gui.main_window import MainWindow
    window = MainWindow()
    window.top_bar.notifications_clicked.emit()
    assert "Notification Center" in window.status_label.text()
    window.deleteLater()


def test_settings_icon_navigates_and_syncs_sidebar(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.settings_page import SettingsPage
    window = MainWindow()
    settings_page = SettingsPage(window)
    window.register_page("settings", settings_page)
    window.top_bar.settings_clicked.emit()
    assert window.content_stack.currentWidget() is settings_page
    assert window.sidebar._active_key == "settings"
    window.deleteLater()


def test_set_status_default_color_reflects_current_theme(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.theme import Colors
    window = MainWindow()
    Colors.set_theme("light")
    window.set_status("test message")
    assert Colors.ACCENT_GREEN in window.status_label.styleSheet()
    assert Colors.ACCENT_GREEN == "#16a34a"
    window.deleteLater()


def test_navigate_syncs_sidebar_regardless_of_trigger_source(qapp):
    from app.gui.main_window import MainWindow
    window = MainWindow()
    window._navigate("projects")
    assert window.sidebar._active_key == "projects"
    window.deleteLater()
