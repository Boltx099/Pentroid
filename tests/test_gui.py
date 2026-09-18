"""
Tests for Module 4: GUI shell.

Runs entirely offscreen (see conftest.py). Verifies construction
doesn't crash, navigation actually switches pages, and the Dashboard
page's data-refresh logic works correctly against both an empty
database (real empty-state rendering) and a populated one (seeded via
the real WorkflowManager, not fake fixtures) -- consistent with how
every other module in this codebase is tested end-to-end rather than
purely mocked.
"""

from __future__ import annotations

import zipfile

import pytest


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


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


# --------------------------------------------------------------------------- #
# Main window / navigation
# --------------------------------------------------------------------------- #
def test_main_window_constructs_without_error(qapp):
    from app.gui.main_window import MainWindow

    window = MainWindow()
    assert window.windowTitle().startswith("Pentroid")
    window.deleteLater()


def test_sidebar_navigate_switches_active_page(qapp):
    from app.gui.main_window import MainWindow

    window = MainWindow()
    from app.gui.pages.dashboard_page import DashboardPage
    dashboard = DashboardPage(window)
    window.register_page("dashboard", dashboard)
    window.content_stack.setCurrentWidget(dashboard)

    window.sidebar.navigate.emit("projects")
    assert "projects" in window._pages
    assert window.content_stack.currentWidget() is window._pages["projects"]
    window.deleteLater()


def test_unbuilt_page_falls_back_to_placeholder_not_crash(qapp):
    from app.gui.main_window import MainWindow

    window = MainWindow()
    window.sidebar.navigate.emit("settings")  # not built yet
    assert window.content_stack.currentWidget() is not None
    window.deleteLater()


def test_set_status_updates_label(qapp):
    from app.gui.main_window import MainWindow

    window = MainWindow()
    window.set_status("Testing", "#ff0000")
    assert "Testing" in window.status_label.text()
    window.deleteLater()


# --------------------------------------------------------------------------- #
# Dashboard page -- empty DB (real empty-state rendering)
# --------------------------------------------------------------------------- #
def test_dashboard_renders_empty_state_without_crashing(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.dashboard_page import DashboardPage

    window = MainWindow()
    dashboard = DashboardPage(window)
    window.register_page("dashboard", dashboard)
    dashboard.refresh()  # must not raise against a totally empty DB
    window.deleteLater()


# --------------------------------------------------------------------------- #
# Dashboard page -- populated via the REAL workflow engine
# --------------------------------------------------------------------------- #
def _seed_real_analysis(tmp_path):
    from app.database.database import session_scope
    from app.database.models import Project, Platform, ProjectType
    from app.core.workflow.workflow_manager import get_workflow_manager

    apk_path = tmp_path / "test.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"dex\n")

    with session_scope() as session:
        project = Project(
            name="TestApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(apk_path), workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        project_id = project.id

    wf = get_workflow_manager()
    wf.run_workflow_sync("static_analysis_default", project_id, str(apk_path), str(tmp_path / "ws"))


def test_dashboard_renders_populated_data_without_crashing(qapp, tmp_path):
    from app.gui.main_window import MainWindow
    from app.gui.pages.dashboard_page import DashboardPage
    from app.gui.widgets.cards import StatPill

    _seed_real_analysis(tmp_path)

    window = MainWindow()
    dashboard = DashboardPage(window)
    window.register_page("dashboard", dashboard)
    dashboard.refresh()

    # First stat pill is "Projects" -- must reflect the one real project we seeded
    projects_pill = window.top_bar._stats_row.itemAt(0).widget()
    assert isinstance(projects_pill, StatPill)
    assert projects_pill._value_label.text() == "1"
    window.deleteLater()


def test_dashboard_refresh_idempotent_multiple_calls(qapp, tmp_path):
    """Refreshing repeatedly (as the log-tail timer does every 2s) must not leak widgets or crash."""
    from app.gui.main_window import MainWindow
    from app.gui.pages.dashboard_page import DashboardPage

    _seed_real_analysis(tmp_path)
    window = MainWindow()
    dashboard = DashboardPage(window)
    window.register_page("dashboard", dashboard)

    for _ in range(5):
        dashboard.refresh()
    window.deleteLater()


# --------------------------------------------------------------------------- #
# Chart widgets -- edge cases (zero/empty data must not crash paintEvent)
# --------------------------------------------------------------------------- #
def test_donut_chart_handles_empty_data(qapp):
    from app.gui.widgets.charts import DonutChart

    chart = DonutChart()
    chart.resize(150, 150)
    chart.set_data([], center_value="", center_label="")
    chart.repaint()  # must not raise


def test_donut_chart_handles_zero_total_segments(qapp):
    from app.gui.widgets.charts import DonutChart

    chart = DonutChart()
    chart.resize(150, 150)
    chart.set_data([("A", 0, "#ff0000"), ("B", 0, "#00ff00")], center_value="0")
    chart.repaint()


def test_gauge_chart_handles_zero_value(qapp):
    from app.gui.widgets.charts import GaugeChart

    chart = GaugeChart()
    chart.resize(160, 100)
    chart.set_value(0.0, 10.0)
    chart.repaint()


def test_gauge_chart_color_thresholds():
    from PySide6.QtWidgets import QApplication
    from app.gui.widgets.charts import GaugeChart
    from app.gui.theme import Colors

    QApplication.instance() or QApplication([])
    chart = GaugeChart()

    chart.set_value(2.0, 10.0)  # low
    assert chart._risk_color().name() == Colors.ACCENT_GREEN

    chart.set_value(5.0, 10.0)  # medium
    assert chart._risk_color().name() == Colors.SEVERITY_HIGH

    chart.set_value(8.0, 10.0)  # high
    assert chart._risk_color().name() == Colors.SEVERITY_CRITICAL


def test_sparkline_handles_empty_series(qapp):
    from app.gui.widgets.charts import SparklineChart

    chart = SparklineChart()
    chart.resize(300, 140)
    chart.set_data([], x_labels=[])
    chart.repaint()


def test_severity_bar_handles_zero_total(qapp):
    from app.gui.widgets.charts import SeverityBar

    bar = SeverityBar("Critical", 0, 0, "#ff0000")  # total=0 must not divide-by-zero
    bar.resize(200, 34)
    bar.repaint()
