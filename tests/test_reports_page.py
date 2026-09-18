"""
Tests for Module 9: Reports page.
"""

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


def _seed_report(tmp_path, fmt="html"):
    from app.database.database import session_scope
    from app.database.models import Project, Analysis, Report, Platform, ProjectType, AnalysisType, RunStatus, ReportFormat

    with session_scope() as session:
        project = Project(
            name="ReportsTestApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(tmp_path / "app.apk"), workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        analysis = Analysis(
            project_id=project.id, analysis_type=AnalysisType.STATIC,
            workflow_name="static_analysis_default", status=RunStatus.COMPLETED, risk_score=5.0,
        )
        session.add(analysis)
        session.flush()

        file_path = tmp_path / f"report.{fmt}"
        file_path.write_text("<html>fake report</html>" if fmt == "html" else "fake content")

        report = Report(
            analysis_id=analysis.id, format=ReportFormat(fmt), file_path=str(file_path),
            summary="3 finding(s), risk score 5.0",
        )
        session.add(report)
        session.flush()
        return report.id, str(file_path)


def test_reports_page_shows_empty_state_initially(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.reports_page import ReportsPage

    window = MainWindow()
    page = ReportsPage(window)
    assert page._list_layout.count() == 1
    window.deleteLater()


def test_reports_page_lists_real_report_with_project_context(qapp, tmp_path):
    from app.gui.main_window import MainWindow
    from app.gui.pages.reports_page import ReportsPage

    _seed_report(tmp_path)
    window = MainWindow()
    page = ReportsPage(window)
    page.refresh()

    assert page._list_layout.count() == 1
    row = page._list_layout.itemAt(0).widget()
    assert row.report_id is not None


def test_open_button_disabled_when_file_missing(qapp, tmp_path):
    from app.gui.main_window import MainWindow
    from app.gui.pages.reports_page import ReportsPage
    from app.database.database import session_scope
    from app.database.models import Project, Analysis, Report, Platform, ProjectType, AnalysisType, RunStatus, ReportFormat
    from pathlib import Path

    with session_scope() as session:
        project = Project(
            name="GoneApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(tmp_path / "app.apk"), workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        analysis = Analysis(
            project_id=project.id, analysis_type=AnalysisType.STATIC,
            workflow_name="static_analysis_default", status=RunStatus.COMPLETED,
        )
        session.add(analysis)
        session.flush()
        session.add(Report(
            analysis_id=analysis.id, format=ReportFormat.HTML,
            file_path=str(tmp_path / "does_not_exist.html"),
        ))

    window = MainWindow()
    page = ReportsPage(window)
    page.refresh()
    row = page._list_layout.itemAt(0).widget()
    open_btn = [row.layout().itemAt(i).widget() for i in range(row.layout().count())
                if hasattr(row.layout().itemAt(i).widget(), "text") and row.layout().itemAt(i).widget().text() == "Open"][0]
    assert open_btn.isEnabled() is False


def test_open_calls_qdesktopservices_with_correct_url(qapp, tmp_path, monkeypatch):
    from app.gui.main_window import MainWindow
    from app.gui.pages.reports_page import ReportsPage
    import app.gui.pages.reports_page as page_module

    report_id, file_path = _seed_report(tmp_path)
    window = MainWindow()
    page = ReportsPage(window)
    page.refresh()

    called_urls = []
    monkeypatch.setattr(
        page_module.QDesktopServices, "openUrl",
        staticmethod(lambda url: called_urls.append(url.toLocalFile()) or True),
    )
    page._on_open(file_path)
    assert called_urls == [file_path]


def test_delete_removes_both_file_and_db_row(qapp, tmp_path, monkeypatch):
    from app.gui.main_window import MainWindow
    from app.gui.pages.reports_page import ReportsPage
    import app.gui.pages.reports_page as page_module
    from app.database.database import session_scope
    from app.database.models import Report
    from pathlib import Path

    report_id, file_path = _seed_report(tmp_path)
    assert Path(file_path).exists()

    window = MainWindow()
    page = ReportsPage(window)
    page.refresh()
    row = page._list_layout.itemAt(0).widget()

    monkeypatch.setattr(page_module.QMessageBox, "question", staticmethod(lambda *a, **kw: page_module.QMessageBox.Yes))
    page._on_delete(report_id, file_path, row)

    assert not Path(file_path).exists()
    with session_scope() as session:
        assert session.get(Report, report_id) is None


def test_delete_cancelled_keeps_file_and_db_row(qapp, tmp_path, monkeypatch):
    from app.gui.main_window import MainWindow
    from app.gui.pages.reports_page import ReportsPage
    import app.gui.pages.reports_page as page_module
    from app.database.database import session_scope
    from app.database.models import Report
    from pathlib import Path

    report_id, file_path = _seed_report(tmp_path)
    window = MainWindow()
    page = ReportsPage(window)
    page.refresh()
    row = page._list_layout.itemAt(0).widget()

    monkeypatch.setattr(page_module.QMessageBox, "question", staticmethod(lambda *a, **kw: page_module.QMessageBox.No))
    page._on_delete(report_id, file_path, row)

    assert Path(file_path).exists()
    with session_scope() as session:
        assert session.get(Report, report_id) is not None
