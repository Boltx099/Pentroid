"""
Tests for Module 5: New Project dialog, AnalysisRunner controller, and
Projects page -- the first fully click-to-completion user flow in the
GUI. Runs the real WorkflowManager end-to-end (background thread +
DB), same standard as the rest of the codebase.
"""

from __future__ import annotations

import time
import zipfile

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
    import app.core.workflow.plugin_manager as pm_module
    pm_module.reset_plugin_manager()
    import app.core.workflow.workflow_manager as wf_module
    wf_module._workflow_manager = None
    import app.core.workflow.job_monitor as jm_module
    jm_module._monitor = None
    import app.core.workflow.event_bus as eb_module
    eb_module._bus = None
    import app.gui.controllers.analysis_runner as runner_module
    runner_module._runner = None
    from app.database.database import init_db
    init_db()
    yield
    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None
    pm_module.reset_plugin_manager()
    wf_module._workflow_manager = None
    runner_module._runner = None


def _make_valid_apk(path):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"dex\n")


# --------------------------------------------------------------------------- #
# NewProjectDialog
# --------------------------------------------------------------------------- #
def test_new_project_dialog_rejects_missing_name(qapp, tmp_path):
    from app.gui.dialogs.new_project_dialog import NewProjectDialog

    apk = tmp_path / "app.apk"
    _make_valid_apk(apk)

    dialog = NewProjectDialog()
    dialog._name_edit.setText("")
    dialog._target_path = str(apk)
    dialog._on_create()

    assert dialog.created_project_id is None
    assert "name" in dialog._error_label.text().lower()


def test_new_project_dialog_rejects_missing_file(qapp):
    from app.gui.dialogs.new_project_dialog import NewProjectDialog

    dialog = NewProjectDialog()
    dialog._name_edit.setText("MyApp")
    dialog._target_path = None
    dialog._on_create()

    assert dialog.created_project_id is None
    assert "file" in dialog._error_label.text().lower()


def test_new_project_dialog_rejects_wrong_extension_for_platform(qapp, tmp_path):
    from app.gui.dialogs.new_project_dialog import NewProjectDialog

    wrong_file = tmp_path / "app.ipa"  # iOS extension but platform stays Android (default)
    wrong_file.write_bytes(b"fake")

    dialog = NewProjectDialog()
    dialog._name_edit.setText("MyApp")
    dialog._target_path = str(wrong_file)
    dialog._on_create()

    assert dialog.created_project_id is None
    assert "expected" in dialog._error_label.text().lower()


def test_new_project_dialog_creates_real_project_and_workspace(qapp, tmp_path):
    from app.gui.dialogs.new_project_dialog import NewProjectDialog
    from app.database.database import session_scope
    from app.database.models import Project
    from pathlib import Path

    apk = tmp_path / "ChatApp.apk"
    _make_valid_apk(apk)

    dialog = NewProjectDialog()
    dialog._name_edit.setText("ChatApp")
    dialog._target_path = str(apk)
    dialog._on_create()

    assert dialog.created_project_id is not None
    with session_scope() as session:
        project = session.get(Project, dialog.created_project_id)
        assert project.name == "ChatApp"
        assert project.target_path == str(apk)
        assert Path(project.workspace_path).exists()  # real directory, not just a DB string


def test_new_project_dialog_platform_filters_project_types(qapp):
    from app.gui.dialogs.new_project_dialog import NewProjectDialog
    from app.database.models import Platform

    dialog = NewProjectDialog()
    android_types = [dialog._type_combo.itemText(i) for i in range(dialog._type_combo.count())]
    assert any("APK" in t for t in android_types)

    ios_index = dialog._platform_combo.findData(Platform.IOS)
    dialog._platform_combo.setCurrentIndex(ios_index)
    ios_types = [dialog._type_combo.itemText(i) for i in range(dialog._type_combo.count())]
    assert any("IPA" in t for t in ios_types)
    assert not any("APK" in t for t in ios_types)


# --------------------------------------------------------------------------- #
# AnalysisRunner controller
# --------------------------------------------------------------------------- #
def test_analysis_runner_completes_real_workflow_and_emits_signals(qapp, tmp_path):
    from app.gui.controllers.analysis_runner import AnalysisRunner
    from app.database.database import session_scope
    from app.database.models import Project, Platform, ProjectType

    apk = tmp_path / "app.apk"
    _make_valid_apk(apk)
    with session_scope() as session:
        project = Project(
            name="RunnerTest", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(apk), workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        project_id = project.id

    runner = AnalysisRunner()
    completed_events = []
    runner.completed.connect(lambda job_id, status, risk, analysis_id: completed_events.append((job_id, status, risk, analysis_id)))

    job_id = runner.start("static_analysis_default", project_id, str(apk), str(tmp_path / "ws"))
    assert job_id is not None

    from PySide6.QtWidgets import QApplication
    for _ in range(50):
        QApplication.processEvents()
        time.sleep(0.1)
        if completed_events:
            break

    assert len(completed_events) == 1
    assert completed_events[0][0] == job_id
    assert completed_events[0][1] == "completed"
    assert completed_events[0][3] > 0  # real analysis_id


def test_analysis_runner_failed_to_start_emits_signal_for_unknown_workflow(qapp, tmp_path):
    from app.gui.controllers.analysis_runner import AnalysisRunner

    runner = AnalysisRunner()
    errors = []
    runner.failed_to_start.connect(lambda msg: errors.append(msg))

    job_id = runner.start("not_a_real_workflow", 1, str(tmp_path / "x.apk"), str(tmp_path / "ws"))
    assert job_id is None
    assert len(errors) == 1


# --------------------------------------------------------------------------- #
# ProjectsPage -- full click-through flow
# --------------------------------------------------------------------------- #
def test_projects_page_shows_empty_state_with_no_projects(qapp):
    from app.gui.main_window import MainWindow
    from app.gui.pages.projects_page import ProjectsPage

    window = MainWindow()
    page = ProjectsPage(window)
    assert page._list_layout.count() == 1  # just the empty-state label
    window.deleteLater()


def test_projects_page_lists_real_project_after_refresh(qapp, tmp_path):
    from app.gui.main_window import MainWindow
    from app.gui.pages.projects_page import ProjectsPage
    from app.database.database import session_scope
    from app.database.models import Project, Platform, ProjectType

    apk = tmp_path / "app.apk"
    _make_valid_apk(apk)
    with session_scope() as session:
        session.add(Project(
            name="ListedApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(apk), workspace_path=str(tmp_path / "ws"),
        ))

    window = MainWindow()
    page = ProjectsPage(window)
    page.refresh()
    assert page._list_layout.count() == 1
    row = page._list_layout.itemAt(0).widget()
    assert row.project_id is not None
    window.deleteLater()


def test_projects_page_full_click_to_completion_flow(qapp, tmp_path):
    """The complete loop: click Run Static Analysis -> real background job -> DB updated -> row re-enabled."""
    from app.gui.main_window import MainWindow
    from app.gui.pages.projects_page import ProjectsPage
    from app.database.database import session_scope
    from app.database.models import Project, Platform, ProjectType, Analysis

    apk = tmp_path / "app.apk"
    _make_valid_apk(apk)
    with session_scope() as session:
        session.add(Project(
            name="ClickThroughApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(apk), workspace_path=str(tmp_path / "ws"),
        ))

    window = MainWindow()
    page = ProjectsPage(window)
    page.refresh()
    row = page._list_layout.itemAt(0).widget()

    assert row._run_btn.isEnabled() is True
    page._on_run_static(row)
    assert row.project_id in [r.project_id for r in page._job_rows.values()]

    from PySide6.QtWidgets import QApplication
    for _ in range(50):
        QApplication.processEvents()
        time.sleep(0.1)
        if not page._job_rows:
            break

    assert row._run_btn.isEnabled() is True
    assert "completed" in row._status_note.text().lower()

    with session_scope() as session:
        analyses = session.query(Analysis).all()
        assert len(analyses) == 1
        assert analyses[0].status.value == "completed"

    window.deleteLater()


def test_run_button_disabled_when_no_target_file(qapp, tmp_path):
    from app.gui.main_window import MainWindow
    from app.gui.pages.projects_page import ProjectsPage
    from app.database.database import session_scope
    from app.database.models import Project, Platform, ProjectType

    with session_scope() as session:
        session.add(Project(
            name="NoTargetApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=None, workspace_path=str(tmp_path / "ws"),
        ))

    window = MainWindow()
    page = ProjectsPage(window)
    page.refresh()
    row = page._list_layout.itemAt(0).widget()
    assert row._run_btn.isEnabled() is False
    window.deleteLater()


def test_completed_analysis_auto_generates_real_report(qapp, tmp_path):
    """Closes the full loop: GUI click -> real workflow -> real DB -> real report file on disk."""
    from app.gui.main_window import MainWindow
    from app.gui.pages.projects_page import ProjectsPage
    from app.database.database import session_scope
    from app.database.models import Project, Platform, ProjectType, Report
    from pathlib import Path

    apk = tmp_path / "app.apk"
    _make_valid_apk(apk)
    with session_scope() as session:
        session.add(Project(
            name="ReportFlowApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(apk), workspace_path=str(tmp_path / "ws"),
        ))

    window = MainWindow()
    page = ProjectsPage(window)
    page.refresh()
    row = page._list_layout.itemAt(0).widget()
    page._on_run_static(row)

    from PySide6.QtWidgets import QApplication
    for _ in range(50):
        QApplication.processEvents()
        time.sleep(0.1)
        if not page._job_rows:
            break

    with session_scope() as session:
        reports = session.query(Report).all()
        # A completed analysis now emits BOTH an HTML report (for a human) and a
        # SARIF report (for CI / GitHub code scanning / DefectDojo to consume).
        assert len(reports) == 2
        suffixes = {Path(r.file_path).suffix for r in reports}
        assert suffixes == {".html", ".sarif"}
        for report in reports:
            assert Path(report.file_path).exists()

    window.deleteLater()
