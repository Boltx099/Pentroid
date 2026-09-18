"""
Tests for ``search_everything`` / ``SearchResultsDialog`` -- the fix for
the top bar's search field, which used to fire on every keystroke into
a signal connected to nothing anywhere in the app.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="GUI tests need PySide6")

from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    yield QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _isolated_project_root(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))

    import app.core.config as config_module
    config_module.get_settings.cache_clear()

    import app.database.database as db_module
    db_module._engine = None
    db_module._SessionFactory = None

    yield

    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None


@pytest.fixture
def seeded_db(tmp_path):
    from app.database.database import init_db, session_scope
    from app.database.models import (
        Analysis, AnalysisType, Finding, Platform, Project, ProjectType, RunStatus, Severity,
    )

    init_db()
    with session_scope() as session:
        project = Project(
            name="BitGo Wallet", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        analysis = Analysis(
            project_id=project.id, analysis_type=AnalysisType.STATIC,
            workflow_name="static_analysis_default", status=RunStatus.COMPLETED, risk_score=8.5,
        )
        session.add(analysis)
        session.flush()
        finding = Finding(
            analysis_id=analysis.id, title="Hardcoded AWS Access Key", severity=Severity.CRITICAL,
            description="d", file_path="Foo.java", line_number=12,
        )
        session.add(finding)
        session.flush()
        return {"project_id": project.id, "analysis_id": analysis.id, "finding_id": finding.id}


def test_search_matches_project_by_name(seeded_db):
    from app.gui.dialogs.search_results_dialog import search_everything

    results = search_everything("bitgo")
    assert [p["name"] for p in results["projects"]] == ["BitGo Wallet"]


def test_search_matches_analysis_by_workflow_name(seeded_db):
    from app.gui.dialogs.search_results_dialog import search_everything

    results = search_everything("static_analysis")
    assert any(a["workflow_name"] == "static_analysis_default" for a in results["analyses"])
    assert results["analyses"][0]["project_name"] == "BitGo Wallet"


def test_search_matches_finding_by_title(seeded_db):
    from app.gui.dialogs.search_results_dialog import search_everything

    results = search_everything("aws")
    assert [f["title"] for f in results["findings"]] == ["Hardcoded AWS Access Key"]
    assert results["findings"][0]["analysis_id"] == seeded_db["analysis_id"]


def test_search_is_case_insensitive(seeded_db):
    from app.gui.dialogs.search_results_dialog import search_everything

    results = search_everything("BITGO")
    assert len(results["projects"]) == 1


def test_search_no_match_returns_empty(seeded_db):
    from app.gui.dialogs.search_results_dialog import search_everything

    results = search_everything("no_such_thing_xyz")
    assert results == {"projects": [], "analyses": [], "findings": []}


def test_search_blank_query_returns_empty_without_querying_db():
    from app.gui.dialogs.search_results_dialog import search_everything

    assert search_everything("   ") == {"projects": [], "analyses": [], "findings": []}


def test_findings_sorted_by_severity_not_alphabetically(seeded_db):
    """
    Regression guard: Severity's string values ("critical", "high", "medium",
    "low", "info") do NOT sort into severity-priority order alphabetically
    (info < low, backwards) -- sorting must use an explicit rank, not
    ORDER BY severity.
    """
    from app.database.database import session_scope
    from app.database.models import Finding, Severity
    from app.gui.dialogs.search_results_dialog import search_everything

    with session_scope() as session:
        session.add(Finding(
            analysis_id=seeded_db["analysis_id"], title="AWS key in logs", severity=Severity.LOW,
        ))
        session.add(Finding(
            analysis_id=seeded_db["analysis_id"], title="AWS key hardcoded again",
            severity=Severity.HIGH,
        ))

    results = search_everything("aws")
    severities = [f["severity"] for f in results["findings"]]
    assert severities == sorted(severities, key=lambda s: {"critical": 0, "high": 1, "medium": 2,
                                                            "low": 3, "info": 4}[s])
    assert severities[0] == "critical"


def test_search_results_dialog_builds_with_results(qapp, seeded_db):
    from app.gui.dialogs.search_results_dialog import SearchResultsDialog

    main_window = QWidget()
    dialog = SearchResultsDialog(main_window, "aws")
    assert dialog._body.count() > 0


def test_search_results_dialog_builds_with_no_results(qapp, seeded_db):
    from app.gui.dialogs.search_results_dialog import SearchResultsDialog

    main_window = QWidget()
    dialog = SearchResultsDialog(main_window, "no_such_thing_xyz")
    assert dialog._body.count() >= 1  # the "no results" label
