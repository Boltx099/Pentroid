"""
Tests for the FindingsDialog triage workflow.

``FindingStatus`` (OPEN/CONFIRMED/FALSE_POSITIVE/FIXED/ACCEPTED_RISK) was
already a column on the ``Finding`` model but was never referenced
anywhere outside models.py -- every finding was permanently OPEN as far
as the app was concerned, with no way to mark one reviewed and have it
persist. These tests cover the fix: set_finding_status() persisting a
decision, the dialog reading/filtering on it, and the "hide reviewed"
toggle.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="GUI tests need PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402


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
def seeded(tmp_path):
    from app.database.database import init_db, session_scope
    from app.database.models import (
        Analysis, AnalysisType, Finding, FindingStatus, Platform, Project, ProjectType,
        RunStatus, Severity,
    )

    init_db()
    with session_scope() as session:
        project = Project(
            name="Test App", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        analysis = Analysis(
            project_id=project.id, analysis_type=AnalysisType.STATIC,
            workflow_name="static_analysis_default", status=RunStatus.COMPLETED, risk_score=7.2,
        )
        session.add(analysis)
        session.flush()
        f_open = Finding(analysis_id=analysis.id, title="Hardcoded Secret", severity=Severity.CRITICAL)
        f_medium = Finding(analysis_id=analysis.id, title="Weak Hash", severity=Severity.MEDIUM)
        f_already_fp = Finding(
            analysis_id=analysis.id, title="Old False Positive", severity=Severity.LOW,
            status=FindingStatus.FALSE_POSITIVE,
        )
        session.add_all([f_open, f_medium, f_already_fp])
        session.flush()
        return {
            "analysis_id": analysis.id,
            "open_id": f_open.id, "medium_id": f_medium.id, "fp_id": f_already_fp.id,
        }


def test_set_finding_status_persists(seeded):
    from app.database.database import session_scope
    from app.database.models import Finding, FindingStatus
    from app.gui.dialogs.findings_dialog import set_finding_status

    set_finding_status(seeded["medium_id"], FindingStatus.CONFIRMED)

    with session_scope() as session:
        row = session.get(Finding, seeded["medium_id"])
        assert row.status == FindingStatus.CONFIRMED


def test_set_finding_status_on_unknown_id_does_not_raise(tmp_path):
    from app.database.database import init_db
    from app.gui.dialogs.findings_dialog import set_finding_status
    from app.database.models import FindingStatus

    init_db()
    set_finding_status(999999, FindingStatus.CONFIRMED)  # should be a silent no-op


def test_dialog_hides_reviewed_findings_by_default(qapp, seeded):
    from app.gui.dialogs.findings_dialog import FindingsDialog

    dialog = FindingsDialog(seeded["analysis_id"])
    assert dialog._hide_reviewed.isChecked() is True
    assert "1 hidden" in dialog._sub_label.text()
    assert "3 finding(s)" in dialog._sub_label.text()  # total count unaffected by the filter


def test_unchecking_hide_reviewed_shows_everything(qapp, seeded):
    from app.gui.dialogs.findings_dialog import FindingsDialog

    dialog = FindingsDialog(seeded["analysis_id"])
    dialog._hide_reviewed.setChecked(False)
    assert "hidden" not in dialog._sub_label.text()


def test_marking_a_finding_reviewed_persists_and_updates_the_dialog(qapp, seeded):
    from app.database.database import session_scope
    from app.database.models import Finding, FindingStatus
    from app.gui.dialogs.findings_dialog import FindingsDialog

    dialog = FindingsDialog(seeded["analysis_id"])
    assert "1 hidden" in dialog._sub_label.text()

    dialog._on_status_change(seeded["open_id"], FindingStatus.FIXED)

    # persisted to the DB
    with session_scope() as session:
        row = session.get(Finding, seeded["open_id"])
        assert row.status == FindingStatus.FIXED

    # dialog's own state reflects it immediately (hide_reviewed still checked)
    assert "2 hidden" in dialog._sub_label.text()


def test_marking_confirmed_does_not_hide_it(qapp, seeded):
    """CONFIRMED and ACCEPTED_RISK are real, still-relevant states -- only
    FALSE_POSITIVE and FIXED are hidden by the default filter."""
    from app.gui.dialogs.findings_dialog import FindingsDialog
    from app.database.models import FindingStatus

    dialog = FindingsDialog(seeded["analysis_id"])
    dialog._on_status_change(seeded["medium_id"], FindingStatus.CONFIRMED)
    assert "1 hidden" in dialog._sub_label.text()  # still just the pre-existing FP


def test_all_reviewed_shows_empty_state(qapp, seeded):
    from app.gui.dialogs.findings_dialog import FindingsDialog
    from app.database.models import FindingStatus

    dialog = FindingsDialog(seeded["analysis_id"])
    dialog._on_status_change(seeded["open_id"], FindingStatus.FIXED)
    dialog._on_status_change(seeded["medium_id"], FindingStatus.FALSE_POSITIVE)
    # all 3 findings are now in the hidden set; the scroll area should show
    # the "everything reviewed" message rather than an empty findings list
    assert dialog._scroll.widget() is not None


def test_finding_card_shows_correct_initial_status(qapp, seeded):
    from app.database.models import Finding, FindingStatus, Severity
    from app.gui.dialogs.findings_dialog import _FindingCard, _STATUS_ORDER
    from PySide6.QtWidgets import QComboBox

    finding = Finding(severity=Severity.LOW, title="x", status=FindingStatus.ACCEPTED_RISK)
    card = _FindingCard(finding_id=1, finding=finding)
    combo = card.findChild(QComboBox)
    assert combo is not None
    assert combo.currentData() == FindingStatus.ACCEPTED_RISK
    assert combo.currentIndex() == _STATUS_ORDER.index(FindingStatus.ACCEPTED_RISK)


def test_status_change_callback_receives_finding_id_and_status(qapp):
    from app.database.models import Finding, FindingStatus, Severity
    from app.gui.dialogs.findings_dialog import _FindingCard, _STATUS_ORDER
    from PySide6.QtWidgets import QComboBox

    received = {}

    def on_change(finding_id, new_status):
        received["finding_id"] = finding_id
        received["status"] = new_status

    finding = Finding(severity=Severity.LOW, title="x", status=FindingStatus.OPEN)
    card = _FindingCard(finding_id=42, finding=finding, on_status_change=on_change)
    combo = card.findChild(QComboBox)

    combo.setCurrentIndex(_STATUS_ORDER.index(FindingStatus.CONFIRMED))

    assert received == {"finding_id": 42, "status": FindingStatus.CONFIRMED}
