"""
Tests for Module 7: Report Engine.

Seeds a real Analysis with real Finding rows (not fixtures pretending
to be findings) and generates each report format, verifying both that
the file is genuinely written to disk with real content and that a
matching Report row is created in the database.
"""

from __future__ import annotations

import json

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


def _seed_analysis_with_findings(tmp_path):
    from app.database.database import session_scope
    from app.database.models import Project, Analysis, Finding, Platform, ProjectType, AnalysisType, RunStatus, Severity

    with session_scope() as session:
        project = Project(
            name="ReportTestApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(tmp_path / "app.apk"), workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()

        analysis = Analysis(
            project_id=project.id, analysis_type=AnalysisType.STATIC,
            workflow_name="static_analysis_default", status=RunStatus.COMPLETED, risk_score=6.5,
        )
        session.add(analysis)
        session.flush()
        analysis_id = analysis.id

        session.add_all([
            Finding(
                analysis_id=analysis_id, title="Application is debuggable", severity=Severity.HIGH,
                category="Manifest", description="android:debuggable=\"true\" found.",
                owasp_mapping="M10: Extraneous Functionality", masvs_mapping="MASVS-RESILIENCE",
                recommendation="Remove android:debuggable from release builds.",
            ),
            Finding(
                analysis_id=analysis_id, title="Exported activity without permission: .MainActivity",
                severity=Severity.HIGH, category="Exposed Components",
                description="Activity is exported and unprotected.", file_path="AndroidManifest.xml",
            ),
            Finding(
                analysis_id=analysis_id, title="2 dangerous permission(s) requested", severity=Severity.MEDIUM,
                category="Permissions", description="Requested: CAMERA, READ_SMS",
            ),
        ])
    return analysis_id


def test_generate_html_report_contains_real_findings(tmp_path):
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Report, ReportFormat
    from pathlib import Path

    analysis_id = _seed_analysis_with_findings(tmp_path)
    engine = ReportEngine()
    report_id = engine.generate(analysis_id, ReportFormat.HTML)

    with session_scope() as session:
        report = session.get(Report, report_id)
        assert report.format == ReportFormat.HTML
        file_path = Path(report.file_path)

    assert file_path.exists()
    html = file_path.read_text(encoding="utf-8")
    assert "ReportTestApp" in html
    assert "Application is debuggable" in html
    assert "Exported activity without permission" in html
    assert "6.5" in html


def test_generate_json_report_is_valid_and_complete(tmp_path):
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Report, ReportFormat
    from pathlib import Path

    analysis_id = _seed_analysis_with_findings(tmp_path)
    engine = ReportEngine()
    report_id = engine.generate(analysis_id, ReportFormat.JSON)

    with session_scope() as session:
        file_path = Path(session.get(Report, report_id).file_path)

    data = json.loads(file_path.read_text(encoding="utf-8"))
    assert data["project"]["name"] == "ReportTestApp"
    assert data["finding_count"] == 3
    assert data["analysis"]["risk_score"] == 6.5
    assert {f["title"] for f in data["findings"]} == {
        "Application is debuggable",
        "Exported activity without permission: .MainActivity",
        "2 dangerous permission(s) requested",
    }


def test_generate_csv_report_has_correct_row_count(tmp_path):
    import csv
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Report, ReportFormat
    from pathlib import Path

    analysis_id = _seed_analysis_with_findings(tmp_path)
    engine = ReportEngine()
    report_id = engine.generate(analysis_id, ReportFormat.CSV)

    with session_scope() as session:
        file_path = Path(session.get(Report, report_id).file_path)

    with open(file_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0][0] == "Title"  # header
    assert len(rows) == 4  # header + 3 findings


def test_generate_pdf_report_produces_real_pdf_file(tmp_path):
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Report, ReportFormat
    from pathlib import Path

    analysis_id = _seed_analysis_with_findings(tmp_path)
    engine = ReportEngine()
    report_id = engine.generate(analysis_id, ReportFormat.PDF)

    with session_scope() as session:
        file_path = Path(session.get(Report, report_id).file_path)

    assert file_path.exists()
    assert file_path.read_bytes()[:4] == b"%PDF"  # genuine PDF magic bytes, not a stub file
    assert file_path.stat().st_size > 1000  # non-trivial content


def test_generate_markdown_report_contains_findings(tmp_path):
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Report, ReportFormat
    from pathlib import Path

    analysis_id = _seed_analysis_with_findings(tmp_path)
    engine = ReportEngine()
    report_id = engine.generate(analysis_id, ReportFormat.MARKDOWN)

    with session_scope() as session:
        report = session.get(Report, report_id)
        assert report.format == ReportFormat.MARKDOWN
        file_path = Path(report.file_path)

    md = file_path.read_text(encoding="utf-8")
    assert md.startswith("# Pentroid Report - ReportTestApp")
    assert "Application is debuggable" in md
    assert "HIGH" in md


def test_generate_report_for_analysis_with_no_findings(tmp_path):
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Project, Analysis, Platform, ProjectType, AnalysisType, RunStatus, Report, ReportFormat
    from pathlib import Path

    with session_scope() as session:
        project = Project(
            name="CleanApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(tmp_path / "app.apk"), workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        analysis = Analysis(
            project_id=project.id, analysis_type=AnalysisType.STATIC,
            workflow_name="static_analysis_default", status=RunStatus.COMPLETED, risk_score=0.0,
        )
        session.add(analysis)
        session.flush()
        analysis_id = analysis.id

    engine = ReportEngine()
    report_id = engine.generate(analysis_id, ReportFormat.HTML)
    with session_scope() as session:
        file_path = Path(session.get(Report, report_id).file_path)
    html = file_path.read_text(encoding="utf-8")
    assert "No findings recorded" in html


def test_generate_report_raises_for_nonexistent_analysis():
    from app.core.report_engine import ReportEngine
    from app.core.exceptions import ReportGenerationError
    from app.database.models import ReportFormat

    engine = ReportEngine()
    with pytest.raises(ReportGenerationError):
        engine.generate(999999, ReportFormat.HTML)


def test_report_filename_sanitizes_project_name(tmp_path):
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Project, Analysis, Platform, ProjectType, AnalysisType, RunStatus, Report, ReportFormat

    with session_scope() as session:
        project = Project(
            name="Weird / App: Name?!", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
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
        analysis_id = analysis.id

    engine = ReportEngine()
    report_id = engine.generate(analysis_id, ReportFormat.JSON)
    with session_scope() as session:
        file_path = session.get(Report, report_id).file_path
    # No path separators or other dangerous characters leaked into the filename
    from pathlib import Path
    assert Path(file_path).name.count("/") == 0
    assert ":" not in Path(file_path).name
