"""
Tests for the professional-reporting upgrade: knowledge-base enrichment,
schema migration, and SARIF 2.1.0 export.
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


def _seed_analysis():
    from app.database.database import session_scope
    from app.database.models import Project, Analysis, Platform, ProjectType, AnalysisType, RunStatus
    with session_scope() as s:
        p = Project(name="App", platform=Platform.ANDROID,
                    project_type=ProjectType.ANDROID_APK, workspace_path="/tmp")
        s.add(p); s.flush()
        a = Analysis(project_id=p.id, analysis_type=AnalysisType.STATIC,
                     workflow_name="w", status=RunStatus.COMPLETED, risk_score=8.0)
        s.add(a); s.flush()
        return a.id


# --------------------------------------------------------------------------- #
# Knowledge base
# --------------------------------------------------------------------------- #
def test_every_kb_entry_has_the_fields_a_report_needs():
    from app.core.knowledge.finding_kb import KNOWLEDGE_BASE
    for key, kb in KNOWLEDGE_BASE.items():
        assert kb.impact and len(kb.impact) > 80, f"{key}: impact too thin to be useful"
        assert kb.reproduction_steps and "1." in kb.reproduction_steps, f"{key}: no numbered repro steps"
        assert kb.recommendation and len(kb.recommendation) > 60, f"{key}: recommendation too thin"


def test_kb_cvss_scores_are_in_valid_range():
    from app.core.knowledge.finding_kb import KNOWLEDGE_BASE
    for key, kb in KNOWLEDGE_BASE.items():
        if kb.cvss_score is not None:
            assert 0.0 <= kb.cvss_score <= 10.0, f"{key}: CVSS out of range"
            assert kb.cvss_vector and kb.cvss_vector.startswith("CVSS:3.1/"), f"{key}: score without a valid vector"


def test_unknown_finding_key_returns_none_not_crash():
    from app.core.knowledge.finding_kb import get_knowledge
    assert get_knowledge("does.not.exist") is None
    assert get_knowledge(None) is None


def test_aggregator_enriches_finding_from_knowledge_base():
    from app.core.schemas import PluginOutput, PluginFinding, PluginRunStatus, SeverityLevel, ConfidenceLevel
    from app.core.workflow.result_aggregator import ResultAggregator
    from app.database.database import session_scope
    from app.database.models import Finding

    aid = _seed_analysis()
    out = PluginOutput(tool="t", status=PluginRunStatus.SUCCESS, findings=[
        PluginFinding(title="Application is debuggable", severity=SeverityLevel.HIGH,
                      finding_key="android.debuggable", confidence=ConfidenceLevel.CONFIRMED,
                      file_path="AndroidManifest.xml"),
    ])
    ResultAggregator().persist(aid, "t", out)

    with session_scope() as s:
        f = s.query(Finding).one()
        assert f.cwe_id == "CWE-489"
        assert f.cvss_score == 6.8
        assert f.impact and "debugger" in f.impact.lower()
        assert f.reproduction_steps and "apktool" in f.reproduction_steps
        assert f.references
        assert f.affected_components == "AndroidManifest.xml"


def test_plugin_supplied_values_override_knowledge_base():
    """The KB is a quality floor, not an override -- a plugin that knows
    something specific about THIS instance must win."""
    from app.core.schemas import PluginOutput, PluginFinding, PluginRunStatus, SeverityLevel
    from app.core.workflow.result_aggregator import ResultAggregator
    from app.database.database import session_scope
    from app.database.models import Finding

    aid = _seed_analysis()
    out = PluginOutput(tool="t", status=PluginRunStatus.SUCCESS, findings=[
        PluginFinding(title="Debuggable", severity=SeverityLevel.HIGH,
                      finding_key="android.debuggable",
                      impact="Instance-specific impact.",
                      recommendation="Instance-specific fix.",
                      cwe_id="CWE-999"),
    ])
    ResultAggregator().persist(aid, "t", out)

    with session_scope() as s:
        f = s.query(Finding).one()
        assert f.impact == "Instance-specific impact."
        assert f.recommendation == "Instance-specific fix."
        assert f.cwe_id == "CWE-999"


def test_finding_without_key_still_persists_cleanly():
    from app.core.schemas import PluginOutput, PluginFinding, PluginRunStatus, SeverityLevel
    from app.core.workflow.result_aggregator import ResultAggregator
    from app.database.database import session_scope
    from app.database.models import Finding

    aid = _seed_analysis()
    out = PluginOutput(tool="t", status=PluginRunStatus.SUCCESS, findings=[
        PluginFinding(title="Untagged finding", severity=SeverityLevel.LOW),
    ])
    ResultAggregator().persist(aid, "t", out)
    with session_scope() as s:
        f = s.query(Finding).one()
        assert f.impact is None and f.cwe_id is None  # no KB match, no invented data


# --------------------------------------------------------------------------- #
# SARIF export
# --------------------------------------------------------------------------- #
def _sample_report_data():
    return {
        "project": {"name": "App", "platform": "android"},
        "analysis": {"status": "completed", "workflow_name": "static",
                     "risk_score": 7.5, "analysis_type": "static"},
        "findings": [
            {"title": "Debuggable", "severity": "high", "finding_key": "android.debuggable",
             "cwe_id": "CWE-489", "cvss_score": 6.8, "file_path": "AndroidManifest.xml",
             "line_number": 8, "confidence": "confirmed", "impact": "i",
             "reproduction_steps": "r", "recommendation": "rec", "references": ["https://a"]},
            {"title": "Debuggable", "severity": "high", "finding_key": "android.debuggable",
             "file_path": "other.xml", "confidence": "confirmed"},
            {"title": "No location", "severity": "info", "confidence": "low"},
        ],
    }


def test_sarif_has_correct_version_and_schema():
    from app.core.sarif_export import build_sarif
    s = build_sarif(_sample_report_data())
    assert s["version"] == "2.1.0"
    assert "sarif-2.1.0" in s["$schema"]


def test_sarif_deduplicates_rules_across_results():
    """Two findings of the same type share one rule -- this is what lets
    consuming tools group, suppress, and trend them."""
    from app.core.sarif_export import build_sarif
    s = build_sarif(_sample_report_data())
    rules = s["runs"][0]["tool"]["driver"]["rules"]
    results = s["runs"][0]["results"]
    assert len(results) == 3
    rule_ids = [r["id"] for r in rules]
    assert rule_ids.count("android.debuggable") == 1
    assert len(rules) == 2  # android.debuggable + the untagged one


def test_sarif_severity_maps_to_valid_levels():
    from app.core.sarif_export import build_sarif
    s = build_sarif(_sample_report_data())
    for result in s["runs"][0]["results"]:
        assert result["level"] in {"error", "warning", "note", "none"}


def test_sarif_preserves_precise_severity_in_properties():
    """SARIF's 4 levels are lossy vs our 5 severities -- the exact value
    must survive in properties so nothing is lost for richer consumers."""
    from app.core.sarif_export import build_sarif
    s = build_sarif(_sample_report_data())
    props = s["runs"][0]["results"][0]["properties"]
    assert props["severity"] == "high"
    assert props["confidence"] == "confirmed"
    assert props["cvssScore"] == 6.8


def test_sarif_security_severity_uses_cvss_when_available():
    from app.core.sarif_export import build_sarif
    s = build_sarif(_sample_report_data())
    rule = next(r for r in s["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "android.debuggable")
    assert rule["properties"]["security-severity"] == "6.8"


def test_sarif_emits_github_style_cwe_tag():
    from app.core.sarif_export import build_sarif
    s = build_sarif(_sample_report_data())
    rule = next(r for r in s["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "android.debuggable")
    assert "external/cwe/cwe-489" in rule["properties"]["tags"]


def test_sarif_omits_region_when_line_number_unknown():
    """A default startLine of 1 would point reviewers at the wrong code."""
    from app.core.sarif_export import build_sarif
    s = build_sarif(_sample_report_data())
    second = s["runs"][0]["results"][1]
    assert "region" not in second["locations"][0]["physicalLocation"]


def test_sarif_relativizes_absolute_paths_when_uribaseid_present():
    """Spec requires uri to be relative whenever uriBaseId is set."""
    from app.core.sarif_export import build_sarif
    data = _sample_report_data()
    data["findings"][0]["file_path"] = "/absolute/path/File.java"
    s = build_sarif(data)
    loc = s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc["uriBaseId"] == "%SRCROOT%"
    assert not loc["uri"].startswith("/")


def test_sarif_finding_without_file_still_has_a_location():
    from app.core.sarif_export import build_sarif
    s = build_sarif(_sample_report_data())
    assert s["runs"][0]["results"][2]["locations"]


def test_report_engine_generates_sarif_file():
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Finding, Severity, Report, ReportFormat, Confidence
    from pathlib import Path

    aid = _seed_analysis()
    with session_scope() as s:
        s.add(Finding(analysis_id=aid, title="Debuggable", severity=Severity.HIGH,
                      cwe_id="CWE-489", confidence=Confidence.CONFIRMED,
                      file_path="AndroidManifest.xml", line_number=8))

    rid = ReportEngine().generate(aid, ReportFormat.SARIF)
    with session_scope() as s:
        path = Path(s.get(Report, rid).file_path)
    assert path.suffix == ".sarif"
    doc = json.loads(path.read_text())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Pentroid"


def test_html_report_contains_professional_sections():
    from app.core.report_engine import ReportEngine
    from app.database.database import session_scope
    from app.database.models import Finding, Severity, Report, ReportFormat, Confidence
    from pathlib import Path

    aid = _seed_analysis()
    with session_scope() as s:
        s.add(Finding(analysis_id=aid, title="Debuggable", severity=Severity.HIGH,
                      confidence=Confidence.CONFIRMED, cwe_id="CWE-489", cvss_score=6.8,
                      cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                      impact="Real impact text.", reproduction_steps="1. do this",
                      recommendation="Fix it.", affected_components="AndroidManifest.xml",
                      references=["https://mas.owasp.org/"]))

    rid = ReportEngine().generate(aid, ReportFormat.HTML)
    with session_scope() as s:
        html = Path(s.get(Report, rid).file_path).read_text()

    for section in ("Impact", "Affected Components", "Steps to Reproduce",
                    "CVSS v3.1 Vector", "Remediation", "References", "Executive Summary"):
        assert section in html, f"HTML report missing '{section}' section"
    assert "CWE-489" in html


# --------------------------------------------------------------------------- #
# Schema migration
# --------------------------------------------------------------------------- #
def test_migration_adds_columns_to_preexisting_database(tmp_path, monkeypatch):
    """
    create_all() creates missing TABLES but never adds missing COLUMNS, so a
    user upgrading with an existing pentroid.db would hit "no such column".
    Verifies the additive migration runs and preserves existing rows.
    """
    import sqlite3
    import app.core.config as config_module
    import app.database.database as db_module

    root = tmp_path / "upgrade"
    (root / "database").mkdir(parents=True)
    db_file = root / "database" / "pentroid.db"

    # Build an OLD-schema findings table, as a pre-upgrade install would have.
    conn = sqlite3.connect(db_file)
    conn.execute("""CREATE TABLE findings (
        id INTEGER PRIMARY KEY, uuid VARCHAR(36), analysis_id INTEGER, plugin_id INTEGER,
        title VARCHAR(500), description TEXT, severity VARCHAR(8), category VARCHAR(255),
        owasp_mapping VARCHAR(255), masvs_mapping VARCHAR(255), mitre_mapping VARCHAR(255),
        evidence TEXT, file_path VARCHAR(1024), line_number INTEGER, recommendation TEXT,
        status VARCHAR(14), created_at DATETIME)""")
    # SQLAlchemy's Enum persists the member NAME, not its value.
    conn.execute("INSERT INTO findings (id, title, severity, status) VALUES (1, 'Legacy', 'HIGH', 'OPEN')")
    conn.commit()
    conn.close()

    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(root))
    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None

    from app.database.database import init_db, session_scope
    from app.database.models import Finding, Confidence

    init_db()  # must not raise

    with session_scope() as s:
        row = s.query(Finding).one()
        assert row.title == "Legacy"          # pre-existing data survived
        assert row.confidence == Confidence.MEDIUM  # new column default readable
        assert row.impact is None

    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None


def test_migration_is_idempotent(tmp_path, monkeypatch):
    import app.core.config as config_module
    import app.database.database as db_module

    root = tmp_path / "idem"
    root.mkdir()
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(root))
    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None

    from app.database.database import init_db
    init_db()
    init_db()  # second run must be a no-op, not a duplicate-column error
    init_db()

    config_module.get_settings.cache_clear()
    db_module._engine = None
    db_module._SessionFactory = None
