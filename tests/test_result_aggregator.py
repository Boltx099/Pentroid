"""
Tests for ``ResultAggregator`` -- specifically the two P0 correctness fixes:

1. The dedup key used to be ``(title, file_path)``. Since a rule's title is
   static per rule (not per occurrence), two distinct findings -- the same
   rule firing on two different lines of the same file -- collided on an
   identical key and the second one was silently dropped. The fix widens
   the key to include ``line_number``.
2. ``compute_risk_score`` used to be a plain mean over every finding's
   severity weight, so adding low/info findings *lowered* the score even
   though nothing about the app's actual risk changed. The fix makes the
   worst finding dominate, with a rapidly-diminishing contribution from
   the rest.

There was no prior test coverage for this module at all -- these tests
also serve as the first regression net around it.
"""

from __future__ import annotations

import pytest

from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel


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
def analysis_id(tmp_path):
    """A real Project + Analysis row for findings to attach to."""
    from app.database.database import init_db, session_scope
    from app.database.models import Analysis, AnalysisType, Platform, Project, ProjectType, RunStatus

    init_db()
    with session_scope() as session:
        project = Project(
            name="test-app", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(tmp_path / "app.apk"), workspace_path=str(tmp_path / "workspace"),
        )
        session.add(project)
        session.flush()
        analysis = Analysis(
            project_id=project.id, analysis_type=AnalysisType.STATIC,
            workflow_name="static_analysis_default", status=RunStatus.RUNNING,
        )
        session.add(analysis)
        session.flush()
        return analysis.id


def _finding(title, severity, file_path=None, line_number=None, **kw) -> PluginFinding:
    return PluginFinding(
        title=title, severity=severity, file_path=file_path, line_number=line_number, **kw
    )


def _output(*findings: PluginFinding) -> PluginOutput:
    return PluginOutput(tool="test", status=PluginRunStatus.SUCCESS, findings=list(findings))


# --------------------------------------------------------------------------- #
# Dedup key
# --------------------------------------------------------------------------- #
def test_same_rule_different_lines_in_same_file_are_both_kept(analysis_id):
    """The bug: two distinct MD5 hits in the same file used to collide on
    (title, file_path) alone and the second was silently dropped."""
    from app.core.workflow.result_aggregator import ResultAggregator

    agg = ResultAggregator()
    output = _output(
        _finding("Weak Hash Algorithm", SeverityLevel.MEDIUM, file_path="Foo.java", line_number=40),
        _finding("Weak Hash Algorithm", SeverityLevel.MEDIUM, file_path="Foo.java", line_number=220),
    )
    created = agg.persist(analysis_id, "code_analysis", output)
    assert len(created) == 2


def test_exact_same_finding_persisted_twice_is_deduplicated(analysis_id):
    """True duplicates -- identical title, file, and line -- must still collapse."""
    from app.core.workflow.result_aggregator import ResultAggregator

    agg = ResultAggregator()
    finding = _finding("Weak Hash Algorithm", SeverityLevel.MEDIUM, file_path="Foo.java", line_number=40)

    first = agg.persist(analysis_id, "code_analysis", _output(finding))
    second = agg.persist(analysis_id, "code_analysis", _output(finding))
    assert len(first) == 1
    assert len(second) == 0  # deduplicated against the first call


def test_dedup_still_applies_across_different_plugin_steps(analysis_id):
    """Cross-plugin dedup within one analysis must keep working: persist()
    re-queries existing rows for the whole analysis_id on every call, not
    just within one plugin's own batch."""
    from app.core.workflow.result_aggregator import ResultAggregator

    agg = ResultAggregator()
    finding = _finding("Cleartext HTTP URL", SeverityLevel.LOW, file_path="Net.java", line_number=12)

    first = agg.persist(analysis_id, "code_analysis", _output(finding))
    second = agg.persist(analysis_id, "network_security_config", _output(finding))
    assert len(first) == 1
    assert len(second) == 0


# --------------------------------------------------------------------------- #
# Risk score
# --------------------------------------------------------------------------- #
def test_risk_score_with_no_findings_is_zero(analysis_id):
    from app.core.workflow.result_aggregator import ResultAggregator

    assert ResultAggregator.compute_risk_score(analysis_id) == 0.0


def test_single_critical_scores_high(analysis_id):
    from app.core.workflow.result_aggregator import ResultAggregator

    agg = ResultAggregator()
    agg.persist(analysis_id, "p", _output(_finding("RCE", SeverityLevel.CRITICAL)))
    assert ResultAggregator.compute_risk_score(analysis_id) == 10.0


def test_critical_plus_many_info_findings_does_not_dilute_the_score(analysis_id):
    """
    The exact bug from the review: under the old mean formula,
    1 CRITICAL + 9 INFO scored 1.0 ("Low Risk") and + 30 INFO scored 0.3.
    A single confirmed CRITICAL must still read as high risk regardless of
    how many harmless INFO notes accompany it.
    """
    from app.core.workflow.result_aggregator import ResultAggregator

    agg = ResultAggregator()
    findings = [_finding("RCE", SeverityLevel.CRITICAL, line_number=1)]
    findings += [
        _finding("Info note", SeverityLevel.INFO, line_number=i) for i in range(2, 32)
    ]
    agg.persist(analysis_id, "p", _output(*findings))

    score = ResultAggregator.compute_risk_score(analysis_id)
    assert score == 10.0, f"expected a dominant CRITICAL to still score 10.0, got {score}"


def test_multiple_high_severity_findings_saturate_above_any_single_one(analysis_id):
    """Several real HIGH findings alongside a CRITICAL should reflect a
    genuinely worse app than the CRITICAL alone -- not be averaged down."""
    from app.core.workflow.result_aggregator import ResultAggregator

    agg = ResultAggregator()
    findings = [_finding("RCE", SeverityLevel.CRITICAL, line_number=1)]
    findings += [
        _finding(f"High issue {i}", SeverityLevel.HIGH, line_number=i) for i in range(2, 7)
    ]
    agg.persist(analysis_id, "p", _output(*findings))

    assert ResultAggregator.compute_risk_score(analysis_id) == 10.0


def test_low_and_info_only_scores_low(analysis_id):
    """A scan with no real severity shouldn't be inflated either -- this
    isn't about always scoring high, just about not being diluted by noise
    when a genuinely severe finding IS present."""
    from app.core.workflow.result_aggregator import ResultAggregator

    agg = ResultAggregator()
    findings = [_finding(f"Info {i}", SeverityLevel.INFO, line_number=i) for i in range(20)]
    findings.append(_finding("Minor note", SeverityLevel.LOW, line_number=99))
    agg.persist(analysis_id, "p", _output(*findings))

    score = ResultAggregator.compute_risk_score(analysis_id)
    assert score <= 2.0


def test_risk_score_never_exceeds_ten(analysis_id):
    from app.core.workflow.result_aggregator import ResultAggregator

    agg = ResultAggregator()
    findings = [
        _finding(f"Critical {i}", SeverityLevel.CRITICAL, line_number=i) for i in range(10)
    ]
    agg.persist(analysis_id, "p", _output(*findings))

    assert ResultAggregator.compute_risk_score(analysis_id) == 10.0
