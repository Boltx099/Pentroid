"""
Integration tests for Module 2: Workflow Orchestrator + Plugin System.

Builds a real, minimal APK (valid zip w/ AndroidManifest.xml +
classes.dex) and a deliberately broken one, then runs the actual
``static_analysis_default`` workflow end-to-end through the real
Plugin Manager / Workflow Manager / Result Aggregator / Event Bus --
no mocks on the core path.
"""

from __future__ import annotations

import zipfile

import pytest


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

    import app.core.workflow.job_monitor as jm_module
    jm_module._monitor = None

    import app.core.workflow.event_bus as eb_module
    eb_module._bus = None

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


def _make_valid_apk(path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"\x64\x65\x78\n")
        zf.writestr("res/values/strings.xml", "<resources/>")


def _make_broken_apk(path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("not_a_manifest.txt", "nope")


def _make_project(tmp_path, name="ChatApp"):
    from app.database.database import session_scope
    from app.database.models import Project, Platform, ProjectType

    with session_scope() as session:
        project = Project(
            name=name,
            platform=Platform.ANDROID,
            project_type=ProjectType.ANDROID_APK,
            workspace_path=str(tmp_path / "workspace" / name),
        )
        session.add(project)
        session.flush()
        return project.id


# --------------------------------------------------------------------------- #
# Plugin Manager
# --------------------------------------------------------------------------- #
def test_plugin_discovery_finds_apk_validator():
    from app.core.workflow.plugin_manager import get_plugin_manager

    manager = get_plugin_manager()
    installed = manager.list_installed()
    plugin_ids = {p["plugin_id"] for p in installed}
    assert "apk_validator" in plugin_ids


def test_plugin_instantiate_and_run_directly(tmp_path):
    from app.core.workflow.plugin_manager import get_plugin_manager
    from app.core.schemas import WorkflowStepContext, PluginRunStatus

    apk_path = tmp_path / "test.apk"
    _make_valid_apk(apk_path)

    manager = get_plugin_manager()
    plugin = manager.instantiate("apk_validator")
    context = WorkflowStepContext(
        project_id=1, analysis_id=1,
        target_path=str(apk_path), workspace_path=str(tmp_path),
    )
    output = plugin.execute(context)
    assert output.status == PluginRunStatus.SUCCESS
    assert output.duration >= 0
    assert output.tool == "apk_validator"


def test_disabling_plugin_prevents_instantiation():
    from app.core.workflow.plugin_manager import get_plugin_manager
    from app.core.exceptions import PluginNotFoundError

    manager = get_plugin_manager()
    manager.set_enabled("apk_validator", False)
    with pytest.raises(PluginNotFoundError):
        manager.instantiate("apk_validator")


# --------------------------------------------------------------------------- #
# Event Bus
# --------------------------------------------------------------------------- #
def test_event_bus_publish_subscribe():
    from app.core.workflow.event_bus import EventBus

    bus = EventBus()
    received = []
    bus.subscribe("test.event", lambda payload: received.append(payload))
    bus.publish("test.event", {"hello": "world"})
    assert received == [{"hello": "world"}]


def test_event_bus_survives_bad_subscriber():
    from app.core.workflow.event_bus import EventBus

    bus = EventBus()
    def _bad_callback(_payload):
        raise RuntimeError("boom")
    good_calls = []
    bus.subscribe("test.event", _bad_callback)
    bus.subscribe("test.event", lambda p: good_calls.append(p))
    bus.publish("test.event", {})  # must not raise
    assert good_calls == [{}]


# --------------------------------------------------------------------------- #
# Full workflow, end to end
# --------------------------------------------------------------------------- #
def test_static_analysis_workflow_succeeds_on_valid_apk(tmp_path):
    from app.core.workflow.workflow_manager import get_workflow_manager
    from app.core.workflow.event_bus import get_event_bus
    from app.database.database import session_scope
    from app.database.models import Analysis, RunStatus

    apk_path = tmp_path / "chatapp.apk"
    _make_valid_apk(apk_path)
    project_id = _make_project(tmp_path)

    events = []
    get_event_bus().subscribe("workflow.completed", lambda p: events.append(p))

    wf = get_workflow_manager()
    analysis_id = wf.run_workflow_sync(
        "static_analysis_default", project_id, str(apk_path), str(tmp_path / "workspace")
    )

    with session_scope() as session:
        analysis = session.get(Analysis, analysis_id)
        assert analysis.status == RunStatus.COMPLETED
        assert analysis.risk_score == 0.0  # valid APK -> no findings -> 0 risk

    assert len(events) == 1
    assert events[0]["status"] == "completed"


def test_static_analysis_workflow_fails_on_broken_apk_and_creates_finding(tmp_path):
    from app.core.workflow.workflow_manager import get_workflow_manager
    from app.database.database import session_scope
    from app.database.models import Analysis, Finding, RunStatus

    apk_path = tmp_path / "broken.apk"
    _make_broken_apk(apk_path)
    project_id = _make_project(tmp_path, name="Broken")

    wf = get_workflow_manager()
    analysis_id = wf.run_workflow_sync(
        "static_analysis_default", project_id, str(apk_path), str(tmp_path / "workspace")
    )

    with session_scope() as session:
        analysis = session.get(Analysis, analysis_id)
        assert analysis.status == RunStatus.FAILED
        assert analysis.error_message  # populated by error handler
        findings = session.query(Finding).filter_by(analysis_id=analysis_id).all()
        assert len(findings) == 1
        assert "missing required" in findings[0].title.lower() or "invalid" in findings[0].title.lower()


def test_skipped_steps_are_recorded_with_reason_not_silently_lost(tmp_path):
    """
    Regression test for a real bug: a completed analysis with 0 findings
    (e.g. APKTool/JADX not installed, so most static-analysis steps
    SKIP) previously left zero trace of *why* -- error_message only
    tracked FAILED steps, not SKIPPED ones. A user would see
    "completed" + 0 findings with no explanation anywhere.
    """
    from app.core.workflow.workflow_manager import get_workflow_manager
    from app.database.database import session_scope
    from app.database.models import Analysis, RunStatus

    apk_path = tmp_path / "clean.apk"
    _make_valid_apk(apk_path)
    project_id = _make_project(tmp_path, name="CleanApp")

    wf = get_workflow_manager()
    # apktool/jadx are NOT installed in this isolated test tools_dir, so
    # APKTool Decode / JADX Decompile / everything depending on them SKIP.
    analysis_id = wf.run_workflow_sync(
        "static_analysis_default", project_id, str(apk_path), str(tmp_path / "workspace")
    )

    with session_scope() as session:
        analysis = session.get(Analysis, analysis_id)
        assert analysis.status == RunStatus.COMPLETED
        assert analysis.error_message  # NOT None/empty -- skip reasons are now recorded
        assert "SKIPPED" in analysis.error_message
        assert "APKTool Decode" in analysis.error_message


def test_job_monitor_tracks_progress_to_completion(tmp_path):
    from app.core.workflow.workflow_manager import get_workflow_manager
    from app.core.workflow.job_monitor import get_job_monitor

    apk_path = tmp_path / "app.apk"
    _make_valid_apk(apk_path)
    project_id = _make_project(tmp_path, name="ProgressApp")

    wf = get_workflow_manager()
    job_id = wf.run_workflow_async(
        "static_analysis_default", project_id, str(apk_path), str(tmp_path / "workspace")
    )

    from app.core.workflow.task_scheduler import get_task_scheduler
    get_task_scheduler().result(job_id, timeout=10)

    progress = get_job_monitor().get(job_id)
    assert progress.status == "completed"
    assert progress.percent == 100.0


def test_unknown_workflow_raises():
    from app.core.workflow.workflow_manager import get_workflow_manager
    from app.core.exceptions import WorkflowNotFoundError

    wf = get_workflow_manager()
    with pytest.raises(WorkflowNotFoundError):
        wf.run_workflow_sync("does_not_exist", 1, "/tmp/x.apk", "/tmp/ws")
