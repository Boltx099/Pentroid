"""
Tests for Module 13c: network_security_config + tracker_detection
plugin wrappers, and their integration into the (now 9-step)
static_analysis_default workflow.
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


def _make_context(tmp_path):
    from app.core.schemas import WorkflowStepContext
    return WorkflowStepContext(
        project_id=1, analysis_id=1, target_path=str(tmp_path / "x.apk"), workspace_path=str(tmp_path),
    )


# --------------------------------------------------------------------------- #
# network_security_config plugin
# --------------------------------------------------------------------------- #
def test_nsc_plugin_skips_without_apktool_output(tmp_path):
    from app.plugins.installed.network_security_config.plugin import NetworkSecurityConfigPlugin

    output = NetworkSecurityConfigPlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_nsc_plugin_reports_info_when_no_custom_config(tmp_path):
    from app.plugins.installed.network_security_config.plugin import NetworkSecurityConfigPlugin

    apktool_dir = tmp_path / "apktool_output"
    apktool_dir.mkdir()
    context = _make_context(tmp_path)
    context.shared_data["apktool_output_dir"] = str(apktool_dir)

    output = NetworkSecurityConfigPlugin().run(context)
    assert output.status.value == "success"
    assert len(output.findings) == 1
    assert output.findings[0].severity.value == "info"


def test_nsc_plugin_finds_config_at_default_path(tmp_path):
    from app.plugins.installed.network_security_config.plugin import NetworkSecurityConfigPlugin

    apktool_dir = tmp_path / "apktool_output"
    (apktool_dir / "res" / "xml").mkdir(parents=True)
    (apktool_dir / "res" / "xml" / "network_security_config.xml").write_text(
        '<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>'
    )
    context = _make_context(tmp_path)
    context.shared_data["apktool_output_dir"] = str(apktool_dir)

    output = NetworkSecurityConfigPlugin().run(context)
    assert output.status.value == "success"
    assert any("Cleartext" in f.title for f in output.findings)


def test_nsc_plugin_resolves_custom_path_from_manifest_reference(tmp_path):
    from app.plugins.installed.network_security_config.plugin import NetworkSecurityConfigPlugin

    apktool_dir = tmp_path / "apktool_output"
    (apktool_dir / "res" / "xml").mkdir(parents=True)
    (apktool_dir / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application android:networkSecurityConfig="@xml/my_custom_config" /></manifest>'
    )
    (apktool_dir / "res" / "xml" / "my_custom_config.xml").write_text(
        '<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>'
    )
    context = _make_context(tmp_path)
    context.shared_data["apktool_output_dir"] = str(apktool_dir)

    output = NetworkSecurityConfigPlugin().run(context)
    assert output.status.value == "success"
    assert any("Cleartext" in f.title for f in output.findings)


def test_nsc_plugin_handles_malformed_config_gracefully(tmp_path):
    from app.plugins.installed.network_security_config.plugin import NetworkSecurityConfigPlugin

    apktool_dir = tmp_path / "apktool_output"
    (apktool_dir / "res" / "xml").mkdir(parents=True)
    (apktool_dir / "res" / "xml" / "network_security_config.xml").write_text("<broken><xml")
    context = _make_context(tmp_path)
    context.shared_data["apktool_output_dir"] = str(apktool_dir)

    output = NetworkSecurityConfigPlugin().run(context)
    assert output.status.value == "failed"


# --------------------------------------------------------------------------- #
# tracker_detection plugin
# --------------------------------------------------------------------------- #
def test_tracker_plugin_skips_without_jadx_output(tmp_path):
    from app.plugins.installed.tracker_detection.plugin import TrackerDetectionPlugin

    output = TrackerDetectionPlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_tracker_plugin_detects_real_sdk_in_decompiled_structure(tmp_path):
    from app.plugins.installed.tracker_detection.plugin import TrackerDetectionPlugin

    sources_dir = tmp_path / "jadx_output" / "sources"
    (sources_dir / "com" / "google" / "firebase" / "analytics").mkdir(parents=True)
    (sources_dir / "com" / "myapp" / "ui").mkdir(parents=True)

    context = _make_context(tmp_path)
    context.shared_data["jadx_output_dir"] = str(sources_dir)

    output = TrackerDetectionPlugin().run(context)
    assert output.status.value == "success"
    assert len(output.findings) == 1
    assert "Firebase Analytics" in output.findings[0].title
    assert output.findings[0].severity.value == "info"  # informational, not a vulnerability


def test_tracker_plugin_no_findings_for_clean_app(tmp_path):
    from app.plugins.installed.tracker_detection.plugin import TrackerDetectionPlugin

    sources_dir = tmp_path / "jadx_output" / "sources"
    (sources_dir / "com" / "myapp" / "ui").mkdir(parents=True)
    context = _make_context(tmp_path)
    context.shared_data["jadx_output_dir"] = str(sources_dir)

    output = TrackerDetectionPlugin().run(context)
    assert output.status.value == "success"
    assert output.findings == []


# --------------------------------------------------------------------------- #
# Full 9-step workflow integration
# --------------------------------------------------------------------------- #
def test_full_static_workflow_completes_with_all_nine_steps(tmp_path):
    from app.core.workflow.workflow_manager import get_workflow_manager, WORKFLOW_REGISTRY
    from app.database.database import session_scope
    from app.database.models import Analysis, Project, Platform, ProjectType, RunStatus

    assert len(WORKFLOW_REGISTRY["static_analysis_default"].steps) == 9

    apk_path = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"dex\n")

    with session_scope() as session:
        project = Project(
            name="NineStepApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
            target_path=str(apk_path), workspace_path=str(tmp_path / "ws"),
        )
        session.add(project)
        session.flush()
        project_id = project.id

    wf = get_workflow_manager()
    analysis_id = wf.run_workflow_sync(
        "static_analysis_default", project_id, str(apk_path), str(tmp_path / "ws")
    )

    with session_scope() as session:
        analysis = session.get(Analysis, analysis_id)
        assert analysis.status == RunStatus.COMPLETED
