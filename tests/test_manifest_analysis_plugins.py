"""
Tests for Module 6b: apktool_decode + manifest_analysis plugins, and
their integration into the static_analysis_default workflow.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

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


def _make_context(tmp_path, target_path="x.apk"):
    from app.core.schemas import WorkflowStepContext
    return WorkflowStepContext(
        project_id=1, analysis_id=1, target_path=str(tmp_path / target_path), workspace_path=str(tmp_path),
    )


# --------------------------------------------------------------------------- #
# apktool_decode plugin
# --------------------------------------------------------------------------- #
def test_apktool_decode_skips_when_not_installed(tmp_path, monkeypatch):
    from app.plugins.installed.apktool_decode.plugin import ApktoolDecodePlugin
    import app.plugins.installed.apktool_decode.plugin as plugin_module
    from app.core.exceptions import ToolNotFoundError

    class _FakeDeps:
        def status(self, name):
            @dataclass
            class S:
                installed: bool
            return S(installed=False)

        def get_binary_path(self, name):
            raise ToolNotFoundError("not installed")

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())

    plugin = ApktoolDecodePlugin()
    output = plugin.run(_make_context(tmp_path))
    assert output.status.value == "skipped"
    assert output.tool == "apktool_decode"


def test_apktool_decode_health_reflects_dependency_status(monkeypatch):
    from app.plugins.installed.apktool_decode.plugin import ApktoolDecodePlugin
    import app.plugins.installed.apktool_decode.plugin as plugin_module
    from app.plugins.base import PluginHealth

    class _FakeDeps:
        def status(self, name):
            @dataclass
            class S:
                installed: bool
            return S(installed=True)

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    assert ApktoolDecodePlugin().health() == PluginHealth.HEALTHY


def test_apktool_decode_success_sets_shared_data(tmp_path, monkeypatch):
    from app.plugins.installed.apktool_decode.plugin import ApktoolDecodePlugin
    import app.plugins.installed.apktool_decode.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    class _FakeDeps:
        def status(self, name):
            @dataclass
            class S:
                installed: bool
            return S(installed=True)

        def get_binary_path(self, name):
            return Path("/fake/apktool.jar")

    class _FakeToolManager:
        def run(self, tool_name, args, timeout=300):
            output_dir = Path(args[args.index("-o") + 1])
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "AndroidManifest.xml").write_text("<manifest/>")
            return ToolExecutionResult(
                tool=tool_name, command=[tool_name, *args], exit_code=0,
                stdout="decoded", stderr="", duration=1.2,
            )

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())

    context = _make_context(tmp_path)
    output = ApktoolDecodePlugin().run(context)

    assert output.status.value == "success"
    assert "apktool_output_dir" in context.shared_data
    assert Path(context.shared_data["apktool_output_dir"]).exists()


def test_apktool_decode_failure_on_nonzero_exit(tmp_path, monkeypatch):
    from app.plugins.installed.apktool_decode.plugin import ApktoolDecodePlugin
    import app.plugins.installed.apktool_decode.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    class _FakeDeps:
        def status(self, name):
            @dataclass
            class S:
                installed: bool
            return S(installed=True)

        def get_binary_path(self, name):
            return Path("/fake/apktool.jar")

    class _FakeToolManager:
        def run(self, tool_name, args, timeout=300):
            return ToolExecutionResult(
                tool=tool_name, command=[tool_name, *args], exit_code=1,
                stdout="", stderr="brut.androlib.AndrolibException: invalid APK", duration=0.5,
            )

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())

    output = ApktoolDecodePlugin().run(_make_context(tmp_path))
    assert output.status.value == "failed"
    assert "AndrolibException" in output.errors[0]


# --------------------------------------------------------------------------- #
# manifest_analysis plugin
# --------------------------------------------------------------------------- #
def test_manifest_analysis_skips_without_apktool_output(tmp_path):
    from app.plugins.installed.manifest_analysis.plugin import ManifestAnalysisPlugin

    output = ManifestAnalysisPlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_manifest_analysis_reads_real_decoded_file(tmp_path):
    from app.plugins.installed.manifest_analysis.plugin import ManifestAnalysisPlugin

    apktool_dir = tmp_path / "apktool_output"
    apktool_dir.mkdir()
    (apktool_dir / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.test"><application android:debuggable="true" /></manifest>'
    )

    context = _make_context(tmp_path)
    context.shared_data["apktool_output_dir"] = str(apktool_dir)

    output = ManifestAnalysisPlugin().run(context)
    assert output.status.value == "success"
    assert any("debuggable" in f.title.lower() for f in output.findings)


def test_manifest_analysis_handles_malformed_manifest_gracefully(tmp_path):
    from app.plugins.installed.manifest_analysis.plugin import ManifestAnalysisPlugin

    apktool_dir = tmp_path / "apktool_output"
    apktool_dir.mkdir()
    (apktool_dir / "AndroidManifest.xml").write_text("<manifest><broken>")

    context = _make_context(tmp_path)
    context.shared_data["apktool_output_dir"] = str(apktool_dir)

    output = ManifestAnalysisPlugin().run(context)
    assert output.status.value == "failed"
    assert output.errors


# --------------------------------------------------------------------------- #
# Full workflow integration -- apktool not installed in this isolated env,
# so both new steps should SKIP gracefully and the workflow still completes.
# --------------------------------------------------------------------------- #
def test_static_workflow_completes_when_apktool_not_installed(tmp_path):
    from app.core.workflow.workflow_manager import get_workflow_manager
    from app.database.database import session_scope
    from app.database.models import Analysis, Project, Platform, ProjectType, RunStatus

    apk_path = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"dex\n")

    with session_scope() as session:
        project = Project(
            name="App", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
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
        # apktool isn't installed in this isolated tools_dir -> both new steps
        # are non-required and SKIPPED -> overall workflow still COMPLETED.
        assert analysis.status == RunStatus.COMPLETED
