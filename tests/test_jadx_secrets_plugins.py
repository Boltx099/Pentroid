"""
Tests for Module 10b: jadx_decompile + secrets_detection plugins, and
their integration into the (now 5-step) static_analysis_default workflow.
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


def _make_context(tmp_path):
    from app.core.schemas import WorkflowStepContext
    return WorkflowStepContext(
        project_id=1, analysis_id=1, target_path=str(tmp_path / "x.apk"), workspace_path=str(tmp_path),
    )


# --------------------------------------------------------------------------- #
# jadx_decompile plugin
# --------------------------------------------------------------------------- #
def test_jadx_decompile_skips_when_not_installed(tmp_path, monkeypatch):
    from app.plugins.installed.jadx_decompile.plugin import JadxDecompilePlugin
    import app.plugins.installed.jadx_decompile.plugin as plugin_module
    from app.core.exceptions import ToolNotFoundError

    class _FakeDeps:
        def get_binary_path(self, name):
            raise ToolNotFoundError("not installed")

        def status(self, name):
            @dataclass
            class S:
                installed: bool
            return S(installed=False)

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    output = JadxDecompilePlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_jadx_decompile_success_sets_shared_data(tmp_path, monkeypatch):
    from app.plugins.installed.jadx_decompile.plugin import JadxDecompilePlugin
    import app.plugins.installed.jadx_decompile.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    class _FakeDeps:
        def get_binary_path(self, name):
            return Path("/fake/jadx")

    class _FakeToolManager:
        def run(self, tool_name, args, timeout=300):
            output_dir = Path(args[args.index("-d") + 1])
            (output_dir / "sources" / "com" / "example").mkdir(parents=True, exist_ok=True)
            (output_dir / "sources" / "com" / "example" / "MainActivity.java").write_text("class MainActivity {}")
            return ToolExecutionResult(tool=tool_name, command=[tool_name, *args], exit_code=0,
                                        stdout="", stderr="", duration=2.0)

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())

    context = _make_context(tmp_path)
    output = JadxDecompilePlugin().run(context)
    assert output.status.value == "success"
    assert "jadx_output_dir" in context.shared_data
    assert Path(context.shared_data["jadx_output_dir"]).name == "sources"


def test_jadx_decompile_failure_when_no_sources_produced(tmp_path, monkeypatch):
    from app.plugins.installed.jadx_decompile.plugin import JadxDecompilePlugin
    import app.plugins.installed.jadx_decompile.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    class _FakeDeps:
        def get_binary_path(self, name):
            return Path("/fake/jadx")

    class _FakeToolManager:
        def run(self, tool_name, args, timeout=300):
            return ToolExecutionResult(tool=tool_name, command=[tool_name, *args], exit_code=1,
                                        stdout="", stderr="corrupt dex file", duration=0.5)

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())

    output = JadxDecompilePlugin().run(_make_context(tmp_path))
    assert output.status.value == "failed"
    assert "corrupt dex file" in output.errors[0]


# --------------------------------------------------------------------------- #
# secrets_detection plugin
# --------------------------------------------------------------------------- #
def test_secrets_detection_skips_without_any_source(tmp_path):
    from app.plugins.installed.secrets_detection.plugin import SecretsDetectionPlugin

    output = SecretsDetectionPlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_secrets_detection_scans_jadx_output_and_finds_real_secret(tmp_path):
    from app.plugins.installed.secrets_detection.plugin import SecretsDetectionPlugin

    sources_dir = tmp_path / "jadx_output" / "sources"
    sources_dir.mkdir(parents=True)
    (sources_dir / "Config.java").write_text(
        'public class Config {\n    public static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n}'
    )

    context = _make_context(tmp_path)
    context.shared_data["jadx_output_dir"] = str(sources_dir)

    output = SecretsDetectionPlugin().run(context)
    assert output.status.value == "success"
    assert len(output.findings) == 1
    assert output.findings[0].file_path == "Config.java"
    assert output.findings[0].line_number == 2
    assert "AKIAIOSFODNN7EXAMPLE" not in output.findings[0].description  # redacted


def test_secrets_detection_scans_apktool_resources_too(tmp_path):
    from app.plugins.installed.secrets_detection.plugin import SecretsDetectionPlugin

    apktool_dir = tmp_path / "apktool_output"
    (apktool_dir / "res" / "values").mkdir(parents=True)
    (apktool_dir / "res" / "values" / "strings.xml").write_text(
        '<resources><string name="api_key">AIzaSyD-1234567890abcdefghijklmnopqrstuv</string></resources>'
    )

    context = _make_context(tmp_path)
    context.shared_data["apktool_output_dir"] = str(apktool_dir)

    output = SecretsDetectionPlugin().run(context)
    assert output.status.value == "success"
    assert any(f.masvs_mapping == "MASVS-STORAGE" for f in output.findings)


def test_secrets_detection_ignores_non_source_files(tmp_path):
    from app.plugins.installed.secrets_detection.plugin import SecretsDetectionPlugin

    sources_dir = tmp_path / "jadx_output" / "sources"
    sources_dir.mkdir(parents=True)
    (sources_dir / "binary.dex").write_bytes(b"AKIAIOSFODNN7EXAMPLE" * 5)  # secret-shaped, but wrong extension

    context = _make_context(tmp_path)
    context.shared_data["jadx_output_dir"] = str(sources_dir)

    output = SecretsDetectionPlugin().run(context)
    assert output.findings == []


def test_secrets_detection_plugin_handles_entropy_only_match_without_crashing(tmp_path):
    """
    Regression test for a real bug: entropy-based generic secret
    detection (secret_patterns.find_high_entropy_strings) produces
    severity="low" matches, but the plugin's _SEVERITY_MAP only had
    "critical"/"high"/"medium" -- any entropy-only hit (no known-format
    secret, just a high-entropy string) raised an uncaught KeyError,
    silently killing this step on real-world APKs where that's common.
    Every prior test used a known-pattern secret (AWS key -> critical),
    which is exactly why this gap wasn't caught until tested end-to-end.
    """
    from app.plugins.installed.secrets_detection.plugin import SecretsDetectionPlugin

    sources_dir = tmp_path / "jadx_output" / "sources"
    sources_dir.mkdir(parents=True)
    # Genuinely random-looking string -- matches ONLY the entropy detector
    # (severity="low"), no known-format pattern (AWS/Google/JWT/etc.).
    (sources_dir / "Config.java").write_text('String x = "aB3xR9kL2mZ8pQ7vN4wT6yU1sD5fG0hJ";')

    context = _make_context(tmp_path)
    context.shared_data["jadx_output_dir"] = str(sources_dir)

    output = SecretsDetectionPlugin().run(context)  # must not raise KeyError
    assert output.status.value == "success"
    assert any(f.severity.value == "low" for f in output.findings)


# --------------------------------------------------------------------------- #
# Full 5-step workflow integration
# --------------------------------------------------------------------------- #
def test_full_static_workflow_still_completes_with_all_five_steps(tmp_path):
    from app.core.workflow.workflow_manager import get_workflow_manager
    from app.database.database import session_scope
    from app.database.models import Analysis, Project, Platform, ProjectType, RunStatus

    apk_path = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"dex\n")

    with session_scope() as session:
        project = Project(
            name="FiveStepApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
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
        # apktool/jadx aren't installed in this isolated env -> all 4 non-required
        # steps SKIP or FAIL gracefully -> workflow still COMPLETED overall.
        assert analysis.status == RunStatus.COMPLETED
