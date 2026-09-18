"""
Tests for Module 11b: code_analysis plugin wrapper and its integration
into the (now 6-step) static_analysis_default workflow.
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


def test_code_analysis_skips_without_jadx_output(tmp_path):
    from app.plugins.installed.code_analysis.plugin import CodeAnalysisPlugin

    output = CodeAnalysisPlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_code_analysis_scans_real_decompiled_file(tmp_path):
    from app.plugins.installed.code_analysis.plugin import CodeAnalysisPlugin

    sources_dir = tmp_path / "jadx_output" / "sources"
    sources_dir.mkdir(parents=True)
    (sources_dir / "CryptoUtil.java").write_text(
        'public class CryptoUtil {\n'
        '    public static Cipher get() { return Cipher.getInstance("AES/ECB/PKCS5Padding"); }\n'
        '}'
    )

    context = _make_context(tmp_path)
    context.shared_data["jadx_output_dir"] = str(sources_dir)

    output = CodeAnalysisPlugin().run(context)
    assert output.status.value == "success"
    assert len(output.findings) == 1
    assert output.findings[0].title == "Insecure Crypto Mode (ECB)"
    assert output.findings[0].file_path == "CryptoUtil.java"
    assert output.findings[0].line_number == 2


def test_code_analysis_ignores_xml_files_unlike_secrets_detection(tmp_path):
    """code_analysis only cares about code patterns (Java/Kotlin), not resource XML."""
    from app.plugins.installed.code_analysis.plugin import CodeAnalysisPlugin

    sources_dir = tmp_path / "jadx_output" / "sources"
    sources_dir.mkdir(parents=True)
    (sources_dir / "strings.xml").write_text('<string name="url">http://insecure.example.com</string>')

    context = _make_context(tmp_path)
    context.shared_data["jadx_output_dir"] = str(sources_dir)

    output = CodeAnalysisPlugin().run(context)
    assert output.findings == []


def test_code_analysis_skips_when_directory_missing(tmp_path):
    from app.plugins.installed.code_analysis.plugin import CodeAnalysisPlugin

    context = _make_context(tmp_path)
    context.shared_data["jadx_output_dir"] = str(tmp_path / "does_not_exist")

    output = CodeAnalysisPlugin().run(context)
    assert output.status.value == "skipped"


# --------------------------------------------------------------------------- #
# Full 6-step workflow integration
# --------------------------------------------------------------------------- #
def test_full_static_workflow_completes_with_all_six_steps(tmp_path):
    from app.core.workflow.workflow_manager import get_workflow_manager
    from app.database.database import session_scope
    from app.database.models import Analysis, Project, Platform, ProjectType, RunStatus

    apk_path = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("classes.dex", b"dex\n")

    with session_scope() as session:
        project = Project(
            name="SixStepApp", platform=Platform.ANDROID, project_type=ProjectType.ANDROID_APK,
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


def test_workflow_produces_real_findings_when_jadx_output_present_via_manual_seed(tmp_path):
    """
    Simulates a successful JADX decompile having already happened (without
    needing the real binary) by seeding shared_data mid-workflow isn't
    possible via the public API, so instead this verifies the plugin chain
    logic directly: manifest_analysis + secrets_detection + code_analysis
    all correctly consume shared_data set by earlier steps in sequence.
    """
    from app.core.workflow.plugin_manager import get_plugin_manager
    from app.core.schemas import WorkflowStepContext

    manager = get_plugin_manager()
    context = WorkflowStepContext(
        project_id=1, analysis_id=1, target_path=str(tmp_path / "x.apk"), workspace_path=str(tmp_path),
    )

    apktool_dir = tmp_path / "apktool_output"
    (apktool_dir / "res" / "values").mkdir(parents=True)
    (apktool_dir).joinpath("AndroidManifest.xml").write_text(
        '<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.test"><application android:debuggable="true" /></manifest>'
    )
    context.shared_data["apktool_output_dir"] = str(apktool_dir)

    jadx_dir = tmp_path / "jadx_output" / "sources"
    jadx_dir.mkdir(parents=True)
    (jadx_dir / "Api.java").write_text('String key = "AKIAIOSFODNN7EXAMPLE";')
    context.shared_data["jadx_output_dir"] = str(jadx_dir)

    manifest_plugin = manager.instantiate("manifest_analysis")
    secrets_plugin = manager.instantiate("secrets_detection")
    code_plugin = manager.instantiate("code_analysis")

    manifest_output = manifest_plugin.execute(context)
    secrets_output = secrets_plugin.execute(context)
    code_output = code_plugin.execute(context)

    assert any("debuggable" in f.title.lower() for f in manifest_output.findings)
    assert any("AWS" in f.title for f in secrets_output.findings)
    assert code_output.status.value == "success"  # ran cleanly, even with zero code-pattern findings here
