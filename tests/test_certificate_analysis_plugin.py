"""
Tests for Module 12c: certificate_analysis plugin.

Unlike apktool_decode/jadx_decompile (which need mocks since we can't
fabricate a real compiled APK in this sandbox), this plugin can be
tested fully for real: the fixtures under
``tests/fixtures/signed_apks/`` are genuine JAR/ZIP files signed with
real ``jarsigner`` against real ``keytool``-generated certificates
(debug-style, release-style, expired, and deliberately weak
SHA1withRSA/1024-bit). No mocking of DependencyManager/ToolManager
needed -- this exercises the real keytool binary on $PATH end to end.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_FIXTURES = Path(__file__).parent / "fixtures" / "signed_apks"


def _make_context(apk_name: str, tmp_path):
    from app.core.schemas import WorkflowStepContext
    return WorkflowStepContext(
        project_id=1, analysis_id=1,
        target_path=str(_FIXTURES / apk_name), workspace_path=str(tmp_path),
    )


def test_debug_signed_apk_flagged(tmp_path):
    from app.plugins.installed.certificate_analysis.plugin import CertificateAnalysisPlugin

    output = CertificateAnalysisPlugin().run(_make_context("debug_signed.apk", tmp_path))
    assert output.status.value == "success"
    assert any("debug certificate" in f.title.lower() for f in output.findings)
    assert not any(f.severity.value == "high" and "weak" in f.title.lower() for f in output.findings)


def test_release_signed_apk_not_flagged_as_debug(tmp_path):
    from app.plugins.installed.certificate_analysis.plugin import CertificateAnalysisPlugin

    output = CertificateAnalysisPlugin().run(_make_context("release_signed.apk", tmp_path))
    assert output.status.value == "success"
    assert not any("debug certificate" in f.title.lower() for f in output.findings)
    assert output.findings == []  # modern algorithm, valid, non-debug -- genuinely clean


def test_weak_signed_apk_flags_both_weak_algorithm_and_key(tmp_path):
    from app.plugins.installed.certificate_analysis.plugin import CertificateAnalysisPlugin

    output = CertificateAnalysisPlugin().run(_make_context("weak_signed.apk", tmp_path))
    assert output.status.value == "success"
    titles = [f.title for f in output.findings]
    assert any("SHA1withRSA" in t for t in titles)
    assert any("1024-bit" in t for t in titles)
    assert not any("debug certificate" in t.lower() for t in titles)


def test_expired_signed_apk_flagged(tmp_path):
    from app.plugins.installed.certificate_analysis.plugin import CertificateAnalysisPlugin

    output = CertificateAnalysisPlugin().run(_make_context("expired_signed.apk", tmp_path))
    assert output.status.value == "success"
    assert any("expired" in f.title.lower() for f in output.findings)


def test_health_reflects_real_keytool_availability(tmp_path):
    from app.plugins.installed.certificate_analysis.plugin import CertificateAnalysisPlugin
    from app.plugins.base import PluginHealth

    # keytool is genuinely on $PATH in this sandbox (verified earlier this session)
    assert CertificateAnalysisPlugin().health() == PluginHealth.HEALTHY


def test_unsigned_file_returns_skipped_not_crash(tmp_path):
    import zipfile
    from app.plugins.installed.certificate_analysis.plugin import CertificateAnalysisPlugin
    from app.core.schemas import WorkflowStepContext

    unsigned = tmp_path / "unsigned.apk"
    with zipfile.ZipFile(unsigned, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")

    context = WorkflowStepContext(
        project_id=1, analysis_id=1, target_path=str(unsigned), workspace_path=str(tmp_path),
    )
    output = CertificateAnalysisPlugin().run(context)
    assert output.status.value == "skipped"
