"""
Tests for Module 16c: virustotal_lookup and quark_engine plugin wrappers.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

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


def _make_context(tmp_path):
    from app.core.schemas import WorkflowStepContext
    return WorkflowStepContext(
        project_id=1, analysis_id=1, target_path=str(tmp_path / "x.apk"), workspace_path=str(tmp_path),
    )


# --------------------------------------------------------------------------- #
# virustotal_lookup plugin
# --------------------------------------------------------------------------- #
def test_vt_plugin_skips_without_file_hashes(tmp_path):
    from app.plugins.installed.virustotal_lookup.plugin import VirusTotalLookupPlugin

    output = VirusTotalLookupPlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_vt_plugin_skips_without_api_key(tmp_path):
    from app.plugins.installed.virustotal_lookup.plugin import VirusTotalLookupPlugin

    context = _make_context(tmp_path)
    context.shared_data["file_hashes"] = {"sha256": "a" * 64}
    output = VirusTotalLookupPlugin().run(context)
    assert output.status.value == "skipped"
    assert "api key" in output.logs[0].lower()


def test_vt_plugin_reports_not_found(tmp_path):
    from app.plugins.installed.virustotal_lookup.plugin import VirusTotalLookupPlugin
    from app.database.database import set_setting

    set_setting("virustotal_api_key", "fake-key")
    context = _make_context(tmp_path)
    context.shared_data["file_hashes"] = {"sha256": "a" * 64}

    mock_response = MagicMock(status_code=404)
    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get", return_value=mock_response):
        output = VirusTotalLookupPlugin().run(context)

    assert output.status.value == "success"
    assert "Not previously seen" in output.findings[0].title


def test_vt_plugin_reports_malicious_detection(tmp_path):
    from app.plugins.installed.virustotal_lookup.plugin import VirusTotalLookupPlugin
    from app.database.database import set_setting

    set_setting("virustotal_api_key", "fake-key")
    context = _make_context(tmp_path)
    context.shared_data["file_hashes"] = {"sha256": "a" * 64}

    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {
        "data": {"id": "a" * 64, "attributes": {
            "last_analysis_stats": {"malicious": 40, "suspicious": 2, "undetected": 20, "harmless": 0, "timeout": 0},
            "last_analysis_results": {"EngineA": {"category": "malicious", "result": "Trojan"}},
        }}
    }
    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get", return_value=mock_response):
        output = VirusTotalLookupPlugin().run(context)

    assert output.status.value == "success"
    assert output.findings[0].severity.value == "critical"  # 40/62 = ~65% >= 30% threshold
    assert "40/" in output.findings[0].title


def test_vt_plugin_handles_api_error_as_failed(tmp_path):
    from app.plugins.installed.virustotal_lookup.plugin import VirusTotalLookupPlugin
    from app.database.database import set_setting

    set_setting("virustotal_api_key", "bad-key")
    context = _make_context(tmp_path)
    context.shared_data["file_hashes"] = {"sha256": "a" * 64}

    mock_response = MagicMock(status_code=401)
    with patch("app.plugins.installed.virustotal_lookup.vt_client.requests.get", return_value=mock_response):
        output = VirusTotalLookupPlugin().run(context)

    assert output.status.value == "failed"


# --------------------------------------------------------------------------- #
# quark_engine plugin
# --------------------------------------------------------------------------- #
def test_quark_plugin_skips_when_not_installed(tmp_path, monkeypatch):
    from app.plugins.installed.quark_engine.plugin import QuarkEnginePlugin
    import app.plugins.installed.quark_engine.plugin as plugin_module
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
    output = QuarkEnginePlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"


def test_quark_plugin_skips_when_rules_missing(tmp_path, monkeypatch):
    from app.plugins.installed.quark_engine.plugin import QuarkEnginePlugin
    import app.plugins.installed.quark_engine.plugin as plugin_module

    class _FakeDeps:
        def get_binary_path(self, name):
            return Path("/fake/quark")

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    monkeypatch.setattr(plugin_module, "_DEFAULT_RULES_DIR", tmp_path / "nonexistent_rules")

    output = QuarkEnginePlugin().run(_make_context(tmp_path))
    assert output.status.value == "skipped"
    assert "freshquark" in output.logs[0]


def test_quark_plugin_success_parses_real_schema(tmp_path, monkeypatch):
    from app.plugins.installed.quark_engine.plugin import QuarkEnginePlugin
    import app.plugins.installed.quark_engine.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    class _FakeDeps:
        def get_binary_path(self, name):
            return Path("/fake/quark")

    class _FakeToolManager:
        def run(self, tool_name, args, timeout=300):
            output_path = Path(args[args.index("-o") + 1])
            output_path.write_text(
                '{"threat_level": "High Risk", "total_score": 4, "crimes": '
                '[{"crime": "Send Location via SMS", "score": 4, "weight": 4.0, "confidence": "100%"}]}'
            )
            return ToolExecutionResult(tool=tool_name, command=[tool_name, *args], exit_code=0,
                                        stdout="", stderr="", duration=3.0)

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())
    monkeypatch.setattr(plugin_module, "_DEFAULT_RULES_DIR", rules_dir)

    output = QuarkEnginePlugin().run(_make_context(tmp_path))
    assert output.status.value == "success"
    assert any("High Risk" in f.title for f in output.findings)
    assert any("Send Location via SMS" in f.title for f in output.findings)


def test_quark_plugin_failed_when_output_missing_despite_exit_zero(tmp_path, monkeypatch):
    """The real lesson learned this session: exit_code 0 doesn't guarantee success -- check for real output."""
    from app.plugins.installed.quark_engine.plugin import QuarkEnginePlugin
    import app.plugins.installed.quark_engine.plugin as plugin_module
    from app.core.tool_manager import ToolExecutionResult

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    class _FakeDeps:
        def get_binary_path(self, name):
            return Path("/fake/quark")

    class _FakeToolManager:
        def run(self, tool_name, args, timeout=300):
            # exit_code 0 but no output file written -- matches Quark's real observed behavior
            return ToolExecutionResult(tool=tool_name, command=[tool_name, *args], exit_code=0,
                                        stdout="", stderr="Not a DEX file, Header too small", duration=0.3)

    monkeypatch.setattr(plugin_module, "get_dependency_manager", lambda: _FakeDeps())
    monkeypatch.setattr(plugin_module, "get_tool_manager", lambda: _FakeToolManager())
    monkeypatch.setattr(plugin_module, "_DEFAULT_RULES_DIR", rules_dir)

    output = QuarkEnginePlugin().run(_make_context(tmp_path))
    assert output.status.value == "failed"
    assert "DEX" in output.errors[0]
