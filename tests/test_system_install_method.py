"""
Tests for InstallMethod.SYSTEM (Module 12a foundation) - tools resolved
via $PATH rather than downloaded, honestly modeled rather than silently
bypassing the "never depend on PATH" principle.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))
    import app.core.config as config_module
    config_module.get_settings.cache_clear()
    yield
    config_module.get_settings.cache_clear()


def test_keytool_resolves_via_system_path(tmp_path):
    from app.core.dependency_manager import DependencyManager

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    status = dm.status("keytool")
    assert status.installed is True
    assert status.binary_path is not None
    assert status.binary_path.exists()


def test_system_tool_install_raises_clear_message(tmp_path):
    from app.core.dependency_manager import DependencyManager
    from app.core.exceptions import ToolNotFoundError

    dm = DependencyManager(tools_dir=tmp_path / "tools")
    with pytest.raises(ToolNotFoundError, match="PATH"):
        dm.install("keytool")


def test_system_tool_not_found_when_missing_from_path(tmp_path, monkeypatch):
    from app.core.dependency_manager import DependencyManager
    from app.core.exceptions import ToolNotFoundError
    import app.core.dependency_manager as dm_module

    monkeypatch.setattr(dm_module.shutil, "which", lambda name: None)
    dm = DependencyManager(tools_dir=tmp_path / "tools")
    status = dm.status("keytool")
    assert status.installed is False
    with pytest.raises(ToolNotFoundError):
        dm.get_binary_path("keytool")
