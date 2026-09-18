"""
Unit tests for Module 3b: Tool Manager.

Uses real subprocess execution against a trivial shell script standing
in for a "tool" (registered into a temp copy of TOOL_REGISTRY-shaped
dependency resolution), so the actual subprocess/timeout/streaming
code paths are genuinely exercised -- not mocked away.
"""

from __future__ import annotations

import stat
import sys
import time
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTROID_PATHS__ROOT", str(tmp_path))
    import app.core.config as config_module
    config_module.get_settings.cache_clear()
    yield
    config_module.get_settings.cache_clear()


def _make_fake_dependency_manager(tmp_path, script_body: str):
    """
    Build a fake DependencyManager whose get_binary_path() returns a
    real, executable shell script -- so ToolManager genuinely spawns
    a process rather than mocking subprocess itself.
    """
    from app.core.dependency_manager import DependencyManager

    script_path = tmp_path / "fake_tool.sh"
    script_path.write_text(f"#!/bin/sh\n{script_body}\n")
    script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)

    class _FakeDependencyManager(DependencyManager):
        def __init__(self):
            pass  # skip real __init__/tools_dir creation

        def get_binary_path(self, name: str) -> Path:
            return script_path

    return _FakeDependencyManager()


def test_run_captures_stdout_and_exit_code(tmp_path, monkeypatch):
    from app.core.tool_manager import ToolManager
    import app.core.tool_manager as tm_module

    fake_dm = _make_fake_dependency_manager(tmp_path, "echo hello-from-tool; exit 0")
    monkeypatch.setitem(tm_module.TOOL_REGISTRY, "jadx", tm_module.TOOL_REGISTRY["jadx"])

    tool = ToolManager(dependency_manager=fake_dm)
    result = tool.run("jadx", [])
    assert result.exit_code == 0
    assert "hello-from-tool" in result.stdout
    assert result.timed_out is False


def test_run_captures_nonzero_exit_code(tmp_path):
    from app.core.tool_manager import ToolManager

    fake_dm = _make_fake_dependency_manager(tmp_path, "echo failure-message 1>&2; exit 7")
    tool = ToolManager(dependency_manager=fake_dm)
    result = tool.run("jadx", [])
    assert result.exit_code == 7
    assert "failure-message" in result.stderr


def test_run_enforces_timeout(tmp_path):
    from app.core.tool_manager import ToolManager

    fake_dm = _make_fake_dependency_manager(tmp_path, "sleep 5")
    tool = ToolManager(dependency_manager=fake_dm)
    result = tool.run("jadx", [], timeout=0.5)
    assert result.timed_out is True
    assert result.exit_code is None


def test_run_rejects_unregistered_tool(tmp_path):
    from app.core.tool_manager import ToolManager
    from app.core.exceptions import ToolExecutionError

    fake_dm = _make_fake_dependency_manager(tmp_path, "echo hi")
    tool = ToolManager(dependency_manager=fake_dm)
    with pytest.raises(ToolExecutionError):
        tool.run("some_arbitrary_binary_name", [])


def test_run_streaming_delivers_lines_incrementally(tmp_path):
    from app.core.tool_manager import ToolManager

    fake_dm = _make_fake_dependency_manager(
        tmp_path,
        "for i in 1 2 3; do echo line-$i; done",
    )
    tool = ToolManager(dependency_manager=fake_dm)

    received = []
    result = tool.run_streaming("jadx", [], on_line=lambda stream, line: received.append((stream, line)))

    assert result.exit_code == 0
    assert ("stdout", "line-1") in received
    assert ("stdout", "line-2") in received
    assert ("stdout", "line-3") in received


def test_run_streaming_cooperative_cancel(tmp_path):
    from app.core.tool_manager import ToolManager

    fake_dm = _make_fake_dependency_manager(tmp_path, "sleep 10")
    tool = ToolManager(dependency_manager=fake_dm)

    start = time.monotonic()
    result = tool.run_streaming(
        "jadx", [], on_line=lambda s, l: None, should_cancel=lambda: True, timeout=30,
    )
    elapsed = time.monotonic() - start
    assert result.cancelled is True
    assert elapsed < 5  # terminated quickly, did not wait for the 10s sleep or 30s timeout


def test_run_never_uses_shell_true(tmp_path):
    """Regression guard: a malicious-looking arg must not be shell-interpreted."""
    from app.core.tool_manager import ToolManager

    fake_dm = _make_fake_dependency_manager(tmp_path, 'echo "arg was: $1"')
    tool = ToolManager(dependency_manager=fake_dm)
    dangerous_arg = "; rm -rf / #"
    result = tool.run("jadx", [dangerous_arg])
    # The dangerous string is passed as a literal argument, never executed as a shell command
    assert dangerous_arg in result.stdout
    assert result.exit_code == 0
