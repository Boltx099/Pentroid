"""
app.core.tool_manager
========================

The *only* place in Pentroid that spawns an external process. Plugins
call ``ToolManager.run(...)`` / ``run_streaming(...)`` instead of
touching ``subprocess`` themselves, which gives us one enforcement
point for every safety property the architecture requires:

* Binaries are only ever resolved via the Dependency Manager's
  fully-qualified path -- ``tool_name`` must exist in
  ``TOOL_REGISTRY``, so a plugin can never shell out to an arbitrary
  system binary.
* ``shell=False`` always -- args are passed as a list, never
  interpolated into a shell string, eliminating shell-injection risk
  even if a finding/filename contains attacker-controlled characters.
* Every invocation has a timeout; a hung external tool cannot hang a
  workflow forever.
* stdout/stderr are always captured (or streamed line-by-line for
  long-running tools like logcat/frida) and logged, never silently
  discarded.
"""

from __future__ import annotations

import subprocess
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.core.dependency_manager import DependencyManager, TOOL_REGISTRY, get_dependency_manager
from app.core.exceptions import ToolExecutionError
from app.core.logger import get_logger

logger = get_logger(__name__)

_DEFAULT_TIMEOUT = 300  # seconds


@dataclass
class ToolExecutionResult:
    tool: str
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    cancelled: bool = False


class ToolManager:
    """Resolves and safely executes tools registered in the Dependency Manager."""

    def __init__(self, dependency_manager: DependencyManager | None = None) -> None:
        self._deps = dependency_manager or get_dependency_manager()

    def _build_command(self, tool_name: str, args: list[str]) -> list[str]:
        if tool_name not in TOOL_REGISTRY:
            raise ToolExecutionError(f"'{tool_name}' is not a registered tool")
        binary = self._deps.get_binary_path(tool_name)  # raises ToolNotFoundError if missing
        spec = TOOL_REGISTRY[tool_name]
        return [*spec.launch_prefix, str(binary), *args]

    def run(
        self,
        tool_name: str,
        args: list[str],
        cwd: str | Path | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        env: dict[str, str] | None = None,
    ) -> ToolExecutionResult:
        """Run a registered tool to completion and capture its output."""
        command = self._build_command(tool_name, args)
        logger.info("Executing: %s", " ".join(command))

        start = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
            duration = time.monotonic() - start
            return ToolExecutionResult(
                tool=tool_name, command=command, exit_code=proc.returncode,
                stdout=proc.stdout, stderr=proc.stderr, duration=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            logger.warning("Tool '%s' timed out after %.1fs", tool_name, timeout)
            return ToolExecutionResult(
                tool=tool_name, command=command, exit_code=None,
                stdout=exc.stdout or "", stderr=exc.stderr or "",
                duration=duration, timed_out=True,
            )
        except OSError as exc:
            raise ToolExecutionError(
                f"Failed to execute '{tool_name}'", details={"error": str(exc), "command": command}
            ) from exc

    def run_streaming(
        self,
        tool_name: str,
        args: list[str],
        on_line: Callable[[str, str], None],
        cwd: str | Path | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        should_cancel: Callable[[], bool] | None = None,
        poll_interval: float = 0.2,
    ) -> ToolExecutionResult:
        """
        Run a registered tool, invoking ``on_line(stream, line)`` for each
        line of output as it arrives (``stream`` is ``"stdout"`` or
        ``"stderr"``). Used for long-running/streaming tools: logcat
        capture, frida trace output, mitmdump traffic logs.

        ``should_cancel`` is polled every ``poll_interval`` seconds so the
        Workflow Engine's ``Plugin.cancel()`` can cooperatively stop a
        streaming capture promptly -- even while the tool is silent
        (e.g. blocked waiting on a device). Output is read on background
        threads specifically so a blocking ``readline()`` can never
        delay that cancellation check.
        """
        command = self._build_command(tool_name, args)
        logger.info("Executing (streaming): %s", " ".join(command))

        start = time.monotonic()
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        cancelled = False
        timed_out = False

        proc = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            shell=False,
        )

        line_queue: queue.Queue[tuple[str, str]] = queue.Queue()

        def _reader(stream, stream_name: str) -> None:
            try:
                for raw_line in iter(stream.readline, ""):
                    line_queue.put((stream_name, raw_line.rstrip("\n")))
            finally:
                stream.close()

        reader_threads = [
            threading.Thread(target=_reader, args=(proc.stdout, "stdout"), daemon=True),
            threading.Thread(target=_reader, args=(proc.stderr, "stderr"), daemon=True),
        ]
        for t in reader_threads:
            t.start()

        try:
            while True:
                if should_cancel is not None and should_cancel():
                    cancelled = True
                    break

                if time.monotonic() - start > timeout:
                    timed_out = True
                    break

                try:
                    stream_name, line = line_queue.get(timeout=poll_interval)
                except queue.Empty:
                    if proc.poll() is not None and not any(t.is_alive() for t in reader_threads):
                        break
                    continue

                (stdout_lines if stream_name == "stdout" else stderr_lines).append(line)
                on_line(stream_name, line)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            for t in reader_threads:
                t.join(timeout=2)

        # Drain any lines that arrived after the loop exited (clean completion case)
        while not line_queue.empty():
            stream_name, line = line_queue.get_nowait()
            (stdout_lines if stream_name == "stdout" else stderr_lines).append(line)

        duration = time.monotonic() - start
        return ToolExecutionResult(
            tool=tool_name, command=command, exit_code=proc.returncode,
            stdout="\n".join(stdout_lines), stderr="\n".join(stderr_lines),
            duration=duration, timed_out=timed_out, cancelled=cancelled,
        )


_tool_manager: ToolManager | None = None


def get_tool_manager() -> ToolManager:
    global _tool_manager
    if _tool_manager is None:
        _tool_manager = ToolManager()
    return _tool_manager
