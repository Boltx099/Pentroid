"""
app.plugins.base
=================

Every capability in Pentroid -- APKTool invocation, JADX decompilation,
YARA scanning, Frida hooking, VirusTotal lookups, custom user scripts
-- is implemented as a ``Plugin`` subclass following this exact
lifecycle contract:

    initialize() -> run() -> [cancel()] -> cleanup()
    status() / health() may be polled at any time in between.

The Workflow Engine is the *only* caller of these methods. The GUI
never instantiates or calls a plugin directly (see architecture rule:
"GUI must NEVER execute tools directly").
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from enum import Enum

from app.core.exceptions import PluginExecutionError
from app.core.logger import get_logger
from app.core.schemas import PluginOutput, PluginRunStatus, WorkflowStepContext

logger = get_logger(__name__)


class PluginHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"   # e.g. underlying tool present but outdated
    UNAVAILABLE = "unavailable"  # e.g. underlying tool binary missing


class PluginMetadata:
    """Static, declarative metadata every plugin subclass must provide."""

    __slots__ = ("plugin_id", "name", "version", "author", "description", "requires_device")

    def __init__(
        self,
        plugin_id: str,
        name: str,
        version: str,
        author: str = "Pentroid",
        description: str = "",
        requires_device: bool = False,
    ) -> None:
        self.plugin_id = plugin_id
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.requires_device = requires_device


class Plugin(ABC):
    """
    Abstract base class for all Pentroid plugins.

    Subclasses must set ``metadata`` (a ``PluginMetadata`` instance)
    as a class attribute and implement ``run()``. ``initialize()``,
    ``cancel()``, ``health()``, and ``cleanup()`` have sensible no-op
    defaults but are commonly overridden.
    """

    metadata: PluginMetadata

    def __init__(self) -> None:
        self._cancelled = False
        self._status = "idle"

    # ------------------------------------------------------------------ #
    # Lifecycle - override as needed
    # ------------------------------------------------------------------ #
    def initialize(self) -> None:
        """
        One-time setup before ``run()`` (e.g. verify the wrapped tool's
        binary exists via the Dependency Manager). Default: no-op.
        """
        self._status = "initialized"

    @abstractmethod
    def run(self, context: WorkflowStepContext) -> PluginOutput:
        """
        Execute this plugin's work against the given workflow context
        and return a ``PluginOutput``. Must not raise for *expected*
        failure modes (tool exits non-zero, target malformed, etc.) --
        those should be captured in ``PluginOutput.errors`` with
        ``status=FAILED``. Raising is reserved for programming errors.
        """
        raise NotImplementedError

    def cancel(self) -> None:
        """Request cooperative cancellation of an in-flight ``run()``."""
        self._cancelled = True
        self._status = "cancelling"

    def status(self) -> str:
        """Current lifecycle state: idle/initialized/running/cancelling/done/error."""
        return self._status

    def health(self) -> PluginHealth:
        """
        Whether this plugin's underlying tool is usable right now.
        Overridden by tool-wrapping plugins to check the Dependency
        Manager; pure-Python plugins (no external binary) are always
        ``HEALTHY``.
        """
        return PluginHealth.HEALTHY

    def cleanup(self) -> None:
        """Release any resources (temp files, subprocess handles). Default: no-op."""
        self._status = "idle"

    def parse_output(self, raw: str) -> PluginOutput:
        """
        Optional helper for plugins that wrap a CLI tool: parse the
        tool's raw stdout/stderr into a ``PluginOutput``. Pure-Python
        plugins that build ``PluginOutput`` directly in ``run()`` can
        ignore this.
        """
        raise NotImplementedError(
            f"{self.metadata.plugin_id} does not implement parse_output()"
        )

    # ------------------------------------------------------------------ #
    # Invoked by the Plugin Manager, not by subclasses
    # ------------------------------------------------------------------ #
    def execute(self, context: WorkflowStepContext) -> PluginOutput:
        """
        Wraps ``run()`` with timing, status tracking, and a hard
        boundary that converts unexpected exceptions into a proper
        ``PluginExecutionError`` rather than letting a buggy plugin
        crash the whole workflow engine.
        """
        self._status = "running"
        start = time.monotonic()
        try:
            output = self.run(context)
        except Exception as exc:
            elapsed = time.monotonic() - start
            self._status = "error"
            logger.exception("Plugin %s raised during run()", self.metadata.plugin_id)
            raise PluginExecutionError(
                f"Plugin '{self.metadata.plugin_id}' failed unexpectedly",
                details={"error": str(exc), "duration": elapsed},
            ) from exc

        output.duration = time.monotonic() - start
        self._status = "done" if output.status != PluginRunStatus.FAILED else "error"
        return output
