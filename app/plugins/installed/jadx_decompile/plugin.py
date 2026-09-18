"""
app.plugins.installed.jadx_decompile.plugin
==============================================

"JADX" step of the Static Analysis workflow. Decompiles the APK's DEX
bytecode into readable Java source via the real ``jadx`` binary
(resolved through the Dependency Manager -> Tool Manager). Output
feeds ``secrets_detection``.

Same graceful-degradation pattern as ``apktool_decode``: SKIPPED (not
FAILED) if jadx isn't installed, since this step is registered
``required=False`` in the workflow.
"""

from __future__ import annotations

from pathlib import Path

from app.core.dependency_manager import get_dependency_manager
from app.core.exceptions import ToolNotFoundError
from app.core.schemas import PluginOutput, PluginRunStatus, WorkflowStepContext
from app.core.tool_manager import get_tool_manager
from app.plugins.base import Plugin, PluginHealth, PluginMetadata

_DECOMPILE_TIMEOUT = 300


class JadxDecompilePlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="jadx_decompile",
        name="JADX Decompile",
        version="1.0.0",
        description="Decompiles APK DEX bytecode to Java source via JADX.",
        requires_device=False,
    )

    def health(self) -> PluginHealth:
        status = get_dependency_manager().status("jadx")
        return PluginHealth.HEALTHY if status.installed else PluginHealth.UNAVAILABLE

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        deps = get_dependency_manager()
        logs: list[str] = []

        try:
            deps.get_binary_path("jadx")
        except ToolNotFoundError:
            logs.append("jadx is not installed (Settings > Dependency Manager) -- skipping decompilation.")
            return PluginOutput(tool="jadx_decompile", status=PluginRunStatus.SKIPPED, logs=logs)

        output_dir = Path(context.workspace_path) / "jadx_output"
        tool_manager = get_tool_manager()
        result = tool_manager.run(
            "jadx", [context.target_path, "-d", str(output_dir)], timeout=_DECOMPILE_TIMEOUT,
        )
        logs.append(f"jadx exit_code={result.exit_code}, duration={result.duration:.1f}s")

        # jadx frequently exits 0 even when some classes fail to decompile (partial output is
        # still useful), so the real success signal is "did it produce a sources/ directory" --
        # not the exit code alone.
        sources_dir = output_dir / "sources"
        if not sources_dir.exists():
            return PluginOutput(
                tool="jadx_decompile", status=PluginRunStatus.FAILED,
                logs=logs, errors=[result.stderr.strip() or "jadx produced no sources/ directory"],
            )

        context.shared_data["jadx_output_dir"] = str(sources_dir)
        logs.append(f"Decompiled to {sources_dir}")
        return PluginOutput(tool="jadx_decompile", status=PluginRunStatus.SUCCESS, logs=logs)
