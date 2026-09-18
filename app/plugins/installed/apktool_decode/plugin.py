"""
app.plugins.installed.apktool_decode.plugin
==============================================

Second step of the Static Analysis workflow ("APKTool" in the
architecture diagram). Shells out to the real ``apktool`` binary
(resolved via the Dependency Manager -> Tool Manager, never a bare
``apktool`` on $PATH) to decode the APK's compiled resources and
binary AndroidManifest.xml into plain-text XML, which
``manifest_analysis`` then parses.

If apktool isn't installed, this returns ``SKIPPED`` (not a crash and
not a hard failure) -- the workflow step is marked ``required=False``
in the registry precisely so a missing optional tool degrades the
pipeline gracefully instead of aborting the whole analysis.
"""

from __future__ import annotations

from pathlib import Path

from app.core.dependency_manager import get_dependency_manager
from app.core.exceptions import ToolNotFoundError
from app.core.schemas import PluginOutput, PluginRunStatus, WorkflowStepContext
from app.core.tool_manager import get_tool_manager
from app.plugins.base import Plugin, PluginHealth, PluginMetadata

_DECODE_TIMEOUT = 180


class ApktoolDecodePlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="apktool_decode",
        name="APKTool Decode",
        version="1.0.0",
        description="Decodes APK resources and manifest via APKTool.",
        requires_device=False,
    )

    def health(self) -> PluginHealth:
        status = get_dependency_manager().status("apktool")
        return PluginHealth.HEALTHY if status.installed else PluginHealth.UNAVAILABLE

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        deps = get_dependency_manager()
        logs: list[str] = []

        try:
            deps.get_binary_path("apktool")
        except ToolNotFoundError:
            logs.append("apktool is not installed (Settings > Dependency Manager) -- skipping decode.")
            return PluginOutput(tool="apktool_decode", status=PluginRunStatus.SKIPPED, logs=logs)

        output_dir = Path(context.workspace_path) / "apktool_output"
        tool_manager = get_tool_manager()
        result = tool_manager.run(
            "apktool", ["d", context.target_path, "-o", str(output_dir), "-f"],
            timeout=_DECODE_TIMEOUT,
        )
        logs.append(f"apktool exit_code={result.exit_code}, duration={result.duration:.1f}s")

        if result.exit_code != 0:
            return PluginOutput(
                tool="apktool_decode", status=PluginRunStatus.FAILED,
                logs=logs, errors=[result.stderr.strip() or "apktool decode failed with no stderr output"],
            )

        manifest_path = output_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return PluginOutput(
                tool="apktool_decode", status=PluginRunStatus.FAILED,
                logs=logs, errors=[f"apktool succeeded but {manifest_path} was not produced"],
            )

        context.shared_data["apktool_output_dir"] = str(output_dir)
        logs.append(f"Decoded to {output_dir}")
        return PluginOutput(tool="apktool_decode", status=PluginRunStatus.SUCCESS, logs=logs)
