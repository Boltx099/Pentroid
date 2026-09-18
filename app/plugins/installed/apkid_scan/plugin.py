"""
app.plugins.installed.apkid_scan.plugin
===========================================

Runs the real ``apkid`` binary (resolved via Dependency Manager) on
the raw APK with ``-j`` for JSON output. Like YARA, APKiD scans
compiled bytes directly -- no APKTool/JADX dependency.
"""

from __future__ import annotations

from app.core.dependency_manager import get_dependency_manager
from app.core.exceptions import ToolNotFoundError
from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.core.tool_manager import get_tool_manager
from app.plugins.base import Plugin, PluginHealth, PluginMetadata
from app.plugins.installed.apkid_scan.apkid_parser import parse_apkid_output

_SEVERITY_MAP = {"high": SeverityLevel.HIGH, "medium": SeverityLevel.MEDIUM, "info": SeverityLevel.INFO}
_SCAN_TIMEOUT = 60


class ApkidScanPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="apkid_scan",
        name="APKiD Scan",
        version="1.0.0",
        description="Detects compilers, packers, obfuscators, and anti-VM/anti-debug techniques via APKiD.",
        requires_device=False,
    )

    def health(self) -> PluginHealth:
        status = get_dependency_manager().status("apkid")
        return PluginHealth.HEALTHY if status.installed else PluginHealth.UNAVAILABLE

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        deps = get_dependency_manager()
        logs: list[str] = []

        try:
            deps.get_binary_path("apkid")
        except ToolNotFoundError:
            logs.append("apkid is not installed (Settings > Dependency Manager) -- skipping scan.")
            return PluginOutput(tool="apkid_scan", status=PluginRunStatus.SKIPPED, logs=logs)

        tool_manager = get_tool_manager()
        result = tool_manager.run("apkid", ["-j", context.target_path], timeout=_SCAN_TIMEOUT)

        if result.exit_code != 0:
            return PluginOutput(
                tool="apkid_scan", status=PluginRunStatus.FAILED, logs=logs,
                errors=[result.stderr.strip() or "apkid exited non-zero with no stderr output"],
            )

        matches = parse_apkid_output(result.stdout)
        findings = [
            PluginFinding(
                title=f"APKiD: {m.category} -- {m.detection}",
                severity=_SEVERITY_MAP[m.severity],
                description=f"APKiD identified '{m.detection}' under category '{m.category}' in {m.filename}.",
                category="APKiD Detection",
            )
            for m in matches
        ]

        logs.append(f"APKiD scan complete: {len(matches)} detection(s)")
        return PluginOutput(tool="apkid_scan", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
