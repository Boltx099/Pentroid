"""
app.plugins.installed.quark_engine.plugin
=============================================

Runs the real ``quark`` binary against the raw APK. Two real-world
quirks discovered by actually running Quark in this sandbox (not
assumed):

1. Quark requires a separate rule database (fetched via its own
   ``freshquark`` companion tool, not bundled with the pip package).
   If it's missing, Quark exits with a clear CLI error -- caught here
   and reported as SKIPPED with the exact fix, rather than a generic
   failure.
2. Quark can exit 0 while having failed internally (e.g. on a
   malformed DEX) -- same lesson learned from ``jadx_decompile``, so
   success is judged by whether the output JSON file actually exists,
   not the exit code alone.
"""

from __future__ import annotations

from pathlib import Path

from app.core.dependency_manager import get_dependency_manager
from app.core.exceptions import ToolNotFoundError
from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.core.tool_manager import get_tool_manager
from app.plugins.base import Plugin, PluginHealth, PluginMetadata
from app.plugins.installed.quark_engine.quark_parser import (
    parse_quark_report, severity_for_confidence, severity_for_threat_level,
)

_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL, "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW,
}
_SCAN_TIMEOUT = 180
_DEFAULT_RULES_DIR = Path.home() / ".quark-engine" / "quark-rules" / "rules"


class QuarkEnginePlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="quark_engine",
        name="Quark-Engine Scan",
        version="1.0.0",
        description="Behavioral scoring analysis for known malicious patterns via Quark-Engine.",
        requires_device=False,
    )

    def health(self) -> PluginHealth:
        status = get_dependency_manager().status("quark")
        return PluginHealth.HEALTHY if status.installed else PluginHealth.UNAVAILABLE

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        deps = get_dependency_manager()
        logs: list[str] = []

        try:
            deps.get_binary_path("quark")
        except ToolNotFoundError:
            logs.append("quark is not installed (Settings > Dependency Manager) -- skipping scan.")
            return PluginOutput(tool="quark_engine", status=PluginRunStatus.SKIPPED, logs=logs)

        if not _DEFAULT_RULES_DIR.exists():
            logs.append(
                f"Quark rule database not found at {_DEFAULT_RULES_DIR}. Run 'freshquark' "
                "(in quark's virtualenv bin/ directory) once to download it, then retry."
            )
            return PluginOutput(tool="quark_engine", status=PluginRunStatus.SKIPPED, logs=logs)

        output_path = Path(context.workspace_path) / "quark_report.json"
        tool_manager = get_tool_manager()
        result = tool_manager.run(
            "quark", ["-a", context.target_path, "-s", "-o", str(output_path)], timeout=_SCAN_TIMEOUT,
        )
        logs.append(f"quark exit_code={result.exit_code}, duration={result.duration:.1f}s")

        if not output_path.exists():
            return PluginOutput(
                tool="quark_engine", status=PluginRunStatus.FAILED, logs=logs,
                errors=[result.stderr.strip()[-1000:] or "quark did not produce a report file"],
            )

        report_text = output_path.read_text(encoding="utf-8", errors="replace")
        report = parse_quark_report(report_text)
        if report is None:
            return PluginOutput(
                tool="quark_engine", status=PluginRunStatus.FAILED, logs=logs,
                errors=["Quark report file exists but could not be parsed as JSON."],
            )

        findings = [
            PluginFinding(
                title=f"Quark threat level: {report.threat_level} (score {report.total_score})",
                severity=_SEVERITY_MAP[severity_for_threat_level(report.threat_level)],
                description=f"Quark-Engine's overall behavioral risk score for this sample is "
                             f"{report.total_score}, classified as {report.threat_level}.",
                category="Quark-Engine",
            )
        ]
        for crime in report.crimes:
            findings.append(
                PluginFinding(
                    title=f"Quark behavior: {crime.crime}",
                    severity=_SEVERITY_MAP[severity_for_confidence(crime.confidence)],
                    description=f"Confidence {crime.confidence}, score {crime.score} (weight {crime.weight}). "
                                 + (f"Related permissions: {', '.join(crime.permissions)}" if crime.permissions else ""),
                    category="Quark-Engine",
                )
            )

        logs.append(f"Quark scan complete: threat_level={report.threat_level}, {len(report.crimes)} behavior(s)")
        return PluginOutput(tool="quark_engine", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
