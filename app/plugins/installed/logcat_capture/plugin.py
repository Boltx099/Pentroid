"""
app.plugins.installed.logcat_capture.plugin
===============================================

Captures ``adb logcat`` for a bounded duration using
``ToolManager.run_streaming`` (the same streaming infrastructure
built and tested in Module 3, including the cooperative-cancellation
fix). Unlike other tools where a timeout means something went wrong,
a deliberately-bounded capture *should* end via timeout -- that's the
expected, correct termination path here, not a failure.
"""

from __future__ import annotations

from app.core.device.connection_manager import get_connection_manager
from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.core.tool_manager import get_tool_manager
from app.database.database import session_scope
from app.database.models import Device
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.logcat_capture.logcat_parser import find_secrets_in_lines, is_crash_line, parse_logcat_line

_CAPTURE_DURATION_SECONDS = 15


class LogcatCapturePlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="logcat_capture",
        name="Logcat Capture & Analysis",
        version="1.0.0",
        description="Captures logcat for a bounded window and flags crashes/exceptions and runtime-logged secrets.",
        requires_device=True,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        if context.device_id is None:
            return PluginOutput(
                tool="logcat_capture", status=PluginRunStatus.SKIPPED,
                logs=["No device selected for this analysis; dynamic analysis requires one."],
            )

        with session_scope() as session:
            device_row = session.get(Device, context.device_id)
            serial = device_row.identifier if device_row else None

        if not serial:
            return PluginOutput(
                tool="logcat_capture", status=PluginRunStatus.SKIPPED,
                logs=[f"Device id {context.device_id} not found in database."],
            )

        tool_manager = get_tool_manager()
        raw_lines: list[str] = []
        result = tool_manager.run_streaming(
            "adb", ["-s", serial, "logcat", "-v", "brief"],
            on_line=lambda stream, line: raw_lines.append(line) if stream == "stdout" else None,
            timeout=_CAPTURE_DURATION_SECONDS,
        )

        # A deliberately-bounded capture is EXPECTED to end via timeout (adb logcat
        # streams forever otherwise) -- that's success here, not a failure signal.
        if not result.timed_out and result.exit_code not in (0, None):
            return PluginOutput(
                tool="logcat_capture", status=PluginRunStatus.FAILED,
                errors=[result.stderr.strip() or "adb logcat exited unexpectedly"],
            )

        parsed = [parse_logcat_line(line) for line in raw_lines]
        parsed = [line for line in parsed if line is not None]

        findings: list[PluginFinding] = []

        crash_lines = [line for line in parsed if is_crash_line(line)]
        if crash_lines:
            sample = crash_lines[0]
            findings.append(PluginFinding(
                title=f"Crash/exception observed at runtime ({len(crash_lines)} line(s))",
                severity=SeverityLevel.MEDIUM,
                category="Dynamic Analysis",
                description=f"First occurrence: [{sample.tag}] {sample.message}",
                recommendation="Review the full stack trace to determine whether this is a stability issue "
                               "or a security-relevant crash (e.g. triggered by malformed input).",
            ))

        secret_hits = find_secrets_in_lines(parsed)
        if secret_hits:
            pattern_names = sorted({name for _, name in secret_hits})
            findings.append(PluginFinding(
                title=f"Potential secret(s) logged at runtime ({len(secret_hits)} occurrence(s))",
                severity=SeverityLevel.HIGH,
                category="Dynamic Analysis",
                masvs_mapping="MASVS-STORAGE",
                description=f"Pattern(s) matched in live logcat output: {', '.join(pattern_names)}.",
                recommendation="Remove sensitive values from log statements, especially in release builds.",
            ))

        logs = [f"Captured {len(raw_lines)} logcat line(s) over {_CAPTURE_DURATION_SECONDS}s"]
        return PluginOutput(tool="logcat_capture", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
