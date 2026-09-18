"""
app.plugins.installed.code_analysis.plugin
=============================================

"Code Analysis" step of the Static Analysis workflow -- runs
``code_analysis_rules.analyze_source`` against every decompiled
Java/Kotlin file from ``jadx_decompile``. Returns SKIPPED (not FAILED)
if JADX output isn't available, same graceful-degradation pattern as
``secrets_detection``.
"""

from __future__ import annotations

from pathlib import Path

from app.core.schemas import (
    ConfidenceLevel, PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext,
)
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.code_analysis.code_analysis_rules import analyze_source

_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL, "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW, "info": SeverityLevel.INFO,
}
_SCAN_EXTENSIONS = {".java", ".kt"}
_MAX_FILE_SIZE = 2 * 1024 * 1024


class CodeAnalysisPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="code_analysis",
        name="Code Analysis",
        version="1.0.0",
        description="Scans decompiled source for insecure coding patterns (crypto, WebView, TrustManager, logging).",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        jadx_dir = context.shared_data.get("jadx_output_dir")
        if not jadx_dir:
            return PluginOutput(
                tool="code_analysis", status=PluginRunStatus.SKIPPED,
                logs=["No decompiled source available (JADX step was skipped or failed); skipping code analysis."],
            )

        root = Path(jadx_dir)
        if not root.exists():
            return PluginOutput(
                tool="code_analysis", status=PluginRunStatus.SKIPPED,
                logs=[f"JADX output directory not found: {root}"],
            )

        findings: list[PluginFinding] = []
        files_scanned = 0

        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > _MAX_FILE_SIZE:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            files_scanned += 1
            for code_finding in analyze_source(text):
                findings.append(
                    PluginFinding(
                        title=code_finding.rule_name,
                        severity=_SEVERITY_MAP[code_finding.severity],
                        description=code_finding.description,
                        category="Code Analysis",
                        masvs_mapping=code_finding.masvs_mapping,
                        file_path=str(path.relative_to(root)),
                        line_number=code_finding.line_number,
                        evidence=code_finding.snippet,
                        recommendation=code_finding.recommendation,
                        finding_key=code_finding.finding_key,
                        # Static pattern matches on decompiled source: strong but not
                        # directly observed at runtime, hence HIGH rather than CONFIRMED.
                        confidence=ConfidenceLevel.HIGH,
                    )
                )

        logs = [f"Scanned {files_scanned} source file(s) for insecure coding patterns"]
        return PluginOutput(tool="code_analysis", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
