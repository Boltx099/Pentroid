"""
app.plugins.installed.secrets_detection.plugin
==================================================

"Secrets Detection" step of the Static Analysis workflow. Scans
whatever decompiled/decoded source is available -- ``jadx_decompile``'s
Java output and/or ``apktool_decode``'s resource XML -- for hardcoded
secrets via ``secret_patterns.scan_text``.

Returns SKIPPED (not FAILED) when neither prior step produced usable
output -- this step is entirely dependent on them and a missing
optional dependency shouldn't read as broken.
"""

from __future__ import annotations

from pathlib import Path

from app.core.schemas import (
    ConfidenceLevel, PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext,
)
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.secrets_detection.secret_patterns import scan_text

_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL, "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW, "info": SeverityLevel.INFO,
}
_SCAN_EXTENSIONS = {".java", ".kt", ".xml"}
_MAX_FILE_SIZE = 2 * 1024 * 1024  # skip pathologically large generated/minified files


class SecretsDetectionPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="secrets_detection",
        name="Secrets Detection",
        version="1.0.0",
        description="Scans decompiled source and resources for hardcoded secrets.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        scan_roots: list[Path] = []
        jadx_dir = context.shared_data.get("jadx_output_dir")
        if jadx_dir:
            scan_roots.append(Path(jadx_dir))
        apktool_dir = context.shared_data.get("apktool_output_dir")
        if apktool_dir:
            scan_roots.append(Path(apktool_dir))

        if not scan_roots:
            return PluginOutput(
                tool="secrets_detection", status=PluginRunStatus.SKIPPED,
                logs=["No decompiled source or decoded resources available; skipping secrets scan."],
            )

        findings: list[PluginFinding] = []
        files_scanned = 0

        for root in scan_roots:
            if not root.exists():
                continue
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
                for match in scan_text(text):
                    findings.append(
                        PluginFinding(
                            title=f"Potential {match.pattern_name} found",
                            severity=_SEVERITY_MAP[match.severity],
                            description=f"Pattern '{match.pattern_name}' matched: {match.redacted_snippet}",
                            category="Secrets Detection",
                            masvs_mapping=match.masvs_mapping,
                            file_path=str(path.relative_to(root)),
                            line_number=match.line_number,
                            finding_key="secrets.hardcoded_credential",
                            # Entropy hits are heuristic by construction and produce
                            # false positives; a matched vendor key format is far
                            # stronger evidence. Reporting both at one confidence
                            # level would waste the reviewer's triage time.
                            confidence=(
                                ConfidenceLevel.LOW if "High-Entropy" in match.pattern_name
                                else ConfidenceLevel.HIGH
                            ),
                            recommendation=(
                                "Remove this credential from source/resources; use the Android Keystore "
                                "or a runtime-fetched remote config instead, and rotate the exposed credential."
                            ),
                        )
                    )

        logs = [f"Scanned {files_scanned} file(s) across {len(scan_roots)} source root(s)"]
        return PluginOutput(tool="secrets_detection", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
