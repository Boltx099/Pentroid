"""
app.plugins.installed.apk_validator.plugin
============================================

First step of the Static Analysis workflow ("Validate APK"). Needs no
external tool binary, so it's a genuine, fully-working plugin today --
not a placeholder for a future Tool Manager integration. Later
static-analysis steps (APKTool, JADX, ...) will be their own plugins
that read ``context.target_path`` after this one confirms it's safe
to hand to those tools.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.plugins.base import Plugin, PluginMetadata

_REQUIRED_ENTRIES = ("AndroidManifest.xml", "classes.dex")


class ApkValidatorPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="apk_validator",
        name="APK Validator",
        version="1.0.0",
        description="Validates APK structure before further static analysis.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        target = Path(context.target_path)
        logs: list[str] = [f"Validating target: {target}"]
        errors: list[str] = []
        findings: list[PluginFinding] = []

        if not target.exists():
            errors.append(f"Target file does not exist: {target}")
            return PluginOutput(
                tool="apk_validator", status=PluginRunStatus.FAILED,
                logs=logs, errors=errors,
            )

        if not zipfile.is_zipfile(target):
            errors.append("Target is not a valid ZIP/APK archive")
            findings.append(
                PluginFinding(
                    title="Invalid APK file",
                    severity=SeverityLevel.INFO,
                    description="The provided file is not a valid ZIP/APK archive and cannot be analyzed.",
                    category="Validation",
                )
            )
            return PluginOutput(
                tool="apk_validator", status=PluginRunStatus.FAILED,
                findings=findings, logs=logs, errors=errors,
            )

        with zipfile.ZipFile(target) as archive:
            names = set(archive.namelist())
            missing = [entry for entry in _REQUIRED_ENTRIES if entry not in names]
            entry_count = len(names)

        logs.append(f"Archive contains {entry_count} entries")

        if missing:
            errors.append(f"Missing required APK entries: {missing}")
            findings.append(
                PluginFinding(
                    title="APK missing required components",
                    severity=SeverityLevel.INFO,
                    description=(
                        f"The archive is missing: {', '.join(missing)}. "
                        "This may not be a standard compiled APK."
                    ),
                    category="Validation",
                )
            )
            status = PluginRunStatus.FAILED
        else:
            logs.append("AndroidManifest.xml and classes.dex present")
            status = PluginRunStatus.SUCCESS

        return PluginOutput(
            tool="apk_validator",
            status=status,
            findings=findings,
            logs=logs,
            errors=errors,
            metadata={"entry_count": entry_count},
        )
