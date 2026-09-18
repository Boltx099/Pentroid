"""
app.plugins.installed.tracker_detection.plugin
==================================================

Reports detected third-party SDKs as INFO-severity findings -- this is
privacy-relevant transparency information for the report reader, not
a vulnerability in itself (matching how every mainstream mobile
scanner presents tracker detection: informational, not a "finding"
that needs fixing).
"""

from __future__ import annotations

from pathlib import Path

from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.tracker_detection.tracker_registry import KNOWN_TRACKERS, detect_trackers


class TrackerDetectionPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="tracker_detection",
        name="Tracker & SDK Detection",
        version="1.0.0",
        description="Detects known third-party analytics/advertising/tracking SDKs.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        jadx_dir = context.shared_data.get("jadx_output_dir")
        if not jadx_dir:
            return PluginOutput(
                tool="tracker_detection", status=PluginRunStatus.SKIPPED,
                logs=["No decompiled source available; skipping tracker/SDK detection."],
            )

        root = Path(jadx_dir)
        if not root.exists():
            return PluginOutput(
                tool="tracker_detection", status=PluginRunStatus.SKIPPED,
                logs=[f"JADX output directory not found: {root}"],
            )

        detected = detect_trackers(root)
        findings = [
            PluginFinding(
                title=f"Third-party SDK detected: {name} ({category})",
                severity=SeverityLevel.INFO,
                description=f"Package '{pkg_path.replace('/', '.')}' found in decompiled source, "
                             f"indicating use of the {name} SDK.",
                category="Third-Party SDKs",
                masvs_mapping="MASVS-PRIVACY",
                recommendation="Confirm this SDK's data collection is disclosed in the app's privacy policy "
                               "and complies with applicable regulations (GDPR/CCPA/etc.).",
            )
            for pkg_path, name, category in detected
        ]

        logs = [f"Checked {len(KNOWN_TRACKERS)} known SDK signatures, found {len(detected)}"]
        return PluginOutput(tool="tracker_detection", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
