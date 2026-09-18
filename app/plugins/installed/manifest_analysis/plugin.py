"""
app.plugins.installed.manifest_analysis.plugin
==================================================

Third step of the Static Analysis workflow ("Manifest Analysis" /
"Permission Analysis" in the architecture diagram). Reads the
AndroidManifest.xml that ``apktool_decode`` produced and runs the
checks in ``manifest_parser``.

Returns ``SKIPPED`` (not ``FAILED``) when ``apktool_decode``'s output
isn't available -- this step is inherently dependent on that prior
step's success, and a missing optional dependency shouldn't read as
"this step is broken."
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from app.core.schemas import PluginOutput, PluginRunStatus, WorkflowStepContext
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.manifest_analysis.manifest_parser import analyze_manifest, extract_all_permissions


class ManifestAnalysisPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="manifest_analysis",
        name="Manifest Analysis",
        version="1.0.0",
        description="Analyzes AndroidManifest.xml for permissions, exported components, and hardening flags.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        apktool_dir = context.shared_data.get("apktool_output_dir")
        if not apktool_dir:
            return PluginOutput(
                tool="manifest_analysis", status=PluginRunStatus.SKIPPED,
                logs=["No APKTool output available (decode step was skipped or failed); skipping manifest analysis."],
            )

        manifest_path = Path(apktool_dir) / "AndroidManifest.xml"
        if not manifest_path.exists():
            return PluginOutput(
                tool="manifest_analysis", status=PluginRunStatus.SKIPPED,
                logs=[f"AndroidManifest.xml not found at {manifest_path}"],
            )

        try:
            xml_text = manifest_path.read_text(encoding="utf-8", errors="replace")
            findings, logs = analyze_manifest(xml_text)
            context.shared_data["requested_permissions"] = extract_all_permissions(xml_text)
            package_name = ET.fromstring(xml_text).get("package")
            if package_name:
                context.shared_data["package_name"] = package_name
        except ET.ParseError as exc:
            return PluginOutput(
                tool="manifest_analysis", status=PluginRunStatus.FAILED,
                errors=[f"Failed to parse {manifest_path}: {exc}"],
            )

        return PluginOutput(tool="manifest_analysis", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
