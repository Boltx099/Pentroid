"""
app.plugins.installed.network_security_config.plugin
========================================================

Locates the app's Network Security Config file (default path, or
resolved from ``android:networkSecurityConfig`` in the decoded
manifest) and runs ``nsc_parser`` against it. If no custom config
exists at all, that's a legitimate normal outcome (OS defaults apply)
-- reported as an informational finding, not a skip, since it's
useful context either way.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from app.core.schemas import (
    ConfidenceLevel, PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext,
)
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.network_security_config.nsc_parser import analyze_network_security_config

_SEVERITY_MAP = {"high": SeverityLevel.HIGH, "medium": SeverityLevel.MEDIUM, "info": SeverityLevel.INFO}
_DEFAULT_RELATIVE_PATH = "res/xml/network_security_config.xml"
_MANIFEST_REF_RE = re.compile(r'android:networkSecurityConfig="@xml/([\w.]+)"')


class NetworkSecurityConfigPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="network_security_config",
        name="Network Security Config Analysis",
        version="1.0.0",
        description="Analyzes network_security_config.xml for cleartext traffic and user-CA trust.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        apktool_dir = context.shared_data.get("apktool_output_dir")
        if not apktool_dir:
            return PluginOutput(
                tool="network_security_config", status=PluginRunStatus.SKIPPED,
                logs=["No APKTool output available; skipping Network Security Config analysis."],
            )

        root = Path(apktool_dir)
        nsc_path = self._locate_config_file(root)

        if nsc_path is None or not nsc_path.exists():
            return PluginOutput(
                tool="network_security_config", status=PluginRunStatus.SUCCESS,
                findings=[
                    PluginFinding(
                        title="No custom Network Security Config found",
                        severity=SeverityLevel.INFO,
                        description="The app does not declare a custom network_security_config.xml, so "
                                     "platform defaults apply (cleartext traffic is blocked by default for "
                                     "apps targeting API 28+, permitted by default below that).",
                        category="Network Security",
                        masvs_mapping="MASVS-NETWORK",
                    )
                ],
                logs=["No network_security_config.xml found (default path or manifest reference)."],
            )

        try:
            xml_text = nsc_path.read_text(encoding="utf-8", errors="replace")
            nsc_findings = analyze_network_security_config(xml_text)
        except ET.ParseError as exc:
            return PluginOutput(
                tool="network_security_config", status=PluginRunStatus.FAILED,
                errors=[f"Failed to parse {nsc_path}: {exc}"],
            )

        findings = [
            PluginFinding(
                title=f.title, severity=_SEVERITY_MAP[f.severity], description=f.description,
                category="Network Security", masvs_mapping="MASVS-NETWORK",
                file_path=str(nsc_path.relative_to(root)), recommendation=f.recommendation,
                finding_key=f.finding_key, confidence=ConfidenceLevel.CONFIRMED,
            )
            for f in nsc_findings
        ]
        return PluginOutput(
            tool="network_security_config", status=PluginRunStatus.SUCCESS, findings=findings,
            logs=[f"Analyzed {nsc_path.relative_to(root)}"],
        )

    def _locate_config_file(self, root: Path) -> Path | None:
        default_path = root / _DEFAULT_RELATIVE_PATH
        if default_path.exists():
            return default_path

        manifest_path = root / "AndroidManifest.xml"
        if manifest_path.exists():
            manifest_text = manifest_path.read_text(encoding="utf-8", errors="replace")
            match = _MANIFEST_REF_RE.search(manifest_text)
            if match:
                candidate = root / "res" / "xml" / f"{match.group(1)}.xml"
                if candidate.exists():
                    return candidate

        return None
