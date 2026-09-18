"""
app.plugins.installed.virustotal_lookup.plugin
==================================================

Looks up the sample's SHA256 (from ``file_hashing``'s shared_data) via
VirusTotal API v3. Skips gracefully if no API key is configured
(Settings > Service API Keys) or if ``file_hashing`` hasn't run.
"""

from __future__ import annotations

from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.database.database import get_setting
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.virustotal_lookup.vt_client import VirusTotalError, parse_vt_response, query_virustotal


class VirusTotalLookupPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="virustotal_lookup",
        name="VirusTotal Lookup",
        version="1.0.0",
        description="Looks up the sample's hash against VirusTotal's file intelligence database.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        file_hashes = context.shared_data.get("file_hashes")
        if not file_hashes:
            return PluginOutput(
                tool="virustotal_lookup", status=PluginRunStatus.SKIPPED,
                logs=["No file hash available (File Hashing step was skipped or failed)."],
            )

        api_key = get_setting("virustotal_api_key", default="")
        if not api_key:
            return PluginOutput(
                tool="virustotal_lookup", status=PluginRunStatus.SKIPPED,
                logs=["No VirusTotal API key configured (Settings > Service API Keys) -- skipping lookup."],
            )

        sha256 = file_hashes["sha256"]
        try:
            raw = query_virustotal(sha256, api_key)
        except VirusTotalError as exc:
            return PluginOutput(tool="virustotal_lookup", status=PluginRunStatus.FAILED, errors=[str(exc)])

        result = parse_vt_response(raw)

        if not result.found:
            return PluginOutput(
                tool="virustotal_lookup", status=PluginRunStatus.SUCCESS,
                findings=[PluginFinding(
                    title="Not previously seen by VirusTotal",
                    severity=SeverityLevel.INFO, category="VirusTotal",
                    description=f"SHA256 {sha256} has no existing VirusTotal report. This means "
                                 "'not known', not 'confirmed clean'.",
                )],
                logs=[f"VT lookup: hash not found ({sha256[:16]}...)"],
            )

        if result.malicious == 0:
            severity = SeverityLevel.INFO
            title = f"VirusTotal: 0/{result.total_engines} engines flagged this file"
        else:
            ratio = result.malicious / result.total_engines if result.total_engines else 1.0
            severity = SeverityLevel.CRITICAL if ratio >= 0.3 else SeverityLevel.HIGH
            title = f"VirusTotal: {result.malicious}/{result.total_engines} engines flagged this file as malicious"

        description = f"Malicious: {result.malicious}, Suspicious: {result.suspicious}, " \
                       f"Undetected: {result.undetected}, Harmless: {result.harmless}."
        if result.detecting_engines:
            description += f" Detecting engines: {', '.join(result.detecting_engines[:15])}"
        if result.permalink:
            description += f" | {result.permalink}"

        finding = PluginFinding(title=title, severity=severity, category="VirusTotal", description=description)
        return PluginOutput(
            tool="virustotal_lookup", status=PluginRunStatus.SUCCESS, findings=[finding],
            logs=[f"VT lookup: {result.malicious}/{result.total_engines} detections"],
        )
