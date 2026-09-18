"""
app.plugins.installed.ioc_extraction.plugin
==============================================

Scans decompiled source and decoded resources for network IOCs.
Results are stored in ``context.shared_data["extracted_iocs"]`` for a
later MITRE/threat-intel correlation step, and reported as INFO
findings for report visibility (these are indicators to review, not
confirmed malicious by themselves -- a legitimate app's own API
endpoints show up here too).
"""

from __future__ import annotations

from pathlib import Path

from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.ioc_extraction.ioc_extractor import extract_iocs

_SCAN_EXTENSIONS = {".java", ".kt", ".xml"}
_MAX_FILE_SIZE = 2 * 1024 * 1024


class IocExtractionPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="ioc_extraction",
        name="IOC Extraction",
        version="1.0.0",
        description="Extracts URLs, IPs, and domains as indicators of compromise.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        scan_roots = []
        for key in ("jadx_output_dir", "apktool_output_dir"):
            value = context.shared_data.get(key)
            if value:
                scan_roots.append(Path(value))

        if not scan_roots:
            return PluginOutput(
                tool="ioc_extraction", status=PluginRunStatus.SKIPPED,
                logs=["No decompiled source or decoded resources available; skipping IOC extraction."],
            )

        all_urls: set[str] = set()
        all_ips: set[str] = set()
        all_domains: set[str] = set()
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
                for ioc in extract_iocs(text):
                    {"url": all_urls, "ip": all_ips, "domain": all_domains}[ioc.ioc_type].add(ioc.value)

        context.shared_data["extracted_iocs"] = {
            "urls": sorted(all_urls), "ips": sorted(all_ips), "domains": sorted(all_domains),
        }

        findings = []
        if all_ips:
            findings.append(PluginFinding(
                title=f"{len(all_ips)} hardcoded IP address(es) found",
                severity=SeverityLevel.INFO, category="IOC Extraction",
                description="IP addresses: " + ", ".join(sorted(all_ips)[:20]),
            ))
        if all_domains:
            findings.append(PluginFinding(
                title=f"{len(all_domains)} unique domain(s) contacted",
                severity=SeverityLevel.INFO, category="IOC Extraction",
                description="Domains: " + ", ".join(sorted(all_domains)[:20]),
            ))

        logs = [f"Scanned {files_scanned} file(s): {len(all_urls)} URLs, {len(all_ips)} IPs, {len(all_domains)} domains"]
        return PluginOutput(tool="ioc_extraction", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
