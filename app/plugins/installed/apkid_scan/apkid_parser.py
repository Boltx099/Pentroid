"""
app.plugins.installed.apkid_scan.apkid_parser
=================================================

Pure parsing of ``apkid -j`` JSON output.

Honesty note on confidence level: the top-level envelope shape
(``{"apkid_version", "files": [...], "rules_sha256"}``) was verified
directly by installing real APKiD and running it in this sandbox. The
per-file ``matches`` sub-schema (category names like "compiler",
"packer", "obfuscator", "anti_vm") is APKiD's own documented output,
but wasn't observed firing on a real detection here (the synthetic
test APK has no real DEX magic bytes for APKiD to classify). Parsing
is therefore written generically/tolerantly -- it iterates whatever
category keys are actually present rather than hardcoding an assumed
vocabulary, so it degrades gracefully if the exact category names
differ from what's documented.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# Category names APKiD documents as evasion-relevant get elevated severity;
# everything else (e.g. "compiler") is informational.
_HIGH_SEVERITY_CATEGORIES = {"anti_vm", "anti_debug", "anti_disassembly"}
_MEDIUM_SEVERITY_CATEGORIES = {"obfuscator", "packer", "manipulator"}


@dataclass(frozen=True)
class ApkidMatch:
    filename: str
    category: str
    detection: str
    severity: str  # "high" | "medium" | "info"


def _severity_for_category(category: str) -> str:
    key = category.lower()
    if key in _HIGH_SEVERITY_CATEGORIES:
        return "high"
    if key in _MEDIUM_SEVERITY_CATEGORIES:
        return "medium"
    return "info"


def parse_apkid_output(raw_json: str) -> list[ApkidMatch]:
    """Parse `apkid -j` output into a flat list of matches. Returns [] on any parse failure -- never raises."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, dict):
        return []

    results: list[ApkidMatch] = []
    for file_entry in data.get("files", []):
        if not isinstance(file_entry, dict):
            continue
        filename = file_entry.get("filename", "unknown")
        matches = file_entry.get("matches", {})
        if not isinstance(matches, dict):
            continue

        for category, detections in matches.items():
            if isinstance(detections, str):
                detections = [detections]
            if not isinstance(detections, list):
                continue
            for detection in detections:
                results.append(ApkidMatch(
                    filename=filename, category=category, detection=str(detection),
                    severity=_severity_for_category(category),
                ))

    return results
