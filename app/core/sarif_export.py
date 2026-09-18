"""
app.core.sarif_export
========================

SARIF 2.1.0 export (OASIS standard, schema at
https://json.schemastore.org/sarif-2.1.0.json).

Why SARIF specifically
----------------------
It is the interchange format static-analysis tooling has actually
standardised on, so emitting it plugs Pentroid into an existing
ecosystem rather than asking anyone to parse a bespoke JSON shape:

* **GitHub Advanced Security / code scanning** ingests SARIF directly,
  which turns a Pentroid run in CI into inline PR annotations.
* **Azure DevOps, GitLab, DefectDojo, VS Code (SARIF Viewer)** all
  consume it.
* Findings carry `ruleId`, so results deduplicate and trend across
  runs instead of appearing as unrelated one-offs.

Design notes
------------
* Each distinct ``finding_key`` (falling back to a slugged category)
  becomes a SARIF *rule* in ``tool.driver.rules``; individual findings
  become *results* referencing it. That is what makes suppression and
  trend-tracking work in consuming tools.
* SARIF has no severity taxonomy matching ours: its ``level`` is only
  error/warning/note/none. We map onto that for compatibility AND
  carry the precise severity, confidence, CVSS and CWE in
  ``properties`` so nothing is lost for consumers that look deeper.
* ``region.startLine`` is only emitted when a real line number exists;
  emitting a bogus line 1 would point reviewers at the wrong code.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Our 5-level severity -> SARIF's 4-level `level`. Deliberately lossy; the
# original value is preserved in properties.severity.
_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# SARIF security-severity is a 0.0-10.0 string; GitHub uses it to bucket
# alerts into critical/high/medium/low. Used only when no CVSS score exists.
_SECURITY_SEVERITY_FALLBACK = {
    "critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "0.0",
}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "finding").lower()).strip("-") or "finding"


def _rule_id(finding: dict) -> str:
    """Stable rule identity: prefer the KB key, else a slug of the category/title."""
    if finding.get("finding_key"):
        return str(finding["finding_key"])
    if finding.get("category"):
        return f"pentroid.{_slug(finding['category'])}"
    return f"pentroid.{_slug(finding.get('title', ''))}"


def _build_rule(finding: dict) -> dict[str, Any]:
    rule_id = _rule_id(finding)
    severity = (finding.get("severity") or "info").lower()

    help_parts = []
    if finding.get("impact"):
        help_parts.append(f"## Impact\n\n{finding['impact']}")
    if finding.get("reproduction_steps"):
        help_parts.append(f"## Reproduction\n\n```\n{finding['reproduction_steps']}\n```")
    if finding.get("recommendation"):
        help_parts.append(f"## Remediation\n\n{finding['recommendation']}")
    refs = finding.get("references") or []
    if refs:
        help_parts.append("## References\n\n" + "\n".join(f"- {r}" for r in refs))

    properties: dict[str, Any] = {
        "security-severity": (
            str(finding["cvss_score"]) if finding.get("cvss_score") is not None
            else _SECURITY_SEVERITY_FALLBACK.get(severity, "0.0")
        ),
        "tags": ["security"],
    }
    # GitHub renders these tags as filterable labels.
    for key in ("category", "owasp_mapping", "masvs_mapping", "mitre_mapping"):
        if finding.get(key):
            properties["tags"].append(str(finding[key]))
    if finding.get("cwe_id"):
        properties["tags"].append(str(finding["cwe_id"]))
        # external/cwe/cwe-NNN is the convention GitHub recognises for CWE linking.
        cwe_num = str(finding["cwe_id"]).replace("CWE-", "").strip()
        if cwe_num.isdigit():
            properties["tags"].append(f"external/cwe/cwe-{cwe_num}")

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": finding.get("title", rule_id),
        "shortDescription": {"text": (finding.get("title") or rule_id)[:200]},
        "fullDescription": {"text": finding.get("description") or finding.get("title") or rule_id},
        "defaultConfiguration": {"level": _LEVEL_MAP.get(severity, "note")},
        "properties": properties,
    }
    if help_parts:
        rule["help"] = {"markdown": "\n\n".join(help_parts), "text": re.sub(r"[#`]", "", "\n\n".join(help_parts))}
    return rule


def _build_result(finding: dict, rule_index: int) -> dict[str, Any]:
    severity = (finding.get("severity") or "info").lower()

    message_parts = [finding.get("description") or finding.get("title") or "Security finding"]
    if finding.get("evidence"):
        message_parts.append(f"Evidence: {finding['evidence']}")
    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "level": _LEVEL_MAP.get(severity, "note"),
        "message": {"text": "\n".join(message_parts)},
        "properties": {
            "severity": severity,
            "confidence": finding.get("confidence", "medium"),
        },
    }
    if finding.get("cvss_score") is not None:
        result["properties"]["cvssScore"] = finding["cvss_score"]
    if finding.get("cvss_vector"):
        result["properties"]["cvssVector"] = finding["cvss_vector"]

    file_path = finding.get("file_path")
    if file_path:
        # The spec requires `uri` to be RELATIVE whenever `uriBaseId` is present,
        # so strip any leading separator or drive-absolute prefix rather than
        # emitting a technically-invalid log that some consumers reject.
        uri = str(file_path).replace("\\", "/").lstrip("/")
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
        }
        line_number = finding.get("line_number")
        # Only emit a region when we genuinely know the line -- a default of 1
        # would silently point reviewers at the wrong code.
        if isinstance(line_number, int) and line_number > 0:
            physical["region"] = {"startLine": line_number}
        result["locations"] = [{"physicalLocation": physical}]
    else:
        # SARIF requires *something* locatable for a result to be actionable;
        # fall back to naming the analysed artifact rather than omitting it.
        result["locations"] = [{
            "physicalLocation": {"artifactLocation": {"uri": finding.get("target_name") or "application"}}
        }]

    return result


def build_sarif(report_data: dict, tool_version: str = "3.2.0") -> dict[str, Any]:
    """
    Build a SARIF 2.1.0 log from the ``_load_analysis_data`` dict the
    Report Engine already produces, so SARIF stays in lockstep with every
    other output format instead of drifting on a separate code path.
    """
    findings = report_data.get("findings", [])
    project = report_data.get("project", {})
    analysis = report_data.get("analysis", {})

    rules: list[dict[str, Any]] = []
    rule_index_by_id: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        enriched = dict(finding)
        enriched.setdefault("target_name", project.get("name"))
        rule_id = _rule_id(enriched)
        if rule_id not in rule_index_by_id:
            rule_index_by_id[rule_id] = len(rules)
            rules.append(_build_rule(enriched))
        results.append(_build_result(enriched, rule_index_by_id[rule_id]))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Pentroid",
                    "version": tool_version,
                    "informationUri": "https://github.com/Boltx099",
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": analysis.get("status") == "completed",
                "commandLine": f"pentroid {analysis.get('workflow_name', '')}".strip(),
            }],
            "properties": {
                "projectName": project.get("name"),
                "platform": project.get("platform"),
                "analysisType": analysis.get("analysis_type"),
                "riskScore": analysis.get("risk_score"),
            },
            "results": results,
        }],
    }


def write_sarif(report_data: dict, file_path: Path, tool_version: str = "3.2.0") -> None:
    file_path.write_text(json.dumps(build_sarif(report_data, tool_version), indent=2), encoding="utf-8")
