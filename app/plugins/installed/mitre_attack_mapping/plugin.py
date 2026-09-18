"""
app.plugins.installed.mitre_attack_mapping.plugin
=====================================================

Consumes ``requested_permissions`` from ``manifest_analysis``'s
shared_data (this step must run after it in the workflow) and reports
one INFO finding per matched MITRE ATT&CK technique, each finding's
``mitre_mapping`` field set to the real technique ID.
"""

from __future__ import annotations

from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.plugins.base import Plugin, PluginMetadata
from app.plugins.installed.mitre_attack_mapping.mitre_map import PERMISSION_TO_TECHNIQUE, map_permissions


class MitreAttackMappingPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="mitre_attack_mapping",
        name="MITRE ATT&CK Mapping",
        version="1.0.0",
        description="Maps requested permissions to MITRE ATT&CK for Mobile techniques.",
        requires_device=False,
    )

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        permissions = context.shared_data.get("requested_permissions")
        if not permissions:
            return PluginOutput(
                tool="mitre_attack_mapping", status=PluginRunStatus.SKIPPED,
                logs=["No permission data available (Manifest Analysis step was skipped or failed)."],
            )

        grouped = map_permissions(permissions)
        findings = []
        for technique_id, perms in grouped.items():
            technique = next(t for t in PERMISSION_TO_TECHNIQUE.values() if t.technique_id == technique_id)
            findings.append(
                PluginFinding(
                    title=f"{technique.name} ({technique_id})",
                    severity=SeverityLevel.INFO,
                    description=f"Requested permission(s) {', '.join(perms)} map to MITRE ATT&CK for Mobile "
                                 f"technique {technique_id} ({technique.tactic}). See {technique.url}",
                    category="MITRE ATT&CK",
                    mitre_mapping=technique_id,
                )
            )

        logs = [f"Mapped {len(permissions)} permission(s) to {len(grouped)} MITRE technique(s)"]
        return PluginOutput(tool="mitre_attack_mapping", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
