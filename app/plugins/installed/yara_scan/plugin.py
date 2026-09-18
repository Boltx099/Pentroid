"""
app.plugins.installed.yara_scan.plugin
==========================================

Compiles the bundled rule file (``rules/android_heuristics.yar``) and
scans the raw APK bytes directly -- YARA's strength is binary string
matching, so this deliberately does NOT need APKTool/JADX output; it
runs straight off ``context.target_path``.

``yara-python`` is a direct app dependency (imported in-process), not
a Dependency-Manager-tracked external tool -- it's a library Pentroid
itself uses, not a CLI Pentroid shells out to (same reasoning as
``androguard`` would follow if added later).
"""

from __future__ import annotations

from pathlib import Path

from app.core.schemas import PluginFinding, PluginOutput, PluginRunStatus, SeverityLevel, WorkflowStepContext
from app.plugins.base import Plugin, PluginHealth, PluginMetadata

_RULES_PATH = Path(__file__).resolve().parent / "rules" / "android_heuristics.yar"
_SEVERITY_MAP = {"high": SeverityLevel.HIGH, "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW}

_compiled_rules = None  # module-level cache -- compile once per process, not once per analysis


def _get_compiled_rules():
    global _compiled_rules
    if _compiled_rules is None:
        import yara
        _compiled_rules = yara.compile(filepath=str(_RULES_PATH))
    return _compiled_rules


class YaraScanPlugin(Plugin):
    metadata = PluginMetadata(
        plugin_id="yara_scan",
        name="YARA Scan",
        version="1.0.0",
        description="Scans the raw APK against bundled YARA heuristic rules.",
        requires_device=False,
    )

    def health(self) -> PluginHealth:
        try:
            import yara  # noqa: F401
            return PluginHealth.HEALTHY
        except ImportError:
            return PluginHealth.UNAVAILABLE

    def run(self, context: WorkflowStepContext) -> PluginOutput:
        try:
            import yara
        except ImportError:
            return PluginOutput(
                tool="yara_scan", status=PluginRunStatus.SKIPPED,
                logs=["yara-python is not installed; skipping YARA scan."],
            )

        target = Path(context.target_path)
        if not target.exists():
            return PluginOutput(tool="yara_scan", status=PluginRunStatus.FAILED, errors=[f"Target file not found: {target}"])

        try:
            rules = _get_compiled_rules()
            matches = rules.match(filepath=str(target))
        except yara.Error as exc:
            return PluginOutput(tool="yara_scan", status=PluginRunStatus.FAILED, errors=[f"YARA scan failed: {exc}"])

        findings = []
        for match in matches:
            meta = match.meta
            severity = _SEVERITY_MAP.get(meta.get("severity", "medium"), SeverityLevel.MEDIUM)
            findings.append(
                PluginFinding(
                    title=f"YARA match: {match.rule}",
                    severity=severity,
                    description=meta.get("description", "No description provided."),
                    category=f"YARA / {meta.get('category', 'Heuristic')}",
                    recommendation="Investigate the matched indicator manually -- a single static heuristic "
                                   "match is a lead, not a confirmed malware verdict.",
                )
            )

        logs = [f"YARA scan complete: {len(matches)} rule match(es)"]
        return PluginOutput(tool="yara_scan", status=PluginRunStatus.SUCCESS, findings=findings, logs=logs)
