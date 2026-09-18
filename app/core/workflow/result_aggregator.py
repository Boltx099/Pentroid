"""
app.core.workflow.result_aggregator
=====================================

Converts a plugin's ``PluginOutput.findings`` (Pydantic schema objects,
transient) into persisted ``Finding`` ORM rows tied to an analysis, and
applies lightweight deduplication so a workflow with overlapping
detections (e.g. two plugins both flagging the same hardcoded secret)
doesn't produce duplicate rows in the GUI's findings list.
"""

from __future__ import annotations

from app.core.logger import get_logger
from app.core.schemas import ConfidenceLevel, PluginOutput, SeverityLevel
from app.database.database import session_scope
from app.core.knowledge.finding_kb import get_knowledge
from app.database.models import Confidence, Finding, Plugin as PluginRecord, Severity

logger = get_logger(__name__)

_CONFIDENCE_MAP = {
    ConfidenceLevel.CONFIRMED: Confidence.CONFIRMED,
    ConfidenceLevel.HIGH: Confidence.HIGH,
    ConfidenceLevel.MEDIUM: Confidence.MEDIUM,
    ConfidenceLevel.LOW: Confidence.LOW,
}

_SEVERITY_MAP = {
    SeverityLevel.CRITICAL: Severity.CRITICAL,
    SeverityLevel.HIGH: Severity.HIGH,
    SeverityLevel.MEDIUM: Severity.MEDIUM,
    SeverityLevel.LOW: Severity.LOW,
    SeverityLevel.INFO: Severity.INFO,
}


class ResultAggregator:
    """Persists plugin findings into the database, deduplicated per analysis."""

    def persist(self, analysis_id: int, plugin_id: str, output: PluginOutput) -> list[int]:
        """
        Insert ``output.findings`` as ``Finding`` rows for ``analysis_id``.
        Returns the list of newly created Finding primary keys (empty
        entries that were deduplicated against existing rows are
        skipped and not counted).
        """
        if not output.findings:
            return []

        created_ids: list[int] = []
        with session_scope() as session:
            plugin_record = (
                session.query(PluginRecord).filter_by(plugin_id=plugin_id).one_or_none()
            )

            # KEY INCLUDES line_number -- this used to be just (title, file_path),
            # which is coarser than it looks. A rule's title is static per rule,
            # not per occurrence (e.g. code_analysis always emits the literal
            # title "Weak Hash Algorithm"), so two genuinely different findings
            # -- the same rule firing on two different lines of the *same* file
            # -- collided on an identical key and the second one was silently
            # dropped as a "duplicate", losing a real finding rather than
            # deduplicating one. Including line_number fixes that: distinct
            # locations are always kept. True exact duplicates (the same
            # plugin re-persisting the same finding, e.g. on a retried step)
            # still collide and are still skipped, since title+file_path+
            # line_number is unchanged for those.
            #
            # This does NOT catch every duplicate -- e.g. the same secret
            # found via both apktool's and jadx's decompile output lands
            # under two different file_paths and correctly isn't deduplicated
            # by this key. Closing that gap needs evidence-based fingerprinting
            # (hashing the matched value/pattern, not the location), which is
            # a bigger, separate change than this fix.
            existing_keys = {
                (row.title, row.file_path, row.line_number)
                for row in session.query(Finding.title, Finding.file_path, Finding.line_number)
                .filter_by(analysis_id=analysis_id)
                .all()
            }

            for finding in output.findings:
                key = (finding.title, finding.file_path, finding.line_number)
                if key in existing_keys:
                    logger.debug(
                        "Skipping duplicate finding '%s' at %s:%s for analysis %s",
                        finding.title, finding.file_path, finding.line_number, analysis_id,
                    )
                    continue
                existing_keys.add(key)

                # Enrich from the central knowledge base. Plugin-supplied values
                # always win -- the KB provides a floor for report quality, it
                # does not override a plugin that knows something more specific
                # about this particular instance.
                kb = get_knowledge(finding.finding_key)

                affected = finding.affected_components or (
                    [finding.file_path] if finding.file_path else []
                )

                row = Finding(
                    analysis_id=analysis_id,
                    plugin_id=plugin_record.id if plugin_record else None,
                    title=finding.title,
                    description=finding.description,
                    severity=_SEVERITY_MAP[finding.severity],
                    category=finding.category,
                    owasp_mapping=finding.owasp_mapping,
                    masvs_mapping=finding.masvs_mapping,
                    mitre_mapping=finding.mitre_mapping,
                    evidence=finding.evidence,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    recommendation=finding.recommendation or (kb.recommendation if kb else None),
                    impact=finding.impact or (kb.impact if kb else None),
                    reproduction_steps=finding.reproduction_steps or (kb.reproduction_steps if kb else None),
                    affected_components="\n".join(affected) if affected else None,
                    cwe_id=finding.cwe_id or (kb.cwe_id if kb else None),
                    cvss_vector=kb.cvss_vector if kb else None,
                    cvss_score=kb.cvss_score if kb else None,
                    confidence=_CONFIDENCE_MAP[finding.confidence],
                    references=finding.references or (list(kb.references) if kb else []),
                )
                session.add(row)
                session.flush()
                created_ids.append(row.id)

        return created_ids

    @staticmethod
    def compute_risk_score(analysis_id: int) -> float:
        """
        Risk score in [0, 10] from an analysis's findings, dominated by the
        single worst finding rather than averaged across all of them.

        This used to be a plain mean (``sum(weights) / count``), which had a
        precise, checkable, and backwards failure mode: adding more low/info
        findings *lowered* the score even though nothing about the app's
        actual risk changed.

            1 CRITICAL alone            -> 10 / 1  = 10.0  (High Risk)
            1 CRITICAL + 9 INFO         -> 10 / 10 =  1.0  (Low Risk)
            1 CRITICAL + 30 INFO        -> 10 / 31 =  0.3  (Low Risk)

        A single confirmed CRITICAL doesn't become less risky because a scan
        also produced a pile of informational notes -- but the mean made it
        look that way, on the exact number the dashboard gauge leads with.

        The replacement takes the worst finding's weight in full, then adds
        a rapidly-diminishing contribution from the rest (each next-worst
        finding counts for half of the previous one's contribution). That
        keeps a single bad finding dominant regardless of volume, while
        still letting several serious findings push the score higher than
        any one of them alone (e.g. five HIGHs alongside one CRITICAL still
        saturates to 10.0, reflecting a genuinely worse app than the
        CRITICAL by itself) -- see test_result_aggregator.py for the worked
        cases above as regression tests.
        """
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0,
        }
        with session_scope() as session:
            rows = session.query(Finding.severity).filter_by(analysis_id=analysis_id).all()

        if not rows:
            return 0.0

        weighted = sorted((weights[severity] for (severity,) in rows), reverse=True)
        primary, rest = weighted[0], weighted[1:]
        secondary = sum(w * (0.5 ** i) for i, w in enumerate(rest, start=1))
        return round(min(primary + secondary, 10.0), 1)
