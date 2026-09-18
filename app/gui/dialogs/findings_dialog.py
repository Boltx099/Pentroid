"""
app.gui.dialogs.findings_dialog
==================================

A real in-app findings report -- the thing that was actually missing
compared to MobSF. Before this, an analysis's results existed only as
a number ("N findings") plus whatever the generated HTML report said
(a file you'd have to leave the app to open). The ``Finding`` rows
themselves -- title, severity, category, OWASP/MASVS/MITRE mappings,
evidence, recommendation -- were always in the database; there was
just no view for them.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFrame, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget,
)

from app.database.database import session_scope
from app.database.models import Analysis, Finding, FindingStatus, Project, Severity
from app.gui.theme import Colors

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEVERITY_COLOR = {
    Severity.CRITICAL: Colors.SEVERITY_CRITICAL,
    Severity.HIGH: Colors.SEVERITY_HIGH if hasattr(Colors, "SEVERITY_HIGH") else "#f97316",
    Severity.MEDIUM: Colors.SEVERITY_MEDIUM,
    Severity.LOW: Colors.SEVERITY_LOW if hasattr(Colors, "SEVERITY_LOW") else "#3b82f6",
    Severity.INFO: Colors.TEXT_MUTED,
}

# Order shown in each card's status combo box, and the plain-English label
# for each FindingStatus value -- the enum's own .value strings ("false_positive")
# aren't what a researcher should see in the UI.
_STATUS_LABELS = {
    FindingStatus.OPEN: "Open",
    FindingStatus.CONFIRMED: "Confirmed",
    FindingStatus.FALSE_POSITIVE: "False Positive",
    FindingStatus.FIXED: "Fixed",
    FindingStatus.ACCEPTED_RISK: "Accepted Risk",
}
_STATUS_ORDER = [
    FindingStatus.OPEN, FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE,
    FindingStatus.FIXED, FindingStatus.ACCEPTED_RISK,
]
_STATUS_COLOR = {
    FindingStatus.OPEN: Colors.TEXT_SECONDARY,
    FindingStatus.CONFIRMED: Colors.STATUS_ERROR if hasattr(Colors, "STATUS_ERROR") else "#ef4444",
    FindingStatus.FALSE_POSITIVE: Colors.TEXT_MUTED,
    FindingStatus.FIXED: Colors.ACCENT_GREEN,
    FindingStatus.ACCEPTED_RISK: Colors.STATUS_WARNING if hasattr(Colors, "STATUS_WARNING") else "#f59e0b",
}
# Statuses hidden by the dialog's "Hide reviewed" checkbox by default -- the
# two outcomes where a researcher has decided there's nothing left to act on.
_HIDDEN_BY_DEFAULT = {FindingStatus.FALSE_POSITIVE, FindingStatus.FIXED}


def set_finding_status(finding_id: int, status: FindingStatus) -> None:
    """
    Persist a triage decision for one finding.

    Before this function existed, ``FindingStatus`` (OPEN/CONFIRMED/
    FALSE_POSITIVE/FIXED/ACCEPTED_RISK) was defined on the ``Finding`` model
    and never referenced anywhere else in the codebase -- every finding was
    permanently OPEN as far as the UI was concerned, and a researcher
    triaging a long list had no way to record "I've looked at this" and have
    it stick.
    """
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is not None:
            finding.status = status


def _badge(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color: {color}; font-size: 9px; font-weight: 700; "
        f"border: 1px solid {color}; border-radius: 5px; padding: 1px 6px;"
    )
    return lbl


class _FindingCard(QFrame):
    def __init__(self, finding_id: int, finding: Finding, on_status_change=None, parent=None):
        super().__init__(parent)
        self.setProperty("class", "Card")
        color = _SEVERITY_COLOR.get(finding.severity, Colors.TEXT_MUTED)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        bar = QFrame()
        bar.setFixedWidth(4)
        bar.setStyleSheet(f"background-color: {color}; border-top-left-radius: 6px; border-bottom-left-radius: 6px;")
        outer.addWidget(bar)

        body = QVBoxLayout()
        body.setContentsMargins(12, 10, 12, 10)
        body.setSpacing(6)

        header = QHBoxLayout()
        header.setSpacing(6)
        title = QLabel(finding.title)
        title.setWordWrap(True)
        title.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 13px; font-weight: 700;")
        header.addWidget(title, stretch=1)
        header.addWidget(_badge(finding.severity.value.upper(), color))
        body.addLayout(header)

        badges = QHBoxLayout()
        badges.setSpacing(6)
        if finding.category:
            badges.addWidget(_badge(finding.category, Colors.TEXT_SECONDARY))
        if finding.owasp_mapping:
            badges.addWidget(_badge(finding.owasp_mapping, Colors.ACCENT_PURPLE))
        if finding.masvs_mapping:
            badges.addWidget(_badge(finding.masvs_mapping, Colors.ACCENT_CYAN))
        if finding.mitre_mapping:
            badges.addWidget(_badge(finding.mitre_mapping, Colors.ACCENT_ORANGE))
        badges.addStretch()
        if badges.count() > 1:  # more than just the trailing stretch
            body.addLayout(badges)

        if finding.description:
            desc = QLabel(finding.description)
            desc.setWordWrap(True)
            desc.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 11px;")
            body.addWidget(desc)

        if finding.evidence:
            evidence = QLabel(finding.evidence)
            evidence.setWordWrap(True)
            evidence.setTextInteractionFlags(Qt.TextSelectableByMouse)
            evidence.setStyleSheet(
                f"color: {Colors.TEXT_PRIMARY}; font-size: 10px; font-family: 'Consolas', 'Monaco', monospace; "
                f"background-color: {Colors.BG_INPUT}; border: 1px solid {Colors.BORDER}; "
                f"border-radius: 4px; padding: 6px;"
            )
            body.addWidget(evidence)

        if finding.file_path:
            loc = finding.file_path + (f":{finding.line_number}" if finding.line_number else "")
            loc_lbl = QLabel(loc)
            loc_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 9px; font-family: monospace;")
            body.addWidget(loc_lbl)

        if finding.recommendation:
            rec = QLabel(f"\u2192 {finding.recommendation}")
            rec.setWordWrap(True)
            rec.setStyleSheet(f"color: {Colors.ACCENT_GREEN}; font-size: 10px;")
            body.addWidget(rec)

        # Triage row: FindingStatus already existed on the model (OPEN /
        # CONFIRMED / FALSE_POSITIVE / FIXED / ACCEPTED_RISK) but nothing in
        # the app ever set or displayed it, so a researcher working through
        # a long list had no way to record "I've reviewed this" and have it
        # persist. One combo box per card, backed by set_finding_status().
        status_row = QHBoxLayout()
        status_row.setSpacing(6)
        status_caption = QLabel("Status:")
        status_caption.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        status_row.addWidget(status_caption)
        combo = QComboBox()
        combo.setFixedWidth(150)
        for status in _STATUS_ORDER:
            combo.addItem(_STATUS_LABELS[status], status)
        combo.setCurrentIndex(_STATUS_ORDER.index(finding.status))
        self._apply_status_color(combo, finding.status)
        if on_status_change is not None:
            combo.currentIndexChanged.connect(
                lambda idx: self._on_status_index_changed(finding_id, combo, on_status_change)
            )
        status_row.addWidget(combo)
        status_row.addStretch()
        body.addLayout(status_row)

        outer.addLayout(body, stretch=1)

    @staticmethod
    def _apply_status_color(combo: QComboBox, status: FindingStatus) -> None:
        color = _STATUS_COLOR.get(status, Colors.TEXT_SECONDARY)
        combo.setStyleSheet(f"QComboBox {{ color: {color}; border-color: {color}; }}")

    def _on_status_index_changed(self, finding_id: int, combo: QComboBox, on_status_change) -> None:
        new_status = combo.currentData()
        self._apply_status_color(combo, new_status)
        on_status_change(finding_id, new_status)


class FindingsDialog(QDialog):
    """Full findings report for one analysis, grouped by severity."""

    # Column indices into each row tuple in self._all_findings -- named so
    # _rebuild_list doesn't rely on remembering row[0] vs row[11] by position.
    _COL_ID, _COL_STATUS = 11, 12

    def __init__(self, analysis_id: int, parent=None):
        super().__init__(parent)
        self.setMinimumSize(720, 640)

        with session_scope() as session:
            analysis = session.get(Analysis, analysis_id)
            project = session.get(Project, analysis.project_id) if analysis else None
            findings = (
                session.query(Finding).filter_by(analysis_id=analysis_id).all()
                if analysis else []
            )
            # id and status are now included -- previously this tuple had
            # neither, so there was no way to persist a triage decision back
            # to the right row, and no way to know a finding's current status
            # to display it.
            self._all_findings = [
                (f.severity, f.title, f.category, f.owasp_mapping, f.masvs_mapping,
                 f.mitre_mapping, f.description, f.evidence, f.file_path, f.line_number,
                 f.recommendation, f.id, f.status)
                for f in findings
            ]
            self._project_name = project.name if project else "Unknown Project"
            self._workflow_name = analysis.workflow_name if analysis else ""
            self._risk_score = analysis.risk_score if analysis else None

        self.setWindowTitle(f"Findings \u2014 {self._project_name}")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(10)

        header = QLabel(f"{self._project_name} \u2014 {self._workflow_name}")
        header.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 16px; font-weight: 700;")
        outer.addWidget(header)

        self._sub_label = QLabel()
        self._sub_label.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 11px;")
        outer.addWidget(self._sub_label)

        # FindingStatus (OPEN/CONFIRMED/FALSE_POSITIVE/FIXED/ACCEPTED_RISK)
        # already existed on the model but nothing ever set or filtered on
        # it. Checked by default so a re-opened dialog leads with what still
        # needs attention rather than re-showing everything already dismissed.
        self._hide_reviewed = QCheckBox("Hide reviewed (false positive / fixed)")
        self._hide_reviewed.setChecked(True)
        self._hide_reviewed.toggled.connect(self._rebuild_list)
        outer.addWidget(self._hide_reviewed)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        outer.addWidget(self._scroll, stretch=1)

        self._rebuild_list()

    def _on_status_change(self, finding_id: int, new_status: FindingStatus) -> None:
        set_finding_status(finding_id, new_status)
        # Update the in-memory copy too, so a rebuild (from toggling the
        # filter checkbox right after) reflects the change without a re-query.
        self._all_findings = [
            row[: self._COL_STATUS] + (new_status,) if row[self._COL_ID] == finding_id else row
            for row in self._all_findings
        ]
        if self._hide_reviewed.isChecked() and new_status in _HIDDEN_BY_DEFAULT:
            self._rebuild_list()

    def _rebuild_list(self) -> None:
        hide_reviewed = self._hide_reviewed.isChecked()
        visible = [
            row for row in self._all_findings
            if not (hide_reviewed and row[self._COL_STATUS] in _HIDDEN_BY_DEFAULT)
        ]
        hidden_count = len(self._all_findings) - len(visible)

        if self._risk_score is not None:
            text = f"Risk score: {self._risk_score:.1f}/10 \u2022 {len(self._all_findings)} finding(s)"
        else:
            text = f"{len(self._all_findings)} finding(s)"
        if hidden_count:
            text += f" \u2022 {hidden_count} hidden (reviewed)"
        self._sub_label.setText(text)

        container = QWidget()
        col = QVBoxLayout(container)
        col.setSpacing(8)
        col.setAlignment(Qt.AlignTop)

        if not self._all_findings:
            empty = QLabel("No findings for this analysis (a clean result, or every step was skipped).")
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 12px; padding: 30px;")
            empty.setAlignment(Qt.AlignCenter)
            col.addWidget(empty)
        elif not visible:
            empty = QLabel("Every finding here has been reviewed. Uncheck \u201cHide reviewed\u201d to see them.")
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 12px; padding: 30px;")
            empty.setAlignment(Qt.AlignCenter)
            col.addWidget(empty)
        else:
            by_severity: dict[Severity, list] = {s: [] for s in _SEVERITY_ORDER}
            for row in visible:
                by_severity.setdefault(row[0], []).append(row)

            for severity in _SEVERITY_ORDER:
                rows = by_severity.get(severity, [])
                if not rows:
                    continue
                section = QLabel(f"{severity.value.upper()} ({len(rows)})")
                section.setStyleSheet(
                    f"color: {_SEVERITY_COLOR[severity]}; font-size: 11px; font-weight: 700; "
                    f"letter-spacing: 1px; margin-top: 6px;"
                )
                col.addWidget(section)
                for row in rows:
                    finding_id, status = row[self._COL_ID], row[self._COL_STATUS]
                    finding = Finding(
                        severity=row[0], title=row[1], category=row[2], owasp_mapping=row[3],
                        masvs_mapping=row[4], mitre_mapping=row[5], description=row[6],
                        evidence=row[7], file_path=row[8], line_number=row[9], recommendation=row[10],
                        status=status,
                    )
                    col.addWidget(_FindingCard(finding_id, finding, self._on_status_change))

        self._scroll.setWidget(container)
