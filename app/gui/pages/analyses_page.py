"""
app.gui.pages.analyses_page
==============================

Lists every real ``Analysis`` row (joined with its ``Project`` for
context): workflow, status, risk score, finding count, and -- this is
the part that matters -- *why* a run has 0 findings if it does
(SKIPPED steps because a required tool like APKTool/JADX isn't
installed, or a FAILED step). Before this page existed, the only way
to see that was a status-bar toast that scrolled away.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from app.database.database import session_scope
from app.database.models import Analysis, Finding, Project, RunStatus
from app.gui.dialogs.findings_dialog import FindingsDialog
from app.gui.icon_provider import get_icon, get_pixmap
from app.gui.theme import Colors

_STATUS_STYLE = {
    RunStatus.COMPLETED: ("check-circle-outline", Colors.ACCENT_GREEN),
    RunStatus.FAILED: ("close-circle-outline", Colors.STATUS_ERROR),
    RunStatus.RUNNING: ("progress-clock", Colors.STATUS_RUNNING),
    RunStatus.PENDING: ("timer-sand-empty", Colors.TEXT_MUTED),
    RunStatus.QUEUED: ("timer-sand", Colors.TEXT_MUTED),
    RunStatus.CANCELLED: ("cancel", Colors.STATUS_WARNING),
}


def _skip_summary(error_message: str | None) -> list[str]:
    if not error_message:
        return []
    return [
        line.split("]:")[0].split("[")[-1]
        for line in error_message.splitlines()
        if line.startswith("SKIPPED")
    ]


class _AnalysisRow(QFrame):
    def __init__(self, analysis_id: int, project_name: str, workflow_name: str,
                 status: RunStatus, risk_score: float | None, finding_count: int,
                 created_at, error_message: str | None, on_details, on_view_findings, parent=None):
        super().__init__(parent)
        self.setProperty("class", "Card")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        icon_name, color = _STATUS_STYLE.get(status, ("help-circle-outline", Colors.TEXT_MUTED))
        icon = QLabel()
        icon.setPixmap(get_pixmap(icon_name, color, 20))
        layout.addWidget(icon)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        name_lbl = QLabel(f"{project_name} \u2014 {workflow_name}")
        name_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 13px; font-weight: 700;")
        text_col.addWidget(name_lbl)

        skipped = _skip_summary(error_message)
        if status == RunStatus.COMPLETED and finding_count == 0 and skipped:
            detail = f"0 findings \u2014 {len(skipped)} step(s) skipped ({', '.join(skipped)})"
            detail_color = Colors.STATUS_WARNING
        elif status == RunStatus.FAILED:
            detail = (error_message or "Failed").splitlines()[0][:120]
            detail_color = Colors.STATUS_ERROR
        else:
            detail = f"{finding_count} finding(s)"
            detail_color = Colors.TEXT_MUTED
        detail_lbl = QLabel(f"{detail} \u2022 {created_at:%Y-%m-%d %H:%M}")
        detail_lbl.setWordWrap(True)
        detail_lbl.setStyleSheet(f"color: {detail_color}; font-size: 10px;")
        text_col.addWidget(detail_lbl)
        layout.addLayout(text_col, stretch=1)

        if risk_score is not None:
            risk_lbl = QLabel(f"{risk_score:.1f}")
            risk_color = (
                Colors.SEVERITY_CRITICAL if risk_score >= 7
                else Colors.SEVERITY_MEDIUM if risk_score >= 4
                else Colors.ACCENT_GREEN
            )
            risk_lbl.setStyleSheet(f"color: {risk_color}; font-size: 14px; font-weight: 700;")
            layout.addWidget(risk_lbl)

        status_badge = QLabel(status.value.upper())
        status_badge.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: 700; "
            f"border: 1px solid {color}; border-radius: 6px; padding: 2px 8px;"
        )
        layout.addWidget(status_badge)

        if finding_count > 0:
            findings_btn = QPushButton(f"View {finding_count} Finding(s)")
            findings_btn.setProperty("class", "Primary")
            findings_btn.clicked.connect(lambda: on_view_findings(analysis_id))
            layout.addWidget(findings_btn)

        if error_message:
            details_btn = QPushButton("Details")
            details_btn.clicked.connect(lambda: on_details(analysis_id, error_message))
            layout.addWidget(details_btn)


class AnalysesPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(14)

        header = QHBoxLayout()
        title = QLabel("All Analyses")
        title.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setIcon(get_icon("refresh", Colors.TEXT_PRIMARY, 14))
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)
        outer.addLayout(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        list_container = QWidget()
        self._list_layout = QVBoxLayout(list_container)
        self._list_layout.setSpacing(8)
        self._list_layout.setAlignment(Qt.AlignTop)
        scroll.setWidget(list_container)
        outer.addWidget(scroll, stretch=1)

        self.refresh()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        self.refresh()

    def _on_details(self, analysis_id: int, error_message: str) -> None:
        QMessageBox.information(self, f"Analysis #{analysis_id} details", error_message)

    def _on_view_findings(self, analysis_id: int) -> None:
        FindingsDialog(analysis_id, self).exec()

    def refresh(self) -> None:
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        with session_scope() as session:
            analyses = session.query(Analysis).order_by(Analysis.created_at.desc()).all()
            rows_data = []
            for a in analyses:
                project = session.get(Project, a.project_id)
                finding_count = session.query(Finding).filter_by(analysis_id=a.id).count()
                rows_data.append((
                    a.id, project.name if project else "Unknown Project", a.workflow_name,
                    a.status, a.risk_score, finding_count, a.created_at, a.error_message,
                ))

        if not rows_data:
            empty = QLabel(
                "No analyses yet. Open a project and click \u201cRun Static Analysis\u201d "
                "(or another workflow) to see results here."
            )
            empty.setAlignment(Qt.AlignCenter)
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 12px; padding: 40px;")
            self._list_layout.addWidget(empty)
            return

        for row_data in rows_data:
            self._list_layout.addWidget(
                _AnalysisRow(*row_data, on_details=self._on_details, on_view_findings=self._on_view_findings)
            )
