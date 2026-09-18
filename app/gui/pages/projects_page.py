"""
app.gui.pages.projects_page
==============================

Lists every real project in the database, lets the user create a new
one (``NewProjectDialog``), and trigger a real static-analysis run
against it via ``AnalysisRunner`` -- which goes through
``WorkflowManager`` exactly as the architecture requires; this page
never touches a Plugin or Tool directly.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from app.database.database import session_scope
from app.database.models import Analysis, Project
from app.gui.controllers.analysis_runner import get_analysis_runner
from app.gui.dialogs.new_project_dialog import NewProjectDialog
from app.gui.icon_provider import icon_label
from app.gui.theme import Colors, severity_color


class _ProjectRow(QFrame):
    def __init__(self, project_id: int, name: str, platform: str, project_type: str,
                 target_path: str | None, latest_status: str | None, latest_risk: float | None,
                 on_run_static, parent=None):
        super().__init__(parent)
        self.project_id = project_id
        self.setProperty("class", "Card")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        icon_lbl = icon_label("android_apk" if platform == "android" else "ios_analysis", size=20)
        layout.addWidget(icon_lbl)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 13px; font-weight: 700;")
        text_col.addWidget(name_lbl)
        sub_lbl = QLabel(f"{platform} \u2022 {project_type} \u2022 {target_path or 'no target file'}")
        sub_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        text_col.addWidget(sub_lbl)
        layout.addLayout(text_col, stretch=1)

        if latest_status:
            color = {
                "completed": Colors.ACCENT_GREEN, "failed": Colors.STATUS_ERROR,
                "running": Colors.STATUS_RUNNING,
            }.get(latest_status, Colors.TEXT_MUTED)
            status_lbl = QLabel(latest_status.upper())
            status_lbl.setStyleSheet(
                f"color: {color}; font-size: 10px; font-weight: 700; "
                f"border: 1px solid {color}; border-radius: 6px; padding: 2px 8px;"
            )
            layout.addWidget(status_lbl)

        if latest_risk is not None:
            risk_lbl = QLabel(f"Risk {latest_risk:.1f}")
            risk_color = severity_color("critical" if latest_risk >= 7 else "high" if latest_risk >= 4 else "low")
            risk_lbl.setStyleSheet(f"color: {risk_color}; font-size: 11px; font-weight: 600;")
            layout.addWidget(risk_lbl)

        self._run_btn = QPushButton("Run Static Analysis")
        self._run_btn.setEnabled(bool(target_path))
        self._run_btn.clicked.connect(lambda: on_run_static(self))
        layout.addWidget(self._run_btn)

        self._status_note = QLabel("")
        self._status_note.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        layout.addWidget(self._status_note)

    def set_running(self, percent: float, step: str) -> None:
        self._run_btn.setEnabled(False)
        self._status_note.setText(f"{step} ({percent:.0f}%)")

    def set_done(self, status: str, detail: str = "") -> None:
        self._run_btn.setEnabled(True)
        text = f"Last run: {status}"
        if detail:
            text += f" -- {detail}"
        self._status_note.setText(text)
        self._status_note.setToolTip(detail)


class ProjectsPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._runner = get_analysis_runner()
        self._runner.progress.connect(self._on_progress)
        self._runner.completed.connect(self._on_completed)
        self._runner.failed_to_start.connect(self._on_failed_to_start)
        self._job_rows: dict[str, _ProjectRow] = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(14)

        header = QHBoxLayout()
        title = QLabel("Projects")
        title.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()
        new_btn = QPushButton("+ New Project")
        new_btn.setProperty("class", "Primary")
        new_btn.clicked.connect(self._on_new_project)
        header.addWidget(new_btn)
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

    def _on_new_project(self) -> None:
        dialog = NewProjectDialog(self)
        if dialog.exec() == dialog.DialogCode.Accepted and dialog.created_project_id:
            self._main_window.set_status(f"Project created (id={dialog.created_project_id})", Colors.ACCENT_GREEN)
            self.refresh()

    def _on_run_static(self, row: "_ProjectRow") -> None:
        with session_scope() as session:
            project = session.get(Project, row.project_id)
            if project is None or not project.target_path:
                return
            target_path, workspace_path = project.target_path, project.workspace_path

        job_id = self._runner.start("static_analysis_default", row.project_id, target_path, workspace_path)
        if job_id:
            self._job_rows[job_id] = row
            self._main_window.set_status(f"Started static analysis for {row.project_id}", Colors.STATUS_RUNNING)

    def _on_progress(self, job_id: str, percent: float, step: str) -> None:
        row = self._job_rows.get(job_id)
        if row:
            row.set_running(percent, step or "Starting...")

    def _on_completed(self, job_id: str, status: str, risk_score: float, analysis_id: int) -> None:
        row = self._job_rows.pop(job_id, None)

        detail = ""
        if status == "completed":
            with session_scope() as session:
                from app.database.models import Finding
                finding_count = session.query(Finding).filter_by(analysis_id=analysis_id).count()
                analysis = session.get(Analysis, analysis_id)
                notes = analysis.error_message or ""

            skipped_steps = [
                line.split("]:")[0].split("[")[-1]
                for line in notes.splitlines() if line.startswith("SKIPPED")
            ]
            if finding_count == 0 and skipped_steps:
                detail = (
                    f"0 findings -- {len(skipped_steps)} step(s) skipped "
                    f"({', '.join(skipped_steps)}). Install missing tools in Settings for a full scan."
                )
            elif finding_count == 0:
                detail = "0 findings (a clean result, not a broken scan)"
            else:
                detail = f"{finding_count} finding(s)"

        if row:
            row.set_done(status, detail)

        report_note = ""
        if status == "completed":
            # HTML for a human to read, SARIF for everything else to consume
            # (GitHub code scanning, DefectDojo, VS Code, CI gates). Generating
            # both automatically is what makes the tool usable in a pipeline
            # rather than only interactively.
            from app.core.report_engine import get_report_engine
            from app.database.models import ReportFormat

            generated, failed = [], []
            for fmt in (ReportFormat.HTML, ReportFormat.SARIF):
                try:
                    get_report_engine().generate(analysis_id, fmt)
                    generated.append(fmt.value.upper())
                except Exception as exc:  # noqa: BLE001 - a report failure must not hide the analysis result
                    failed.append(f"{fmt.value}: {exc}")
            if generated:
                report_note = f" -- {'/'.join(generated)} report(s) generated"
            if failed:
                report_note += f" -- report generation failed ({'; '.join(failed)})"

        status_message = f"Analysis {status} (risk score {risk_score:.1f})"
        if detail:
            status_message += f" -- {detail}"
        status_message += report_note

        self._main_window.set_status(
            status_message,
            Colors.ACCENT_GREEN if status == "completed" else Colors.STATUS_ERROR,
        )
        self.refresh()

    def _on_failed_to_start(self, message: str) -> None:
        self._main_window.set_status(f"Failed to start analysis: {message}", Colors.STATUS_ERROR)

    def refresh(self) -> None:
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        with session_scope() as session:
            projects = session.query(Project).order_by(Project.updated_at.desc()).all()
            rows_data = []
            for p in projects:
                latest = (
                    session.query(Analysis)
                    .filter_by(project_id=p.id)
                    .order_by(Analysis.created_at.desc())
                    .first()
                )
                rows_data.append((
                    p.id, p.name, p.platform.value, p.project_type.value, p.target_path,
                    latest.status.value if latest else None,
                    latest.risk_score if latest else None,
                ))

        if not rows_data:
            empty = QLabel("No projects yet. Click \u201c+ New Project\u201d to get started.")
            empty.setAlignment(Qt.AlignCenter)
            empty.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 12px; padding: 40px;")
            self._list_layout.addWidget(empty)
            return

        for row_data in rows_data:
            row = _ProjectRow(*row_data, on_run_static=self._on_run_static)
            self._list_layout.addWidget(row)
