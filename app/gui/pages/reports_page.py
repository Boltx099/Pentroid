"""
app.gui.pages.reports_page
=============================

Lists every real ``Report`` row (joined with its ``Analysis`` ->
``Project`` for context), lets the user open a report in the OS's
default application for that file type, or delete it (removes both
the file on disk and the DB row -- never one without the other).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget

from app.database.database import session_scope
from app.database.models import Analysis, Project, Report
from app.gui.icon_provider import get_icon, get_pixmap
from app.gui.theme import Colors

_FORMAT_ICONS = {
    "html": ("web", Colors.ACCENT_CYAN),
    "pdf": ("file-pdf-box", Colors.SEVERITY_CRITICAL),
    "json": ("code-json", Colors.SEVERITY_MEDIUM),
    "csv": ("file-table-outline", Colors.ACCENT_GREEN),
    "markdown": ("language-markdown-outline", Colors.TEXT_SECONDARY),
    "sarif": ("shield-check-outline", Colors.ACCENT_PURPLE),
}


class _ReportRow(QFrame):
    def __init__(self, report_id: int, file_path: str, fmt: str, project_name: str,
                 analysis_type: str, generated_at, summary: str | None,
                 on_open, on_delete, parent=None):
        super().__init__(parent)
        self.report_id = report_id
        self.file_path = file_path
        self.setProperty("class", "Card")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        icon_name, icon_color = _FORMAT_ICONS.get(fmt, ("file-document-outline", Colors.TEXT_MUTED))
        icon = QLabel()
        icon.setPixmap(get_pixmap(icon_name, icon_color, 20))
        layout.addWidget(icon)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        name_lbl = QLabel(f"{project_name} \u2014 {analysis_type}")
        name_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 13px; font-weight: 700;")
        text_col.addWidget(name_lbl)
        detail = f"{Path(file_path).name} \u2022 {generated_at:%Y-%m-%d %H:%M}"
        if summary:
            detail += f" \u2022 {summary}"
        detail_lbl = QLabel(detail)
        detail_lbl.setWordWrap(True)
        detail_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        text_col.addWidget(detail_lbl)
        layout.addLayout(text_col, stretch=1)

        fmt_badge = QLabel(fmt.upper())
        fmt_badge.setStyleSheet(
            f"color: {icon_color}; font-size: 10px; font-weight: 700; "
            f"border: 1px solid {icon_color}; border-radius: 6px; padding: 2px 8px;"
        )
        layout.addWidget(fmt_badge)

        open_btn = QPushButton("Open")
        open_btn.setEnabled(Path(file_path).exists())
        open_btn.clicked.connect(lambda: on_open(file_path))
        layout.addWidget(open_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(lambda: on_delete(report_id, file_path, self))
        layout.addWidget(delete_btn)


class ReportsPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window

        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(14)

        header = QHBoxLayout()
        title = QLabel("Reports")
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

    def _on_open(self, file_path: str) -> None:
        path = Path(file_path)
        if not path.exists():
            self._main_window.set_status(f"File no longer exists: {path.name}", Colors.STATUS_ERROR)
            return
        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        if opened:
            self._main_window.set_status(f"Opened {path.name}", Colors.ACCENT_GREEN)
        else:
            self._main_window.set_status(f"Could not open {path.name} (no default application?)", Colors.STATUS_WARNING)

    def _on_delete(self, report_id: int, file_path: str, row_widget) -> None:
        confirm = QMessageBox.question(
            self, "Delete Report",
            f"Delete {Path(file_path).name}? This removes the file from disk and cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        with session_scope() as session:
            report = session.get(Report, report_id)
            if report is not None:
                session.delete(report)

        path = Path(file_path)
        if path.exists():
            try:
                path.unlink()
            except OSError as exc:
                self._main_window.set_status(f"Removed DB record but failed to delete file: {exc}", Colors.STATUS_WARNING)
                self.refresh()
                return

        self._main_window.set_status("Report deleted", Colors.ACCENT_GREEN)
        self.refresh()

    def refresh(self) -> None:
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        with session_scope() as session:
            reports = session.query(Report).order_by(Report.generated_at.desc()).all()
            rows_data = []
            for r in reports:
                analysis = session.get(Analysis, r.analysis_id)
                project = session.get(Project, analysis.project_id) if analysis else None
                rows_data.append((
                    r.id, r.file_path, r.format.value,
                    project.name if project else "Unknown Project",
                    analysis.analysis_type.value if analysis else "unknown",
                    r.generated_at, r.summary,
                ))

        if not rows_data:
            empty = QLabel("No reports generated yet. Reports are created automatically when an analysis completes.")
            empty.setAlignment(Qt.AlignCenter)
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 12px; padding: 40px;")
            self._list_layout.addWidget(empty)
            return

        for row_data in rows_data:
            self._list_layout.addWidget(_ReportRow(*row_data, on_open=self._on_open, on_delete=self._on_delete))
