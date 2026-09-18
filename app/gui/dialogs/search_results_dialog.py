"""
app.gui.dialogs.search_results_dialog
========================================

Real behaviour behind the top bar's search field.

Before this, ``TopBar.search_changed`` fired on every keystroke and was
connected to nothing anywhere in the codebase (confirmed by grep) -- a
field labelled "Search (Ctrl+K)" that looked interactive and did
absolutely nothing, which is worse than not having a search box at all
because it actively misleads. This dialog is what pressing Enter in
that field, or Ctrl+K, now opens: a single query across the three
things worth finding by name -- projects, analyses, and findings --
with each result clickable straight to where it lives.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QFrame, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from app.database.database import session_scope
from app.database.models import Analysis, Finding, Project
from app.gui.theme import Colors

_MAX_RESULTS_PER_KIND = 8
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _label(text: str, size: int = 12, color: str | None = None, bold: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(
        f"color: {color or Colors.TEXT_PRIMARY}; font-size: {size}px; "
        f"font-weight: {700 if bold else 400};"
    )
    return lbl


def search_everything(query: str) -> dict[str, list]:
    """
    Case-insensitive substring search across project names, analysis
    workflow names, and finding titles. Returns plain dicts (not ORM
    objects) so the results outlive the session they were queried in --
    the dialog is built after this returns, well past the ``with``
    block's session lifetime.
    """
    query = query.strip()
    if not query:
        return {"projects": [], "analyses": [], "findings": []}

    like = f"%{query}%"
    with session_scope() as session:
        projects = (
            session.query(Project)
            .filter(Project.name.ilike(like))
            .order_by(Project.updated_at.desc())
            .limit(_MAX_RESULTS_PER_KIND)
            .all()
        )
        project_hits = [{"id": p.id, "name": p.name, "platform": p.platform.value} for p in projects]

        analyses = (
            session.query(Analysis, Project)
            .join(Project, Analysis.project_id == Project.id)
            .filter(Analysis.workflow_name.ilike(like))
            .order_by(Analysis.created_at.desc())
            .limit(_MAX_RESULTS_PER_KIND)
            .all()
        )
        analysis_hits = [
            {
                "id": a.id, "workflow_name": a.workflow_name, "status": a.status.value,
                "project_name": p.name,
            }
            for a, p in analyses
        ]

        # Fetched without an ORDER BY on severity: the enum's string values
        # ("critical", "high", "medium", "low", "info") don't sort into
        # severity-priority order alphabetically (info < low, backwards), so
        # sorting happens below with an explicit rank instead.
        findings = (
            session.query(Finding, Analysis, Project)
            .join(Analysis, Finding.analysis_id == Analysis.id)
            .join(Project, Analysis.project_id == Project.id)
            .filter(Finding.title.ilike(like))
            .limit(_MAX_RESULTS_PER_KIND * 4)  # over-fetch, then take the worst N after ranking
            .all()
        )
        finding_hits = [
            {
                "id": f.id, "title": f.title, "severity": f.severity.value,
                "analysis_id": a.id, "project_name": p.name,
            }
            for f, a, p in findings
        ]
        finding_hits.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 99))
        finding_hits = finding_hits[:_MAX_RESULTS_PER_KIND]

    return {"projects": project_hits, "analyses": analysis_hits, "findings": finding_hits}


class _ResultRow(QFrame):
    def __init__(self, title: str, subtitle: str, on_click, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CardAlt")
        self.setCursor(Qt.PointingHandCursor)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)
        layout.addWidget(_label(title, size=12, bold=True))
        layout.addWidget(_label(subtitle, size=10, color=Colors.TEXT_MUTED))
        self._on_click = on_click

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self._on_click()
        super().mouseReleaseEvent(event)


class SearchResultsDialog(QDialog):
    """
    Pass the ``MainWindow`` so results can navigate the real sidebar pages
    (``main_window._navigate``) or open ``FindingsDialog`` directly rather
    than duplicating that logic here.
    """

    def __init__(self, main_window, query: str, parent=None):
        super().__init__(parent or main_window)
        self.main_window = main_window
        self.setWindowTitle(f"Search: {query}")
        self.resize(520, 560)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(10)
        outer.addWidget(_label(f"Results for \u201c{query}\u201d", size=16, bold=True))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        content = QWidget()
        self._body = QVBoxLayout(content)
        self._body.setContentsMargins(0, 0, 0, 0)
        self._body.setSpacing(10)
        scroll.setWidget(content)

        results = search_everything(query)
        total = sum(len(v) for v in results.values())
        if total == 0:
            self._body.addWidget(_label(
                "No projects, analyses, or findings match that search.",
                size=11, color=Colors.TEXT_MUTED,
            ))
        else:
            self._add_section("PROJECTS", results["projects"], self._project_row)
            self._add_section("ANALYSES", results["analyses"], self._analysis_row)
            self._add_section("FINDINGS", results["findings"], self._finding_row)
        self._body.addStretch()

    def _add_section(self, heading: str, items: list[dict], row_builder) -> None:
        if not items:
            return
        self._body.addWidget(_label(heading, size=10, color=Colors.TEXT_SECONDARY, bold=True))
        for item in items:
            self._body.addWidget(row_builder(item))

    def _project_row(self, item: dict) -> _ResultRow:
        def go():
            self.accept()
            self.main_window._navigate("projects")
            self.main_window.set_status(f"Opened Projects \u2014 showing '{item['name']}'", Colors.ACCENT_GREEN)

        return _ResultRow(item["name"], f"{item['platform']} project", go)

    def _analysis_row(self, item: dict) -> _ResultRow:
        def go():
            self.accept()
            self.main_window._navigate("analyses")
            self.main_window.set_status(
                f"Opened Analyses \u2014 '{item['workflow_name']}' on {item['project_name']}",
                Colors.ACCENT_GREEN,
            )

        return _ResultRow(
            item["workflow_name"], f"{item['project_name']}  \u2022  {item['status']}", go
        )

    def _finding_row(self, item: dict) -> _ResultRow:
        def go():
            self.accept()
            from app.gui.dialogs.findings_dialog import FindingsDialog
            FindingsDialog(item["analysis_id"], self.main_window).exec()

        return _ResultRow(
            item["title"], f"{item['severity'].upper()}  \u2022  {item['project_name']}", go
        )
