"""
app.gui.pages.dashboard_page
===============================

The Dashboard page from the mockup. Every number and list on this
page comes from a real SQLAlchemy query against the actual Pentroid
database -- there is no fake/sample data baked into the GUI. On a
fresh install with zero projects, panels render genuine empty states
("No projects yet -- click New Project to get started") rather than
placeholder numbers.

Per architecture rule, this page never touches a Plugin or Tool
directly -- "New Project" / "Static Analysis" etc. quick-action
buttons will, once wired, call into ``WorkflowManager`` only.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPlainTextEdit,
    QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from app.core.config import get_settings
from app.core.dependency_manager import get_dependency_manager
from app.database.database import session_scope
from app.database.models import Analysis, Device, Finding, Project, Report, RunStatus, Severity
from app.gui.theme import Colors, severity_color
from app.gui.widgets.cards import ListRow, QuickActionCard
from app.gui.widgets.charts import DonutChart, GaugeChart, SeverityBar, SparklineChart


def _card(title: str | None = None) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setProperty("class", "Card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(8)
    if title:
        header = QLabel(title)
        header.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 12px; font-weight: 700;")
        layout.addWidget(header)
    return frame, layout


def _empty_state(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 11px; padding: 16px;")
    return lbl


class DashboardPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        content = QWidget()
        self._layout = QVBoxLayout(content)
        self._layout.setContentsMargins(18, 16, 18, 16)
        self._layout.setSpacing(14)
        scroll.setWidget(content)

        self._layout.addWidget(self._build_header())
        self._layout.addWidget(self._build_quick_actions())

        row1 = QHBoxLayout()
        row1.setSpacing(14)
        self._recent_projects_card, self._recent_projects_layout = _card("RECENT PROJECTS")
        self._analyses_chart_card, self._analyses_chart_layout = _card("ANALYSES OVER TIME (Last 7 Days)")
        self._findings_category_card, self._findings_category_layout = _card("FINDINGS BY CATEGORY")
        row1.addWidget(self._recent_projects_card, stretch=1)
        row1.addWidget(self._analyses_chart_card, stretch=1)
        row1.addWidget(self._findings_category_card, stretch=1)
        self._layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(14)
        self._recent_analyses_card, self._recent_analyses_layout = _card("RECENT ANALYSES")
        self._severity_card, self._severity_layout = _card("FINDINGS SEVERITY")
        self._logs_card, self._logs_layout = _card("LIVE LOGS")
        row2.addWidget(self._recent_analyses_card, stretch=1)
        row2.addWidget(self._severity_card, stretch=1)
        row2.addWidget(self._logs_card, stretch=1)
        self._layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.setSpacing(14)
        self._devices_card, self._devices_layout = _card("CONNECTED DEVICES")
        self._queue_card, self._queue_layout = _card("ANALYSIS QUEUE")
        self._reports_card, self._reports_layout = _card("RECENT REPORTS")
        row3.addWidget(self._devices_card, stretch=1)
        row3.addWidget(self._queue_card, stretch=1)
        row3.addWidget(self._reports_card, stretch=1)
        self._layout.addLayout(row3)

        self._layout.addStretch()

        self._build_right_panel()

        self.refresh()
        self._log_timer = QTimer(self)
        self._log_timer.timeout.connect(self._refresh_logs)
        self._log_timer.start(2000)

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        # Re-pull real data every time the user navigates back to this tab,
        # not just on first load -- otherwise a scan run from the Projects
        # page (or any other tab) leaves Dashboard showing stale recent-
        # projects/analyses lists and right-panel numbers until restart.
        super().showEvent(event)
        self.refresh()

    # ------------------------------------------------------------------ #
    # Header / quick actions
    # ------------------------------------------------------------------ #
    def _build_header(self) -> QWidget:
        wrap = QWidget()
        layout = QHBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)

        text_col = QVBoxLayout()
        settings = get_settings()
        welcome = QLabel("Welcome back!")
        welcome.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 20px; font-weight: 700;")
        text_col.addWidget(welcome)
        sub = QLabel("Complete Mobile Application Security Assessment Platform")
        sub.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px;")
        text_col.addWidget(sub)
        layout.addLayout(text_col)
        layout.addStretch()
        return wrap

    def _build_quick_actions(self) -> QWidget:
        wrap = QWidget()
        layout = QHBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        actions = [
            ("add", "New Project", "Start a new assessment", self._on_new_project),
            ("static_analysis", "Static Analysis", "Analyze APK / IPA", lambda: self._navigate_stub("static_analysis")),
            ("dynamic_analysis", "Dynamic Analysis", "Run on Device", lambda: self._navigate_stub("dynamic_analysis")),
            ("android_malware", "Malware Analysis", "Detect & Analyze", lambda: self._navigate_stub("android_malware")),
            ("import", "Import Project", "Import existing project", self._on_import_project),
        ]
        for icon, title, subtitle, handler in actions:
            card = QuickActionCard(icon, title, subtitle)
            card.clicked.connect(handler)
            layout.addWidget(card)
        return wrap

    def _on_new_project(self) -> None:
        from app.gui.dialogs.new_project_dialog import NewProjectDialog

        dialog = NewProjectDialog(self)
        if dialog.exec() == dialog.DialogCode.Accepted and dialog.created_project_id:
            self._main_window.set_status(f"Project created (id={dialog.created_project_id})", Colors.ACCENT_GREEN)
            self.refresh()
            if "projects" in self._main_window._pages:
                self._main_window._pages["projects"].refresh()

    def _on_import_project(self) -> None:
        self._on_new_project()  # "Import" and "New Project" both go through the same real creation flow

    def _navigate_stub(self, key: str) -> None:
        if key == "static_analysis":
            self._main_window.sidebar.navigate.emit("projects")
            self._main_window.set_status("Select a project and click 'Run Static Analysis'", Colors.STATUS_RUNNING)
        else:
            self._main_window.set_status(f"'{key.replace('_', ' ').title()}' page is not built yet", Colors.STATUS_WARNING)

    # ------------------------------------------------------------------ #
    # Right panel (Risk Score, Risk Distribution, Tips, System Status, Quick Actions)
    # ------------------------------------------------------------------ #
    def _build_right_panel(self) -> None:
        panel_layout = self._main_window.right_panel_layout
        while panel_layout.count():
            item = panel_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        risk_card, risk_layout = _card("RISK SCORE OVERVIEW")
        self._gauge = GaugeChart()
        risk_layout.addWidget(self._gauge)
        self._risk_note = _empty_state("")
        risk_layout.addWidget(self._risk_note)
        panel_layout.addWidget(risk_card)

        dist_card, dist_layout = _card("RISK DISTRIBUTION")
        self._risk_donut = DonutChart()
        dist_layout.addWidget(self._risk_donut)
        panel_layout.addWidget(dist_card)

        tips_card, tips_layout = _card("ANALYSIS TIPS")
        tips = [
            "Enable ProGuard/R8 mapping upload for better deobfuscation results.",
            "Use Dynamic Analysis for runtime behavior JADX/APKTool alone can't see.",
            "Check Network Traffic captures for sensitive data leaks.",
            "Review the MASVS checklist for baseline compliance.",
        ]
        for tip in tips:
            lbl = QLabel(f"\u25C8  {tip}")
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 10px;")
            tips_layout.addWidget(lbl)
        panel_layout.addWidget(tips_card)

        status_card, status_layout = _card("SYSTEM STATUS")
        self._system_status_layout = status_layout
        panel_layout.addWidget(status_card)

        actions_card, actions_layout = _card("QUICK ACTIONS")
        for label, handler in [
            ("Update Tools", self._on_update_tools),
            ("Take Screenshot", self._on_take_screenshot),
            ("Clear Cache", self._on_clear_cache),
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            actions_layout.addWidget(btn)
        panel_layout.addWidget(actions_card)

        panel_layout.addStretch()

    def _on_update_tools(self) -> None:
        self._main_window.set_status("Checking installed tool versions...", Colors.STATUS_RUNNING)
        deps = get_dependency_manager()
        installed = [name for name, status in deps.status_all().items() if status.installed]
        self._main_window.set_status(f"{len(installed)} tool(s) installed and available", Colors.ACCENT_GREEN)

    def _on_take_screenshot(self) -> None:
        pixmap = self._main_window.grab()
        settings = get_settings()
        out_dir = settings.paths.reports_dir / "screenshots"
        out_dir.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        out_path = out_dir / f"pentroid_{datetime.now():%Y%m%d_%H%M%S}.png"
        pixmap.save(str(out_path))
        self._main_window.set_status(f"Screenshot saved: {out_path.name}", Colors.ACCENT_GREEN)

    def _on_clear_cache(self) -> None:
        self._main_window.set_status("Cache clearing is not implemented yet (no cache layer exists)", Colors.STATUS_WARNING)

    # ------------------------------------------------------------------ #
    # Data refresh -- everything below reads the real database
    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        with session_scope() as session:
            projects = session.query(Project).order_by(Project.updated_at.desc()).limit(5).all()
            all_projects_count = session.query(Project).count()
            analyses = session.query(Analysis).order_by(Analysis.created_at.desc()).limit(5).all()
            all_analyses_count = session.query(Analysis).count()
            findings_by_severity = dict(
                Counter(row[0].value for row in session.query(Finding.severity).all())
            )
            findings_by_category = dict(
                Counter(row[0] or "Uncategorized" for row in session.query(Finding.category).all())
            )
            total_findings = sum(findings_by_severity.values())
            devices = session.query(Device).all()
            queued = (
                session.query(Analysis)
                .filter(Analysis.status.in_([RunStatus.PENDING, RunStatus.QUEUED, RunStatus.RUNNING]))
                .order_by(Analysis.created_at.desc())
                .limit(5)
                .all()
            )
            reports = session.query(Report).order_by(Report.generated_at.desc()).limit(5).all()
            risk_scores = [a.risk_score for a in session.query(Analysis).all() if a.risk_score is not None]

            # Detach the data we need as plain values before the session closes
            project_rows = [(p.name, p.platform.value, p.project_type.value, p.target_path) for p in projects]
            analysis_rows = [(a.analysis_type.value, a.status.value, a.risk_score, a.workflow_name) for a in analyses]
            device_rows = [(d.display_name, d.platform.value, d.connection_type.value, d.status.value) for d in devices]
            queue_rows = [(a.id, a.analysis_type.value, a.status.value) for a in queued]
            report_rows = [(r.format.value, r.file_path, r.generated_at) for r in reports]

        avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0

        self._main_window.top_bar.set_stats(
            projects=all_projects_count, analyses=all_analyses_count,
            findings=total_findings,
            findings_breakdown=[(s, findings_by_severity.get(s, 0)) for s in ("critical", "high", "medium")],
            risk_score=avg_risk,
        )
        self._main_window.top_bar.set_devices([
            {"icon": "android_apk" if plat == "android" else "ios_analysis", "name": name,
             "subtitle": f"{conn} \u2022 {status}", "status": status.upper(), "connected": status == "ready"}
            for name, plat, conn, status in device_rows
        ] or [{"icon": "warning", "name": "No devices", "subtitle": "connect a device", "status": "NONE", "connected": False}])

        self._populate_list(
            self._recent_projects_layout, project_rows,
            lambda row: ListRow("projects", row[0], f"{row[1]} \u2022 {row[2]}", row[1][:3].upper(), Colors.ACCENT_CYAN),
            "No projects yet -- click New Project to get started.",
        )
        self._populate_list(
            self._recent_analyses_layout, analysis_rows,
            lambda row: ListRow(
                "analyses", row[3], row[0],
                row[1].upper(), Colors.ACCENT_GREEN if row[1] == "completed" else (Colors.STATUS_ERROR if row[1] == "failed" else Colors.STATUS_RUNNING),
            ),
            "No analyses run yet.",
        )
        self._populate_list(
            self._devices_layout, device_rows,
            lambda row: ListRow("android_apk" if row[1] == "android" else "ios_analysis", row[0], row[2], row[3].upper(), Colors.ACCENT_GREEN if row[3] == "ready" else Colors.TEXT_MUTED),
            "No devices detected. Run the Device Setup Wizard from Devices.",
        )
        self._populate_list(
            self._queue_layout, queue_rows,
            lambda row: ListRow("queue", f"Analysis #{row[0]}", row[1], row[2].upper(), Colors.STATUS_RUNNING),
            "Queue is empty.",
        )
        self._populate_list(
            self._reports_layout, report_rows,
            lambda row: ListRow("reports", Path(row[1]).name, row[0].upper(), "", Colors.TEXT_MUTED),
            "No reports generated yet.",
        )

        self._render_severity_bars(findings_by_severity, total_findings)
        self._render_category_donut(findings_by_category, total_findings)
        self._render_risk_panel(findings_by_severity, avg_risk)
        self._render_activity_chart()
        self._render_system_status()
        self._refresh_logs()

    def _populate_list(self, layout: QVBoxLayout, rows: list, row_factory, empty_text: str) -> None:
        while layout.count() > 1:  # keep the header label (index 0)
            item = layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        if not rows:
            layout.addWidget(_empty_state(empty_text))
            return
        for row in rows:
            layout.addWidget(row_factory(row))

    def _render_severity_bars(self, by_severity: dict[str, int], total: int) -> None:
        while self._severity_layout.count() > 1:
            item = self._severity_layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        if total == 0:
            self._severity_layout.addWidget(_empty_state("No findings recorded yet."))
            return
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_severity.get(sev, 0)
            if count == 0 and sev in ("low", "info") and by_severity.get("low", 0) + by_severity.get("info", 0) == 0:
                continue
            self._severity_layout.addWidget(SeverityBar(sev.title(), count, total, severity_color(sev)))

    def _render_category_donut(self, by_category: dict[str, int], total: int) -> None:
        while self._findings_category_layout.count() > 1:
            item = self._findings_category_layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        palette = [Colors.SEVERITY_CRITICAL, Colors.SEVERITY_HIGH, Colors.ACCENT_BLUE, Colors.ACCENT_GREEN, Colors.SEVERITY_INFO]
        donut = DonutChart()
        segments = [
            (name, count, palette[i % len(palette)])
            for i, (name, count) in enumerate(sorted(by_category.items(), key=lambda kv: -kv[1]))
        ]
        donut.set_data(segments, center_value=str(total) if total else "0", center_label="Total")
        self._findings_category_layout.addWidget(donut)
        if total == 0:
            self._findings_category_layout.addWidget(_empty_state("No findings recorded yet."))

    def _render_risk_panel(self, by_severity: dict[str, int], avg_risk: float) -> None:
        self._gauge.set_value(avg_risk, 10.0)
        label = "High Risk" if avg_risk >= 7 else ("Medium Risk" if avg_risk >= 4 else ("Low Risk" if avg_risk > 0 else "No data yet"))
        self._risk_note.setText(label)

        segments = [
            (sev.title(), by_severity.get(sev, 0), severity_color(sev))
            for sev in ("critical", "high", "medium", "low", "info")
            if by_severity.get(sev, 0) > 0
        ]
        total = sum(by_severity.values())
        self._risk_donut.set_data(segments, center_value=str(total) if total else "", center_label="Findings" if total else "")

    def _render_activity_chart(self) -> None:
        while self._analyses_chart_layout.count() > 1:
            item = self._analyses_chart_layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()

        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc).date()
        days = [today - timedelta(days=i) for i in range(6, -1, -1)]
        with session_scope() as session:
            analyses = session.query(Analysis.created_at, Analysis.status).all()

        completed_by_day = Counter()
        failed_by_day = Counter()
        for created_at, status in analyses:
            d = created_at.date()
            if d in days:
                if status == RunStatus.COMPLETED:
                    completed_by_day[d] += 1
                elif status == RunStatus.FAILED:
                    failed_by_day[d] += 1

        if not analyses:
            self._analyses_chart_layout.addWidget(_empty_state("No analysis activity yet -- run your first analysis to see trends here."))
            return

        chart = SparklineChart()
        chart.set_data(
            [
                ("Completed", [completed_by_day.get(d, 0) for d in days], Colors.ACCENT_GREEN),
                ("Failed", [failed_by_day.get(d, 0) for d in days], Colors.SEVERITY_CRITICAL),
            ],
            x_labels=[d.strftime("%d %b") for d in days],
        )
        self._analyses_chart_layout.addWidget(chart)

    def _render_system_status(self) -> None:
        while self._system_status_layout.count():
            item = self._system_status_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        deps = get_dependency_manager()
        rows = [
            ("ADB", deps.status("adb").installed),
            ("Frida CLI", deps.status("frida").installed),
            ("Database", True),  # if we got query results above, it's connected
        ]
        for label, ok in rows:
            row = QHBoxLayout()
            name_lbl = QLabel(label)
            name_lbl.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 11px;")
            row.addWidget(name_lbl)
            row.addStretch()
            status_lbl = QLabel("Installed" if ok else "Not installed")
            status_lbl.setStyleSheet(f"color: {Colors.ACCENT_GREEN if ok else Colors.TEXT_MUTED}; font-size: 11px; font-weight: 600;")
            row.addWidget(status_lbl)
            row_widget = QWidget()
            row_widget.setLayout(row)
            self._system_status_layout.addWidget(row_widget)

    def _refresh_logs(self) -> None:
        while self._logs_layout.count() > 1:
            item = self._logs_layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()

        settings = get_settings()
        log_file = settings.paths.logs_dir / "pentroid.log"
        if not log_file.exists():
            self._logs_layout.addWidget(_empty_state("No log activity yet."))
            return

        try:
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
        except OSError:
            lines = []

        text = QPlainTextEdit("\n".join(lines))
        text.setReadOnly(True)
        text.setFixedHeight(180)
        text.setStyleSheet(
            f"background-color: {Colors.BG_INPUT}; color: {Colors.ACCENT_GREEN}; "
            f"font-family: Consolas, monospace; font-size: 10px; border: 1px solid {Colors.BORDER}; border-radius: 6px;"
        )
        self._logs_layout.addWidget(text)
