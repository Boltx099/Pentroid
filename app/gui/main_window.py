"""
app.gui.main_window
======================

Top-level frameless window. Assembles:

    TopBar (spans full width)
    Sidebar | content (QStackedWidget) | RightPanel
    StatusBar (spans full width)

Page switching goes through ``_pages: dict[str, QWidget]`` keyed by
the same page keys ``Sidebar`` emits, so adding a new nav destination
is "build the page widget, register it here" -- no branching logic to
touch elsewhere.
every key the Sidebar can emit now has a page registered in
``main._launch_gui``; ``_UnregisteredPage`` remains only as a loud
fallback so a future nav key added without a page is obvious rather
than crashing.

Per the architecture rule ("GUI must NEVER execute tools directly"),
this module and everything under ``app/gui`` only ever calls into
``app.core.workflow.workflow_manager`` / read-only DB queries -- never
a Plugin or ToolManager directly.
"""

from __future__ import annotations

from collections import Counter

from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QMainWindow, QScrollArea, QStackedWidget,
    QVBoxLayout, QWidget,
)

from app.core.config import get_settings
from app.core.logger import get_logger
from app.database.database import session_scope
from app.database.models import Analysis, Finding, Project
from app.gui.controllers.analysis_runner import get_analysis_runner
from app.gui.theme import Colors, build_stylesheet
from app.gui.widgets.sidebar import Sidebar
from app.gui.widgets.top_bar import TopBar

logger = get_logger(__name__)


class _UnregisteredPage(QWidget):
    """
    Fallback for a nav key with no page registered against it.

    This used to read "<Title>\n\n(coming soon)", which was shown for sixteen
    of the sidebar's twenty-two destinations and told the user nothing useful:
    the underlying capability usually existed, only the page hadn't been built
    and wired up in ``main._launch_gui``. Now that every nav key has a real
    page, reaching this widget means a genuine wiring bug, so it says that
    instead of implying a feature is merely unreleased.
    """

    def __init__(self, key: str, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(6)

        title = QLabel(key.replace("_", " ").title())
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 18px; font-weight: 700;")
        layout.addWidget(title)

        detail = QLabel(
            f"No page is registered for the nav key '{key}'.\n"
            f"Register one in main._launch_gui() via MainWindow.register_page()."
        )
        detail.setAlignment(Qt.AlignCenter)
        detail.setWordWrap(True)
        detail.setStyleSheet(f"color: {Colors.STATUS_WARNING}; font-size: 12px;")
        layout.addWidget(detail)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlag(Qt.FramelessWindowHint)
        self.setMinimumSize(1180, 720)

        settings = get_settings()
        self.setWindowTitle(f"{settings.app_name} v{settings.version}")

        self._drag_pos: QPoint | None = None
        self._pages: dict[str, QWidget] = {}

        root = QWidget()
        root.setObjectName("AppRoot")
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self.top_bar = TopBar()
        self.top_bar.minimize_clicked.connect(self.showMinimized)
        self.top_bar.maximize_clicked.connect(self._toggle_maximize)
        self.top_bar.close_clicked.connect(self.close)
        self.top_bar.theme_toggled.connect(self._on_theme_toggled)
        self.top_bar.notifications_clicked.connect(self._on_notifications_clicked)
        self.top_bar.settings_clicked.connect(lambda: self._navigate("settings"))
        self.top_bar.search_changed.connect(self._on_search_submitted)
        root_layout.addWidget(self.top_bar)

        # The search field's own placeholder text has always promised
        # "Ctrl+K"; nothing actually bound the shortcut until now.
        search_shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
        search_shortcut.activated.connect(self._focus_search)

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        self.sidebar = Sidebar()
        self.sidebar.navigate.connect(self._navigate)
        body_layout.addWidget(self.sidebar)

        self.content_stack = QStackedWidget()
        body_layout.addWidget(self.content_stack, stretch=1)

        # The right panel scrolls. Without this it was a plain QFrame holding a
        # QVBoxLayout of five stacked cards whose combined sizeHint exceeds the
        # window height on anything but a very tall display. QVBoxLayout then
        # compressed every child toward its minimum -- and where a child had a
        # hard minimum it could not go below (the gauge's setMinimumSize), the
        # layout ran the following widgets *over* it. That is why the big "0.9"
        # and the "Low Risk" caption underneath it were drawn on top of each
        # other. Inside a scroll area each card gets the height it asks for and
        # the panel scrolls instead of overlapping.
        self.right_panel = QFrame()
        self.right_panel.setObjectName("RightPanel")
        self.right_panel.setFixedWidth(300)
        right_panel_outer = QVBoxLayout(self.right_panel)
        right_panel_outer.setContentsMargins(0, 0, 0, 0)
        right_panel_outer.setSpacing(0)

        right_panel_scroll = QScrollArea()
        right_panel_scroll.setWidgetResizable(True)
        right_panel_scroll.setFrameShape(QScrollArea.NoFrame)
        right_panel_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        right_panel_content = QWidget()
        self.right_panel_layout = QVBoxLayout(right_panel_content)
        self.right_panel_layout.setContentsMargins(14, 14, 14, 14)
        self.right_panel_layout.setSpacing(12)
        right_panel_scroll.setWidget(right_panel_content)
        right_panel_outer.addWidget(right_panel_scroll)
        body_layout.addWidget(self.right_panel)

        root_layout.addWidget(body, stretch=1)

        self.status_bar_widget = self._build_status_bar()
        root_layout.addWidget(self.status_bar_widget)

        self.setStyleSheet(build_stylesheet())

        # The top bar's Projects/Analyses/Findings/Risk counters used to only
        # refresh when DashboardPage.refresh() happened to run (page init, or
        # its own New Project dialog). A scan started from the Projects page
        # -- the normal way to run one -- never touched them, so the header
        # would sit at stale numbers (e.g. "Analyses: 0") even after a real
        # run completed. Hooking the single shared AnalysisRunner here means
        # it's correct no matter which page kicked the run off.
        get_analysis_runner().completed.connect(lambda *_: self.refresh_top_bar_stats())
        self.refresh_top_bar_stats()
        # Only mark the nav item active here. Calling _navigate("dashboard")
        # at this point ran before main._launch_gui had registered any page,
        # so it registered a fallback widget under the "dashboard" key and
        # pushed it onto the stack; the real DashboardPage then arrived
        # afterwards and the stack was left holding both. main._launch_gui
        # selects the starting page once everything is registered.
        self.sidebar._set_active("dashboard")

    def refresh_top_bar_stats(self) -> None:
        with session_scope() as session:
            projects_count = session.query(Project).count()
            analyses_count = session.query(Analysis).count()
            severities = [row[0].value for row in session.query(Finding.severity).all()]
            risk_scores = [a.risk_score for a in session.query(Analysis).all() if a.risk_score is not None]

        by_severity = Counter(severities)
        avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0
        self.top_bar.set_stats(
            projects=projects_count,
            analyses=analyses_count,
            findings=sum(by_severity.values()),
            findings_breakdown=[(s, by_severity.get(s, 0)) for s in ("critical", "high", "medium")],
            risk_score=avg_risk,
        )

    # ------------------------------------------------------------------ #
    # Page registration / navigation
    # ------------------------------------------------------------------ #
    def register_page(self, key: str, widget: QWidget) -> None:
        self._pages[key] = widget
        self.content_stack.addWidget(widget)

    def _navigate(self, key: str) -> None:
        if key not in self._pages:
            logger.error("No page registered for nav key %r -- showing the fallback", key)
            self.register_page(key, _UnregisteredPage(key))
        self.content_stack.setCurrentWidget(self._pages[key])
        self.sidebar._set_active(key)

    # ------------------------------------------------------------------ #
    # Frameless window chrome: drag-to-move + maximize toggle
    # ------------------------------------------------------------------ #
    def _toggle_maximize(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.top_bar.geometry().contains(event.position().toPoint()):
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._drag_pos = None
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        if self.top_bar.geometry().contains(event.position().toPoint()):
            self._toggle_maximize()
        super().mouseDoubleClickEvent(event)

    # ------------------------------------------------------------------ #
    # Status bar
    # ------------------------------------------------------------------ #
    def _build_status_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("StatusBar")
        bar.setFixedHeight(28)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 0, 14, 0)

        self.status_label = QLabel("\u25CF Ready")
        self.status_label.setStyleSheet(f"color: {Colors.ACCENT_GREEN}; font-size: 11px;")
        layout.addWidget(self.status_label)
        layout.addStretch()

        settings = get_settings()
        self.env_label = QLabel(f"Python 3.11+   |   Theme: {Colors.current_theme.title()}   |   v{settings.version}")
        self.env_label.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(self.env_label)
        return bar

    def set_status(self, text: str, color: str | None = None) -> None:
        # Resolved fresh every call -- a signature default would bake in the
        # palette value at import time and never reflect a later theme change.
        self.status_label.setText(f"\u25CF {text}")
        self.status_label.setStyleSheet(f"color: {color or Colors.ACCENT_GREEN}; font-size: 11px;")

    def _on_theme_toggled(self) -> None:
        from PySide6.QtWidgets import QApplication
        new_theme = "light" if Colors.current_theme == "dark" else "dark"
        Colors.set_theme(new_theme)
        self.setStyleSheet(build_stylesheet())
        for widget in QApplication.instance().allWidgets():
            widget.update()
        old_label = "Theme: Dark" if new_theme == "light" else "Theme: Light"
        self.env_label.setText(self.env_label.text().replace(old_label, f"Theme: {new_theme.title()}"))
        self.set_status(f"Switched to {new_theme} theme", Colors.ACCENT_GREEN)

    def _on_notifications_clicked(self) -> None:
        self.set_status("Notification Center isn't built yet", Colors.STATUS_WARNING)

    def _focus_search(self) -> None:
        """Ctrl+K -- the shortcut the search field's own placeholder text has
        always promised, now actually bound (see TopBar's search_field)."""
        self.top_bar.search_field.setFocus()
        self.top_bar.search_field.selectAll()

    def _on_search_submitted(self, query: str) -> None:
        """Fired on Enter in the top-bar search field (TopBar.search_changed,
        despite its name, now only emits on submit -- see top_bar.py)."""
        query = query.strip()
        if not query:
            return
        from app.gui.dialogs.search_results_dialog import SearchResultsDialog
        SearchResultsDialog(self, query).exec()
