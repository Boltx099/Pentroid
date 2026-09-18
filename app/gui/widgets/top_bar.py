"""
app.gui.widgets.top_bar
==========================

Top bar: brand logo + title, connected-device summary cards, key stat
pills (Projects/Analyses/Findings/Risk Score), a search field, and
theme/notifications/settings icon buttons plus the frameless window's
own minimize/maximize/close controls.
"""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from app.gui.icon_provider import icon_for_key
from app.gui.theme import Colors
from app.gui.widgets.brand_logo import PentroidMark
from app.gui.widgets.cards import BreakdownStatPill, DeviceCard, StatPill


class _IconButton(QPushButton):
    def __init__(self, icon_key: str, tooltip: str = "", parent=None):
        super().__init__(parent)
        self.setIcon(icon_for_key(icon_key, size=16))
        self.setIconSize(QSize(16, 16))
        self.setFixedSize(34, 34)
        self.setToolTip(tooltip)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(
            f"QPushButton {{ background-color: {Colors.BG_PANEL_ALT}; border: 1px solid {Colors.BORDER}; "
            f"border-radius: 17px; }}"
            f"QPushButton:hover {{ border-color: {Colors.ACCENT_CYAN}; }}"
        )


class TopBar(QFrame):
    theme_toggled = Signal()
    notifications_clicked = Signal()
    settings_clicked = Signal()
    minimize_clicked = Signal()
    maximize_clicked = Signal()
    close_clicked = Signal()
    search_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("TopBar")
        # Height policy, and why it is Fixed rather than a minimum:
        #
        # This started as setFixedHeight(64) -- too short for a populated
        # BreakdownStatPill (title + value + subtitle + severity-dot row) or a
        # two-line DeviceCard -- and was then "fixed" with setMinimumHeight(88),
        # which did NOT solve it. An explicit minimum tells the parent layout
        # how far the bar may be *compressed*, and the dashboard below it is
        # tall enough that QVBoxLayout happily compressed the bar from its
        # 107px sizeHint down to that 88px floor. The stat pills then got 50px
        # for 67px of content, so an 18px value label was allotted 9px and Qt
        # clipped the glyphs top and bottom -- the "garbled/glitched font".
        #
        # QSizePolicy.Fixed makes the layout use sizeHint() as both the minimum
        # and the maximum, so the bar always gets exactly the height its
        # children need and can never be squeezed into clipping them again.
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 10, 12, 10)
        layout.setSpacing(14)

        layout.addWidget(self._build_brand())

        # Every nested row below sets zero contents margins explicitly. A
        # QLayout installed on a QWidget otherwise inherits the style's default
        # 9px margin on all four sides, which silently ate 18px of vertical
        # space per nesting level and was the other half of the squeeze above.
        self._device_row = QHBoxLayout()
        self._device_row.setContentsMargins(0, 0, 0, 0)
        self._device_row.setSpacing(8)
        device_row_widget = QWidget()
        device_row_widget.setLayout(self._device_row)
        layout.addWidget(device_row_widget)

        self._stats_row = QHBoxLayout()
        self._stats_row.setContentsMargins(0, 0, 0, 0)
        self._stats_row.setSpacing(8)
        stats_row_widget = QWidget()
        stats_row_widget.setLayout(self._stats_row)
        layout.addWidget(stats_row_widget, stretch=1)

        # Was textChanged -> search_changed.emit, wired to nothing anywhere in
        # the app: a field labelled "Search (Ctrl+K)" that looked interactive
        # and silently did nothing on every keystroke, which is worse than no
        # search box at all. Now: Enter runs a real query (MainWindow opens
        # SearchResultsDialog); Ctrl+K, matching the field's own placeholder
        # text, focuses it (wired in MainWindow via a QShortcut). Firing on
        # a deliberate Enter rather than every keystroke also avoids a DB
        # query per character once something IS listening.
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Search (Ctrl+K)")
        self.search_field.setFixedWidth(180)
        self.search_field.returnPressed.connect(
            lambda: self.search_changed.emit(self.search_field.text())
        )
        layout.addWidget(self.search_field)

        theme_btn = _IconButton("theme_toggle", "Toggle theme")
        theme_btn.clicked.connect(self.theme_toggled.emit)
        layout.addWidget(theme_btn)

        notifications_btn = _IconButton("notifications", "Notifications")
        notifications_btn.clicked.connect(self.notifications_clicked.emit)
        layout.addWidget(notifications_btn)

        settings_icon_btn = _IconButton("settings", "Settings")
        settings_icon_btn.clicked.connect(self.settings_clicked.emit)
        layout.addWidget(settings_icon_btn)

        divider = QFrame()
        divider.setFixedWidth(1)
        divider.setFixedHeight(24)
        divider.setStyleSheet(f"background-color: {Colors.BORDER};")
        layout.addWidget(divider)

        window_controls = QHBoxLayout()
        window_controls.setContentsMargins(0, 0, 0, 0)
        window_controls.setSpacing(4)
        min_btn = _IconButton("minimize", "Minimize")
        min_btn.clicked.connect(self.minimize_clicked.emit)
        max_btn = _IconButton("maximize", "Maximize")
        max_btn.clicked.connect(self.maximize_clicked.emit)
        close_btn = _IconButton("close", "Close")
        close_btn.setStyleSheet(
            close_btn.styleSheet() + f"QPushButton:hover {{ background-color: {Colors.STATUS_ERROR}; border-color: {Colors.STATUS_ERROR}; }}"
        )
        close_btn.clicked.connect(self.close_clicked.emit)
        for b in (min_btn, max_btn, close_btn):
            window_controls.addWidget(b)
        controls_widget = QWidget()
        controls_widget.setLayout(window_controls)
        layout.addWidget(controls_widget)

    def _build_brand(self) -> QWidget:
        from app.core.config import get_settings

        settings = get_settings()

        wrap = QWidget()
        row = QHBoxLayout(wrap)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)

        row.addWidget(PentroidMark(size=40))

        text_col = QVBoxLayout()
        text_col.setSpacing(0)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(6)
        title = QLabel("PENTROID")
        title.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 15px; font-weight: 700; letter-spacing: 1px;")
        title_row.addWidget(title)
        version_pill = QLabel(f"v{settings.version}")
        version_pill.setStyleSheet(
            f"color: {Colors.TEXT_MUTED}; font-size: 9px; font-weight: 600; "
            f"border: 1px solid {Colors.BORDER}; border-radius: 6px; padding: 1px 5px;"
        )
        title_row.addWidget(version_pill)
        title_row.addStretch()
        text_col.addLayout(title_row)

        subtitle = QLabel("Next-Generation Mobile Application Security Platform")
        subtitle.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 9px;")
        text_col.addWidget(subtitle)
        row.addLayout(text_col)
        return wrap

    def set_devices(self, devices: list[dict]) -> None:
        """``devices``: list of {icon, name, subtitle, status, connected}."""
        while self._device_row.count():
            item = self._device_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for d in devices:
            self._device_row.addWidget(
                DeviceCard(d["icon"], d["name"], d["subtitle"], d["status"], d["connected"])
            )

    def set_stats(self, projects: int, analyses: int, findings: int, findings_breakdown: list[tuple[str, int]], risk_score: float) -> None:
        while self._stats_row.count():
            item = self._stats_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._stats_row.addWidget(StatPill("Projects", str(projects), "Total"))
        self._stats_row.addWidget(StatPill("Analyses", str(analyses), "Total"))
        self._stats_row.addWidget(BreakdownStatPill("Findings", str(findings), findings_breakdown))
        risk_label = "High Risk" if risk_score >= 7 else ("Medium Risk" if risk_score >= 4 else "Low Risk")
        risk_color = Colors.SEVERITY_CRITICAL if risk_score >= 7 else (Colors.SEVERITY_HIGH if risk_score >= 4 else Colors.ACCENT_GREEN)
        self._stats_row.addWidget(StatPill("Risk Score", f"{risk_score:.1f} /10", risk_label, accent=risk_color))
