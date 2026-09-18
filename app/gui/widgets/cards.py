"""
app.gui.widgets.cards
========================

Reusable card-style widgets: top-bar stat pills, connected-device
cards, dashboard quick-action cards, and the list rows used for
Recent Projects / Recent Analyses / Recent Reports panels.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from app.gui.icon_provider import icon_label
from app.gui.theme import Colors, severity_color


def _label(text: str, css_class: str = "", color: str | None = None) -> QLabel:
    lbl = QLabel(text)
    if css_class:
        lbl.setProperty("class", css_class)
    if color:
        lbl.setStyleSheet(f"color: {color};")
    return lbl


class StatPill(QFrame):
    """Top bar metric pill: e.g. 'PROJECTS  12  Total'."""

    def __init__(self, title: str, value: str, subtitle: str = "", accent: str | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setProperty("class", "CardAlt")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        title_lbl = _label(title.upper(), color=Colors.TEXT_MUTED)
        title_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px; font-weight: 600; letter-spacing: 0.5px;")
        layout.addWidget(title_lbl)

        value_lbl = _label(value)
        value_lbl.setStyleSheet(f"color: {accent or Colors.TEXT_PRIMARY}; font-size: 18px; font-weight: 700;")
        layout.addWidget(value_lbl)

        if subtitle:
            sub_lbl = _label(subtitle, color=Colors.TEXT_SECONDARY)
            sub_lbl.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 10px;")
            layout.addWidget(sub_lbl)

        self._value_label = value_lbl

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)


class BreakdownStatPill(StatPill):
    """A StatPill with an extra row of small colored severity dots (e.g. Findings: 342, ● 123 ● 158 ● 61)."""

    def __init__(self, title: str, value: str, breakdown: list[tuple[str, int]], parent=None):
        super().__init__(title, value, parent=parent)
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 2, 0, 0)
        row_layout.setSpacing(8)
        for sev_name, count in breakdown:
            dot_and_count = _label(f"● {count}")
            dot_and_count.setStyleSheet(f"color: {severity_color(sev_name)}; font-size: 10px;")
            row_layout.addWidget(dot_and_count)
        row_layout.addStretch()
        self.layout().addWidget(row)


class DeviceCard(QFrame):
    """Top bar connected-device summary card."""

    def __init__(self, platform_icon: str, name: str, subtitle: str, status: str, connected: bool, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CardAlt")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(8)

        icon_lbl = icon_label(platform_icon, size=18)
        layout.addWidget(icon_lbl)

        text_col = QVBoxLayout()
        text_col.setSpacing(0)
        name_lbl = _label(name)
        name_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 12px; font-weight: 600;")
        text_col.addWidget(name_lbl)
        sub_lbl = _label(subtitle)
        status_color = Colors.ACCENT_GREEN if connected else Colors.TEXT_MUTED
        sub_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        text_col.addWidget(sub_lbl)
        layout.addLayout(text_col)

        status_lbl = _label(status)
        status_lbl.setStyleSheet(f"color: {status_color}; font-size: 10px; font-weight: 600;")
        layout.addWidget(status_lbl)


class QuickActionCard(QFrame):
    """Dashboard quick-action button card (New Project / Static Analysis / ...)."""

    clicked = Signal()

    def __init__(self, icon: str, title: str, subtitle: str, parent=None):
        super().__init__(parent)
        self.setProperty("class", "Card")
        self.setCursor(Qt.PointingHandCursor)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        icon_lbl = icon_label(icon, size=20)
        layout.addWidget(icon_lbl)

        text_col = QVBoxLayout()
        text_col.setSpacing(0)
        title_lbl = _label(title)
        title_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 13px; font-weight: 600;")
        text_col.addWidget(title_lbl)
        sub_lbl = _label(subtitle)
        sub_lbl.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 10px;")
        text_col.addWidget(sub_lbl)
        layout.addLayout(text_col)
        layout.addStretch()

    def mousePressEvent(self, event):
        self.clicked.emit()
        super().mousePressEvent(event)


class ListRow(QFrame):
    """A single row for Recent Projects / Recent Analyses / Recent Reports lists."""

    def __init__(self, icon: str, title: str, subtitle: str, badge_text: str, badge_color: str, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 6, 4, 6)
        layout.setSpacing(10)

        icon_lbl = icon_label(icon, size=16)
        layout.addWidget(icon_lbl)

        text_col = QVBoxLayout()
        text_col.setSpacing(0)
        title_lbl = _label(title)
        title_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 12px; font-weight: 600;")
        text_col.addWidget(title_lbl)
        sub_lbl = _label(subtitle)
        sub_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        text_col.addWidget(sub_lbl)
        layout.addLayout(text_col, stretch=1)

        badge = _label(badge_text)
        badge.setStyleSheet(
            f"color: {badge_color}; font-size: 11px; font-weight: 700; "
            f"border: 1px solid {badge_color}; border-radius: 6px; padding: 2px 8px;"
        )
        layout.addWidget(badge)
