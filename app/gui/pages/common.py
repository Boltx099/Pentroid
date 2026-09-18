"""
app.gui.pages.common
=======================

Shared building blocks for the pages under ``app/gui/pages``.

Before this module existed only six of the sidebar's twenty-two nav
destinations had a real page; the rest fell through to
``MainWindow._PlaceholderPage`` and rendered "(coming soon)". Building
the remaining sixteen meant repeating the same scaffolding -- scrolling
page body, section card, key/value row, status pill -- sixteen times,
so it lives here instead.

Nothing in this module talks to the database, a Plugin, or a Tool. It
is presentation only; pages own their own data access, and per the
architecture rule they reach the workflow engine through
``AnalysisRunner`` and blocking work through ``BackgroundTaskRunner``.
"""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QSizePolicy,
    QVBoxLayout, QWidget,
)

from app.gui.theme import Colors


def label(
    text: str,
    size: int = 12,
    color: str | None = None,
    bold: bool = False,
    wrap: bool = False,
    extra_css: str = "",
) -> QLabel:
    """A QLabel with its font size set in px, matching the app's QSS.

    Note the deliberate use of ``font-size`` in the widget's own style sheet
    rather than ``setFont``: Qt computes the label's sizeHint from the
    resolved style sheet font, so the hint and the painted glyphs agree.
    (They only disagreed in the old top bar because its *container* was
    compressed below the hint, not because of the font declaration itself.)
    """
    lbl = QLabel(text)
    lbl.setWordWrap(wrap)
    lbl.setStyleSheet(
        f"color: {color or Colors.TEXT_PRIMARY}; font-size: {size}px; "
        f"font-weight: {700 if bold else 400}; {extra_css}"
    )
    return lbl


def pill(text: str, color: str) -> QLabel:
    """A small outlined status badge (INSTALLED / READY / MISSING / ...)."""
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color: {color}; font-size: 10px; font-weight: 700; "
        f"border: 1px solid {color}; border-radius: 6px; padding: 2px 8px;"
    )
    lbl.setAlignment(Qt.AlignCenter)
    return lbl


def card(title: str | None = None, subtitle: str | None = None) -> tuple[QFrame, QVBoxLayout]:
    """A titled panel. Returns ``(frame, body_layout)``; callers append to the layout."""
    frame = QFrame()
    frame.setProperty("class", "Card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    if title:
        layout.addWidget(label(title, size=12, bold=True,
                               extra_css="letter-spacing: 0.5px;"))
    if subtitle:
        layout.addWidget(label(subtitle, size=10, color=Colors.TEXT_MUTED, wrap=True))
    return frame, layout


def kv_row(key: str, value: str, value_color: str | None = None) -> QWidget:
    """A single ``label .......... value`` line."""
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)
    layout.addWidget(label(key, size=11, color=Colors.TEXT_SECONDARY))
    layout.addStretch()
    val = label(value, size=11, color=value_color or Colors.TEXT_PRIMARY, bold=True)
    val.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
    val.setTextInteractionFlags(Qt.TextSelectableByMouse)
    layout.addWidget(val)
    return row


def empty_state(text: str) -> QLabel:
    lbl = label(text, size=11, color=Colors.TEXT_MUTED, wrap=True,
                extra_css="padding: 20px;")
    lbl.setAlignment(Qt.AlignCenter)
    return lbl


def clear_layout(layout, keep: int = 0) -> None:
    """Remove every widget past index ``keep`` (used to keep a card's header)."""
    while layout.count() > keep:
        item = layout.takeAt(keep)
        if item.widget():
            item.widget().deleteLater()


class ActionRow(QFrame):
    """A card-styled row: icon-less title + description on the left, buttons right.

    Used by Toolbox, Frida Hub, ADB Toolkit, Plugin Center and Utilities for
    their "here is a thing, here is what you can do to it" lists.
    """

    def __init__(self, title: str, description: str, parent=None):
        super().__init__(parent)
        self.setProperty("class", "Card")
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(14, 10, 14, 10)
        self._layout.setSpacing(12)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(2)
        text_col.addWidget(label(title, size=13, bold=True))
        self._desc = label(description, size=10, color=Colors.TEXT_MUTED, wrap=True)
        text_col.addWidget(self._desc)
        self._layout.addLayout(text_col, stretch=1)

        self._status = pill("", Colors.TEXT_MUTED)
        self._status.hide()
        self._layout.addWidget(self._status)

    def set_description(self, text: str) -> None:
        self._desc.setText(text)

    def set_status(self, text: str, color: str) -> None:
        self._status.setText(text)
        self._status.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: 700; "
            f"border: 1px solid {color}; border-radius: 6px; padding: 2px 8px;"
        )
        self._status.show()

    def add_button(self, text: str, handler: Callable[[], None], primary: bool = False) -> QPushButton:
        btn = QPushButton(text)
        if primary:
            btn.setProperty("class", "Primary")
        btn.clicked.connect(handler)
        self._layout.addWidget(btn)
        return btn


class BasePage(QWidget):
    """
    Scrolling page shell with a title, optional subtitle, a header button
    slot, and a status line that pages use to report the result of the last
    action without stealing the main window's status bar.

    Subclasses build into ``self.body`` (a QVBoxLayout) and may override
    ``refresh()``; it is called on construction and every time the page
    becomes visible, so navigating back to a page never shows stale state.
    """

    title_text: str = ""
    subtitle_text: str = ""

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(14)
        scroll.setWidget(content)

        header = QWidget()
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(10)

        title_col = QVBoxLayout()
        title_col.setContentsMargins(0, 0, 0, 0)
        title_col.setSpacing(2)
        title_col.addWidget(label(self.title_text, size=20, bold=True))
        if self.subtitle_text:
            title_col.addWidget(
                label(self.subtitle_text, size=11, color=Colors.TEXT_SECONDARY, wrap=True)
            )
        header_row.addLayout(title_col, stretch=1)
        self.header_actions = header_row
        root.addWidget(header)

        self.status_line = label("", size=11, color=Colors.TEXT_MUTED, wrap=True)
        self.status_line.hide()
        root.addWidget(self.status_line)

        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(14)
        root.addLayout(self.body)
        root.addStretch()

        self._built = False

    def add_header_button(self, text: str, handler: Callable[[], None],
                          primary: bool = False) -> QPushButton:
        btn = QPushButton(text)
        if primary:
            btn.setProperty("class", "Primary")
        btn.clicked.connect(handler)
        self.header_actions.addWidget(btn)
        return btn

    def set_status(self, text: str, color: str | None = None) -> None:
        """Page-local status. Also mirrored to the window status bar so the
        message is visible even if the user has scrolled the page."""
        if not text:
            self.status_line.hide()
            return
        self.status_line.setText(text)
        self.status_line.setStyleSheet(
            f"color: {color or Colors.TEXT_MUTED}; font-size: 11px;"
        )
        self.status_line.show()
        if self.main_window is not None:
            self.main_window.set_status(text, color or Colors.TEXT_SECONDARY)

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        self.refresh()

    def refresh(self) -> None:
        """Re-read whatever this page displays. Default is a no-op."""


class NoticeCard(QFrame):
    """
    A prominent, honest statement of a capability boundary.

    Pentroid has working backends for Android static/malware/dynamic analysis
    but genuinely has no IPA-parsing plugin and no traffic-capture plugin. The
    iOS and Network pages use this to say so plainly and list what *is*
    wired up, rather than presenting an empty UI that implies the feature
    exists and is merely misconfigured.
    """

    def __init__(self, heading: str, message: str, bullets: list[str] | None = None, parent=None):
        super().__init__(parent)
        self.setProperty("class", "Card")
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)
        layout.addWidget(label(heading, size=12, bold=True, color=Colors.STATUS_WARNING))
        layout.addWidget(label(message, size=11, color=Colors.TEXT_SECONDARY, wrap=True))
        for bullet in bullets or []:
            layout.addWidget(
                label(f"\u25C8  {bullet}", size=10, color=Colors.TEXT_MUTED, wrap=True)
            )
