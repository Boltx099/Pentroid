"""
app.gui.widgets.sidebar
==========================

Left navigation panel: MAIN / ANALYSIS / TOOLS / PLUGINS / SYSTEM
sections, each a list of clickable nav items, plus the user profile
footer. Emits ``navigate(str)`` with a stable page key when an item is
clicked -- ``MainWindow`` owns the actual page-switching logic so this
widget stays purely presentational.
"""

from __future__ import annotations

import getpass

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from app.gui.icon_provider import icon_for_key, icon_label
from app.gui.theme import Colors

# (icon_key, label, page_key) -- icon_key looks up app.gui.icon_provider.ICONS
NAV_SECTIONS: list[tuple[str, list[tuple[str, str, str]]]] = [
    ("MAIN", [
        ("dashboard", "Dashboard", "dashboard"),
        ("projects", "Projects", "projects"),
        ("analyses", "All Analyses", "analyses"),
        ("devices", "Devices", "devices"),
        ("reports", "Reports", "reports"),
    ]),
    ("ANALYSIS", [
        ("android_apk", "Android APK", "android_apk"),
        ("android_malware", "Android Malware", "android_malware"),
        ("ios_analysis", "iOS Analysis", "ios_analysis"),
        ("dynamic_analysis", "Dynamic Analysis", "dynamic_analysis"),
        ("network_analysis", "Network Analysis", "network_analysis"),
        ("privacy_analysis", "Privacy Analysis", "privacy_analysis"),
        ("static_analysis", "Static Analysis", "static_analysis"),
    ]),
    ("TOOLS", [
        ("toolbox", "Toolbox", "toolbox"),
        ("frida_hub", "Frida Hub", "frida_hub"),
        ("adb_toolkit", "ADB Toolkit", "adb_toolkit"),
        ("reverse_engineering", "Reverse Engineering", "reverse_engineering"),
        ("utilities", "Utilities", "utilities"),
    ]),
    ("PLUGINS", [
        ("plugin_center", "Plugin Center", "plugin_center"),
        ("installed_plugins", "Installed Plugins", "installed_plugins"),
    ]),
    ("SYSTEM", [
        ("dependency_manager", "Dependency Manager", "dependency_manager"),
        ("settings", "Settings", "settings"),
        ("logs", "Logs", "logs"),
    ]),
]


class _ClickableFrame(QFrame):
    """A QFrame that emits ``clicked`` -- used where a button's look is wanted
    but a button's text-derived sizeHint would clip a rich child layout."""

    clicked = Signal()

    def mouseReleaseEvent(self, event):  # noqa: N802 - Qt override
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class Sidebar(QWidget):
    navigate = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(230)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        content = QWidget()
        self._content_layout = QVBoxLayout(content)
        self._content_layout.setContentsMargins(12, 16, 12, 16)
        self._content_layout.setSpacing(4)

        self._nav_buttons: dict[str, QPushButton] = {}
        self._active_key = "dashboard"

        for section_title, items in NAV_SECTIONS:
            section_lbl = QLabel(section_title)
            section_lbl.setProperty("class", "SectionLabel")
            section_lbl.setStyleSheet(
                f"color: {Colors.TEXT_MUTED}; font-size: 10px; font-weight: 700; "
                f"letter-spacing: 1px; margin-top: 10px; margin-bottom: 2px;"
            )
            self._content_layout.addWidget(section_lbl)

            for icon_key, label, key in items:
                btn = QPushButton(f"  {label}")
                btn.setIcon(icon_for_key(icon_key, size=16))
                btn.setIconSize(QSize(16, 16))
                btn.setProperty("class", "NavItem")
                btn.setCheckable(True)
                btn.setFlat(True)
                btn.clicked.connect(lambda _checked=False, k=key: self._on_click(k))
                self._content_layout.addWidget(btn)
                self._nav_buttons[key] = btn

        self._content_layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

        outer.addWidget(self._build_profile_footer())

        self._set_active("dashboard")

    def _build_profile_footer(self) -> QWidget:
        """Pinned footer below the scroll area: OS username + a shortcut into
        Settings. There's no accounts/login system in Pentroid (it's a local
        single-user tool), so this intentionally uses the real OS username
        rather than a fabricated "Pro User" label -- unlike the mockup, it
        won't invent data that isn't real.

        This is a ``_ClickableFrame``, not a QPushButton, on purpose. A
        QPushButton computes sizeHint() from its own (here empty) text plus
        the style's padding and ignores any child layout installed on it, so
        the button reported a 34px hint while the avatar + two text lines
        inside needed 50px. Qt then clipped the username and ran it into the
        "Local Install" line below. A QFrame derives its hint from its layout,
        so the footer is always tall enough for its contents.
        """
        footer = _ClickableFrame()
        footer.setObjectName("SidebarProfile")
        footer.setCursor(Qt.PointingHandCursor)
        footer.clicked.connect(lambda: self._on_click("settings"))

        row = QHBoxLayout(footer)
        row.setContentsMargins(12, 10, 12, 10)
        row.setSpacing(10)

        avatar = icon_label("account", size=16)
        avatar.setFixedSize(30, 30)
        avatar.setStyleSheet(
            f"background-color: {Colors.BG_PANEL_ALT}; border: 1px solid {Colors.BORDER}; "
            f"border-radius: 15px;"
        )
        row.addWidget(avatar)

        text_col = QVBoxLayout()
        text_col.setSpacing(0)
        try:
            username = getpass.getuser().upper()
        except Exception:
            username = "LOCAL USER"
        name_lbl = QLabel(username)
        name_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 12px; font-weight: 700;")
        text_col.addWidget(name_lbl)
        sub_lbl = QLabel("Local Install")
        sub_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px;")
        text_col.addWidget(sub_lbl)
        row.addLayout(text_col, stretch=1)

        gear = icon_label("settings", size=14)
        row.addWidget(gear)

        return footer

    def _on_click(self, key: str) -> None:
        self._set_active(key)
        self.navigate.emit(key)

    def _set_active(self, key: str) -> None:
        self._active_key = key
        for btn_key, btn in self._nav_buttons.items():
            is_active = btn_key == key
            btn.setChecked(is_active)
            btn.setProperty("class", "NavItemActive" if is_active else "NavItem")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
