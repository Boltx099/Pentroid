"""
app.gui.theme
==============
Central color palette + QSS stylesheet. Colors holds the CURRENT
palette as live class attributes; set_theme() reassigns them in
place so every widget (QSS-cascaded or hand-painted QPainter) picks
up the change.
"""

from __future__ import annotations

_DARK = {
    "BG_APP": "#080b12", "BG_SIDEBAR": "#0b0f18", "BG_PANEL": "#0f1520",
    "BG_PANEL_ALT": "#131a28", "BG_INPUT": "#0c111c",
    "BORDER": "#1c2536", "BORDER_SUBTLE": "#161d2b",
    "TEXT_PRIMARY": "#e6ebf5", "TEXT_SECONDARY": "#8b96ab", "TEXT_MUTED": "#5b6478",
    "ACCENT_GREEN": "#39ff8a", "ACCENT_GREEN_DIM": "#1f8a52", "ACCENT_CYAN": "#38bdf8",
    "ACCENT_BLUE": "#3b82f6", "ACCENT_PURPLE": "#a78bfa", "ACCENT_ORANGE": "#fb923c",
    "LOGO_TRIM": "#a3b83c",
    "SEVERITY_CRITICAL": "#ef4444", "SEVERITY_HIGH": "#f97316",
    "SEVERITY_MEDIUM": "#eab308", "SEVERITY_LOW": "#3b82f6", "SEVERITY_INFO": "#8b96ab",
    "STATUS_SUCCESS": "#39ff8a", "STATUS_WARNING": "#f59e0b",
    "STATUS_ERROR": "#ef4444", "STATUS_RUNNING": "#38bdf8",
}

_LIGHT = {
    "BG_APP": "#f5f7fa", "BG_SIDEBAR": "#ffffff", "BG_PANEL": "#ffffff",
    "BG_PANEL_ALT": "#eef1f6", "BG_INPUT": "#ffffff",
    "BORDER": "#d8dee8", "BORDER_SUBTLE": "#e4e8ef",
    "TEXT_PRIMARY": "#131a28", "TEXT_SECONDARY": "#5b6478", "TEXT_MUTED": "#8b96ab",
    "ACCENT_GREEN": "#16a34a", "ACCENT_GREEN_DIM": "#15803d", "ACCENT_CYAN": "#0284c7",
    "ACCENT_BLUE": "#2563eb", "ACCENT_PURPLE": "#7c3aed", "ACCENT_ORANGE": "#ea580c",
    "LOGO_TRIM": "#7c8f2e",
    "SEVERITY_CRITICAL": "#dc2626", "SEVERITY_HIGH": "#ea580c",
    "SEVERITY_MEDIUM": "#ca8a04", "SEVERITY_LOW": "#2563eb", "SEVERITY_INFO": "#64748b",
    "STATUS_SUCCESS": "#16a34a", "STATUS_WARNING": "#d97706",
    "STATUS_ERROR": "#dc2626", "STATUS_RUNNING": "#0284c7",
}

_PALETTES = {"dark": _DARK, "light": _LIGHT}


class Colors:
    current_theme = "dark"


def _apply_palette(name: str) -> None:
    for key, value in _PALETTES[name].items():
        setattr(Colors, key, value)
    Colors.current_theme = name


_apply_palette("dark")


def set_theme(name: str) -> None:
    if name in _PALETTES:
        _apply_palette(name)


Colors.set_theme = staticmethod(set_theme)


def severity_color(severity: str) -> str:
    return {
        "critical": Colors.SEVERITY_CRITICAL, "high": Colors.SEVERITY_HIGH,
        "medium": Colors.SEVERITY_MEDIUM, "low": Colors.SEVERITY_LOW, "info": Colors.SEVERITY_INFO,
    }.get(severity.lower(), Colors.SEVERITY_INFO)


def build_stylesheet() -> str:
    c = Colors
    return f"""
    QWidget {{ background-color: transparent; color: {c.TEXT_PRIMARY};
        font-family: "Segoe UI", "Inter", "Noto Sans", "DejaVu Sans", "Ubuntu",
        "Cantarell", "Helvetica Neue", Arial, sans-serif; font-size: 13px; }}
    QMainWindow, QDialog, #AppRoot {{ background-color: {c.BG_APP}; }}
    #Sidebar {{ background-color: {c.BG_SIDEBAR}; border-right: 1px solid {c.BORDER_SUBTLE}; }}
    #TopBar {{ background-color: {c.BG_PANEL}; border-bottom: 1px solid {c.BORDER_SUBTLE}; }}
    #RightPanel {{ background-color: {c.BG_PANEL}; border-left: 1px solid {c.BORDER_SUBTLE}; }}
    #StatusBar {{ background-color: {c.BG_SIDEBAR}; border-top: 1px solid {c.BORDER_SUBTLE};
        color: {c.TEXT_SECONDARY}; font-size: 11px; }}
    QFrame.Card, #Card {{ background-color: {c.BG_PANEL}; border: 1px solid {c.BORDER}; border-radius: 10px; }}
    QFrame.CardAlt {{ background-color: {c.BG_PANEL_ALT}; border: 1px solid {c.BORDER}; border-radius: 8px; }}
    QLabel.HeaderTitle {{ color: {c.TEXT_PRIMARY}; font-size: 20px; font-weight: 600; }}
    QLabel.HeaderSubtitle {{ color: {c.TEXT_SECONDARY}; font-size: 12px; }}
    QLabel.SectionLabel {{ color: {c.TEXT_SECONDARY}; font-size: 11px; font-weight: 600; letter-spacing: 1px; }}
    QLabel.Muted {{ color: {c.TEXT_MUTED}; font-size: 11px; }}
    QLabel.MetricValue {{ color: {c.TEXT_PRIMARY}; font-size: 22px; font-weight: 700; }}
    QPushButton {{ background-color: {c.BG_PANEL_ALT}; color: {c.TEXT_PRIMARY}; border: 1px solid {c.BORDER};
        border-radius: 8px; padding: 8px 14px; }}
    QPushButton:hover {{ border-color: {c.ACCENT_GREEN}; }}
    QPushButton:pressed {{ background-color: {c.BG_INPUT}; }}
    QPushButton.Primary {{ background-color: {c.ACCENT_GREEN}; color: #06110a; border: none; font-weight: 600; }}
    QPushButton.Primary:hover {{ background-color: #5dffa4; }}
    QPushButton.NavItem {{ background-color: transparent; border: none; border-radius: 8px; text-align: left;
        padding: 8px 12px; color: {c.TEXT_SECONDARY}; font-size: 13px; }}
    QPushButton.NavItem:hover {{ background-color: {c.BG_PANEL_ALT}; color: {c.TEXT_PRIMARY}; }}
    QPushButton.NavItemActive {{ background-color: rgba(57, 255, 138, 0.12); border: none; border-radius: 8px;
        text-align: left; padding: 8px 12px; color: {c.ACCENT_GREEN}; font-weight: 600; font-size: 13px; }}
    QLineEdit {{ background-color: {c.BG_INPUT}; border: 1px solid {c.BORDER}; border-radius: 8px;
        padding: 6px 10px; color: {c.TEXT_PRIMARY}; }}
    QLineEdit:focus {{ border-color: {c.ACCENT_CYAN}; }}
    QScrollArea {{ border: none; background-color: transparent; }}
    #SidebarProfile {{ background-color: {c.BG_PANEL_ALT}; border: 1px solid {c.BORDER_SUBTLE};
        border-radius: 10px; }}
    #SidebarProfile:hover {{ border-color: {c.ACCENT_GREEN_DIM}; }}
    QComboBox {{ background-color: {c.BG_INPUT}; border: 1px solid {c.BORDER}; border-radius: 8px;
        padding: 6px 10px; color: {c.TEXT_PRIMARY}; min-height: 18px; }}
    QComboBox:hover {{ border-color: {c.ACCENT_GREEN_DIM}; }}
    QComboBox::drop-down {{ border: none; width: 18px; }}
    QComboBox QAbstractItemView {{ background-color: {c.BG_PANEL}; color: {c.TEXT_PRIMARY};
        border: 1px solid {c.BORDER}; selection-background-color: {c.BG_PANEL_ALT};
        selection-color: {c.ACCENT_GREEN}; outline: none; }}
    QCheckBox {{ color: {c.TEXT_SECONDARY}; spacing: 8px; }}
    QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {c.BORDER};
        border-radius: 4px; background-color: {c.BG_INPUT}; }}
    QCheckBox::indicator:checked {{ background-color: {c.ACCENT_GREEN}; border-color: {c.ACCENT_GREEN}; }}
    QProgressBar {{ background-color: {c.BG_INPUT}; border: 1px solid {c.BORDER}; border-radius: 6px;
        height: 8px; text-align: center; color: {c.TEXT_MUTED}; font-size: 10px; }}
    QProgressBar::chunk {{ background-color: {c.ACCENT_GREEN}; border-radius: 5px; }}
    QPlainTextEdit, QTextEdit {{ background-color: {c.BG_INPUT}; color: {c.TEXT_SECONDARY};
        border: 1px solid {c.BORDER}; border-radius: 8px; selection-background-color: {c.ACCENT_GREEN_DIM}; }}
    QSplitter::handle {{ background-color: {c.BORDER_SUBTLE}; }}
    QScrollBar:vertical {{ background: transparent; width: 8px; }}
    QScrollBar::handle:vertical {{ background: {c.BORDER}; border-radius: 4px; min-height: 24px; }}
    QScrollBar::handle:vertical:hover {{ background: {c.ACCENT_GREEN_DIM}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
    QScrollBar:horizontal {{ background: transparent; height: 8px; }}
    QScrollBar::handle:horizontal {{ background: {c.BORDER}; border-radius: 4px; min-width: 24px; }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}
    QToolTip {{ background-color: {c.BG_PANEL_ALT}; color: {c.TEXT_PRIMARY}; border: 1px solid {c.BORDER}; padding: 4px 8px; }}
    """
