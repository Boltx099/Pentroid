"""
app.gui.icon_provider
========================

Central icon registry for Pentroid.

Every "icon" in the GUI used to be a raw unicode emoji glyph
(``"\U0001F916"``, ``"\u2620"``, ...) drawn as plain text. That looked
fine in the mockup screenshot but is fragile in practice: real emoji
glyphs render through whatever color emoji font the OS happens to
ship (Noto Color Emoji / Segoe UI Emoji / Apple Color Emoji / nothing
at all on a minimal Linux box), so the same build can show a crisp
icon on one machine and a black-and-white "tofu" box -- or nothing --
on another. None of that art direction is under this app's control.

This module replaces that with real vector icons from Material Design
Icons (bundled inside the ``qtawesome`` package, so no network access
or extra system fonts are needed at runtime), rendered at an explicit
size and color that matches Pentroid's own palette. Results are
cached so repainting a page full of nav items / list rows doesn't
re-rasterize the same glyph over and over.

Usage:
    get_icon("cog-outline", Colors.TEXT_SECONDARY, 16)   -> QIcon
    get_pixmap("android", Colors.ACCENT_GREEN, 20)       -> QPixmap
    icon_label("android_apk", size=20)                   -> QLabel (uses the
                                                             registered default
                                                             color for that key)
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import QLabel

from app.gui.theme import Colors

# Semantic key -> (Material Design Icons glyph name, default color).
# Colors are chosen per-category (not per active/inactive state) so an
# icon keeps its identity color everywhere it appears, the same way
# the reference design uses a consistent color per icon "family".
ICONS: dict[str, tuple[str, str]] = {
    # Main navigation
    "dashboard": ("view-dashboard-outline", Colors.ACCENT_GREEN),
    "projects": ("folder-outline", Colors.ACCENT_BLUE),
    "analyses": ("clipboard-text-outline", Colors.ACCENT_PURPLE),
    "devices": ("cellphone", Colors.ACCENT_ORANGE),
    "reports": ("file-document-outline", Colors.ACCENT_ORANGE),
    # Analysis pipelines
    "android_apk": ("android", Colors.ACCENT_GREEN),
    "android_malware": ("biohazard", Colors.STATUS_ERROR),
    "ios_analysis": ("apple", Colors.TEXT_SECONDARY),
    "dynamic_analysis": ("flash-outline", Colors.SEVERITY_MEDIUM),
    "network_analysis": ("web", Colors.ACCENT_CYAN),
    "privacy_analysis": ("lock-outline", Colors.ACCENT_PURPLE),
    "static_analysis": ("file-code-outline", Colors.ACCENT_CYAN),
    # Tools
    "toolbox": ("toolbox-outline", Colors.ACCENT_BLUE),
    "frida_hub": ("needle", Colors.ACCENT_PURPLE),
    "adb_toolkit": ("usb", Colors.ACCENT_GREEN),
    "reverse_engineering": ("chip", Colors.TEXT_SECONDARY),
    "utilities": ("wrench-outline", Colors.ACCENT_CYAN),
    # Plugins
    "plugin_center": ("puzzle-outline", Colors.ACCENT_PURPLE),
    "installed_plugins": ("package-variant-closed", Colors.ACCENT_BLUE),
    # System
    "dependency_manager": ("download-outline", Colors.ACCENT_GREEN),
    "settings": ("cog-outline", Colors.TEXT_SECONDARY),
    "logs": ("script-text-outline", Colors.TEXT_SECONDARY),
    # Misc / shared
    "account": ("account-circle-outline", Colors.TEXT_SECONDARY),
    "add": ("plus-circle-outline", Colors.ACCENT_GREEN),
    "import": ("tray-arrow-down", Colors.ACCENT_GREEN),
    "queue": ("progress-clock", Colors.STATUS_RUNNING),
    "warning": ("alert-outline", Colors.STATUS_WARNING),
    "refresh": ("refresh", Colors.TEXT_PRIMARY),
    # Top-bar chrome
    "theme_toggle": ("weather-night", Colors.ACCENT_CYAN),
    "notifications": ("bell-outline", Colors.TEXT_PRIMARY),
    "search": ("magnify", Colors.TEXT_SECONDARY),
    "minimize": ("window-minimize", Colors.TEXT_PRIMARY),
    "maximize": ("window-maximize", Colors.TEXT_PRIMARY),
    "close": ("close", Colors.TEXT_PRIMARY),
}

_pixmap_cache: dict[tuple[str, str, int], QPixmap] = {}


def get_pixmap(name: str, color: str, size: int = 20) -> QPixmap:
    """Render a Material Design Icons glyph to a QPixmap at ``size``x``size``.

    ``name`` is the bare glyph name without the ``mdi6.`` prefix (e.g.
    ``"cog-outline"``, not ``"mdi6.cog-outline"``).
    """
    key = (name, color, size)
    cached = _pixmap_cache.get(key)
    if cached is not None:
        return cached

    import qtawesome as qta

    try:
        icon = qta.icon(f"mdi6.{name}", color=color)
        pixmap = icon.pixmap(size, size)
    except Exception:
        # Unknown glyph name -- fail soft with a blank pixmap rather than
        # crashing the GUI over a cosmetic icon.
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
    _pixmap_cache[key] = pixmap
    return pixmap


def get_icon(name: str, color: str, size: int = 20) -> QIcon:
    return QIcon(get_pixmap(name, color, size))


def icon_for_key(key: str, size: int = 18, color: str | None = None) -> QIcon:
    """Look up a semantic key in ``ICONS`` and return a QIcon using its
    registered default color, unless ``color`` overrides it."""
    name, default_color = ICONS.get(key, ("help-circle-outline", Colors.TEXT_MUTED))
    return get_icon(name, color or default_color, size)


def icon_label(key: str, size: int = 18, color: str | None = None) -> QLabel:
    """Build a QLabel showing an icon for a registered semantic ``key``.

    Falls back to rendering ``key`` itself as plain text if it isn't a
    registered icon -- a safety net so an un-migrated call site renders
    *something* instead of raising.
    """
    lbl = QLabel()
    lbl.setAlignment(Qt.AlignCenter)
    if key in ICONS:
        name, default_color = ICONS[key]
        lbl.setPixmap(get_pixmap(name, color or default_color, size))
        lbl.setFixedSize(size, size)
    else:
        lbl.setText(key)
        lbl.setStyleSheet(f"font-size: {max(10, size - 2)}px;")
    return lbl
