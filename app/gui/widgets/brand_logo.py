"""
app.gui.widgets.brand_logo
=============================

The Pentroid hexagon brand mark. Loads the real logo artwork
(app/assets/branding/pentroid_logo.png) rather than approximating it
with QPainter primitives -- the actual design has gradients, bevels,
and glow effects that hand-drawn shapes can't reproduce faithfully.

The source PNG ships with a solid black background baked into its
pixels (not real alpha transparency, despite being RGBA). That
background was made transparent via a border-flood-fill (only pixels
connected to the image edge through near-black tones are cleared,
so the badge's own dark interior fill is preserved rather than
punched through by a naive color threshold) -- necessary for the
logo to look right on both the dark and light themes instead of
showing a black square/hexagon behind it.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QLabel

_LOGO_PATH = Path(__file__).resolve().parent.parent.parent / "assets" / "branding" / "pentroid_logo.png"
_pixmap_cache: dict[int, QPixmap] = {}


def _get_scaled_pixmap(size: int) -> QPixmap:
    cached = _pixmap_cache.get(size)
    if cached is not None:
        return cached

    source = QPixmap(str(_LOGO_PATH))
    if source.isNull():
        # Asset missing/corrupt -- fail soft with a blank pixmap rather than crashing the GUI.
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
    else:
        pixmap = source.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)

    _pixmap_cache[size] = pixmap
    return pixmap


class PentroidMark(QLabel):
    def __init__(self, size: int = 40, parent=None):
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        self.setAlignment(Qt.AlignCenter)
        self.setPixmap(_get_scaled_pixmap(size))
