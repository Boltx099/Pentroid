"""
app.gui.widgets.charts
========================

Hand-drawn (QPainter) chart widgets rather than QtCharts, so the
visual style (thin donut rings, neon gauge arc, dark-theme grid lines)
matches the mockup exactly instead of QtCharts' default look. Each
widget takes plain Python data in ``set_data`` -- no chart-library
data model to wire up -- so pages can feed them straight from a
SQLAlchemy query result.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from app.gui.theme import Colors


class DonutChart(QWidget):
    """Segmented donut with a big center label (total) -- used for Risk Distribution / Findings by Category."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._segments: list[tuple[str, float, str]] = []  # (label, value, color)
        self._center_value = ""
        self._center_label = ""
        self.setMinimumSize(140, 140)

    def set_data(self, segments: list[tuple[str, float, str]], center_value: str = "", center_label: str = ""):
        self._segments = segments
        self._center_value = center_value
        self._center_label = center_label
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        side = min(self.width(), self.height()) - 12
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        thickness = max(10, int(side * 0.16))

        total = sum(v for _, v, _ in self._segments) or 1.0
        start_angle = 90 * 16  # start at 12 o'clock, Qt angles are in 1/16th degrees, clockwise negative

        pen_base = QPen()
        pen_base.setWidth(thickness)
        pen_base.setCapStyle(Qt.FlatCap)

        inset = thickness / 2
        arc_rect = rect.adjusted(inset, inset, -inset, -inset)

        if not self._segments:
            pen_base.setColor(QColor(Colors.BORDER))
            painter.setPen(pen_base)
            painter.drawArc(arc_rect, 0, 360 * 16)
        else:
            for _, value, color in self._segments:
                span = -int(360 * 16 * (value / total))
                pen = QPen(pen_base)
                pen.setColor(QColor(color))
                painter.setPen(pen)
                painter.drawArc(arc_rect, start_angle, span)
                start_angle += span

        # The value band and the label band below it are kept disjoint (they
        # used to overlap between 0.06 and 0.08 of the diameter), and both use
        # pixel sizes so they scale with the ring rather than with desktop DPI.
        cy = rect.center().y()
        if self._center_value:
            painter.setPen(QColor(Colors.TEXT_PRIMARY))
            font = QFont()
            font.setPixelSize(int(max(13, side * 0.15)))
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(
                QRectF(rect.x(), cy - side * 0.22, rect.width(), side * 0.24),
                Qt.AlignCenter, self._center_value,
            )

        if self._center_label:
            painter.setPen(QColor(Colors.TEXT_SECONDARY))
            font = QFont()
            font.setPixelSize(int(max(9, side * 0.08)))
            painter.setFont(font)
            painter.drawText(
                QRectF(rect.x(), cy + side * 0.04, rect.width(), side * 0.15),
                Qt.AlignCenter, self._center_label,
            )

        painter.end()


class GaugeChart(QWidget):
    """Semicircular risk-score gauge (green -> yellow -> red arc with a needle-less filled indicator)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0.0
        self._max_value = 10.0
        self.setMinimumSize(160, 104)

    def set_value(self, value: float, max_value: float = 10.0):
        self._value = max(0.0, min(value, max_value))
        self._max_value = max_value
        self.update()

    def _risk_color(self) -> QColor:
        ratio = self._value / self._max_value if self._max_value else 0
        if ratio >= 0.7:
            return QColor(Colors.SEVERITY_CRITICAL)
        if ratio >= 0.4:
            return QColor(Colors.SEVERITY_HIGH)
        return QColor(Colors.ACCENT_GREEN)

    def paintEvent(self, event):
        """
        Geometry note: the old version derived the circle diameter from the
        widget *width* only (``side = min(w, h*2) - 16``) and then placed the
        value text at ``rect.y() + side * 0.28`` with a height of
        ``side * 0.3``. In the 300px-wide right panel that put the bottom of
        the text well past the widget's own bottom edge, so the big "0.9"
        bled over the "Low Risk" caption label sitting underneath it in the
        card layout, and the "/ 10" caption was pushed out of view entirely.

        Everything below is laid out relative to the semicircle's flat edge
        (``baseline``) and stays inside it by construction: the value sits in
        the upper half of the dial, the "/ 10" caption in a band just above
        the flat edge, and nothing is ever drawn below ``baseline``.
        """
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        pad = 8
        # A semicircle of diameter d needs d/2 of height, so the diameter is
        # capped by both the available width and twice the available height.
        diameter = max(48.0, min(w - 2 * pad, (h - 2 * pad) * 2.0))
        radius = diameter / 2.0
        cx = w / 2.0
        baseline = (h + radius) / 2.0  # vertically centre the half-dial in the widget
        rect = QRectF(cx - radius, baseline - radius, diameter, diameter)

        thickness = int(max(8.0, min(26.0, diameter * 0.13)))
        inset = thickness / 2.0
        arc_rect = rect.adjusted(inset, inset, -inset, -inset)

        track_pen = QPen(QColor(Colors.BORDER))
        track_pen.setWidth(thickness)
        track_pen.setCapStyle(Qt.FlatCap)
        painter.setPen(track_pen)
        painter.drawArc(arc_rect, 0, 180 * 16)

        ratio = self._value / self._max_value if self._max_value else 0
        if ratio > 0:
            value_pen = QPen(self._risk_color())
            value_pen.setWidth(thickness)
            value_pen.setCapStyle(Qt.FlatCap)
            painter.setPen(value_pen)
            painter.drawArc(arc_rect, 180 * 16, -int(180 * 16 * ratio))

        # Pixel sizes, not point sizes: every other font size in Pentroid is
        # expressed in px via QSS, and point sizes rescale with the desktop DPI
        # setting independently of the arc, which would reintroduce overflow on
        # a high-DPI display.
        font = QFont()
        font.setPixelSize(int(max(15.0, radius * 0.42)))
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor(Colors.TEXT_PRIMARY))
        painter.drawText(
            QRectF(rect.x(), baseline - radius * 0.62, diameter, radius * 0.46),
            Qt.AlignCenter, f"{self._value:.1f}",
        )

        font.setPixelSize(int(max(9.0, radius * 0.17)))
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor(Colors.TEXT_MUTED))
        painter.drawText(
            QRectF(rect.x(), baseline - radius * 0.17, diameter, radius * 0.17),
            Qt.AlignCenter, f"/ {self._max_value:.0f}",
        )

        painter.end()


class SparklineChart(QWidget):
    """Multi-series line chart (Analyses Over Time) with a light dotted grid, dark-theme style."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._series: list[tuple[str, list[float], str]] = []  # (name, values, color)
        self._x_labels: list[str] = []
        self.setMinimumHeight(140)

    def set_data(self, series: list[tuple[str, list[float], str]], x_labels: list[str]):
        self._series = series
        self._x_labels = x_labels
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        margin_left, margin_bottom, margin_top = 28, 22, 10
        plot_rect = QRectF(
            margin_left, margin_top,
            self.width() - margin_left - 10,
            self.height() - margin_top - margin_bottom,
        )

        max_value = 1.0
        for _, values, _ in self._series:
            if values:
                max_value = max(max_value, max(values))

        grid_pen = QPen(QColor(Colors.BORDER_SUBTLE))
        grid_pen.setWidth(1)
        painter.setPen(grid_pen)
        for i in range(5):
            y = plot_rect.top() + plot_rect.height() * i / 4
            painter.drawLine(plot_rect.left(), y, plot_rect.right(), y)
            painter.setPen(QColor(Colors.TEXT_MUTED))
            painter.drawText(
                QRectF(0, y - 8, margin_left - 4, 16), Qt.AlignRight | Qt.AlignVCenter,
                str(int(max_value * (4 - i) / 4)),
            )
            painter.setPen(grid_pen)

        n_points = max((len(v) for _, v, _ in self._series), default=1)
        step_x = plot_rect.width() / max(1, n_points - 1) if n_points > 1 else 0

        for _, values, color in self._series:
            if not values:
                continue
            path = QPainterPath()
            for i, val in enumerate(values):
                x = plot_rect.left() + step_x * i
                y = plot_rect.bottom() - (val / max_value) * plot_rect.height()
                if i == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            pen = QPen(QColor(color))
            pen.setWidth(2)
            painter.setPen(pen)
            painter.drawPath(path)

            dot_brush = QColor(color)
            painter.setBrush(dot_brush)
            painter.setPen(Qt.NoPen)
            for i, val in enumerate(values):
                x = plot_rect.left() + step_x * i
                y = plot_rect.bottom() - (val / max_value) * plot_rect.height()
                painter.drawEllipse(QRectF(x - 2.5, y - 2.5, 5, 5))

        painter.setPen(QColor(Colors.TEXT_MUTED))
        font = QFont()
        font.setPixelSize(10)
        painter.setFont(font)
        for i, label in enumerate(self._x_labels):
            x = plot_rect.left() + (step_x * i if n_points > 1 else plot_rect.width() / 2)
            painter.drawText(
                QRectF(x - 20, plot_rect.bottom() + 4, 40, 16), Qt.AlignCenter, label
            )

        painter.end()


class SeverityBar(QWidget):
    """A single labeled horizontal bar (used for Findings Severity breakdown rows)."""

    def __init__(self, label: str, value: int, total: int, color: str, parent=None):
        super().__init__(parent)
        self._label = label
        self._value = value
        self._total = max(total, 1)
        self._color = color
        self.setMinimumHeight(34)

    def set_value(self, value: int, total: int):
        self._value = value
        self._total = max(total, 1)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        dot_color = QColor(self._color)
        painter.setBrush(dot_color)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 4, 8, 8)

        painter.setPen(QColor(Colors.TEXT_SECONDARY))
        font = QFont()
        font.setPixelSize(11)
        painter.setFont(font)
        painter.drawText(QRectF(14, 0, 110, 16), Qt.AlignVCenter | Qt.AlignLeft, self._label)

        pct = round((self._value / self._total) * 100)
        painter.setPen(QColor(Colors.TEXT_PRIMARY))
        painter.drawText(
            QRectF(self.width() - 90, 0, 90, 16), Qt.AlignVCenter | Qt.AlignRight,
            f"{self._value} ({pct}%)",
        )

        bar_rect = QRectF(0, 20, self.width(), 8)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(Colors.BORDER))
        painter.drawRoundedRect(bar_rect, 4, 4)

        fill_width = bar_rect.width() * (self._value / self._total)
        painter.setBrush(dot_color)
        painter.drawRoundedRect(QRectF(0, 20, fill_width, 8), 4, 4)

        painter.end()
