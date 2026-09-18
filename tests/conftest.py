"""
Global pytest configuration.

Forces the Qt offscreen platform plugin before any test imports
PySide6, so the GUI test suite runs headlessly in CI / this sandbox
without requiring a real display. Only takes effect if the person
hasn't already set QT_QPA_PLATFORM themselves.
"""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("PENTROID_HEADLESS", "1")
