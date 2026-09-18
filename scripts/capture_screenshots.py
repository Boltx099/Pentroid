"""
Capture real screenshots of the running application for the README.

Renders the actual widgets offscreen (QT_QPA_PLATFORM=offscreen) against
the seeded demo dataset -- these are not mockups.
"""
import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["PENTROID_HEADLESS"] = "1"
os.environ["PENTROID_PATHS__ROOT"] = "/tmp/pentroid_demo_root"

import sys
sys.path.insert(0, "/home/claude/work/Pentroid")

from main import bootstrap
bootstrap()
import main as entrypoint

from PySide6.QtWidgets import QApplication

app = QApplication.instance() or QApplication([])
entrypoint._launch_gui()

window = next(
    w for w in QApplication.instance().topLevelWidgets() if w.__class__.__name__ == "MainWindow"
)
window.resize(1680, 1000)
for _ in range(6):
    app.processEvents()

OUT = "/home/claude/work/Pentroid/assets/screenshots"
os.makedirs(OUT, exist_ok=True)


import time


def snap(key: str, filename: str, settle_seconds: float = 1.5):
    window._navigate(key)
    deadline = time.monotonic() + settle_seconds
    while time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.05)
    window.grab().save(f"{OUT}/{filename}")
    print(f"  {filename}  <-  {key}")


print("Capturing full-window pages...")
snap("dashboard", "01_dashboard.png")
snap("android_apk", "02_android_apk_pipeline.png")
snap("toolbox", "03_toolbox.png", settle_seconds=3.0)
snap("plugin_center", "04_plugin_center.png", settle_seconds=2.0)
snap("frida_hub", "05_frida_hub.png", settle_seconds=2.0)
snap("adb_toolkit", "06_adb_toolkit.png")
snap("network_analysis", "07_network_analysis.png", settle_seconds=2.0)
snap("logs", "08_logs.png")

print("Capturing FindingsDialog...")
from app.gui.dialogs.findings_dialog import FindingsDialog
from app.database.database import session_scope
from app.database.models import Analysis

with session_scope() as session:
    analysis_id = (
        session.query(Analysis)
        .filter_by(workflow_name="static_analysis_default")
        .first()
        .id
    )

dialog = FindingsDialog(analysis_id, window)
dialog.resize(760, 900)
dialog.show()
for _ in range(6):
    app.processEvents()
dialog.grab().save(f"{OUT}/09_findings_detail.png")
print("  09_findings_detail.png  <-  FindingsDialog (grouped, with triage status)")
dialog.close()

print("Done.")
