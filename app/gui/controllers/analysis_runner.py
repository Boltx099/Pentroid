"""
app.gui.controllers.analysis_runner
======================================

Bridges the GUI to ``WorkflowManager`` safely. Qt widgets must only
ever be touched from the main thread, but ``WorkflowManager`` runs
jobs on background worker threads (``TaskScheduler``) and publishes
progress via ``EventBus`` from those same threads. Rather than
subscribing GUI callbacks directly to ``EventBus`` (which would call
into Qt widgets from a non-GUI thread -- undefined behavior), this
controller polls ``JobMonitor`` on a ``QTimer`` running on the GUI
thread, and re-emits progress as Qt signals. This is the *only* place
in the GUI that touches ``WorkflowManager`` -- pages call
``AnalysisRunner.start(...)``, never the workflow engine directly.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, QTimer, Signal

from app.core.workflow.job_monitor import get_job_monitor
from app.core.workflow.task_scheduler import get_task_scheduler
from app.core.workflow.workflow_manager import get_workflow_manager
from app.database.database import session_scope
from app.database.models import Analysis

_POLL_INTERVAL_MS = 300


class AnalysisRunner(QObject):
    progress = Signal(str, float, str)        # job_id, percent, current_step_name
    completed = Signal(str, str, float, int)  # job_id, status, risk_score, analysis_id
    failed_to_start = Signal(str)              # error message

    def __init__(self, parent=None):
        super().__init__(parent)
        self._job_monitor = get_job_monitor()
        self._workflow_manager = get_workflow_manager()
        self._scheduler = get_task_scheduler()
        self._timer = QTimer(self)
        self._timer.setInterval(_POLL_INTERVAL_MS)
        self._timer.timeout.connect(self._poll)
        self._active_jobs: set[str] = set()

    def start(
        self, workflow_name: str, project_id: int, target_path: str,
        workspace_path: str, device_id: int | None = None,
    ) -> str | None:
        try:
            job_id = self._workflow_manager.run_workflow_async(
                workflow_name, project_id, target_path, workspace_path, device_id
            )
        except Exception as exc:  # noqa: BLE001 - surface any startup failure to the GUI, don't crash it
            self.failed_to_start.emit(str(exc))
            return None

        self._active_jobs.add(job_id)
        if not self._timer.isActive():
            self._timer.start()
        return job_id

    def _poll(self) -> None:
        finished_jobs = []
        for job_id in list(self._active_jobs):
            progress = self._job_monitor.get(job_id)
            if progress is None:
                continue

            self.progress.emit(job_id, progress.percent, progress.current_step_name)

            if progress.status in ("completed", "failed", "cancelled"):
                risk_score = self._lookup_risk_score(job_id)
                self.completed.emit(job_id, progress.status, risk_score, progress.analysis_id)
                finished_jobs.append(job_id)

        for job_id in finished_jobs:
            self._active_jobs.discard(job_id)

        if not self._active_jobs:
            self._timer.stop()

    def _lookup_risk_score(self, job_id: str) -> float:
        """run_workflow_async's background target returns analysis_id; look up its risk_score from the DB."""
        progress = self._job_monitor.get(job_id)
        if progress is None:
            return 0.0
        with session_scope() as session:
            analysis = session.get(Analysis, progress.analysis_id)
            return analysis.risk_score if analysis and analysis.risk_score is not None else 0.0


_runner: AnalysisRunner | None = None


def get_analysis_runner() -> AnalysisRunner:
    global _runner
    if _runner is None:
        _runner = AnalysisRunner()
    return _runner
