"""
app.gui.controllers.background_task_runner
=============================================

Generic GUI-thread-safe bridge for running any blocking callable (ADB
device scans, Setup Wizard steps, future dependency installs) on
``TaskScheduler`` without freezing the UI. Same non-blocking-poll
pattern as ``AnalysisRunner``, generalized: this one doesn't know
anything about workflows or analyses, just "run this callable in the
background, tell me when it's done."
"""

from __future__ import annotations

import concurrent.futures
import uuid
from typing import Any, Callable

from PySide6.QtCore import QObject, QTimer, Signal

from app.core.workflow.task_scheduler import TaskScheduler, get_task_scheduler

_POLL_INTERVAL_MS = 200


class BackgroundTaskRunner(QObject):
    finished = Signal(str, object)  # job_id, result
    failed = Signal(str, str)       # job_id, error message

    def __init__(self, scheduler: TaskScheduler | None = None, parent=None) -> None:
        super().__init__(parent)
        self._scheduler = scheduler or get_task_scheduler()
        self._timer = QTimer(self)
        self._timer.setInterval(_POLL_INTERVAL_MS)
        self._timer.timeout.connect(self._poll)
        self._pending: set[str] = set()

    def run(self, fn: Callable, *args: Any, **kwargs: Any) -> str:
        job_id = str(uuid.uuid4())
        self._scheduler.submit(fn, *args, job_id=job_id, **kwargs)
        self._pending.add(job_id)
        if not self._timer.isActive():
            self._timer.start()
        return job_id

    def _poll(self) -> None:
        done_jobs = []
        for job_id in list(self._pending):
            if not self._scheduler.is_done(job_id):
                continue
            try:
                result = self._scheduler.result(job_id, timeout=0)
            except Exception as exc:  # noqa: BLE001 - any task failure is reported, not swallowed
                self.failed.emit(job_id, str(exc))
            else:
                self.finished.emit(job_id, result)
            done_jobs.append(job_id)

        for job_id in done_jobs:
            self._pending.discard(job_id)
        if not self._pending:
            self._timer.stop()


_runner: BackgroundTaskRunner | None = None


def get_background_task_runner() -> BackgroundTaskRunner:
    global _runner
    if _runner is None:
        _runner = BackgroundTaskRunner()
    return _runner
