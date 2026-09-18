"""
app.core.workflow.job_monitor
===============================

Tracks progress of in-flight workflow jobs so the GUI's Analysis Queue
panel can show live percentage/status without polling the database on
every tick. The Workflow Manager reports into this; the GUI (via the
Event Bus) reads out of it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class JobProgress:
    job_id: str
    analysis_id: int
    total_steps: int
    completed_steps: int = 0
    current_step_name: str = ""
    status: str = "pending"  # pending/running/completed/failed/cancelled

    @property
    def percent(self) -> float:
        if self.total_steps == 0:
            return 0.0
        return round((self.completed_steps / self.total_steps) * 100, 1)


class JobMonitor:
    """Thread-safe in-memory registry of job progress, keyed by job_id."""

    def __init__(self) -> None:
        self._jobs: dict[str, JobProgress] = {}
        self._lock = threading.Lock()

    def register(self, job_id: str, analysis_id: int, total_steps: int) -> None:
        with self._lock:
            self._jobs[job_id] = JobProgress(
                job_id=job_id, analysis_id=analysis_id, total_steps=total_steps
            )

    def mark_running(self, job_id: str) -> None:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = "running"

    def advance_step(self, job_id: str, step_name: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.completed_steps += 1
            job.current_step_name = step_name

    def finish(self, job_id: str, status: str) -> None:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = status

    def get(self, job_id: str) -> JobProgress | None:
        with self._lock:
            return self._jobs.get(job_id)

    def all_jobs(self) -> list[JobProgress]:
        with self._lock:
            return list(self._jobs.values())

    def remove(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)


_monitor: JobMonitor | None = None
_monitor_lock = threading.Lock()


def get_job_monitor() -> JobMonitor:
    global _monitor
    if _monitor is None:
        with _monitor_lock:
            if _monitor is None:
                _monitor = JobMonitor()
    return _monitor
