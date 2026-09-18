"""
app.core.workflow.task_scheduler
==================================

Runs workflow jobs on a bounded worker pool so the GUI thread is never
blocked by a long static/dynamic/malware analysis run. Deliberately
built on plain ``concurrent.futures`` (not ``QThread``) so the core
engine has zero PySide6 dependency and is independently testable/usable
headless (e.g. from a future CLI); the GUI module wraps a submitted
``Future`` with a ``QRunnable``/signal bridge if it wants Qt-native
progress callbacks, but that adapter lives in ``app/gui``, not here.
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable

from app.core.logger import get_logger

logger = get_logger(__name__)


class TaskScheduler:
    """Thin wrapper over a ThreadPoolExecutor with job-id tracking + cancellation."""

    def __init__(self, max_workers: int = 4) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="pentroid-worker"
        )
        self._futures: dict[str, Future] = {}
        self._lock = threading.Lock()

    def submit(self, fn: Callable, *args, job_id: str | None = None, **kwargs) -> str:
        """Submit ``fn(*args, **kwargs)`` to run in the background. Returns the job_id."""
        job_id = job_id or str(uuid.uuid4())
        future = self._executor.submit(fn, *args, **kwargs)
        with self._lock:
            self._futures[job_id] = future

        def _cleanup(f: Future, jid: str = job_id) -> None:
            if f.exception() is not None:
                logger.error("Job %s raised: %s", jid, f.exception())

        future.add_done_callback(_cleanup)
        return job_id

    def cancel(self, job_id: str) -> bool:
        """Attempt to cancel a not-yet-started job. Returns True if cancellation succeeded."""
        with self._lock:
            future = self._futures.get(job_id)
        if future is None:
            return False
        return future.cancel()

    def is_running(self, job_id: str) -> bool:
        with self._lock:
            future = self._futures.get(job_id)
        return future is not None and future.running()

    def is_done(self, job_id: str) -> bool:
        with self._lock:
            future = self._futures.get(job_id)
        return future is not None and future.done()

    def result(self, job_id: str, timeout: float | None = None):
        """Block for and return a job's result (mainly used in tests)."""
        with self._lock:
            future = self._futures.get(job_id)
        if future is None:
            raise KeyError(f"Unknown job_id: {job_id}")
        return future.result(timeout=timeout)

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)


_scheduler: TaskScheduler | None = None
_scheduler_lock = threading.Lock()


def get_task_scheduler() -> TaskScheduler:
    global _scheduler
    if _scheduler is None:
        with _scheduler_lock:
            if _scheduler is None:
                _scheduler = TaskScheduler()
    return _scheduler
