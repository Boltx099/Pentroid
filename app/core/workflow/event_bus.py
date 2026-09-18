"""
app.core.workflow.event_bus
============================

Thread-safe publish/subscribe bus.

The Workflow Engine runs jobs on background threads (see
``task_scheduler.py``); the GUI must never be called into directly
from those threads (Qt widgets are not thread-safe). Instead, the
engine publishes named events here, and the GUI subscribes callbacks
that it marshals onto the Qt main thread itself (typically via a
``QueuedConnection`` signal) -- this module knows nothing about Qt.

Standard event names emitted by the Workflow Engine:
    workflow.started      {analysis_id, workflow_name}
    workflow.step_started {analysis_id, step_name}
    workflow.step_completed {analysis_id, step_name, status}
    workflow.progress      {analysis_id, percent}
    workflow.finding_added {analysis_id, finding_id, severity}
    workflow.completed     {analysis_id, status, risk_score}
    workflow.failed        {analysis_id, error}
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Callable

from app.core.logger import get_logger

logger = get_logger(__name__)

EventCallback = Callable[[dict[str, Any]], None]


class EventBus:
    """A minimal, thread-safe pub/sub bus. One instance per process (see `get_event_bus`)."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventCallback]] = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, event_name: str, callback: EventCallback) -> None:
        with self._lock:
            self._subscribers[event_name].append(callback)

    def unsubscribe(self, event_name: str, callback: EventCallback) -> None:
        with self._lock:
            callbacks = self._subscribers.get(event_name, [])
            if callback in callbacks:
                callbacks.remove(callback)

    def publish(self, event_name: str, payload: dict[str, Any] | None = None) -> None:
        """
        Synchronously invokes every subscriber for ``event_name``.
        A misbehaving subscriber is logged and skipped -- it must
        never take down the workflow thread that published the event.
        """
        payload = payload or {}
        with self._lock:
            callbacks = list(self._subscribers.get(event_name, []))

        for callback in callbacks:
            try:
                callback(payload)
            except Exception:
                logger.exception(
                    "Event subscriber raised while handling '%s'", event_name
                )

    def clear(self) -> None:
        """Remove all subscribers (used in tests)."""
        with self._lock:
            self._subscribers.clear()


_bus: EventBus | None = None
_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """Return the process-wide singleton EventBus."""
    global _bus
    if _bus is None:
        with _bus_lock:
            if _bus is None:
                _bus = EventBus()
    return _bus
