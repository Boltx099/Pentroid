"""
Tests for BackgroundTaskRunner (Module 8a foundation).
"""

from __future__ import annotations

import time

import pytest


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def test_run_success_emits_finished_with_result(qapp):
    from app.gui.controllers.background_task_runner import BackgroundTaskRunner
    from PySide6.QtWidgets import QApplication

    runner = BackgroundTaskRunner()
    results = []
    runner.finished.connect(lambda job_id, result: results.append((job_id, result)))

    job_id = runner.run(lambda: 6 * 7)
    for _ in range(30):
        QApplication.processEvents()
        time.sleep(0.05)
        if results:
            break

    assert len(results) == 1
    assert results[0][0] == job_id
    assert results[0][1] == 42


def test_run_failure_emits_failed_with_error_message(qapp):
    from app.gui.controllers.background_task_runner import BackgroundTaskRunner
    from PySide6.QtWidgets import QApplication

    runner = BackgroundTaskRunner()
    errors = []
    runner.failed.connect(lambda job_id, msg: errors.append((job_id, msg)))

    def _boom():
        raise ValueError("something broke")

    job_id = runner.run(_boom)
    for _ in range(30):
        QApplication.processEvents()
        time.sleep(0.05)
        if errors:
            break

    assert len(errors) == 1
    assert errors[0][0] == job_id
    assert "something broke" in errors[0][1]


def test_run_with_args_and_kwargs(qapp):
    from app.gui.controllers.background_task_runner import BackgroundTaskRunner
    from PySide6.QtWidgets import QApplication

    runner = BackgroundTaskRunner()
    results = []
    runner.finished.connect(lambda job_id, result: results.append(result))

    def _add(a, b, multiplier=1):
        return (a + b) * multiplier

    runner.run(_add, 2, 3, multiplier=10)
    for _ in range(30):
        QApplication.processEvents()
        time.sleep(0.05)
        if results:
            break

    assert results == [50]


def test_multiple_concurrent_jobs_all_complete(qapp):
    from app.gui.controllers.background_task_runner import BackgroundTaskRunner
    from PySide6.QtWidgets import QApplication

    runner = BackgroundTaskRunner()
    results = []
    runner.finished.connect(lambda job_id, result: results.append(result))

    for i in range(5):
        runner.run(lambda x=i: x * x)

    for _ in range(50):
        QApplication.processEvents()
        time.sleep(0.05)
        if len(results) == 5:
            break

    assert sorted(results) == [0, 1, 4, 9, 16]
