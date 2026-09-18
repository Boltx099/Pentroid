"""
app.core.workflow.error_handler
==================================

Centralizes what happens when a workflow step fails, so that policy
(abort vs. continue, what gets logged, what the Analysis row records)
lives in one place instead of being duplicated in every workflow.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.exceptions import PluginExecutionError, PluginInitializationError, PluginNotFoundError
from app.core.logger import get_logger
from app.core.schemas import PluginOutput, PluginRunStatus

logger = get_logger(__name__)


@dataclass
class StepFailure:
    step_name: str
    plugin_id: str
    message: str
    should_abort_workflow: bool


class WorkflowErrorHandler:
    """
    Decides, for a given failed step, whether the workflow should abort
    or continue to the next step -- and produces a normalized
    ``StepFailure`` record either way for logging / Analysis.error_message.
    """

    def handle_exception(
        self, step_name: str, plugin_id: str, required: bool, exc: Exception
    ) -> StepFailure:
        if isinstance(exc, (PluginNotFoundError, PluginInitializationError)):
            message = f"Plugin unavailable: {exc.message if hasattr(exc, 'message') else exc}"
        elif isinstance(exc, PluginExecutionError):
            message = f"Plugin crashed: {exc.message}"
        else:
            message = f"Unexpected error: {exc}"

        logger.error("Step '%s' (%s) failed: %s", step_name, plugin_id, message)
        return StepFailure(
            step_name=step_name,
            plugin_id=plugin_id,
            message=message,
            should_abort_workflow=required,
        )

    def handle_output_failure(
        self, step_name: str, plugin_id: str, required: bool, output: PluginOutput
    ) -> StepFailure:
        message = "; ".join(output.errors) if output.errors else "Plugin reported FAILED status"
        logger.warning("Step '%s' (%s) reported failure: %s", step_name, plugin_id, message)
        return StepFailure(
            step_name=step_name,
            plugin_id=plugin_id,
            message=message,
            should_abort_workflow=required and output.status == PluginRunStatus.FAILED,
        )
