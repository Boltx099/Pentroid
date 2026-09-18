"""
app.core.workflow.workflow_manager
=====================================

The Workflow Orchestrator. This is the *only* place in Pentroid that
sequences plugin execution -- the GUI calls
``WorkflowManager.run_workflow_async(...)`` and everything downstream
(Plugin Manager, Result Aggregator, Database, Event Bus) is driven from
here. Nothing upstream of this module ever touches a Plugin directly.

Workflow definitions are declarative (``WorkflowDefinition`` /
``WorkflowStepDefinition``) and only ever reference plugins that are
actually implemented -- as more Tool Manager-backed plugins land
(APKTool, JADX, YARA, ...) their steps are appended to the relevant
``WORKFLOW_REGISTRY`` entry, not stubbed in ahead of time.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.exceptions import PluginExecutionError, PluginInitializationError, PluginNotFoundError, WorkflowNotFoundError
from app.core.logger import get_logger
from app.core.schemas import PluginRunStatus, WorkflowStepContext
from app.core.workflow.error_handler import WorkflowErrorHandler
from app.core.workflow.event_bus import EventBus, get_event_bus
from app.core.workflow.job_monitor import JobMonitor, get_job_monitor
from app.core.workflow.plugin_manager import PluginManager, get_plugin_manager
from app.core.workflow.result_aggregator import ResultAggregator
from app.core.workflow.task_scheduler import TaskScheduler, get_task_scheduler
from app.database.database import session_scope
from app.database.models import Analysis, AnalysisType, RunStatus

logger = get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(frozen=True)
class WorkflowStepDefinition:
    name: str
    plugin_id: str
    required: bool = True  # if True, a FAILED status aborts the whole workflow


@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    analysis_type: AnalysisType
    steps: list[WorkflowStepDefinition] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Registry of workflows. Only steps with a real, working plugin are listed --
# see module docstring. Steps are appended here as later modules (Tool
# Manager -> APKTool/JADX/YARA/... plugins) land.
# --------------------------------------------------------------------------- #
WORKFLOW_REGISTRY: dict[str, WorkflowDefinition] = {
    "static_analysis_default": WorkflowDefinition(
        name="static_analysis_default",
        analysis_type=AnalysisType.STATIC,
        steps=[
            WorkflowStepDefinition(name="Validate APK", plugin_id="apk_validator", required=True),
            WorkflowStepDefinition(name="Certificate Analysis", plugin_id="certificate_analysis", required=False),
            WorkflowStepDefinition(name="APKTool Decode", plugin_id="apktool_decode", required=False),
            WorkflowStepDefinition(name="JADX Decompile", plugin_id="jadx_decompile", required=False),
            WorkflowStepDefinition(name="Manifest Analysis", plugin_id="manifest_analysis", required=False),
            WorkflowStepDefinition(name="Network Security Config", plugin_id="network_security_config", required=False),
            WorkflowStepDefinition(name="Secrets Detection", plugin_id="secrets_detection", required=False),
            WorkflowStepDefinition(name="Code Analysis", plugin_id="code_analysis", required=False),
            WorkflowStepDefinition(name="Tracker & SDK Detection", plugin_id="tracker_detection", required=False),
        ],
    ),
    "malware_analysis_default": WorkflowDefinition(
        name="malware_analysis_default",
        analysis_type=AnalysisType.MALWARE,
        steps=[
            WorkflowStepDefinition(name="File Hashing", plugin_id="file_hashing", required=True),
            WorkflowStepDefinition(name="Certificate Analysis", plugin_id="certificate_analysis", required=False),
            WorkflowStepDefinition(name="VirusTotal Lookup", plugin_id="virustotal_lookup", required=False),
            WorkflowStepDefinition(name="YARA Scan", plugin_id="yara_scan", required=False),
            WorkflowStepDefinition(name="APKiD Scan", plugin_id="apkid_scan", required=False),
            WorkflowStepDefinition(name="Quark-Engine Scan", plugin_id="quark_engine", required=False),
            WorkflowStepDefinition(name="APKTool Decode", plugin_id="apktool_decode", required=False),
            WorkflowStepDefinition(name="JADX Decompile", plugin_id="jadx_decompile", required=False),
            WorkflowStepDefinition(name="Manifest Analysis", plugin_id="manifest_analysis", required=False),
            WorkflowStepDefinition(name="IOC Extraction", plugin_id="ioc_extraction", required=False),
            WorkflowStepDefinition(name="MITRE ATT&CK Mapping", plugin_id="mitre_attack_mapping", required=False),
        ],
    ),
    "dynamic_analysis_default": WorkflowDefinition(
        name="dynamic_analysis_default",
        analysis_type=AnalysisType.DYNAMIC,
        steps=[
            WorkflowStepDefinition(name="Validate APK", plugin_id="apk_validator", required=True),
            WorkflowStepDefinition(name="APKTool Decode", plugin_id="apktool_decode", required=False),
            WorkflowStepDefinition(name="Manifest Analysis", plugin_id="manifest_analysis", required=False),
            WorkflowStepDefinition(name="App Deployment", plugin_id="app_deployment", required=False),
            WorkflowStepDefinition(name="Frida Instrumentation", plugin_id="frida_instrumentation", required=False),
            WorkflowStepDefinition(name="Logcat Capture", plugin_id="logcat_capture", required=False),
        ],
    ),
    "privacy_analysis_default": WorkflowDefinition(
        name="privacy_analysis_default",
        analysis_type=AnalysisType.PRIVACY,
        steps=[
            WorkflowStepDefinition(name="Validate APK", plugin_id="apk_validator", required=True),
            WorkflowStepDefinition(name="APKTool Decode", plugin_id="apktool_decode", required=False),
            WorkflowStepDefinition(name="Manifest Analysis", plugin_id="manifest_analysis", required=False),
            WorkflowStepDefinition(name="Network Security Config", plugin_id="network_security_config", required=False),
            WorkflowStepDefinition(name="Tracker & SDK Detection", plugin_id="tracker_detection", required=False),
            WorkflowStepDefinition(name="IOC Extraction", plugin_id="ioc_extraction", required=False),
        ],
    ),
    # Decode + decompile only, with no findings-producing analysis steps. That
    # is deliberate: this workflow exists so the Reverse Engineering page can
    # materialise smali/resources/Java sources into the project workspace for
    # manual review, which is a different job from "score this APK". A run that
    # ends with 0 findings here is the expected outcome, not a broken scan.
    "reverse_engineering_default": WorkflowDefinition(
        name="reverse_engineering_default",
        analysis_type=AnalysisType.STATIC,
        steps=[
            WorkflowStepDefinition(name="Validate APK", plugin_id="apk_validator", required=True),
            WorkflowStepDefinition(name="APKTool Decode", plugin_id="apktool_decode", required=False),
            WorkflowStepDefinition(name="JADX Decompile", plugin_id="jadx_decompile", required=False),
        ],
    ),
}


class WorkflowManager:
    """Orchestrates execution of a named workflow against a project's target file."""

    def __init__(
        self,
        plugin_manager: PluginManager | None = None,
        event_bus: EventBus | None = None,
        job_monitor: JobMonitor | None = None,
        scheduler: TaskScheduler | None = None,
        result_aggregator: ResultAggregator | None = None,
        error_handler: WorkflowErrorHandler | None = None,
    ) -> None:
        self._plugin_manager = plugin_manager or get_plugin_manager()
        self._event_bus = event_bus or get_event_bus()
        self._job_monitor = job_monitor or get_job_monitor()
        self._scheduler = scheduler or get_task_scheduler()
        self._aggregator = result_aggregator or ResultAggregator()
        self._error_handler = error_handler or WorkflowErrorHandler()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def run_workflow_async(
        self,
        workflow_name: str,
        project_id: int,
        target_path: str,
        workspace_path: str,
        device_id: int | None = None,
    ) -> str:
        """
        Submit a workflow to run on a background worker thread.
        Returns a ``job_id`` the GUI can use to poll ``JobMonitor``.

        Validates ``workflow_name`` synchronously before submitting --
        an unknown workflow raises immediately here rather than being
        discovered only after a background job has already been
        scheduled (where the failure would have nothing to report to:
        ``JobMonitor.register`` hasn't run yet, so the job would be
        unobservable by any caller polling for its progress).
        """
        if workflow_name not in WORKFLOW_REGISTRY:
            raise WorkflowNotFoundError(f"Unknown workflow: {workflow_name}")

        job_id = str(uuid.uuid4())
        self._scheduler.submit(
            self._execute,
            workflow_name,
            project_id,
            target_path,
            workspace_path,
            device_id,
            job_id,
            job_id=job_id,
        )
        return job_id

    def run_workflow_sync(
        self,
        workflow_name: str,
        project_id: int,
        target_path: str,
        workspace_path: str,
        device_id: int | None = None,
    ) -> int:
        """Run a workflow on the calling thread (used by tests / a future CLI). Returns analysis_id."""
        job_id = str(uuid.uuid4())
        return self._execute(
            workflow_name, project_id, target_path, workspace_path, device_id, job_id
        )

    # ------------------------------------------------------------------ #
    # Core execution
    # ------------------------------------------------------------------ #
    def _execute(
        self,
        workflow_name: str,
        project_id: int,
        target_path: str,
        workspace_path: str,
        device_id: int | None,
        job_id: str,
    ) -> int:
        definition = WORKFLOW_REGISTRY.get(workflow_name)
        if definition is None:
            raise WorkflowNotFoundError(f"Unknown workflow: {workflow_name}")

        analysis_id = self._create_analysis_row(project_id, device_id, definition)
        self._job_monitor.register(job_id, analysis_id, total_steps=len(definition.steps))
        self._job_monitor.mark_running(job_id)

        self._event_bus.publish(
            "workflow.started",
            {"analysis_id": analysis_id, "workflow_name": workflow_name},
        )

        context = WorkflowStepContext(
            project_id=project_id,
            analysis_id=analysis_id,
            target_path=target_path,
            workspace_path=workspace_path,
            device_id=device_id,
        )

        aborted = False
        for step in definition.steps:
            self._event_bus.publish(
                "workflow.step_started",
                {"analysis_id": analysis_id, "step_name": step.name},
            )

            try:
                plugin = self._plugin_manager.instantiate(step.plugin_id)
            except (PluginNotFoundError, PluginInitializationError) as exc:
                failure = self._error_handler.handle_exception(
                    step.name, step.plugin_id, step.required, exc
                )
                self._record_step_failure(analysis_id, failure.message)
                if failure.should_abort_workflow:
                    aborted = True
                    break
                self._job_monitor.advance_step(job_id, step.name)
                continue

            try:
                output = plugin.execute(context)
            except PluginExecutionError as exc:
                failure = self._error_handler.handle_exception(
                    step.name, step.plugin_id, step.required, exc
                )
                self._record_step_failure(analysis_id, failure.message)
                if failure.should_abort_workflow:
                    aborted = True
                    break
                self._job_monitor.advance_step(job_id, step.name)
                continue
            finally:
                plugin.cleanup()

            context.step_outputs[step.name] = output
            created_ids = self._aggregator.persist(analysis_id, step.plugin_id, output)
            for finding_id in created_ids:
                self._event_bus.publish(
                    "workflow.finding_added",
                    {"analysis_id": analysis_id, "finding_id": finding_id},
                )

            if output.status == PluginRunStatus.FAILED:
                failure = self._error_handler.handle_output_failure(
                    step.name, step.plugin_id, step.required, output
                )
                self._record_step_failure(analysis_id, failure.message)
                if failure.should_abort_workflow:
                    aborted = True
                    break
            elif output.status == PluginRunStatus.SKIPPED:
                # Previously silent: a skipped step (e.g. "APKTool not installed") left
                # no trace anywhere the user could see, so a run with several optional
                # tools missing would complete with 0 findings and zero explanation why.
                # Not every plugin puts its skip explanation in the same field (some use
                # logs, some use errors) -- check both rather than assume one convention.
                if output.logs:
                    reason = output.logs[0]
                elif output.errors:
                    reason = output.errors[0]
                else:
                    reason = "step reported SKIPPED with no reason given"
                self._record_step_skip(analysis_id, step.name, reason)

            self._job_monitor.advance_step(job_id, step.name)
            self._event_bus.publish(
                "workflow.step_completed",
                {"analysis_id": analysis_id, "step_name": step.name, "status": output.status.value},
            )
            self._event_bus.publish(
                "workflow.progress",
                {"analysis_id": analysis_id, "percent": self._job_monitor.get(job_id).percent},
            )

        final_status = RunStatus.FAILED if aborted else RunStatus.COMPLETED
        risk_score = self._aggregator.compute_risk_score(analysis_id)
        self._finalize_analysis(analysis_id, final_status, risk_score)
        self._job_monitor.finish(job_id, final_status.value)

        self._event_bus.publish(
            "workflow.completed" if not aborted else "workflow.failed",
            {"analysis_id": analysis_id, "status": final_status.value, "risk_score": risk_score},
        )
        return analysis_id

    # ------------------------------------------------------------------ #
    # Database helpers
    # ------------------------------------------------------------------ #
    def _create_analysis_row(
        self, project_id: int, device_id: int | None, definition: WorkflowDefinition
    ) -> int:
        with session_scope() as session:
            analysis = Analysis(
                project_id=project_id,
                device_id=device_id,
                analysis_type=definition.analysis_type,
                workflow_name=definition.name,
                status=RunStatus.RUNNING,
                started_at=_utcnow(),
            )
            session.add(analysis)
            session.flush()
            return analysis.id

    def _record_step_failure(self, analysis_id: int, message: str) -> None:
        with session_scope() as session:
            analysis = session.get(Analysis, analysis_id)
            if analysis is not None:
                prior = analysis.error_message or ""
                analysis.error_message = (prior + f"\nFAILED: {message}").strip()

    def _record_step_skip(self, analysis_id: int, step_name: str, reason: str) -> None:
        with session_scope() as session:
            analysis = session.get(Analysis, analysis_id)
            if analysis is not None:
                prior = analysis.error_message or ""
                analysis.error_message = (prior + f"\nSKIPPED [{step_name}]: {reason}").strip()

    def _finalize_analysis(self, analysis_id: int, status: RunStatus, risk_score: float) -> None:
        with session_scope() as session:
            analysis = session.get(Analysis, analysis_id)
            if analysis is not None:
                analysis.status = status
                analysis.risk_score = risk_score
                analysis.completed_at = _utcnow()


_workflow_manager: WorkflowManager | None = None


def get_workflow_manager() -> WorkflowManager:
    global _workflow_manager
    if _workflow_manager is None:
        _workflow_manager = WorkflowManager()
    return _workflow_manager
