"""Single-invocation execution through the shared application session."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Awaitable, Callable
from uuid import uuid4

from vulnclaw import headless
from vulnclaw.agent.errors import format_llm_user_error
from vulnclaw.application import (
    ApplicationSession,
    ApplicationStreamSink,
    RuntimeFactory,
    TaskRunner,
)
from vulnclaw.cli.output import CommandOutput
from vulnclaw.input_service import InputRequest
from vulnclaw.task_service import TaskCreateRequest


class HeadlessInteraction:
    """An injected interaction endpoint; it never changes execution permissions."""

    def __init__(self) -> None:
        self.status: str | None = None
        self.details: dict[str, Any] = {}

    def question(self, text: str) -> None:
        self.status = "requires_input"
        self.details = {"question": text}
        raise asyncio.CancelledError

    def channel(self, sink: ApplicationStreamSink):
        interaction = self

        class Channel:
            async def request_approval(self, view) -> str:
                interaction.status = "requires_approval"
                interaction.details = view.to_event_payload()
                sink._event("approval_required", **interaction.details)
                raise asyncio.CancelledError

            async def notify_closed(self, request_hash: str, status: str) -> None:
                sink._event("approval_closed", request_hash=request_hash, status=status)

        return Channel()


class HeadlessExecutor:
    def __init__(
        self,
        output: CommandOutput,
        *,
        runtime_factory: RuntimeFactory = None,
        task_runner: TaskRunner = None,
    ) -> None:
        self.output = output
        self.task_id = f"task-{uuid4().hex}"
        self.interaction = HeadlessInteraction()
        self.terminal: dict[str, Any] | None = None
        self.control_result: dict[str, Any] | None = None
        self.application = ApplicationSession(
            self._event,
            source="headless",
            runtime_factory=runtime_factory,
            task_runner=task_runner,
            approval_channel_factory=self.interaction.channel,
            on_question=self.interaction.question,
        )

    def _event(self, event_type: str, **fields: Any) -> None:
        if event_type == "control_result" and fields.get("request_id") == self.output.request_id:
            self.control_result = fields["result"]
        if event_type in {
            "task_completed",
            "turn_completed",
            "task_failed",
            "turn_failed",
            "task_cancelled",
            "turn_cancelled",
        }:
            self.terminal = {"type": event_type, **fields}
        self.output.event(event_type, **fields)

    async def execute(
        self,
        request: InputRequest,
        *,
        fail_on: str = headless.DEFAULT_FAIL_ON,
        scan_mode: str = headless.DEFAULT_SCAN_MODE,
        scope_mode: str = headless.DEFAULT_SCOPE_MODE,
        profile: headless.ScanProfile | None = None,
        direct: Callable[[ApplicationSession, ApplicationStreamSink], Awaitable[dict[str, Any]]]
        | None = None,
    ) -> dict[str, Any]:
        app = self.application
        result: dict[str, Any] = {}
        error = None
        status = "completed"
        classification: headless.FindingClassification | None = None
        artifacts: list[dict[str, str]] = []
        code = 0
        try:
            await app.handle("initialize", request_id=self.output.request_id)
            if direct is not None:
                from vulnclaw.agent.exec_gate import get_execution_gate

                sink = ApplicationStreamSink(
                    self._event,
                    self.task_id,
                    show_thinking=app.config.session.show_thinking,
                    request_id=self.output.request_id,
                    approval_channel_factory=self.interaction.channel,
                    on_question=self.interaction.question,
                )
                gate = get_execution_gate(app.config)
                previous = gate.channel
                gate.install_channel(self.interaction.channel(sink))
                try:
                    result = await direct(app, sink)
                    sink.on_stream_end()
                except asyncio.CancelledError:
                    sink.on_stream_end("cancelled")
                    raise
                except Exception:
                    sink.on_stream_end("failed")
                    raise
                finally:
                    gate.install_channel(
                        previous
                    ) if previous is not None else gate.uninstall_channel()
            else:
                if request.task is not None:
                    task = request.task
                    payload = (
                        task.model_dump(mode="json", exclude_unset=True)
                        if isinstance(task, TaskCreateRequest)
                        else task
                    )
                    await app.handle(
                        "start_task",
                        request_id=self.output.request_id,
                        task_id=self.task_id,
                        payload={"task": payload},
                    )
                else:
                    await app.handle(
                        "submit_input",
                        request_id=self.output.request_id,
                        task_id=self.task_id,
                        payload={"text": request.text},
                    )
                await app.wait_for_idle()
                event = self.terminal or {}
                result = event.get("result") or self.control_result or {}
                if event.get("type") in {"task_failed", "turn_failed"}:
                    status, code, error = "failed", 1, event["error"]
                elif event.get("type") in {"task_cancelled", "turn_cancelled"}:
                    status, code = "cancelled", 1
                    error = {"code": "cancelled", "message": "Command cancelled."}
            if (
                app.conversation
                and app.conversation.pending_questions
                and not self.interaction.status
            ):
                self.interaction.status = "requires_input"
                self.interaction.details = {"questions": list(app.conversation.pending_questions)}
            if status == "completed" and result.get("status") in {"failed", "interrupted"}:
                status, code = ("cancelled" if result["status"] == "interrupted" else "failed"), 1
                error = {"code": "task_incomplete", "message": "The task did not complete."}
            if status == "completed" and result.get("report_error"):
                status, code = "failed", 1
                error = {"code": "report_export_failed", "message": str(result["report_error"])}
            if (
                status == "completed"
                and not self.interaction.status
                and (
                    request.task is not None
                    or direct is not None
                    or result.get("completed")
                    or app.conversation.auto_mode
                )
            ):
                from vulnclaw.report.findings_output import build_findings_document

                session = getattr(getattr(app.runtime, "agent", None), "session_state", None)
                if (
                    isinstance(request.task, TaskCreateRequest)
                    and request.task.command == "codescan"
                ):
                    classification = headless.FindingClassification(
                        0, len(result.get("findings", []))
                    )
                elif session is not None:
                    classification = headless.classify_report_findings(
                        build_findings_document(session)
                    )
                elif result.get("findings"):
                    classification = headless.FindingClassification(0, len(result["findings"]))
                else:
                    classification = headless.FindingClassification(0, 0)
                code = headless.determine_exit_code(classification, fail_on)
                report = result.get("report") or {}
                for kind, path in report.items():
                    if kind in {"path", "findings_json", "findings_sarif"} and path:
                        artifacts.append(
                            {"kind": "report" if kind == "path" else kind, "path": str(path)}
                        )
                run = result.get("run") or {}
                target = str(result.get("target") or app.current_target)
                root = getattr(request.task, "runs_dir", None)
                from vulnclaw.config.settings import RUNS_DIR

                directory = (
                    Path(run["directory"])
                    if run.get("directory")
                    else headless.run_directory(Path(root or RUNS_DIR), target, self.task_id)
                )
                summary = headless.build_run_summary(
                    target=target,
                    scan_mode=scan_mode,
                    scope_mode=scope_mode,
                    fail_on=fail_on,
                    profile=profile or headless.resolve_scan_profile(app.config, scan_mode),
                    classification=classification,
                    exit_code=code,
                    report_path=report.get("path"),
                )
                path = headless.write_run_artifacts(directory, summary).resolve()
                artifacts.append({"kind": "summary", "path": str(path)})
        except asyncio.CancelledError:
            status, code = "cancelled", 1
            error = {"code": "cancelled", "message": "Command cancelled."}
        except Exception as exc:
            from vulnclaw.cli.feedback import build_feedback

            status, code = "failed", 1
            error = {"code": getattr(exc, "code", "command_failed"), "message": format_llm_user_error(exc)}
            result["feedback"] = build_feedback(exc)
        finally:
            await app.close()
        if status == "failed" and error and "feedback" not in result:
            from vulnclaw.cli.feedback import build_feedback
            from vulnclaw.cli.output import CommandError

            result["feedback"] = build_feedback(CommandError(
                error["code"], error["message"], path=["task"],
            ))
        if self.interaction.status:
            from vulnclaw.cli.feedback import interaction_feedback

            status, code = self.interaction.status, 1
            result["interaction"] = self.interaction.details
            result["feedback"] = interaction_feedback(status)
            error = {
                "code": status,
                "message": "This invocation requires operator input."
                if status == "requires_input"
                else "This invocation requires operator approval.",
            }
        return self.output.finish(
            status=status,
            exit_code=code,
            result=result,
            error=error,
            task_id=self.task_id,
            artifacts=artifacts,
            findings=(
                {"verified": classification.verified, "candidates": classification.candidates}
                if classification
                else None
            ),
        )


async def execute_service(operation, config):
    """Run report/audit operations with the same headless interaction boundary."""
    from vulnclaw.agent.exec_gate import get_execution_gate
    from vulnclaw.cli.output import current_output

    output = current_output()
    interaction = HeadlessInteraction()
    sink = ApplicationStreamSink(
        output.event, f"task-{uuid4().hex}", show_thinking=config.session.show_thinking
    )
    gate = get_execution_gate(config)
    previous = gate.channel
    gate.install_channel(interaction.channel(sink))
    try:
        result = await operation()
    except asyncio.CancelledError:
        from vulnclaw.cli.feedback import interaction_feedback

        status = interaction.status or "cancelled"
        return output.finish(
            status=status,
            exit_code=1,
            result={**interaction.details, "interaction": interaction.details,
                    "feedback": interaction_feedback(status)} if interaction.status else {},
            error={
                "code": status,
                "message": "Operator approval is required."
                if interaction.status
                else "Command cancelled.",
            },
        )
    finally:
        gate.install_channel(previous) if previous is not None else gate.uninstall_channel()
    return result
