"""Transport-independent terminal application sessions and runtime ownership."""

from __future__ import annotations

import asyncio
import inspect
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from vulnclaw.agent.errors import format_llm_user_error
from vulnclaw.agent.streaming import TranscriptStreamSink
from vulnclaw.config.domain_models import validate_action_constraints
from vulnclaw.conversation import ConversationState, run_conversation
from vulnclaw.execution_details import ExecutionDetails
from vulnclaw.input_service import COMMANDS, InputRequest, command_help, parse_input
from vulnclaw.management_service import (
    MANAGEMENT_OPERATIONS,
    adapter_operation,
    execute_management,
)
from vulnclaw.mcp.registry import MCPRegistry
from vulnclaw.report_service import generate_report_for_run
from vulnclaw.scope_service import preview_scope
from vulnclaw.task_service import (
    SCOPE_FIELDS,
    TASK_COMMANDS,
    PreparedTask,
    TaskCreateRequest,
    TaskOptions,
    build_scope_constraints,
    execute_task,
    prepare_task,
    task_request_from_payload,
)


class ApplicationError(ValueError):
    """A rejected application operation, independent of its transport."""

    def __init__(
        self, code: str, message: str, *, request_id: str | None = None, task_id: str | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.request_id = request_id
        self.task_id = task_id


# Concrete management operations are capability-gated feature extensions. The
# base backend owns mutable session scope defaults; client posture remains local.
# Execution decisions and operator-initiated permission changes are usable
# while a task is active. Scope and LLM config mutation remain idle-only.
SUPPORTED_CONTROL_OPERATIONS = MANAGEMENT_OPERATIONS | frozenset(
    {
        "session.scope.reset",
        "session.scope.update",
        "execution.approval.resolve",
        "execution.details.read",
        "session.permission.set",
        "config.read",
        "config.preset",
        "config.models",
        "config.write",
        "session.new",
        "session.target.set",
        "session.compact",
        "session.help",
        "session.think",
        "session.scope.read",
        "session.scope.preview",
        "report.export",
        "task.preview",
    }
)
TASK_ACTIVE_CONTROL_OPERATIONS = frozenset({
    "execution.approval.resolve", "execution.details.read", "session.permission.set",
    "session.scope.read", "session.scope.preview", "session.help",
})
RUNTIME_STATE_FIELDS = frozenset(
    {"target", "phase", "task_constraints", "findings", "evidence", "constraint_violations"}
)


@dataclass
class ApplicationRuntime:
    """The reusable config/MCP/AgentCore aggregate for one application session."""

    config: Any
    mcp_manager: Any
    agent: Any
    mcp_started: int = 0
    stopped: bool = False

    async def stop(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        try:
            close = getattr(self.agent, "aclose", None)
            if close is not None:
                await close()
        finally:
            await self.mcp_manager.astop_all()


RuntimeFactory = Callable[[], Any | Awaitable[Any]]
TaskRunner = Callable[[Any, PreparedTask, "ApplicationStreamSink"], Awaitable[dict[str, Any]]]


class ApplicationStreamSink(TranscriptStreamSink):
    """Adapt AgentCore streaming callbacks to application events."""

    def __init__(
        self, emit: Callable[..., None], task_id: str, *, show_thinking: bool,
        question_ready: Callable[[], None] | None = None, request_id: str | None = None,
        approval_channel_factory: Callable[["ApplicationStreamSink"], Any] | None = None,
        on_question: Callable[[str], None] | None = None,
    ) -> None:
        self._emit_event = emit
        self._task_id = task_id
        self._question_ready = question_ready
        self._request_id = request_id
        self.approval_channel_factory = approval_channel_factory or EventApprovalChannel
        self._on_question = on_question
        super().__init__(self._event, show_thinking=show_thinking)

    def _event(self, event_type: str, **fields: Any) -> None:
        if self._request_id:
            fields.setdefault("request_id", self._request_id)
        self._emit_event(event_type, task_id=self._task_id, **fields)

    def on_question(self, question: str) -> None:
        self.on_content_token(question)
        if self._question_ready is not None:
            self._question_ready()
        if self._on_question is not None:
            self._on_question(question)


class ApplicationSession:
    """Own one runtime and its task/control operations without terminal I/O."""

    def __init__(
        self,
        emit: Callable[..., None],
        *,
        runtime_factory: RuntimeFactory = None,
        task_runner: TaskRunner = None,
        source: str = "tui",
        approval_channel_factory: Callable[[ApplicationStreamSink], Any] | None = None,
        on_question: Callable[[str], None] | None = None,
    ) -> None:
        self.source = source
        self._closed = False
        self._output = emit
        self.messages: dict[str, dict[str, Any]] = {}
        self.execution_details = ExecutionDetails()
        self.emit = self._publish
        self._runtime_factory = runtime_factory or create_runtime
        self._task_runner = task_runner or _run_task
        self._approval_channel_factory = approval_channel_factory
        self._on_question = on_question
        self.runtime: Any | None = None
        self.bootstrap: dict[str, Any] = {}
        self.initialized = False
        self.shutdown_requested = False
        self.active_task: asyncio.Task[None] | None = None
        self.active_control: asyncio.Task[None] | None = None
        self.active_task_id: str | None = None
        self.cancel_request_id: str | None = None
        self.current_target = ""
        self.current_constraints: dict[str, Any] = {}
        self.last_run: dict[str, Any] | None = None
        self.conversation: ConversationState | None = None
        self._queued_input: tuple[str, str, str] | None = None
        self._answer_in_progress = False
        self._mcp_registry: MCPRegistry | None = None
        self._mcp_state_update: asyncio.Handle | None = None

    def _publish(self, event_type: str, **fields: Any) -> None:
        if event_type == "message":
            fields["source"] = fields.get("agent_id") or fields.get("source", "main")
            identifier = fields["message_id"]
            message = self.messages.get(identifier)
            if fields["operation"] == "append":
                if message is None:
                    message = {
                        key: fields[key] for key in
                        ("message_id", "source", "role", "format", "request_id", "task_id")
                        if key in fields
                    }
                    message.update(text="", status="streaming")
                    self.messages[identifier] = message
                message["text"] += fields["text"]
            elif message is not None:
                message["status"] = fields["status"]
        if self.source == "tui":
            fields = self.execution_details.compact(event_type, fields)
        self._output(event_type, **fields)

    def _publish_user(self, text: str, request_id: str, task_id: str) -> None:
        identifier = f"user-{request_id}"
        self.emit("message", request_id=request_id, task_id=task_id, message_id=identifier,
                  source="main", role="user", format="text", operation="append", text=text)
        self.emit("message", request_id=request_id, task_id=task_id, message_id=identifier,
                  source="main", role="user", format="text", operation="end", status="completed")

    def publish_input_state(self) -> None:
        self.emit("state", task_id=self.active_task_id, state=self.state_snapshot())

    def _publish_mcp_state(self) -> None:
        self._mcp_state_update = None
        if not self._closed:
            self.publish_input_state()

    def question_ready(self) -> None:
        self._answer_in_progress = False
        self.publish_input_state()

    @classmethod
    async def open(cls, config: Any = None) -> "ApplicationSession":
        """Open an in-process session; terminal adapters supply their own output."""
        session = cls(
            lambda *_args, **_fields: None,
            runtime_factory=lambda: create_runtime(config),
            source="cli",
        )
        await session.handle("initialize", request_id="local-initialize")
        return session

    @property
    def agent(self) -> Any:
        return self.runtime.agent

    @property
    def config(self) -> Any:
        return self.runtime.config

    async def apply_config(self, config: Any) -> None:
        from vulnclaw.agent.exec_gate import get_execution_gate

        await self.agent.apply_config(config)
        self.runtime.config = config
        get_execution_gate(config).apply_config(config.safety, source=self.source)
        manager = getattr(self.runtime, "mcp_manager", None)
        if manager is not None:
            await manager.apply_config(config)

    @property
    def permission_mode(self) -> str:
        from vulnclaw.agent.exec_gate import get_execution_gate

        return get_execution_gate(getattr(self.runtime, "config", None)).mode

    def set_permission_mode(self, mode: str) -> str:
        from vulnclaw.agent.exec_gate import get_execution_gate

        result = get_execution_gate(getattr(self.runtime, "config", None)).set_mode(
            mode, source=self.source
        )
        self.config.safety.permission_mode = result
        return result

    async def _foreground(self, target: str, call: Callable[[], Awaitable[Any]]) -> Any:
        self._require_initialized("local")
        current = asyncio.current_task()
        if (
            self.active_task is not None
            and not self.active_task.done()
            and self.active_task is not current
        ):
            raise ApplicationError("task_busy", "a task is already active")
        owns_task = self.active_task is None or self.active_task.done()
        self.current_target = target
        if owns_task:
            self.active_task_id = "local-task"
            self.active_task = current
        try:
            return await call()
        finally:
            if owns_task:
                self.active_task = None
                self.active_task_id = None

    def _install_task(self, task: PreparedTask) -> None:
        request = task.request
        self.current_target = request.target
        self.current_constraints = _model_dump(task.constraints)
        if self.conversation is not None:
            if self.conversation.target != request.target:
                from vulnclaw.conversation import ReportRequest

                self.conversation.report = ReportRequest()
            self.conversation.target = request.target
            self.conversation.last_auto_input = task.prompt
            self.conversation.auto_mode = request.command == "run"
            self.conversation.engagement_completed = False
            self.conversation.task = None
            if self.conversation.auto_mode:
                from vulnclaw.config.schema import resolve_engine

                session = self.config.session
                defaults = {
                    "engine": resolve_engine(self.config, request.options.engine),
                    "max_steps": session.solve_max_steps,
                    "max_tool_rounds": session.solve_max_tool_rounds,
                    "max_parallel": session.solve_max_parallel,
                    "max_rounds": session.max_rounds,
                    "rounds_per_cycle": session.persistent_rounds_per_cycle,
                    "max_cycles": session.persistent_max_cycles,
                    "auto_report": (
                        session.persistent_auto_report if request.options.continuous else True
                    ),
                }
                options = request.options.model_copy(update={
                    name: value for name, value in defaults.items()
                    if getattr(request.options, name) is None
                })
                self.conversation.task = PreparedTask(
                    request.model_copy(update={"options": options}), task.prompt, task.constraints,
                )
                self.conversation.report.preference = "required" if options.auto_report else "suppress"
        agent = getattr(self.runtime, "agent", None)
        if agent is not None:
            agent.session_state.target = request.target
            apply_constraints = getattr(agent, "apply_task_constraints", None)
            if callable(apply_constraints):
                apply_constraints(task.constraints)

    async def run_task(self, task: PreparedTask | TaskCreateRequest, **callbacks: Any) -> Any:
        """Run a typed task through the same preparation/execution as JSONL callers."""
        return await self.submit_input(
            InputRequest(task=task.request if isinstance(task, PreparedTask) else task),
            **callbacks,
        )

    async def submit_input(
        self,
        request: InputRequest,
        *,
        stream_sink: Any = None,
        _runner: TaskRunner | None = None,
        **callbacks: Any,
    ) -> Any:
        """The common business entry for text, typed tasks and trusted controls."""
        self._require_initialized("local")
        parsed = parse_input(request)
        if parsed.kind == "display":
            return {"kind": parsed.kind, "operation": parsed.operation, "text": parsed.text}
        if parsed.kind == "adapter":
            operation, arguments = adapter_operation(parsed.operation, parsed.text)
            return await self.submit_input(InputRequest(operation=operation, arguments=arguments))
        if parsed.kind == "control":
            operation = parsed.operation
            if operation not in SUPPORTED_CONTROL_OPERATIONS:
                raise ApplicationError(
                    "unsupported_operation", f"unsupported operation: {operation}"
                )
            if (
                self.active_task is not None
                and not self.active_task.done()
                and operation not in TASK_ACTIVE_CONTROL_OPERATIONS
            ):
                raise ApplicationError("task_busy", "session control requires an idle operation")
            result, state = await self._execute_control_operation(operation, parsed.arguments)
            return {"operation": operation, "result": result, "state": state}
        if parsed.kind == "conversation":
            sink = stream_sink or ApplicationStreamSink(
                self.emit,
                self.active_task_id or "local-task",
                show_thinking=self.config.session.show_thinking,
                approval_channel_factory=self._approval_channel_factory,
                on_question=self._on_question,
            )

            async def converse() -> Any:
                self._answer_in_progress = bool(self.conversation.pending_questions)
                try:
                    if self.permission_mode != "read_only":
                        await self.runtime.mcp_manager.wait_for_startup()
                    return await run_conversation(self, parsed.text, sink)
                finally:
                    self._answer_in_progress = False

            return await self._foreground(self.current_target, converse)
        if self.permission_mode == "read_only":
            raise ApplicationError(
                "read_only", "Read-Only does not execute tasks. Change /permission to run."
            )
        raw = parsed.task
        if isinstance(raw, TaskCreateRequest):
            raw = raw.model_dump(exclude_unset=True)
        task = prepare_task(task_request_from_payload(raw, defaults=self.bootstrap))
        if task.request.command != "codescan":
            await self.runtime.mcp_manager.wait_for_startup()

        async def call() -> Any:
            self._install_task(task)
            if _runner is not None:
                return await _runner(self.runtime, task, stream_sink)
            execution = await execute_task(self.agent, task, stream_sink=stream_sink, **callbacks)
            self.last_run = task_result(self.runtime, task, execution)
            return execution

        return await self._foreground(task.request.target, call)

    async def run_orchestrated(self, **arguments: Any) -> Any:
        """Execute existing dedicated CLI use cases with shared runtime ownership."""
        from vulnclaw.orchestrator import run_agent_task

        if self.permission_mode == "read_only":
            raise ApplicationError("read_only", "Read-Only does not execute tasks.")

        async def call() -> Any:
            await self.runtime.mcp_manager.wait_for_startup()
            return await run_agent_task(agent=self.agent, **arguments)

        return await self._foreground(arguments["target"], call)

    async def cancel(self) -> None:
        """Cancel the active operation and wait for its existing cleanup path."""
        active = self.active_task
        if active is not None and not active.done():
            active.cancel()
            try:
                await active
            except asyncio.CancelledError:
                pass

    async def handle(
        self,
        operation: str,
        *,
        request_id: str,
        task_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        handlers = {
            "initialize": self._initialize,
            "start_task": self._start_task,
            "submit_input": self._start_input,
            "cancel_task": self._cancel_task,
            "get_state": self._get_state,
            "control": self._control,
            "shutdown": self._shutdown,
        }
        await handlers[operation](request_id=request_id, task_id=task_id, payload=payload or {})

    async def _initialize(
        self,
        *,
        request_id: str,
        task_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        if self.initialized:
            raise ApplicationError(
                "already_initialized",
                "backend session is already initialized",
                request_id=request_id,
            )
        bootstrap = payload.get("bootstrap", {})
        if not isinstance(bootstrap, dict):
            raise ApplicationError(
                "invalid_message",
                "initialize payload.bootstrap must be an object",
                request_id=request_id,
            )
        self.bootstrap = bootstrap
        self.current_target = str(bootstrap.get("target") or "")
        bootstrap_command = str(bootstrap.get("command") or "run").lstrip("/")
        if bootstrap_command not in TASK_COMMANDS:
            bootstrap_command = "run"
        try:
            scope = TaskOptions.model_validate(
                {field: bootstrap[field] for field in SCOPE_FIELDS if field in bootstrap}
            )
            initial_constraints = build_scope_constraints(self.current_target, scope.model_dump())
            _validate_task_action(bootstrap_command, initial_constraints)
        except ValueError as exc:
            raise ApplicationError(
                "invalid_bootstrap",
                str(exc),
                request_id=request_id,
            ) from exc
        self.current_constraints = _model_dump(initial_constraints)
        created = self._runtime_factory()
        self.runtime = await created if inspect.isawaitable(created) else created
        registry = getattr(getattr(self.runtime, "mcp_manager", None), "registry", None)
        if isinstance(registry, MCPRegistry):
            self._mcp_registry = registry
            loop = asyncio.get_running_loop()

            def queue_mcp_state() -> None:
                if not self._closed and self._mcp_state_update is None:
                    self._mcp_state_update = loop.call_soon(self._publish_mcp_state)

            registry.on_state_change = lambda: loop.call_soon_threadsafe(queue_mcp_state)
        agent = getattr(self.runtime, "agent", None)
        if agent is not None:
            agent.session_state.target = self.current_target or None
            apply_constraints = getattr(agent, "apply_task_constraints", None)
            if callable(apply_constraints):
                apply_constraints(initial_constraints)
        self.initialized = True
        self.conversation = ConversationState(agent, target=self.current_target or None)
        from vulnclaw.agent.exec_gate import get_execution_gate

        permission_mode = get_execution_gate(getattr(self.runtime, "config", None)).mode
        from vulnclaw.i18n import current_lang

        self.emit(
            "ready",
            request_id=request_id,
            capabilities={
                "language": current_lang(),
                "commands": sorted(TASK_COMMANDS),
                "control_operations": sorted(SUPPORTED_CONTROL_OPERATIONS),
                "cancellation": True,
                "authoritative_state": True,
                # Authoritative policy: the client label must sync to this on
                # startup instead of trusting its own persisted posture.
                "permission_mode": permission_mode,
                "natural_language": True,
                "input_commands": {
                    name: description
                    for name, description in COMMANDS.items()
                },
            },
            runtime=_runtime_metadata(self.runtime),
            state=self.state_snapshot(),
        )

    async def _start_task(
        self,
        *,
        request_id: str,
        task_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        self._require_initialized(request_id, task_id)
        if self.active_control is not None and not self.active_control.done():
            raise ApplicationError("operation_busy", "a management operation is active", request_id=request_id, task_id=task_id)
        if self.permission_mode == "read_only":
            raise ApplicationError(
                "read_only",
                "Read-Only does not execute tasks.",
                request_id=request_id,
                task_id=task_id,
            )
        if self.active_task is not None and not self.active_task.done():
            raise ApplicationError(
                "task_busy",
                f"task {self.active_task_id} is still active",
                request_id=request_id,
                task_id=task_id,
            )
        try:
            request = task_request_from_payload(payload.get("task"), defaults=self.bootstrap)
            task = prepare_task(request)
        except ValueError as exc:
            raise ApplicationError(
                "invalid_task",
                str(exc),
                request_id=request_id,
                task_id=task_id,
            ) from exc

        self._install_task(task)
        self.active_task_id = task_id
        self.cancel_request_id = None
        self.active_task = asyncio.create_task(self._execute_task(
            request_id, task_id or "", task, input_text=payload.get("_input_text"),
        ))

    async def _execute_task(
        self, request_id: str, task_id: str, task: PreparedTask, *, input_text: str | None = None,
    ) -> None:
        self._publish_user(input_text or f"/{task.request.command} {task.request.target}", request_id, task_id)
        self.emit(
            "task_started",
            request_id=request_id,
            task_id=task_id,
            task=task.request.model_dump(mode="json", exclude_none=True),
            state=self.state_snapshot(),
        )
        sink = ApplicationStreamSink(
            self.emit,
            task_id,
            request_id=request_id,
            question_ready=self.question_ready,
            approval_channel_factory=self._approval_channel_factory,
            on_question=self._on_question,
            show_thinking=bool(
                getattr(getattr(self.runtime, "config", None), "session", None)
                and getattr(self.runtime.config.session, "show_thinking", False)
            ),
        )
        succeeded = False
        try:
            result = await self.submit_input(
                InputRequest(task=task.request),
                stream_sink=sink,
                _runner=self._task_runner,
            )
            sink.on_stream_end()
            findings = result.get("findings") if isinstance(result, dict) else None
            if not isinstance(findings, list):
                findings = _runtime_findings(self.runtime)
            for finding in findings:
                if isinstance(finding, dict):
                    self.emit("finding", task_id=task_id, finding=finding)
            self.last_run = _json_safe(result if isinstance(result, dict) else {})
            self.emit(
                "task_completed",
                request_id=request_id,
                task_id=task_id,
                result=self.last_run,
                findings=findings,
                state=self.state_snapshot(active=False),
            )
            self.emit("state", task_id=task_id, state=self.state_snapshot(active=False))
            succeeded = True
        except asyncio.CancelledError:
            sink.on_stream_end("cancelled")
            self.emit(
                "task_cancelled",
                request_id=self.cancel_request_id or request_id,
                task_id=task_id,
                state=self.state_snapshot(active=False),
            )
        except Exception as exc:  # noqa: BLE001 - task failures are protocol data
            sink.on_stream_end("failed")
            self.emit(
                "task_failed",
                request_id=request_id,
                task_id=task_id,
                error={"code": "task_failed", "message": format_llm_user_error(exc)},
                state=self.state_snapshot(active=False),
            )
        finally:
            self._finish_active_input(succeeded)

    def _finish_active_input(self, succeeded: bool) -> None:
        self.active_task_id = None
        self.cancel_request_id = None
        self.active_task = None
        self._answer_in_progress = False
        queued, self._queued_input = self._queued_input, None
        if queued is None:
            return
        request_id, task_id, text = queued
        if not succeeded:
            self.emit(
                "error", request_id=request_id, task_id=task_id,
                code="continuation_cancelled",
                message="The waiting task failed or was cancelled; submit the reply again to retry.",
            )
            return
        self.active_task_id = task_id
        self._answer_in_progress = bool(self.conversation.pending_questions)
        self.active_task = asyncio.create_task(self._execute_turn(request_id, task_id, text))

    async def _start_input(
        self,
        *,
        request_id: str,
        task_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        self._require_initialized(request_id, task_id)
        try:
            text = payload.get("text")
            if not isinstance(text, str):
                raise ValueError("submit_input requires text")
            parsed = parse_input(InputRequest(text=text))
            if parsed.kind == "task":
                await self._start_task(
                    request_id=request_id,
                    task_id=task_id,
                    payload={"task": parsed.task, "_input_text": text},
                )
                return
            if parsed.kind in {"control", "adapter"}:
                operation, arguments = (
                    adapter_operation(parsed.operation, parsed.text)
                    if parsed.kind == "adapter" else (parsed.operation, parsed.arguments)
                )
                await self._control(
                    request_id=request_id,
                    task_id=task_id,
                    payload={
                        "operation": operation,
                        "arguments": arguments,
                    },
                )
                return
            if parsed.kind != "conversation":
                raise ValueError(f"/{parsed.operation} requires client interaction")
            if self.active_control is not None and not self.active_control.done():
                raise ApplicationError("operation_busy", "a management operation is active")
            if self.active_task is not None and not self.active_task.done():
                if (
                    self.permission_mode != "read_only"
                    and self.conversation.auto_mode
                    and self.conversation.pending_questions
                    and self._queued_input is None
                    and not self._answer_in_progress
                ):
                    self._queued_input = (request_id, task_id or "", text)
                    self.publish_input_state()
                    return
                raise ApplicationError("task_busy", "an operation is already active")
        except ValueError as exc:
            raise ApplicationError(
                getattr(exc, "code", "invalid_input"),
                str(exc),
                request_id=request_id,
                task_id=task_id,
            ) from exc
        self.active_task_id = task_id
        self.cancel_request_id = None
        self._answer_in_progress = bool(self.conversation.pending_questions)
        self.active_task = asyncio.create_task(self._execute_turn(request_id, task_id or "", text))

    async def _execute_turn(self, request_id: str, task_id: str, text: str) -> None:
        self._publish_user(text, request_id, task_id)
        sink = ApplicationStreamSink(
            self.emit, task_id, show_thinking=self.config.session.show_thinking,
            request_id=request_id,
            approval_channel_factory=self._approval_channel_factory,
            on_question=self._on_question,
        )
        from vulnclaw.agent.exec_gate import get_execution_gate

        gate = get_execution_gate()
        previous_channel = gate.channel
        gate.install_channel(sink.approval_channel_factory(sink))
        self._answer_in_progress = bool(self.conversation.pending_questions)
        self.emit(
            "turn_started",
            request_id=request_id,
            task_id=task_id,
            text=text,
            state=self.state_snapshot(),
        )
        succeeded = False
        try:
            result = await self.submit_input(InputRequest(text=text), stream_sink=sink)
            sink.on_stream_end()
            self.emit(
                "turn_completed",
                request_id=request_id,
                task_id=task_id,
                result=result,
                state=self.state_snapshot(active=False),
            )
            succeeded = True
        except asyncio.CancelledError:
            sink.on_stream_end("cancelled")
            self.emit(
                "turn_cancelled",
                request_id=self.cancel_request_id or request_id,
                task_id=task_id,
                state=self.state_snapshot(active=False),
            )
        except Exception as exc:
            sink.on_stream_end("failed")
            self.emit(
                "turn_failed",
                request_id=request_id,
                task_id=task_id,
                error={"code": "turn_failed", "message": format_llm_user_error(exc)},
                state=self.state_snapshot(active=False),
            )
        finally:
            if previous_channel is not None:
                gate.install_channel(previous_channel)
            else:
                gate.uninstall_channel()
            self._finish_active_input(succeeded)

    async def _cancel_task(
        self,
        *,
        request_id: str,
        task_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        self._require_initialized(request_id, task_id)
        if self.active_task is None or self.active_task.done() or task_id != self.active_task_id:
            raise ApplicationError(
                "task_not_active",
                f"task {task_id} is not active",
                request_id=request_id,
                task_id=task_id,
            )
        self.cancel_request_id = request_id
        self.active_task.cancel()

    async def _get_state(
        self,
        *,
        request_id: str,
        task_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        self._require_initialized(request_id, task_id)
        self.emit(
            "state",
            request_id=request_id,
            state=self.state_snapshot(),
        )

    async def _control(
        self,
        *,
        request_id: str,
        task_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        self._require_initialized(request_id, task_id)
        current = asyncio.current_task()
        operation = payload.get("operation")
        owns_control = operation not in TASK_ACTIVE_CONTROL_OPERATIONS
        if owns_control:
            if self.active_control is not None and not self.active_control.done():
                raise ApplicationError("operation_busy", "a management operation is active", request_id=request_id)
            self.active_control = current
        try:
            result = await self.submit_input(
                InputRequest(
                    operation=payload.get("operation"),
                    arguments=payload.get("arguments"),
                )
            )
        except ValueError as exc:
            raise ApplicationError(
                getattr(exc, "code", "invalid_control"),
                str(exc),
                request_id=request_id,
                task_id=task_id,
            ) from exc
        finally:
            if owns_control and self.active_control is current:
                self.active_control = None
        self._write_control_result(
            request_id,
            result["operation"],
            result["result"],
            state=result["state"],
        )

    async def _execute_control_operation(
        self, operation: str, arguments: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Extension point for feature-owned management operations."""

        if operation == "execution.details.read":
            return self.execution_details.read(arguments), None

        if operation in MANAGEMENT_OPERATIONS:
            result = await execute_management(self, operation, arguments)
            return result, self.state_snapshot() if operation == "config.update" else None

        if operation == "task.preview":
            from vulnclaw.task_preview import preview_task

            return preview_task(arguments, defaults=self.bootstrap, config=self.config), None

        if operation == "session.permission.set" and not arguments.get("mode"):
            return {"mode": self.permission_mode}, self.state_snapshot()
        if operation == "session.new":
            if self.config.session.auto_save:
                self.agent._maybe_auto_save_session()
            self.conversation.clear()
            self.messages.clear()
            self.current_target = ""
            self.last_run = None
            self._apply_session_scope(self.bootstrap)
            return {"message": "New conversation started."}, self.state_snapshot()
        if operation == "session.target.set":
            target = str(arguments.get("target") or "").strip()
            if target:
                self.conversation.prepare_target(target)
                self.current_target = target
                self._apply_session_scope(self.bootstrap)
            return {
                "target": self.current_target,
                "message": self.current_target,
            }, self.state_snapshot()
        if operation == "session.compact":
            summary = self.agent.context.compact_messages(note="User requested /compact.")
            return {
                "message": f"Context compacted ({len(summary)} characters)."
            }, self.state_snapshot()
        if operation in {"session.scope.read", "session.scope.preview"}:
            raw = _session_scope_defaults(self.bootstrap)
            if operation == "session.scope.preview":
                if "text" in arguments:
                    parsed = parse_input(InputRequest(text=arguments["text"]))
                    if parsed.operation not in {
                        "session.scope.read", "session.scope.update", "session.scope.reset",
                    }:
                        raise ValueError("Scope preview requires /scope")
                    if parsed.operation == "session.scope.reset":
                        raw = {}
                    elif parsed.operation == "session.scope.update":
                        updates = parsed.arguments["scope"]
                        if "allowed_ports" in updates:
                            raw.pop("only_port", None)
                        if "only_port" in updates:
                            raw.pop("allowed_ports", None)
                        raw.update(updates)
                else:
                    raw = arguments.get("scope", raw)
                    if not isinstance(raw, dict):
                        raise ValueError("scope must be an object")
            return preview_scope(raw, target=self.current_target), None
        if operation == "session.help":
            return command_help(str(arguments.get("topic") or "")), None
        if operation == "session.think":
            value = arguments.get("value", "")
            if value not in {"", "on", "off"}:
                raise ValueError("/think accepts on or off")
            current = self.config.session.show_thinking
            self.config.session.show_thinking = not current if not value else value == "on"
            return {"message": f"Reasoning display: {self.config.session.show_thinking}",
                    "show_thinking": self.config.session.show_thinking}, None
        if operation == "report.export":
            if self.permission_mode == "read_only":
                raise ValueError("Read-Only does not export reports. Change /permission to export.")
            from vulnclaw.report_service import export_report

            report = await export_report(
                self.agent,
                self.config,
                kind=arguments.get("kind", self.conversation.report.kind),
                output=arguments.get("output"),
                partial=not self.conversation.engagement_completed,
            )
            return {"report": report, "message": f"Report saved: {report['path']}"}, None

        if operation == "session.permission.set":
            mode = str(arguments.get("mode") or "").strip().lower()
            if mode not in {"read_only", "ask", "auto_review", "full_access"}:
                raise ValueError("mode must be one of: read_only, ask, auto_review, full_access")
            new_mode = self.set_permission_mode(mode)
            return {
                "message": f"Permission mode set to {new_mode}.",
                "mode": new_mode,
            }, self.state_snapshot()

        if operation == "execution.approval.resolve":
            from vulnclaw.agent.exec_gate import get_execution_gate
            from vulnclaw.interaction_contracts import ApprovalResolution

            resolution = ApprovalResolution.model_validate(arguments)
            result = await get_execution_gate().resolve(resolution.request_hash, resolution.decision)
            return result, None

        if operation == "session.scope.update":
            raw_scope = arguments.get("scope")
            if not isinstance(raw_scope, dict) or not raw_scope:
                raise ValueError("session.scope.update requires a non-empty arguments.scope")
            raw = _session_scope_defaults(self.bootstrap)
            if "allowed_ports" in raw_scope:
                raw.pop("only_port", None)
            if "only_port" in raw_scope and raw_scope["only_port"] is not None:
                raw.pop("allowed_ports", None)
            raw.update(raw_scope)
            preview = preview_scope(raw, target=self.current_target)
            if preview["errors"]:
                return preview, None
            bootstrap = {key: value for key, value in self.bootstrap.items()
                         if key not in SCOPE_FIELDS}
            bootstrap.update({key: value for key, value in preview["scope"].items()
                              if value is not None})
            self._apply_session_scope(bootstrap)
            return (
                {
                    "message": "Session scope defaults updated.",
                    **preview,
                },
                self.state_snapshot(),
            )
        if operation == "session.scope.reset":
            bootstrap = {
                key: value for key, value in self.bootstrap.items() if key not in SCOPE_FIELDS
            }
            self._apply_session_scope(bootstrap)
            return (
                {
                    "message": "Session scope defaults cleared.",
                    **preview_scope({}, target=self.current_target),
                },
                self.state_snapshot(),
            )
        if operation == "config.read":
            return self._config_form_payload(), None

        if operation == "config.preset":
            from vulnclaw.config.settings import provider_form_values

            return provider_form_values(str(arguments.get("provider") or "")), None

        if operation == "config.models":
            from vulnclaw.config.settings import fetch_provider_models, normalize_base_url

            base_url = normalize_base_url(str(arguments.get("base_url") or ""))
            api_key = str(arguments.get("api_key") or "").strip()
            # The client never receives the stored key back, so a refresh after
            # the first save must be able to reuse it without a retype.
            used_saved_key = False
            if not api_key:
                api_key = self._saved_api_key()
                used_saved_key = bool(api_key)
            if not base_url or not api_key:
                raise ValueError("config.models requires a base URL and an API key")
            # Blocking network call: ~3 attempts x 10s worst case, so it must
            # not stall the protocol loop (approvals included).
            models = await asyncio.to_thread(fetch_provider_models, base_url, api_key)
            return {"models": models, "used_saved_key": used_saved_key}, None

        if operation == "config.write":
            from vulnclaw.config.settings import apply_llm_form, load_config, save_config

            agent = getattr(self.runtime, "agent", None)
            if agent is None:
                raise ValueError("config.write requires an initialised runtime")

            config = load_config()
            config.safety.permission_mode = self.permission_mode
            apply_llm_form(
                config,
                provider=str(arguments.get("provider") or ""),
                base_url=str(arguments.get("base_url") or ""),
                model=str(arguments.get("model") or ""),
                website_url=str(arguments.get("website_url") or ""),
            )
            # A blank or omitted key keeps whatever is already stored.
            api_key = str(arguments.get("api_key") or "").strip()
            if api_key:
                config.llm.api_key = api_key
            save_config(config)
            # Rebind the live runtime so the new provider/model/key takes effect
            # without restarting the TUI (mirrors the classic REPL `/config`).
            await self.apply_config(config)
            return {
                "message": f"Saved {config.llm.provider}/{config.llm.model}.",
                "provider": config.llm.provider,
                "model": config.llm.model,
                "config_ready": _llm_configured(config.llm),
            }, None

        raise ApplicationError(
            "unsupported_operation",
            f"unsupported control operation: {operation}",
        )

    def _saved_api_key(self) -> str:
        config = getattr(self.runtime, "config", None)
        llm = getattr(config, "llm", None)
        primary_key = getattr(llm, "primary_key", None)
        return str(primary_key() or "") if callable(primary_key) else ""

    def _config_form_payload(self) -> dict[str, Any]:
        """Current LLM settings for the TUI form. Never echoes the API key."""
        from vulnclaw.config.settings import list_providers

        config = getattr(self.runtime, "config", None)
        llm = getattr(config, "llm", None)
        providers = [
            {
                "id": entry["provider"],
                "label": entry["label"],
                "website_url": entry["website_url"],
                "base_url": entry["base_url"],
                "default_model": entry["default_model"],
            }
            for entry in list_providers()
        ]
        return {
            "provider": str(getattr(llm, "provider", "")),
            "website_url": str(getattr(llm, "website_url", "")),
            "base_url": str(getattr(llm, "base_url", "")),
            "model": str(getattr(llm, "model", "")),
            "api_key_set": bool(self._saved_api_key()),
            "providers": providers,
        }

    def _apply_session_scope(self, bootstrap: dict[str, Any]) -> None:
        constraints = build_scope_constraints(self.current_target, bootstrap)
        self.bootstrap = bootstrap
        self.current_constraints = _model_dump(constraints)
        agent = getattr(self.runtime, "agent", None)
        if agent is not None:
            apply_constraints = getattr(agent, "apply_task_constraints", None)
            if callable(apply_constraints):
                apply_constraints(constraints)

    def _write_control_result(
        self,
        request_id: str,
        operation: str,
        result: dict[str, Any],
        *,
        state: dict[str, Any] | None = None,
    ) -> None:
        fields: dict[str, Any] = {"operation": operation, "result": _json_safe(result)}
        if state is not None:
            fields["state"] = state
        self.emit("control_result", request_id=request_id, **fields)

    async def _shutdown(
        self,
        *,
        request_id: str,
        task_id: str | None,
        payload: dict[str, Any],
    ) -> None:
        self.shutdown_requested = True
        if self.active_task is not None and not self.active_task.done():
            active = self.active_task
            self.cancel_request_id = request_id
            active.cancel()
            try:
                await active
            except asyncio.CancelledError:
                pass
        await self.close()
        self.emit("shutdown_complete", request_id=request_id)

    async def close(self) -> None:
        if self._closed:
            return
        control = self.active_control
        if control is not None and control is not asyncio.current_task() and not control.done():
            control.cancel()
            try:
                await control
            except asyncio.CancelledError:
                pass
        active = self.active_task
        if active is not None and not active.done():
            active.cancel()
            try:
                await active
            except asyncio.CancelledError:
                pass
        self._closed = True
        self.execution_details.clear()
        if self._mcp_registry is not None:
            self._mcp_registry.on_state_change = None
        if self._mcp_state_update is not None:
            self._mcp_state_update.cancel()
            self._mcp_state_update = None
        if self.runtime is None:
            return
        stop = getattr(self.runtime, "stop", None)
        if stop is None:
            return
        result = stop()
        if inspect.isawaitable(result):
            await result

    async def wait_for_idle(self) -> None:
        while self.active_task is not None:
            await self.active_task

    def state_snapshot(self, *, active: bool | None = None) -> dict[str, Any]:
        if active is None:
            active = self.active_task is not None and not self.active_task.done()
        state = {
            "permission_mode": self.permission_mode,
            "runtime": _runtime_metadata(self.runtime),
            "target": self.current_target,
            "phase": "idle",
            "task_constraints": self.current_constraints,
            "task": {"active": active, "task_id": self.active_task_id if active else None},
            "last_run": self.last_run,
            "findings": _runtime_findings(self.runtime),
            "evidence": [],
            "constraint_violations": [],
            "messages": list(self.messages.values()),
        }
        runtime_state = getattr(self.runtime, "state_snapshot", None)
        if callable(runtime_state):
            extra = runtime_state()
            if isinstance(extra, dict):
                state.update(
                    {
                        key: _json_safe(value)
                        for key, value in extra.items()
                        if key in RUNTIME_STATE_FIELDS
                    }
                )
        else:
            agent = getattr(self.runtime, "agent", None)
            session = getattr(agent, "session_state", None)
            if session is not None:
                state.update(
                    {
                        "target": str(getattr(session, "target", "") or self.current_target),
                        "phase": _enum_value(getattr(session, "phase", "idle")),
                        "task_constraints": _model_dump(
                            getattr(session, "task_constraints", self.current_constraints)
                        ),
                        "findings": _runtime_findings(self.runtime),
                        "evidence": _collect_evidence(session),
                        "constraint_violations": list(
                            getattr(session, "constraint_violations", []) or []
                        ),
                    }
                )
        state["task"] = {"active": active, "task_id": self.active_task_id if active else None}
        state["task"]["waiting_for_input"] = bool(
            self.permission_mode != "read_only" and self.conversation and self.conversation.auto_mode
            and self.conversation.pending_questions and self._queued_input is None
            and not self._answer_in_progress
        )
        state["last_run"] = self.last_run
        return _json_safe(state)

    def _require_initialized(self, request_id: str, task_id: str | None = None) -> None:
        if not self.initialized:
            raise ApplicationError(
                "not_initialized",
                "initialize must be the first request",
                request_id=request_id,
                task_id=task_id,
            )


def _session_scope_defaults(bootstrap: dict[str, Any]) -> dict[str, Any]:
    return {
        field: _json_safe(bootstrap[field]) for field in sorted(SCOPE_FIELDS) if field in bootstrap
    }


async def create_runtime(config: Any = None) -> ApplicationRuntime:
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.config.settings import load_config
    from vulnclaw.i18n import init_i18n
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    config = config if config is not None else load_config()
    init_i18n(config=config)
    mcp_manager = MCPLifecycleManager(config)
    try:
        started = mcp_manager.start_enabled_servers(background=True)
        agent = AgentCore(config, mcp_manager)
    except BaseException:
        await mcp_manager.astop_all()
        raise
    return ApplicationRuntime(config, mcp_manager, agent, started)


class EventApprovalChannel:
    """Trusted approval interaction through application callbacks.

    Emits the structured ``approval_required`` event, then awaits the
    operator decision arriving as the ``execution.approval.resolve``
    control operation. The decision never travels through model text.
    """

    def __init__(self, sink: ApplicationStreamSink) -> None:
        self._sink = sink

    async def request_approval(self, view: Any) -> str:
        from vulnclaw.agent.exec_gate import get_execution_gate

        self._sink._event("approval_required", **view.to_event_payload())
        gate = get_execution_gate()
        return await gate.wait_decision(view.request_hash)

    async def notify_closed(self, request_hash: str, status: str) -> None:
        """Dismiss the client modal when the pending leaves the queue."""
        self._sink._event("approval_closed", request_hash=request_hash, status=status)


async def _run_task(
    runtime: ApplicationRuntime, task: PreparedTask, sink: ApplicationStreamSink
) -> dict[str, Any]:
    def on_event(kind: str, payload: dict[str, Any]) -> None:
        if kind == "subagent":
            sink._event("subagent", **payload)
        elif kind == "subagent_stream":
            event = dict(payload)
            event_type = event.pop("type")
            if sink.accepts(event_type, **event):
                sink._event(event_type, **event)
        elif kind == "agent_step":
            sink._event("log", message=f"turn {payload.get('step', '?')}")
        elif kind == "error":
            sink._event("log", message=f"error: {payload.get('error', '')}")
        elif kind == "ask_user":
            sink.on_question(str(payload.get("question", "")))
        elif kind == "completed":
            sink._event("status", status="goal reached")
        elif kind == "no_path":
            sink._event("log", message=f"no path: {payload.get('reason', '')}")

    execution = None
    approval_channel = sink.approval_channel_factory(sink)
    from vulnclaw.agent.exec_gate import get_execution_gate

    _approval_gate = get_execution_gate()
    _previous_channel = _approval_gate.channel
    _approval_gate.install_channel(approval_channel)
    try:
        execution = await execute_task(
            runtime.agent,
            task,
            stream_sink=sink,
            on_event=on_event,
            on_cycle_step=lambda round_num, cycle_num, result: sink.on_status(
                f"Cycle {cycle_num}, round {round_num}"
            ),
            on_cycle_complete=lambda cycle_num, result: sink.on_status(
                f"Cycle {cycle_num} complete. Report: {result.report_path or 'none'}"
            ),
        )
    finally:
        if _previous_channel is not None:
            _approval_gate.install_channel(_previous_channel)
        else:
            _approval_gate.uninstall_channel()
    result = execution.run
    report = None
    report_error = None
    if (
        task.request.command == "run"
        and result.status == "completed"
        and task.request.options.auto_report is not False
        and get_execution_gate(runtime.config).mode != "read_only"
    ):
        sink.on_status("Generating report...")
        try:
            report = await generate_report_for_run(
                result, config=runtime.config,
                **({"output_path": task.request.options.report_output}
                   if task.request.options.report_output is not None else {}),
            )
        except Exception as exc:  # Report failures preserve the completed task and saved audit.
            report_error = str(exc) or type(exc).__name__
    return task_result(runtime, task, execution, report=report, report_error=report_error)


def task_result(
    runtime: Any,
    task: PreparedTask,
    execution: Any,
    *,
    report: dict[str, str] | None = None,
    report_error: str | None = None,
) -> dict[str, Any]:
    """Project task execution into the shared application result vocabulary."""
    result = execution.run
    run_context = result.run_context
    action_result = execution.action_result
    if isinstance(action_result, dict) and isinstance(action_result.get("findings"), list):
        findings = action_result["findings"]
    else:
        findings = _runtime_findings(runtime)
    return {
        "command": task.request.command,
        "target": task.request.target,
        "status": result.status,
        "exit_code": result.exit_code,
        "summary": _json_safe(result.summary),
        "run": (
            {
                "name": run_context.run_name,
                "directory": str(run_context.run_dir),
                "manifest": _json_safe(run_context.manifest),
            }
            if run_context is not None
            else None
        ),
        "findings": findings,
        "report": report,
        "report_error": report_error,
    }


def _llm_configured(llm: Any) -> bool:
    """Whether *llm* carries usable credentials (static key or stored OAuth)."""
    if llm is None:
        return False
    try:
        from vulnclaw.config.token_provider import has_llm_credentials

        return bool(has_llm_credentials(llm))
    except Exception:
        return False


def _runtime_metadata(runtime: Any) -> dict[str, Any]:
    custom = getattr(runtime, "metadata", None)
    if callable(custom):
        result = custom()
        if isinstance(result, dict):
            return _json_safe(result)
    config = getattr(runtime, "config", None)
    llm = getattr(config, "llm", None)
    try:
        from vulnclaw.skills.loader import (
            list_core_skills,
            list_custom_skills,
            list_specialized_skills,
            load_skill_by_name,
        )

        names = sorted(set(list_core_skills() + list_specialized_skills() + list_custom_skills()))
        skills = []
        for name in names:
            try:
                if load_skill_by_name(name):
                    skills.append(name)
            except (OSError, ValueError):
                continue
    except Exception:
        skills = []
    manager = getattr(runtime, "mcp_manager", None)
    registry = getattr(manager, "registry", None)
    servers = registry.get_all_servers() if registry is not None else {}
    configured = getattr(getattr(config, "mcp", None), "servers", {})
    mcp_servers = []
    for name, server_config in sorted(configured.items()):
        if not server_config.enabled:
            continue
        server = servers.get(name)
        ready = bool(server is not None and server.health_status == "healthy"
                     and (server.running or server.execution_mode == "local"))
        mcp_servers.append({
            "name": name,
            "ready": ready,
            "status": "ready" if ready else "starting"
                      if server is not None and server.health_status == "starting" else "failed",
        })
    return {
        "config_ready": _llm_configured(llm),
        "provider": str(getattr(llm, "provider", "unknown")),
        "model": str(getattr(llm, "model", "unknown")),
        "mcp_started": int(getattr(runtime, "mcp_started", 0)),
        "mcp_ready": sum(server["ready"] for server in mcp_servers),
        "mcp_servers": mcp_servers,
        "skills_loaded": len(skills),
        "skills": skills,
    }


def _runtime_findings(runtime: Any) -> list[dict[str, Any]]:
    agent = getattr(runtime, "agent", None)
    session = getattr(agent, "session_state", None)
    findings = getattr(session, "findings", []) if session is not None else []
    if not findings:
        custom = getattr(runtime, "findings", None)
        if callable(custom):
            findings = custom()
    result: list[dict[str, Any]] = []
    for finding in findings or []:
        item = _model_dump(finding)
        if not isinstance(item, dict):
            continue
        for field in ("submission_id", "evidence_snapshots", "verification_history", "assessment", "previous_verification"):
            item.pop(field, None)
        item["id"] = item.pop("finding_id", item.get("id", ""))
        result.append(_json_safe(item))
    return result


def _collect_evidence(session: Any) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for finding in getattr(session, "findings", []) or []:
        for ref in getattr(finding, "evidence_refs", []) or []:
            dumped = _model_dump(ref)
            if isinstance(dumped, dict):
                evidence.append(_json_safe(dumped))
    return evidence


def _validate_task_action(command: str, constraints: Any) -> None:
    violation = validate_action_constraints(command, constraints)
    if violation is not None:
        raise ValueError(violation)


def _model_dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump(mode="json"))
    if hasattr(value, "value"):
        return _json_safe(value.value)
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))
