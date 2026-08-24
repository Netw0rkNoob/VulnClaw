"""Long-lived Python backend for the native terminal client.

The backend owns VulnClaw business state and serves protocol-v1 JSONL requests
over stdin/stdout.  Human diagnostics are intentionally kept on stderr.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import sys
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TextIO

from vulnclaw.config.domain_models import validate_action_constraints
from vulnclaw.task_service import (
    SCOPE_FIELDS,
    TASK_COMMANDS,
    PreparedTask,
    TaskOptions,
    build_scope_constraints,
    execute_task,
    prepare_task,
    task_request_from_payload,
)
from vulnclaw.tui_protocol import (
    PROTOCOL_VERSION,
    ClientMessage,
    JsonlWriter,
    ProtocolError,
    decode_client_message,
)

# Concrete management operations are capability-gated feature extensions. The
# base backend owns mutable session scope defaults; client posture remains local.
# ``execution.approval.resolve`` is deliberately usable *while a task is
# active*: it is the trusted channel that resolves a pending ExecutionGate
# request raised by that very task.
SUPPORTED_CONTROL_OPERATIONS = frozenset(
    {
        "session.scope.reset",
        "session.scope.update",
        "execution.approval.resolve",
        "session.permission.set",
    }
)
TASK_ACTIVE_CONTROL_OPERATIONS = frozenset({"execution.approval.resolve"})
RUNTIME_STATE_FIELDS = frozenset(
    {"target", "phase", "task_constraints", "findings", "evidence", "constraint_violations"}
)


@dataclass
class BackendRuntime:
    """The reusable config/MCP/AgentCore aggregate for one TUI session."""

    config: Any
    mcp_manager: Any
    agent: Any
    mcp_started: int = 0
    stopped: bool = False

    async def stop(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        await self.mcp_manager.astop_all()


RuntimeFactory = Callable[[], Any | Awaitable[Any]]
TaskRunner = Callable[[Any, PreparedTask, "BackendStreamSink"], Awaitable[dict[str, Any]]]


class BackendStreamSink:
    """Adapt AgentCore streaming callbacks to protocol-v1 task events."""

    def __init__(self, writer: JsonlWriter, task_id: str, *, show_thinking: bool) -> None:
        self._writer = writer
        self._task_id = task_id
        self._show_thinking = show_thinking
        self._thinking_buffer = ""
        self._content_buffer = ""

    def _event(self, event_type: str, **fields: Any) -> None:
        self._writer.event(event_type, task_id=self._task_id, **fields)

    def _flush_thinking(self) -> None:
        if self._thinking_buffer and self._show_thinking:
            self._event("reasoning", text=self._thinking_buffer)
        self._thinking_buffer = ""

    def _flush_content(self) -> None:
        if self._content_buffer:
            self._event("log", message=self._content_buffer)
        self._content_buffer = ""

    def _flush_all(self) -> None:
        self._flush_thinking()
        self._flush_content()

    def on_status(self, message: str) -> None:
        self._flush_all()
        self._event("status", status=str(message or ""))

    def on_thinking_token(self, token: str) -> None:
        if not token:
            return
        self._flush_content()
        if self._show_thinking:
            self._thinking_buffer += str(token)

    def on_content_token(self, token: str) -> None:
        if not token:
            return
        self._flush_thinking()
        self._content_buffer += str(token)

    def on_tool_call(self, tool_name: str, args: str) -> None:
        self._flush_all()
        self._event("tool_call", tool=str(tool_name), arguments=str(args or ""))

    def on_tool_result(self, result_summary: str) -> None:
        self._flush_all()
        self._event("tool_result", result=str(result_summary or ""))

    def on_stream_end(self) -> None:
        self._flush_all()


class BackendSession:
    """Stateful request dispatcher for one connected TUI client."""

    def __init__(
        self,
        writer: JsonlWriter,
        *,
        runtime_factory: RuntimeFactory = None,
        task_runner: TaskRunner = None,
    ) -> None:
        self.writer = writer
        self._runtime_factory = runtime_factory or _create_runtime
        self._task_runner = task_runner or _run_task
        self.runtime: Any | None = None
        self.bootstrap: dict[str, Any] = {}
        self.initialized = False
        self.shutdown_requested = False
        self.active_task: asyncio.Task[None] | None = None
        self.active_task_id: str | None = None
        self.cancel_request_id: str | None = None
        self.current_target = ""
        self.current_constraints: dict[str, Any] = {}
        self.last_run: dict[str, Any] | None = None

    async def handle(self, message: ClientMessage) -> None:
        handlers = {
            "initialize": self._initialize,
            "start_task": self._start_task,
            "cancel_task": self._cancel_task,
            "get_state": self._get_state,
            "control": self._control,
            "shutdown": self._shutdown,
        }
        await handlers[message.type](message)

    async def _initialize(self, message: ClientMessage) -> None:
        if self.initialized:
            raise ProtocolError(
                "already_initialized",
                "backend session is already initialized",
                request_id=message.request_id,
            )
        bootstrap = message.payload.get("bootstrap", {})
        if not isinstance(bootstrap, dict):
            raise ProtocolError(
                "invalid_message",
                "initialize payload.bootstrap must be an object",
                request_id=message.request_id,
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
            initial_constraints = build_scope_constraints(
                self.current_target, scope.model_dump()
            )
            _validate_task_action(bootstrap_command, initial_constraints)
        except ValueError as exc:
            raise ProtocolError(
                "invalid_bootstrap",
                str(exc),
                request_id=message.request_id,
            ) from exc
        self.current_constraints = _model_dump(initial_constraints)
        created = self._runtime_factory()
        self.runtime = await created if inspect.isawaitable(created) else created
        agent = getattr(self.runtime, "agent", None)
        if agent is not None:
            agent.session_state.target = self.current_target or None
            apply_constraints = getattr(agent, "apply_task_constraints", None)
            if callable(apply_constraints):
                apply_constraints(initial_constraints)
        self.initialized = True
        from vulnclaw.agent.exec_gate import get_execution_gate

        permission_mode = get_execution_gate(
            getattr(self.runtime, "config", None)
        ).mode
        self.writer.event(
            "ready",
            request_id=message.request_id,
            backend={
                "pid": os.getpid(),
                "version": _package_version(),
                "protocol_version": PROTOCOL_VERSION,
            },
            capabilities={
                "commands": sorted(TASK_COMMANDS),
                "control_operations": sorted(SUPPORTED_CONTROL_OPERATIONS),
                "cancellation": True,
                "authoritative_state": True,
                # Authoritative policy: the client label must sync to this on
                # startup instead of trusting its own persisted posture.
                "permission_mode": permission_mode,
            },
            runtime=_runtime_metadata(self.runtime),
            state=self.state_snapshot(),
        )

    async def _start_task(self, message: ClientMessage) -> None:
        self._require_initialized(message)
        if self.active_task is not None and not self.active_task.done():
            raise ProtocolError(
                "task_busy",
                f"task {self.active_task_id} is still active",
                request_id=message.request_id,
                task_id=message.task_id,
            )
        try:
            request = task_request_from_payload(
                message.payload.get("task"), defaults=self.bootstrap
            )
            task = prepare_task(request)
        except ValueError as exc:
            raise ProtocolError(
                "invalid_task",
                str(exc),
                request_id=message.request_id,
                task_id=message.task_id,
            ) from exc

        self.current_target = request.target
        self.current_constraints = _model_dump(task.constraints)
        agent = getattr(self.runtime, "agent", None)
        if agent is not None:
            agent.session_state.target = request.target
            apply_constraints = getattr(agent, "apply_task_constraints", None)
            if callable(apply_constraints):
                apply_constraints(task.constraints)
        self.active_task_id = message.task_id
        self.cancel_request_id = None
        self.active_task = asyncio.create_task(
            self._execute_task(message.request_id, message.task_id or "", task)
        )

    async def _execute_task(self, request_id: str, task_id: str, task: PreparedTask) -> None:
        self.writer.event(
            "task_started",
            request_id=request_id,
            task_id=task_id,
            task=task.request.model_dump(mode="json", exclude_none=True),
            state=self.state_snapshot(),
        )
        sink = BackendStreamSink(
            self.writer,
            task_id,
            show_thinking=bool(
                getattr(getattr(self.runtime, "config", None), "session", None)
                and getattr(self.runtime.config.session, "show_thinking", False)
            ),
        )
        try:
            result = await self._task_runner(self.runtime, task, sink)
            sink.on_stream_end()
            findings = result.get("findings") if isinstance(result, dict) else None
            if not isinstance(findings, list):
                findings = _runtime_findings(self.runtime)
            for finding in findings:
                if isinstance(finding, dict):
                    self.writer.event("finding", task_id=task_id, finding=finding)
            self.last_run = _json_safe(result if isinstance(result, dict) else {})
            self.writer.event(
                "task_completed",
                request_id=request_id,
                task_id=task_id,
                result=self.last_run,
                findings=findings,
                state=self.state_snapshot(active=False),
            )
            self.writer.event("state", task_id=task_id, state=self.state_snapshot(active=False))
        except asyncio.CancelledError:
            sink.on_stream_end()
            self.writer.event(
                "task_cancelled",
                request_id=self.cancel_request_id or request_id,
                task_id=task_id,
                state=self.state_snapshot(active=False),
            )
        except Exception as exc:  # noqa: BLE001 - task failures are protocol data
            sink.on_stream_end()
            self.writer.event(
                "task_failed",
                request_id=request_id,
                task_id=task_id,
                error={"code": "task_failed", "message": str(exc)},
                state=self.state_snapshot(active=False),
            )
        finally:
            self.active_task_id = None
            self.cancel_request_id = None
            self.active_task = None

    async def _cancel_task(self, message: ClientMessage) -> None:
        self._require_initialized(message)
        if (
            self.active_task is None
            or self.active_task.done()
            or message.task_id != self.active_task_id
        ):
            raise ProtocolError(
                "task_not_active",
                f"task {message.task_id} is not active",
                request_id=message.request_id,
                task_id=message.task_id,
            )
        self.cancel_request_id = message.request_id
        self.active_task.cancel()

    async def _get_state(self, message: ClientMessage) -> None:
        self._require_initialized(message)
        self.writer.event(
            "state",
            request_id=message.request_id,
            state=self.state_snapshot(),
        )

    async def _control(self, message: ClientMessage) -> None:
        """Validate the generic management envelope and gate extensions.

        Feature layers add concrete operations and their Python-owned business
        state.  The architecture layer rejects every unadvertised operation so
        replaceable clients can safely rely on capability negotiation.
        """

        self._require_initialized(message)
        operation = message.payload.get("operation")
        arguments = message.payload.get("arguments")
        if not isinstance(operation, str) or not operation.strip():
            raise ProtocolError(
                "invalid_control",
                "control payload.operation must be a non-empty string",
                request_id=message.request_id,
            )
        operation = operation.strip().lower()
        if not isinstance(arguments, dict):
            raise ProtocolError(
                "invalid_control",
                "control payload.arguments must be an object",
                request_id=message.request_id,
            )
        if operation not in SUPPORTED_CONTROL_OPERATIONS:
            raise ProtocolError(
                "unsupported_operation",
                f"unsupported control operation: {operation}",
                request_id=message.request_id,
            )
        if (
            self.active_task is not None
            and not self.active_task.done()
            and operation not in TASK_ACTIVE_CONTROL_OPERATIONS
        ):
            raise ProtocolError(
                "task_busy",
                "session scope cannot change while a task is active",
                request_id=message.request_id,
                task_id=self.active_task_id,
            )
        try:
            result, state = await self._execute_control_operation(operation, arguments)
        except ProtocolError:
            raise
        except ValueError as exc:
            raise ProtocolError(
                "invalid_control",
                str(exc),
                request_id=message.request_id,
            ) from exc
        self._write_control_result(message, operation, result, state=state)

    async def _execute_control_operation(
        self, operation: str, arguments: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Extension point for feature-owned management operations."""

        if operation == "session.permission.set":
            from vulnclaw.agent.exec_gate import get_execution_gate

            mode = str(arguments.get("mode") or "").strip().lower()
            gate = get_execution_gate()
            # Escalation while a task runs would let injected content benefit
            # from a mid-task loosening; de-escalation stays allowed.
            rank = {"ask": 0, "auto_review": 1, "full_access": 2}
            if mode not in rank:
                raise ValueError("mode must be one of: ask, auto_review, full_access")
            if (
                self.active_task is not None
                and not self.active_task.done()
                and rank[mode] > rank[gate.mode]
            ):
                raise ValueError(
                    "permission escalation is not allowed while a task is active"
                )
            new_mode = gate.set_mode(mode, source="tui")
            return {
                "message": f"Permission mode set to {new_mode}.",
                "mode": new_mode,
            }, None

        if operation == "execution.approval.resolve":
            from vulnclaw.agent.exec_gate import get_execution_gate

            request_hash = str(arguments.get("request_hash") or "")
            decision = str(arguments.get("decision") or "")
            if not request_hash or decision not in {"approve", "deny"}:
                raise ValueError(
                    "execution.approval.resolve requires "
                    "request_hash and decision=approve|deny"
                )
            result = await get_execution_gate().resolve(request_hash, decision)
            return result, None

        if operation == "session.scope.update":
            raw_scope = arguments.get("scope")
            if not isinstance(raw_scope, dict) or not raw_scope:
                raise ValueError("session.scope.update requires a non-empty arguments.scope")
            unknown = set(raw_scope) - SCOPE_FIELDS
            if unknown:
                raise ValueError(f"unsupported scope field(s): {', '.join(sorted(unknown))}")
            options = TaskOptions.model_validate(raw_scope)
            updates = {
                key: value
                for key, value in options.model_dump().items()
                if key in SCOPE_FIELDS and key in options.model_fields_set
            }
            bootstrap = dict(self.bootstrap)
            bootstrap.update(updates)
            self._apply_session_scope(bootstrap)
            return (
                {
                    "message": "Session scope defaults updated.",
                    "scope": _session_scope_defaults(self.bootstrap),
                },
                self.state_snapshot(),
            )
        if operation == "session.scope.reset":
            bootstrap = {
                key: value
                for key, value in self.bootstrap.items()
                if key not in SCOPE_FIELDS
            }
            self._apply_session_scope(bootstrap)
            return (
                {
                    "message": "Session scope defaults cleared.",
                    "scope": {},
                },
                self.state_snapshot(),
            )
        raise ProtocolError(
            "unsupported_operation",
            f"unsupported control operation: {operation}",
        )

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
        message: ClientMessage,
        operation: str,
        result: dict[str, Any],
        *,
        state: dict[str, Any] | None = None,
    ) -> None:
        fields: dict[str, Any] = {"operation": operation, "result": _json_safe(result)}
        if state is not None:
            fields["state"] = state
        self.writer.event("control_result", request_id=message.request_id, **fields)

    async def _shutdown(self, message: ClientMessage) -> None:
        self.shutdown_requested = True
        if self.active_task is not None and not self.active_task.done():
            active = self.active_task
            self.cancel_request_id = message.request_id
            active.cancel()
            try:
                await active
            except asyncio.CancelledError:
                pass
        await self.close()
        self.writer.event("shutdown_complete", request_id=message.request_id)

    async def close(self) -> None:
        if self.runtime is None:
            return
        stop = getattr(self.runtime, "stop", None)
        if stop is None:
            return
        result = stop()
        if inspect.isawaitable(result):
            await result

    async def wait_for_idle(self) -> None:
        task = self.active_task
        if task is not None:
            await task

    def state_snapshot(self, *, active: bool | None = None) -> dict[str, Any]:
        if active is None:
            active = self.active_task is not None and not self.active_task.done()
        state = {
            "target": self.current_target,
            "phase": "idle",
            "task_constraints": self.current_constraints,
            "task": {"active": active, "task_id": self.active_task_id if active else None},
            "last_run": self.last_run,
            "findings": _runtime_findings(self.runtime),
            "evidence": [],
            "constraint_violations": [],
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
        state["last_run"] = self.last_run
        return _json_safe(state)

    def _require_initialized(self, message: ClientMessage) -> None:
        if not self.initialized:
            raise ProtocolError(
                "not_initialized",
                "initialize must be the first request",
                request_id=message.request_id,
                task_id=message.task_id,
            )


def _session_scope_defaults(bootstrap: dict[str, Any]) -> dict[str, Any]:
    return {
        field: _json_safe(bootstrap[field])
        for field in sorted(SCOPE_FIELDS)
        if field in bootstrap
    }


async def _create_runtime() -> BackendRuntime:
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.config.settings import load_config
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    config = load_config()
    mcp_manager = MCPLifecycleManager(config)
    started = mcp_manager.start_enabled_servers()
    return BackendRuntime(config, mcp_manager, AgentCore(config, mcp_manager), started)


class TuiApprovalChannel:
    """Trusted approval channel over the TUI JSONL control path.

    Emits the structured ``approval_required`` event, then awaits the
    operator decision arriving as the ``execution.approval.resolve``
    control operation. The decision never travels through model text.
    """

    def __init__(self, sink: BackendStreamSink) -> None:
        self._sink = sink

    async def request_approval(self, view: Any) -> str:
        from vulnclaw.agent.exec_gate import get_execution_gate

        self._sink._event("approval_required", **view.to_event_payload())
        gate = get_execution_gate()
        return await gate.wait_decision(view.request_hash)


async def _run_task(
    runtime: BackendRuntime, task: PreparedTask, sink: BackendStreamSink
) -> dict[str, Any]:
    def on_event(kind: str, payload: dict[str, Any]) -> None:
        if kind == "agent_step":
            sink._event("log", message=f"turn {payload.get('step', '?')}")
        elif kind == "error":
            sink._event("log", message=f"error: {payload.get('error', '')}")
        elif kind == "ask_user":
            sink._event("approval_required", question=str(payload.get("question", "")))
        elif kind == "completed":
            sink._event("status", status="goal reached")
        elif kind == "no_path":
            sink._event("log", message=f"no path: {payload.get('reason', '')}")
    execution = None
    approval_channel = TuiApprovalChannel(sink)
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
        )
    finally:
        if _previous_channel is not None:
            _approval_gate.install_channel(_previous_channel)
        else:
            _approval_gate.uninstall_channel()
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
    }


async def serve(reader: TextIO, writer: JsonlWriter) -> None:
    """Serve one client until EOF or a graceful shutdown request."""

    session = BackendSession(writer)
    try:
        while not session.shutdown_requested:
            line = await asyncio.to_thread(reader.readline)
            if line == "":
                break
            if not line.strip():
                continue
            try:
                message = decode_client_message(line)
                await session.handle(message)
            except ProtocolError as exc:
                writer.write(exc.as_event())
            except Exception as exc:  # noqa: BLE001 - preserve the backend session
                writer.event("error", code="internal_error", message=str(exc))
    finally:
        if not session.shutdown_requested:
            active = session.active_task
            if active is not None and not active.done():
                active.cancel()
                try:
                    await active
                except asyncio.CancelledError:
                    pass
            await session.close()


def main() -> None:
    # Capture protocol stdout first, then redirect all incidental Rich/print
    # output from config, MCP, and AgentCore to stderr for JSONL integrity.
    protocol_output = sys.stdout
    sys.stdout = sys.stderr
    asyncio.run(serve(sys.stdin, JsonlWriter(protocol_output)))


def _runtime_metadata(runtime: Any) -> dict[str, Any]:
    custom = getattr(runtime, "metadata", None)
    if callable(custom):
        result = custom()
        if isinstance(result, dict):
            return _json_safe(result)
    config = getattr(runtime, "config", None)
    llm = getattr(config, "llm", None)
    try:
        from vulnclaw.config.token_provider import has_llm_credentials
        from vulnclaw.skills.loader import (
            list_core_skills,
            list_custom_skills,
            list_specialized_skills,
        )

        configured = bool(llm is not None and has_llm_credentials(llm))
        skills = sorted(
            set(list_core_skills() + list_specialized_skills() + list_custom_skills())
        )
    except Exception:
        configured = False
        skills = []
    return {
        "config_ready": configured,
        "provider": str(getattr(llm, "provider", "unknown")),
        "model": str(getattr(llm, "model", "unknown")),
        "mcp_started": int(getattr(runtime, "mcp_started", 0)),
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


def _package_version() -> str:
    from vulnclaw import __version__

    return __version__


if __name__ == "__main__":
    main()
