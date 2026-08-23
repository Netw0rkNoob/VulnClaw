"""Shared structured task contract and execution service."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Literal, get_args
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnclaw.config.domain_models import TaskConstraints, validate_action_constraints
from vulnclaw.config.schema import resolve_engine
from vulnclaw.orchestrator import OrchestratorRunResult, run_agent_task

TaskCommand = Literal["run", "recon", "scan", "exploit", "persistent", "codescan"]
TASK_COMMANDS = frozenset(get_args(TaskCommand))
SCOPE_FIELDS = frozenset(
    {
        "only_port",
        "only_host",
        "only_path",
        "blocked_host",
        "blocked_path",
        "allow_actions",
        "block_actions",
    }
)


class TaskOptions(BaseModel):
    """Typed command options shared by CLI, Web, and the native TUI."""

    model_config = ConfigDict(extra="forbid")

    engine: Literal["solve", "team", "rounds"] | None = None
    scope: str | None = Field(default=None, max_length=32)
    ports: str | None = Field(default=None, max_length=512)
    max_steps: int | None = Field(default=None, ge=1, le=10000)
    max_directions: int | None = Field(default=None, ge=1, le=100)
    max_tool_rounds: int | None = Field(default=None, ge=1, le=100)
    max_parallel: int | None = Field(default=None, ge=1, le=64)
    max_rounds: int | None = Field(default=None, ge=1, le=1000)
    rounds_per_cycle: int | None = Field(default=None, ge=1, le=1000)
    max_cycles: int | None = Field(default=None, ge=0, le=1000)
    auto_report: bool | None = None
    cve: str | None = Field(default=None, max_length=64)
    cmd: str | None = Field(default=None, max_length=512)
    only_port: int | None = Field(default=None, ge=1, le=65535)
    only_host: str | None = Field(default=None, max_length=253)
    only_path: str | None = Field(default=None, max_length=2048)
    blocked_host: str | None = Field(
        default=None,
        max_length=4096,
        description="Comma- or newline-separated explicitly blocked hosts",
    )
    blocked_path: str | None = Field(default=None, max_length=2048)
    allow_actions: list[str] | None = Field(default=None, max_length=20)
    block_actions: list[str] | None = Field(default=None, max_length=20)

    @field_validator("allow_actions", "block_actions", mode="before")
    @classmethod
    def split_action_lists(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator(
        "scope",
        "ports",
        "cve",
        "cmd",
        "only_host",
        "only_path",
        "blocked_path",
    )
    @classmethod
    def reject_option_control_characters(cls, value: str | None) -> str | None:
        if value is not None and any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("task options must not contain control characters")
        return value


class TaskCreateRequest(BaseModel):
    """Frontend-neutral task DTO consumed by the shared application service."""

    model_config = ConfigDict(extra="forbid")

    command: TaskCommand
    target: str = Field(min_length=1, max_length=2048)
    prompt: str | None = Field(default=None, max_length=32768)
    resume: bool = True
    snapshot_id: str | None = Field(default=None, max_length=160)
    run_name: str | None = Field(default=None, max_length=120)
    resume_run_name: str | None = Field(default=None, max_length=120)
    runs_dir: str | None = Field(default=None, max_length=4096)
    additional_targets: list[str] = Field(default_factory=list, max_length=20)
    target_type: str | None = Field(default=None, max_length=32)
    mount: bool = False
    repair: bool = False
    force_fresh: bool = False
    no_import: bool = False
    options: TaskOptions = Field(default_factory=TaskOptions)

    @field_validator("target", "snapshot_id", "run_name", "resume_run_name", "runs_dir")
    @classmethod
    def reject_control_characters(cls, value: str | None) -> str | None:
        if value is not None and any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("input must not contain control characters")
        if value is not None and not value.strip():
            raise ValueError("input must not be blank")
        return value

    @field_validator("additional_targets")
    @classmethod
    def validate_additional_targets(cls, values: list[str]) -> list[str]:
        if any(any(ord(char) < 32 or ord(char) == 127 for char in value) for value in values):
            raise ValueError("additional_targets must not contain control characters")
        return values

    @model_validator(mode="after")
    def reject_irrelevant_options(self) -> "TaskCreateRequest":
        command_fields = {
            "run": {
                "engine",
                "scope",
                "max_steps",
                "max_directions",
                "max_tool_rounds",
                "max_parallel",
                "max_rounds",
            },
            "scan": {"ports"},
            "exploit": {"cve", "cmd"},
            "persistent": {"rounds_per_cycle", "max_cycles", "auto_report"},
            "recon": set(),
            "codescan": set(),
        }
        common = set(SCOPE_FIELDS)
        supplied = {
            name
            for name in self.options.model_fields_set
            if getattr(self.options, name) is not None
        }
        unsupported = supplied - common - command_fields[self.command]
        if unsupported:
            names = ", ".join(sorted(unsupported))
            raise ValueError(f"unsupported option(s) for {self.command}: {names}")
        return self


@dataclass(frozen=True)
class PreparedTask:
    request: TaskCreateRequest
    prompt: str
    constraints: TaskConstraints


@dataclass(frozen=True)
class TaskExecution:
    run: OrchestratorRunResult
    action_result: Any


def task_request_from_payload(
    payload: Any, *, defaults: dict[str, Any] | None = None
) -> TaskCreateRequest:
    """Validate a protocol DTO and apply session scope defaults once."""

    if not isinstance(payload, dict):
        raise ValueError("task must be an object")
    raw = dict(payload)
    raw_options = raw.get("options", {})
    if not isinstance(raw_options, dict):
        raise ValueError("task.options must be an object")
    options = dict(raw_options)
    for field in SCOPE_FIELDS:
        if field not in options and defaults and defaults.get(field) not in (None, "", []):
            options[field] = defaults[field]
    raw["options"] = options
    if "resume" not in raw and defaults and "resume" in defaults:
        raw["resume"] = bool(defaults["resume"])
    return TaskCreateRequest.model_validate(raw)


def prepare_task(request: TaskCreateRequest) -> PreparedTask:
    constraints = build_task_constraints(request)
    violation = validate_action_constraints(request.command, constraints)
    if violation is not None:
        raise ValueError(violation)
    return PreparedTask(request, build_task_prompt(request, constraints), constraints)


def build_task_constraints(request: TaskCreateRequest) -> TaskConstraints:
    return build_scope_constraints(request.target, request.options.model_dump())


def build_scope_constraints(target: str, scope: dict[str, Any]) -> TaskConstraints:
    """Build authoritative constraints from structured scope fields."""

    host = _target_host(target)
    constraints = TaskConstraints(
        allowed_ports=[scope["only_port"]] if scope.get("only_port") else [],
        allowed_hosts=[scope["only_host"]] if scope.get("only_host") else ([host] if host else []),
        blocked_hosts=_parse_blocked_hosts(scope.get("blocked_host")),
        allowed_paths=_values(scope.get("only_path")),
        blocked_paths=_values(scope.get("blocked_path")),
        allowed_actions=_values(scope.get("allow_actions")),
        blocked_actions=_values(scope.get("block_actions")),
    )
    constraints.strict_mode = not constraints.is_empty()
    return constraints


def build_task_prompt(request: TaskCreateRequest, constraints: TaskConstraints) -> str:
    options = request.options
    if request.prompt:
        prompt = request.prompt
    elif request.command == "recon":
        prompt = f"Perform authorized reconnaissance against {request.target} without exploitation."
    elif request.command == "scan":
        port_hint = f", focusing on ports {options.ports}" if options.ports else ""
        prompt = (
            f"Perform authorized vulnerability scanning against {request.target}{port_hint} "
            "without exploitation."
        )
    elif request.command == "exploit":
        cve_hint = f" using {options.cve}" if options.cve else ""
        prompt = (
            f"Attempt authorized exploitation against {request.target}{cve_hint} and verify "
            f"with command: {options.cmd or 'id'}"
        )
    elif request.command == "persistent":
        prompt = f"Continuously perform an authorized pentest against {request.target} until stopped."
    elif request.command == "codescan":
        prompt = f"Perform a local static source-code security scan of {request.target}."
    else:
        prompt = (
            f"Perform an authorized {options.scope or 'full'} pentest against {request.target}. "
            "This target is explicitly in scope."
        )
    block = constraints.to_prompt_block()
    return f"{prompt}\n\n{block}" if block else prompt


async def _run_codescan(task: PreparedTask, *, stream_sink: Any = None) -> dict[str, Any]:
    """Run a local static code scan without the agent loop.

    Local source scanning is deterministic and needs no LLM, so it bypasses
    the agent/orchestrator entirely. Findings are returned in the shared
    dict shape so the TUI backend emits ``finding`` + ``task_completed``
    protocol events exactly like network tasks.
    """

    import asyncio

    from vulnclaw.codescan.report import _finding_to_vuln_dict
    from vulnclaw.codescan.scanner import scan_code

    # Fields the TUI protocol schema (protocol/tui-v1.schema.json, $defs.finding)
    # allows. ``additionalProperties`` is false, so anything extra is rejected
    # by the strict Python-side validator.
    _FINDING_FIELDS = (
        "id",
        "severity",
        "title",
        "target",
        "vuln_type",
        "description",
        "impact",
        "evidence",
        "cve",
        "cvss",
        "cwe",
        "remediation",
        "endpoint",
        "method",
        "line",
        "code_location",
        "evidence_refs",
        "skill_provenance",
        "subagent_provenance",
        "poc_script",
        "evidence_level",
        "lifecycle_status",
        "verified",
        "verification_status",
        "verified_at",
        "verification_note",
        "chain_depends_on",
    )

    def _clean(item: dict[str, Any]) -> dict[str, Any]:
        return {k: item[k] for k in _FINDING_FIELDS if k in item}

    target = task.request.target
    if stream_sink is not None and hasattr(stream_sink, "on_status"):
        stream_sink.on_status(f"Code scanning {target}...")

    def _run() -> list[dict[str, Any]]:
        result = scan_code(target, layers=("L1", "L2"))
        findings = []
        for f in result.findings:
            item = _finding_to_vuln_dict(f)
            item["id"] = item.get("finding_id") or f"{f.rule_id}:{f.file}:{f.line}"
            findings.append(_clean(item))
        return findings

    findings = await asyncio.to_thread(_run)
    if stream_sink is not None and hasattr(stream_sink, "on_stream_end"):
        stream_sink.on_stream_end()
    return {"command": "codescan", "target": target, "findings": findings}


async def run_task_action(
    agent: Any,
    task: PreparedTask,
    *,
    stream_sink: Any = None,
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
    on_step: Callable[[int, Any], None] | None = None,
    on_cycle_step: Callable[[int, int, Any], None] | None = None,
    on_cycle_complete: Callable[[int, Any], None] | None = None,
) -> Any:
    """Execute one prepared task through public AgentCore APIs."""

    request = task.request
    options = request.options
    if request.command == "codescan":
        return await _run_codescan(task, stream_sink=stream_sink)
    if request.command == "run":
        engine = resolve_engine(agent.config, options.engine)
        if engine == "solve":
            return await agent.solve(
                task.prompt,
                target=request.target,
                max_steps=options.max_steps or agent.config.session.solve_max_steps,
                max_tool_rounds=(
                    options.max_tool_rounds or agent.config.session.solve_max_tool_rounds
                ),
                stream_sink=stream_sink,
                on_event=on_event,
                task_constraints=task.constraints,
            )
        if engine == "team":
            from vulnclaw.agent.team import run_team_pentest

            agent.apply_task_constraints(task.constraints)
            return await run_team_pentest(
                agent,
                user_input=task.prompt,
                target=request.target,
                max_steps=options.max_steps or agent.config.session.solve_max_steps,
                max_directions=options.max_directions,
                max_tool_rounds=(
                    options.max_tool_rounds or agent.config.session.solve_max_tool_rounds
                ),
                max_parallel=options.max_parallel or agent.config.session.solve_max_parallel,
                stream_sink=stream_sink,
                on_event=on_event,
            )
        return await agent.auto_pentest(
            task.prompt,
            target=request.target,
            max_rounds=options.max_rounds or agent.config.session.max_rounds,
            on_step=on_step,
            stream_sink=stream_sink,
            engine="rounds",
            task_constraints=task.constraints,
        )
    if request.command == "persistent":
        return await agent.persistent_pentest(
            task.prompt,
            target=request.target,
            rounds_per_cycle=(
                options.rounds_per_cycle or agent.config.session.persistent_rounds_per_cycle
            ),
            max_cycles=(
                options.max_cycles
                if options.max_cycles is not None
                else agent.config.session.persistent_max_cycles
            ),
            auto_report=(
                options.auto_report
                if options.auto_report is not None
                else agent.config.session.persistent_auto_report
            ),
            on_cycle_step=on_cycle_step,
            on_cycle_complete=on_cycle_complete,
            stream_sink=stream_sink,
            task_constraints=task.constraints,
        )
    return await agent.chat(
        task.prompt,
        target=request.target,
        stream_sink=stream_sink,
        task_constraints=task.constraints,
    )


async def execute_task(
    agent: Any,
    task: PreparedTask,
    *,
    before_restore: Callable[[Any], None] | None = None,
    on_restored: Callable[[Any], None] | None = None,
    on_legacy_import: Callable[[Any], None] | None = None,
    before_action: Callable[[], None] | None = None,
    stream_sink: Any = None,
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
    on_step: Callable[[int, Any], None] | None = None,
    on_cycle_step: Callable[[int, int, Any], None] | None = None,
    on_cycle_complete: Callable[[int, Any], None] | None = None,
) -> TaskExecution:
    """Run a structured task through shared persistence and execution semantics."""

    request = task.request
    action_result: Any = None

    if request.command == "codescan":
        # Local static scanning is deterministic and needs no agent loop,
        # session restore, run directory, or LLM. Short-circuit so the
        # backend stays fully usable without a live agent.
        from vulnclaw.orchestrator import OrchestratorRunResult
        from vulnclaw.target_state.store import SessionRestoreResult

        action_result = await _run_codescan(task, stream_sink=stream_sink)
        run = OrchestratorRunResult(
            restore_result=SessionRestoreResult(restored=False, target=request.target),
            summary={
                "command": "codescan",
                "target": request.target,
                "findings": action_result["findings"],
            },
            status="completed",
            exit_code=1 if action_result["findings"] else 0,
        )
        return TaskExecution(run, action_result)

    async def runner(shared_agent: Any) -> Any:
        nonlocal action_result
        if before_action is not None:
            before_action()
        action_result = await run_task_action(
            shared_agent,
            task,
            stream_sink=stream_sink,
            on_event=on_event,
            on_step=on_step,
            on_cycle_step=on_cycle_step,
            on_cycle_complete=on_cycle_complete,
        )
        return action_result

    run = await run_agent_task(
        agent=agent,
        command=request.command,
        target=request.target,
        resume=request.resume,
        snapshot_id=request.snapshot_id,
        run_name=request.run_name,
        resume_run_name=request.resume_run_name,
        runs_dir=request.runs_dir,
        additional_targets=request.additional_targets,
        target_type=request.target_type,
        mount=request.mount,
        repair=request.repair,
        force_fresh=request.force_fresh,
        no_import=request.no_import,
        before_restore=before_restore,
        on_restored=on_restored,
        on_legacy_import=on_legacy_import,
        runner=runner,
    )
    return TaskExecution(run, action_result)


def _target_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or "").lower()


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    raw = value if isinstance(value, (list, tuple)) else str(value).split(",")
    return [str(item).strip() for item in raw if str(item).strip()]


_BLOCKED_HOST_SEPARATOR_RE = re.compile(r"[,\r\n]+")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def _parse_blocked_hosts(value: Any) -> list[str]:
    """Parse the blocklist field into normalized, ordered host constraints.

    The Web UI lets operators enter several excluded hosts in one field,
    separated by commas or new lines, so a single string can carry many
    constraints. Each host is lower-cased, de-duplicated, and rechecked for
    control characters — newlines are a legitimate separator here, but any
    other control character inside a host is a prompt-injection attempt.
    """
    if value is None:
        return []
    hosts: list[str] = []
    for raw_host in _BLOCKED_HOST_SEPARATOR_RE.split(str(value)):
        host = raw_host.strip().lower()
        if not host:
            continue
        if _CONTROL_CHAR_RE.search(host):
            raise ValueError("blocked_host contains invalid control characters")
        if host not in hosts:
            hosts.append(host)
    return hosts
