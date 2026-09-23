from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from vulnclaw.task_service import TaskCreateRequest, TaskOptions, prepare_task
from vulnclaw.tui_backend import BackendSession
from vulnclaw.tui_protocol import JsonlWriter, ProtocolError, decode_client_message


class FakeRuntime:
    def __init__(self) -> None:
        self.stop_calls = 0
        self.run_count = 0

    def metadata(self) -> dict[str, Any]:
        return {
            "config_ready": True,
            "provider": "fake",
            "model": "fake-1",
            "mcp_started": 0,
            "skills": [],
        }

    def state_snapshot(self) -> dict[str, Any]:
        return {"phase": "idle", "runtime_run_count": self.run_count}

    async def stop(self) -> None:
        self.stop_calls += 1


def request(
    kind: str,
    request_id: str,
    *,
    task_id: str | None = None,
    payload: dict[str, Any] | None = None,
):
    raw: dict[str, Any] = {
        "protocol_version": 1,
        "type": kind,
        "request_id": request_id,
        "payload": payload or {},
    }
    if task_id is not None:
        raw["task_id"] = task_id
    return decode_client_message(json.dumps(raw))


def events(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def task_payload(
    command: str, target: str, *, options: dict[str, Any] | None = None, resume: bool = True
) -> dict[str, Any]:
    return {
        "task": {
            "command": command,
            "target": target,
            "resume": resume,
            "options": options or {},
        }
    }


def protocol_validator() -> Draft202012Validator:
    schema_path = Path(__file__).resolve().parents[2] / "protocol" / "tui-v1.schema.json"
    return Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("show_thinking", [True, False])
async def test_subagent_streams_are_forwarded_live_with_the_main_vocabulary(
    monkeypatch, show_thinking,
) -> None:
    from types import SimpleNamespace

    from vulnclaw.agent.exec_gate import reset_execution_gate
    from vulnclaw.agent.streaming import TranscriptStreamSink
    from vulnclaw.tui_backend import BackendStreamSink, _run_task

    reset_execution_gate()
    stream = io.StringIO()
    sink = BackendStreamSink(JsonlWriter(stream), "t1", show_thinking=show_thinking)

    async def execute(_agent, _task, *, stream_sink, on_event):
        on_event("subagent", {
            "agent_id": "a1", "parent_id": "main", "group_id": "",
            "name": "probe", "agent_type": "general", "status": "running",
        })
        child = TranscriptStreamSink(lambda kind, **fields: on_event(
            "subagent_stream", {"agent_id": "a1", "type": kind, **fields},
        ))
        for target in (stream_sink, child):
            target.on_thinking_token("inspect ")
            target.on_thinking_token("headers")
            target.on_content_token("live ")
            # Nothing has finished or flushed: text is already on the wire.
            assert events(stream)[-1]["message"] == "live "
            target.on_content_token("answer")
            target.on_tool_call("fetch", "{}")
            target.on_tool_result("200 OK")
            target.on_stream_end()
            target.on_content_token("next turn")
            assert events(stream)[-1]["append"] is False
        return SimpleNamespace(
            run=SimpleNamespace(run_context=None, status="completed", exit_code=0, summary={}),
            action_result={"findings": []},
        )

    monkeypatch.setattr("vulnclaw.tui_backend.execute_task", execute)
    task = prepare_task(TaskCreateRequest(command="run", target="example.test"))
    await _run_task(SimpleNamespace(agent=object()), task, sink)
    emitted = events(stream)
    main = [event for event in emitted if "agent_id" not in event]
    child = [
        {key: value for key, value in event.items() if key != "agent_id"}
        for event in emitted if event.get("agent_id") == "a1" and event["type"] != "subagent"
    ]
    assert main == child
    assert any(event["type"] == "reasoning" for event in child) is show_thinking
    assert [event["append"] for event in child if event["type"] == "log"] == [False, True, False]


@pytest.mark.asyncio
async def test_initialize_and_two_tasks_share_one_session_backend_pid() -> None:
    from vulnclaw.agent.exec_gate import reset_execution_gate

    reset_execution_gate()
    stream = io.StringIO()
    runtime = FakeRuntime()

    async def runner(fake: FakeRuntime, task, sink) -> dict[str, Any]:
        fake.run_count += 1
        sink.on_status(f"running {task.request.target}")
        return {
            "status": "completed",
            "run": {"name": f"run-{fake.run_count}"},
            "findings": [
                {
                    "id": f"f-{fake.run_count}",
                    "severity": "high",
                    "title": f"Finding {fake.run_count}",
                    "target": task.request.target,
                }
            ],
        }

    session = BackendSession(
        JsonlWriter(stream), runtime_factory=lambda: runtime, task_runner=runner
    )
    await session.handle(
        request(
            "initialize",
            "r-init",
            payload={
                "bootstrap": {
                    "target": "bootstrap.test",
                    "allow_actions": ["recon", "scan"],
                }
            },
        )
    )
    for index in (1, 2):
        await session.handle(
            request(
                "start_task",
                f"r-{index}",
                task_id=f"t-{index}",
                payload=task_payload("run", f"https://target-{index}.test"),
            )
        )
        await session.wait_for_idle()

    emitted = events(stream)
    validator = protocol_validator()
    for event in emitted:
        validator.validate(event)
    ready = next(event for event in emitted if event["type"] == "ready")
    completed = [event for event in emitted if event["type"] == "task_completed"]
    assert ready["backend"]["pid"] == os.getpid()
    assert ready["capabilities"]["permission_mode"] == "ask"
    assert ready["capabilities"]["control_operations"] == [
        "config.models",
        "config.preset",
        "config.read",
        "config.write",
        "execution.approval.resolve",
        "session.permission.set",
        "session.scope.reset",
        "session.scope.update",
    ]
    assert ready["state"]["target"] == "bootstrap.test"
    assert ready["state"]["task_constraints"]["allowed_actions"] == ["recon", "scan"]
    assert runtime.run_count == 2
    assert [event["task_id"] for event in completed] == ["t-1", "t-2"]
    assert [event["findings"][0]["id"] for event in completed] == ["f-1", "f-2"]


@pytest.mark.asyncio
async def test_unadvertised_control_operation_is_rejected() -> None:
    stream = io.StringIO()
    session = BackendSession(JsonlWriter(stream), runtime_factory=FakeRuntime)
    await session.handle(request("initialize", "r-init"))

    with pytest.raises(ProtocolError) as caught:
        await session.handle(
            request(
                "control",
                "r-control",
                payload={"operation": "example.inspect", "arguments": {}},
            )
        )

    assert caught.value.code == "unsupported_operation"


@pytest.mark.asyncio
async def test_scope_control_updates_defaults_for_later_tasks_and_can_reset() -> None:
    stream = io.StringIO()
    captured_constraints: list[Any] = []

    async def runner(runtime, task, sink):
        captured_constraints.append(task.constraints)
        return {"status": "completed", "findings": []}

    session = BackendSession(
        JsonlWriter(stream), runtime_factory=FakeRuntime, task_runner=runner
    )
    await session.handle(request("initialize", "r-init"))
    await session.handle(
        request(
            "control",
            "r-scope",
            payload={
                "operation": "session.scope.update",
                "arguments": {
                    "scope": {
                        "only_host": "session.test",
                        "only_port": 443,
                        "allow_actions": ["recon", "scan"],
                        "block_actions": ["exploit"],
                    }
                },
            },
        )
    )

    updated = events(stream)[-1]
    protocol_validator().validate(updated)
    assert updated["type"] == "control_result"
    assert updated["operation"] == "session.scope.update"
    assert updated["result"]["scope"]["only_port"] == 443
    assert updated["state"]["task_constraints"]["allowed_hosts"] == ["session.test"]
    assert updated["state"]["task_constraints"]["allowed_actions"] == ["recon", "scan"]

    await session.handle(
        request(
            "start_task",
            "r-task",
            task_id="t-task",
            payload=task_payload("scan", "target.test"),
        )
    )
    await session.wait_for_idle()
    assert captured_constraints[0].allowed_hosts == ["session.test"]
    assert captured_constraints[0].allowed_ports == [443]
    assert captured_constraints[0].allowed_actions == ["recon", "scan"]

    await session.handle(
        request(
            "control",
            "r-reset",
            payload={"operation": "session.scope.reset", "arguments": {}},
        )
    )
    reset = events(stream)[-1]
    protocol_validator().validate(reset)
    assert reset["operation"] == "session.scope.reset"
    assert reset["result"]["scope"] == {}
    assert reset["state"]["task_constraints"]["allowed_ports"] == []
    assert reset["state"]["task_constraints"]["allowed_actions"] == []
    assert reset["state"]["task_constraints"]["allowed_hosts"] == ["target.test"]
    assert not (
        set(session.bootstrap)
        & {
            "only_host",
            "only_port",
            "only_path",
            "blocked_host",
            "blocked_path",
            "allow_actions",
            "block_actions",
        }
    )


@pytest.mark.asyncio
async def test_scope_control_rejects_invalid_options() -> None:
    session = BackendSession(JsonlWriter(io.StringIO()), runtime_factory=FakeRuntime)
    await session.handle(request("initialize", "r-init"))

    with pytest.raises(ProtocolError) as caught:
        await session.handle(
            request(
                "control",
                "r-scope",
                payload={
                    "operation": "session.scope.update",
                    "arguments": {"scope": {"unknown": "value"}},
                },
            )
        )

    assert caught.value.code == "invalid_control"
    assert caught.value.request_id == "r-scope"


@pytest.mark.asyncio
async def test_concurrent_task_is_rejected_as_busy() -> None:
    stream = io.StringIO()
    started = asyncio.Event()
    release = asyncio.Event()

    async def runner(runtime, task, sink):
        started.set()
        await release.wait()
        return {"findings": []}

    session = BackendSession(
        JsonlWriter(stream), runtime_factory=FakeRuntime, task_runner=runner
    )
    await session.handle(request("initialize", "r-init"))
    await session.handle(
        request(
            "start_task",
            "r-1",
            task_id="t-1",
            payload=task_payload("run", "example.test"),
        )
    )
    await started.wait()

    with pytest.raises(ProtocolError) as caught:
        await session.handle(
            request(
                "start_task",
                "r-2",
                task_id="t-2",
                payload=task_payload("run", "other.test"),
            )
        )
    assert caught.value.code == "task_busy"
    with pytest.raises(ProtocolError) as control_error:
        await session.handle(
            request(
                "control",
                "r-scope",
                payload={
                    "operation": "session.scope.update",
                    "arguments": {"scope": {"only_port": 443}},
                },
            )
        )
    assert control_error.value.code == "task_busy"
    release.set()
    await session.wait_for_idle()


@pytest.mark.asyncio
async def test_initialize_without_target_still_owns_bootstrap_scope() -> None:
    stream = io.StringIO()
    session = BackendSession(JsonlWriter(stream), runtime_factory=FakeRuntime)

    await session.handle(
        request(
            "initialize",
            "r-init",
            payload={
                "bootstrap": {
                    "only_port": 443,
                    "allow_actions": ["recon", "scan"],
                    "block_actions": ["exploit"],
                }
            },
        )
    )

    ready = next(event for event in events(stream) if event["type"] == "ready")
    constraints = ready["state"]["task_constraints"]
    assert constraints["allowed_ports"] == [443]
    assert constraints["allowed_actions"] == ["recon", "scan"]
    assert constraints["blocked_actions"] == ["exploit"]


@pytest.mark.asyncio
async def test_cancel_keeps_backend_available_and_shutdown_stops_runtime_once() -> None:
    stream = io.StringIO()
    runtime = FakeRuntime()
    started = asyncio.Event()

    async def runner(fake, task, sink):
        fake.run_count += 1
        if fake.run_count == 1:
            started.set()
            await asyncio.Event().wait()
        return {"status": "completed", "findings": []}

    session = BackendSession(
        JsonlWriter(stream), runtime_factory=lambda: runtime, task_runner=runner
    )
    await session.handle(request("initialize", "r-init"))
    await session.handle(
        request(
            "start_task",
            "r-1",
            task_id="t-1",
            payload=task_payload("run", "first.test"),
        )
    )
    await started.wait()
    await session.handle(request("cancel_task", "r-cancel", task_id="t-1"))
    await session.wait_for_idle()

    await session.handle(
        request(
            "start_task",
            "r-2",
            task_id="t-2",
            payload=task_payload(
                "recon", "second.test", options={"allow_actions": ["recon"]}
            ),
        )
    )
    await session.wait_for_idle()
    await session.handle(request("shutdown", "r-shutdown"))

    emitted = events(stream)
    validator = protocol_validator()
    for event in emitted:
        validator.validate(event)
    emitted_types = [event["type"] for event in emitted]
    cancelled = next(event for event in emitted if event["type"] == "task_cancelled")
    assert "task_cancelled" in emitted_types
    assert cancelled["request_id"] == "r-cancel"
    assert "task_completed" in emitted_types
    assert emitted_types[-1] == "shutdown_complete"
    assert runtime.run_count == 2
    assert runtime.stop_calls == 1


def test_python_prepares_scope_and_action_constraints() -> None:
    task = prepare_task(
        TaskCreateRequest(
            command="scan",
            target="https://app.example/admin",
            resume=False,
            options=TaskOptions(
                only_port=443,
                only_host="app.example",
                only_path="/admin",
                blocked_host="internal.example",
                blocked_path="/debug",
                allow_actions=["recon", "scan"],
                block_actions=["exploit"],
            ),
        )
    )

    assert task.request.command == "scan"
    assert task.request.target == "https://app.example/admin"
    assert task.request.resume is False
    assert task.constraints.allowed_ports == [443]
    assert task.constraints.allowed_hosts == ["app.example"]
    assert task.constraints.allowed_paths == ["/admin"]
    assert task.constraints.blocked_hosts == ["internal.example"]
    assert task.constraints.blocked_paths == ["/debug"]
    assert task.constraints.allowed_actions == ["recon", "scan"]
    assert task.constraints.blocked_actions == ["exploit"]
    assert task.constraints.strict_mode is True


def test_python_rejects_command_outside_allowed_actions() -> None:
    with pytest.raises(ValueError, match="outside allowed actions"):
        prepare_task(
            TaskCreateRequest(
                command="exploit",
                target="target.test",
                options=TaskOptions(allow_actions=["recon", "scan"]),
            )
        )


@pytest.mark.asyncio
async def test_permission_set_updates_gate_policy() -> None:
    from vulnclaw.agent.exec_gate import get_execution_gate, reset_execution_gate

    reset_execution_gate()
    stream = io.StringIO()
    session = BackendSession(JsonlWriter(stream), runtime_factory=FakeRuntime)
    await session.handle(request("initialize", "r-init"))

    await session.handle(
        request(
            "control",
            "r-perm",
            payload={
                "operation": "session.permission.set",
                "arguments": {"mode": "auto_review"},
            },
        )
    )
    result = events(stream)[-1]
    assert result["result"]["mode"] == "auto_review"
    assert get_execution_gate().mode == "auto_review"

    # De-escalation back to ask works while idle too.
    await session.handle(
        request(
            "control",
            "r-perm2",
            payload={"operation": "session.permission.set", "arguments": {"mode": "ask"}},
        )
    )
    reset_execution_gate()


@pytest.mark.asyncio
async def test_permission_set_allows_all_transitions_while_task_active() -> None:
    from vulnclaw.agent.exec_gate import get_execution_gate, reset_execution_gate

    reset_execution_gate()
    stream = io.StringIO()
    session = BackendSession(JsonlWriter(stream), runtime_factory=FakeRuntime)
    await session.handle(request("initialize", "r-init"))
    blocker = asyncio.Event()
    session.active_task = asyncio.create_task(blocker.wait())
    session.active_task_id = "task-active"

    try:
        # Covers ask→full, full→auto, auto→ask, ask→auto,
        # auto→full, and full→ask while the same task remains active.
        modes = ["full_access", "auto_review", "ask", "auto_review", "full_access", "ask"]
        for index, mode in enumerate(modes):
            await session.handle(
                request(
                    "control",
                    f"r-active-{index}",
                    payload={
                        "operation": "session.permission.set",
                        "arguments": {"mode": mode},
                    },
                )
            )
            result = events(stream)[-1]
            assert result["type"] == "control_result"
            assert result["result"]["mode"] == mode
            assert get_execution_gate().mode == mode
            assert session.active_task.done() is False
    finally:
        session.active_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await session.active_task
        session.active_task = None
        session.active_task_id = None
        reset_execution_gate()


@pytest.mark.asyncio
async def test_permission_set_rejects_unknown_mode() -> None:
    session = BackendSession(JsonlWriter(io.StringIO()), runtime_factory=FakeRuntime)
    await session.handle(request("initialize", "r-init"))

    with pytest.raises(ProtocolError) as caught:
        await session.handle(
            request(
                "control",
                "r-perm-bad",
                payload={
                    "operation": "session.permission.set",
                    "arguments": {"mode": "yolo"},
                },
            )
        )
    assert caught.value.code == "invalid_control"


def _fresh_config():
    """Stand-in for ``load_config`` that never touches the real config file."""
    from vulnclaw.config.schema import VulnClawConfig

    return VulnClawConfig()


class _AgentSessionState:
    """The slice of ``AgentCore.session_state`` that ``_initialize`` writes to."""

    def __init__(self) -> None:
        self.target: Any = None


class FakeConfigAgent:
    """Captures the configs handed to ``AgentCore.apply_config``.

    Carries the members ``_initialize`` and the scope paths reach for, so a
    minimal runtime still satisfies the handshake.
    """

    def __init__(self) -> None:
        self.applied: list[Any] = []
        self.session_state = _AgentSessionState()

    def apply_config(self, config: Any) -> None:
        self.applied.append(config)

    def apply_task_constraints(self, constraints: Any) -> None:
        self.constraints = constraints


class FakeConfigRuntime:
    """Runtime carrying a real config; the ``config.*`` operations need both
    a mutable config and an agent to rebind."""

    def __init__(self, config: Any = None) -> None:
        from vulnclaw.config.schema import VulnClawConfig

        self.config = config if config is not None else VulnClawConfig()
        self.agent = FakeConfigAgent()

    async def stop(self) -> None:
        return None


def _config_session(stream: io.StringIO, config: Any = None) -> BackendSession:
    return BackendSession(
        JsonlWriter(stream), runtime_factory=lambda: FakeConfigRuntime(config)
    )


@pytest.mark.asyncio
async def test_config_read_reports_the_form_without_echoing_the_api_key() -> None:
    from vulnclaw.config.schema import VulnClawConfig

    config = VulnClawConfig()
    config.llm.provider = "deepseek"
    config.llm.base_url = "https://api.deepseek.com"
    config.llm.model = "deepseek-v4-pro"
    config.llm.website_url = "https://www.deepseek.com/"
    config.llm.api_key = "sk-secret-value"

    stream = io.StringIO()
    session = _config_session(stream, config)
    await session.handle(request("initialize", "r-init"))
    await session.handle(
        request("control", "r-read", payload={"operation": "config.read", "arguments": {}})
    )

    result = events(stream)[-1]
    protocol_validator().validate(result)
    assert result["operation"] == "config.read"
    assert result["result"]["provider"] == "deepseek"
    assert result["result"]["website_url"] == "https://www.deepseek.com/"
    assert result["result"]["base_url"] == "https://api.deepseek.com"
    assert result["result"]["model"] == "deepseek-v4-pro"
    assert result["result"]["api_key_set"] is True
    # The credential must never travel back over the protocol.
    assert "sk-secret-value" not in stream.getvalue()
    assert "api_key" not in result["result"]

    # Every template is offered with the metadata the form fills from.
    templates = {entry["id"]: entry for entry in result["result"]["providers"]}
    assert templates["custom"]["website_url"] == ""
    assert templates["openai"]["website_url"] == "https://platform.openai.com/"
    assert templates["openai"]["default_model"] == "gpt-5.6-sol"


@pytest.mark.asyncio
async def test_config_preset_blanks_the_preset_fields_for_custom() -> None:
    stream = io.StringIO()
    session = _config_session(stream)
    await session.handle(request("initialize", "r-init"))

    await session.handle(
        request(
            "control",
            "r-preset",
            payload={
                "operation": "config.preset",
                "arguments": {"provider": "deepseek"},
            },
        )
    )
    seeded = events(stream)[-1]["result"]
    protocol_validator().validate(events(stream)[-1])
    assert seeded["website_url"] == "https://www.deepseek.com/"
    assert seeded["base_url"] == "https://api.deepseek.com"
    assert seeded["model"] == "deepseek-v4-pro"

    await session.handle(
        request(
            "control",
            "r-preset-custom",
            payload={"operation": "config.preset", "arguments": {"provider": "custom"}},
        )
    )
    custom = events(stream)[-1]["result"]
    assert custom["provider"] == "custom"
    assert custom["website_url"] == ""
    assert custom["base_url"] == ""
    assert custom["model"] == ""


@pytest.mark.asyncio
async def test_config_preset_rejects_an_unknown_template() -> None:
    session = _config_session(io.StringIO())
    await session.handle(request("initialize", "r-init"))

    with pytest.raises(ProtocolError) as caught:
        await session.handle(
            request(
                "control",
                "r-preset-bad",
                payload={
                    "operation": "config.preset",
                    "arguments": {"provider": "not-a-vendor"},
                },
            )
        )
    assert caught.value.code == "invalid_control"


@pytest.mark.asyncio
async def test_config_models_falls_back_to_the_saved_key(monkeypatch) -> None:
    import vulnclaw.config.settings as settings_mod
    from vulnclaw.config.schema import VulnClawConfig

    seen: list[tuple[str, str]] = []

    def fake_fetch(base_url: str, api_key: str, timeout: float = 10.0) -> list[str]:
        seen.append((base_url, api_key))
        return ["b-model", "a-model"]

    monkeypatch.setattr(settings_mod, "fetch_provider_models", fake_fetch)

    config = VulnClawConfig()
    config.llm.api_key = "sk-stored"
    stream = io.StringIO()
    session = _config_session(stream, config)
    await session.handle(request("initialize", "r-init"))

    await session.handle(
        request(
            "control",
            "r-models",
            payload={
                "operation": "config.models",
                "arguments": {"base_url": "https://api.deepseek.com", "api_key": ""},
            },
        )
    )

    result = events(stream)[-1]
    protocol_validator().validate(result)
    assert result["result"]["models"] == ["b-model", "a-model"]
    # An empty key reuses the stored credential instead of failing outright.
    assert result["result"]["used_saved_key"] is True
    assert seen == [("https://api.deepseek.com", "sk-stored")]


@pytest.mark.asyncio
async def test_config_models_requires_a_base_url_and_a_key() -> None:
    stream = io.StringIO()
    session = _config_session(stream)
    await session.handle(request("initialize", "r-init"))

    with pytest.raises(ProtocolError) as caught:
        await session.handle(
            request(
                "control",
                "r-models-bad",
                payload={
                    "operation": "config.models",
                    "arguments": {"base_url": "", "api_key": "sk-x"},
                },
            )
        )
    assert caught.value.code == "invalid_control"


@pytest.mark.asyncio
async def test_config_write_persists_and_rebinds_the_agent(monkeypatch) -> None:
    import vulnclaw.config.settings as settings_mod

    saved: list[Any] = []
    monkeypatch.setattr(settings_mod, "load_config", _fresh_config)
    monkeypatch.setattr(settings_mod, "save_config", saved.append)

    stream = io.StringIO()
    runtime = FakeConfigRuntime()
    session = BackendSession(JsonlWriter(stream), runtime_factory=lambda: runtime)
    await session.handle(request("initialize", "r-init"))

    await session.handle(
        request(
            "control",
            "r-write",
            payload={
                "operation": "config.write",
                "arguments": {
                    "provider": "deepseek",
                    "website_url": "https://www.deepseek.com/",
                    "base_url": "https://api.deepseek.com",
                    "model": "deepseek-v4-pro",
                    "api_key": "sk-new",
                },
            },
        )
    )

    result = events(stream)[-1]
    protocol_validator().validate(result)
    assert result["result"]["provider"] == "deepseek"
    assert result["result"]["model"] == "deepseek-v4-pro"
    assert result["result"]["config_ready"] is True
    assert saved[0].llm.api_key == "sk-new"
    # The live runtime adopts the new config so no restart is needed.
    assert runtime.config.llm.model == "deepseek-v4-pro"
    assert runtime.agent.applied[0].llm.model == "deepseek-v4-pro"


@pytest.mark.asyncio
async def test_config_write_keeps_the_stored_key_when_none_is_supplied(monkeypatch) -> None:
    import vulnclaw.config.settings as settings_mod
    from vulnclaw.config.schema import VulnClawConfig

    def _config_with_stored_key():
        config = VulnClawConfig()
        config.llm.api_key = "sk-stored"
        return config

    saved: list[Any] = []
    monkeypatch.setattr(settings_mod, "load_config", _config_with_stored_key)
    monkeypatch.setattr(settings_mod, "save_config", saved.append)

    runtime = FakeConfigRuntime()
    session = BackendSession(JsonlWriter(io.StringIO()), runtime_factory=lambda: runtime)
    await session.handle(request("initialize", "r-init"))

    await session.handle(
        request(
            "control",
            "r-write",
            payload={
                "operation": "config.write",
                "arguments": {
                    "provider": "deepseek",
                    "website_url": "",
                    "base_url": "https://api.deepseek.com",
                    "model": "deepseek-v4-pro",
                },
            },
        )
    )

    # The client cannot echo a credential it was never given, so an absent key
    # must leave the stored one intact rather than blanking it.
    assert saved[0].llm.api_key == "sk-stored"


@pytest.mark.asyncio
async def test_config_write_is_refused_while_a_task_is_active(monkeypatch) -> None:
    import vulnclaw.config.settings as settings_mod

    monkeypatch.setattr(settings_mod, "load_config", _fresh_config)

    async def runner(runtime, task, sink):
        return {"status": "completed", "findings": []}

    stream = io.StringIO()
    runtime = FakeConfigRuntime()
    session = BackendSession(
        JsonlWriter(stream), runtime_factory=lambda: runtime, task_runner=runner
    )
    await session.handle(request("initialize", "r-init"))
    await session.handle(
        request(
            "start_task",
            "r-task",
            task_id="t-task",
            payload=task_payload("scan", "target.test"),
        )
    )

    with pytest.raises(ProtocolError) as caught:
        await session.handle(
            request(
                "control",
                "r-write",
                payload={
                    "operation": "config.write",
                    "arguments": {
                        "provider": "deepseek",
                        "base_url": "https://api.deepseek.com",
                        "model": "deepseek-v4-pro",
                    },
                },
            )
        )
    assert caught.value.code == "task_busy"
    await session.wait_for_idle()
