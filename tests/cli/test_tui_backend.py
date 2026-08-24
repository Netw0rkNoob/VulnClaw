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


@pytest.mark.asyncio
async def test_initialize_and_two_tasks_share_one_session_backend_pid() -> None:
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
    assert ready["capabilities"]["control_operations"] == [
        "execution.approval.resolve",
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
