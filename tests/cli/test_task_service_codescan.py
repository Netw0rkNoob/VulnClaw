"""End-to-end tests for the ``codescan`` task command through the TUI backend.

Covers the shared task contract (task_service) and the JSON-RPC backend path:
a ``/codescan <path>`` request must stream ``finding`` events and finish with a
``task_completed`` event carrying the same findings, exactly like network tasks.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from vulnclaw.task_service import (
    TASK_COMMANDS,
    TaskCreateRequest,
    prepare_task,
    task_request_from_payload,
)
from vulnclaw.tui_backend import BackendSession
from vulnclaw.tui_protocol import JsonlWriter, decode_client_message

DEMO = "demo/unsafe-ai-sample.ts"


class FakeRuntime:
    """Minimal runtime stand-in; the codescan path never touches the agent."""

    def __init__(self) -> None:
        self.stop_calls = 0
        self.agent = None  # codescan short-circuits before touching the agent

    def metadata(self) -> dict[str, Any]:
        return {
            "config_ready": True,
            "provider": "fake",
            "model": "fake-1",
            "mcp_started": 0,
            "skills": [],
        }

    def state_snapshot(self) -> dict[str, Any]:
        return {"phase": "idle"}

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


def test_codescan_is_advertised_as_a_task_command() -> None:
    assert "codescan" in TASK_COMMANDS


def test_codescan_request_validates_and_prepares() -> None:
    req = task_request_from_payload({"command": "codescan", "target": DEMO})
    assert isinstance(req, TaskCreateRequest)
    prepared = prepare_task(req)
    assert prepared.request.command == "codescan"
    assert "static source-code security scan" in prepared.prompt


def test_codescan_rejects_irrelevant_options() -> None:
    with pytest.raises(ValueError, match="unsupported option"):
        task_request_from_payload(
            {"command": "codescan", "target": DEMO, "options": {"ports": "80"}}
        )


@pytest.mark.asyncio
async def test_codescan_streams_findings_and_completes() -> None:
    stream = io.StringIO()
    session = BackendSession(JsonlWriter(stream), runtime_factory=FakeRuntime)
    await session.handle(
        request(
            "initialize",
            "r0",
            payload={
                "bootstrap": {
                    "target": "bootstrap.test",
                    "allow_actions": ["recon", "scan", "codescan"],
                }
            },
        )
    )

    await session.handle(
        request(
            "start_task",
            "r1",
            task_id="task-1",
            payload={"task": {"command": "codescan", "target": DEMO}},
        )
    )
    await session.wait_for_idle()

    lines = events(stream)
    types = [line["type"] for line in lines]
    assert "task_started" in types
    finding_events = [line for line in lines if line["type"] == "finding"]
    completed = [line for line in lines if line["type"] == "task_completed"]
    assert len(finding_events) >= 1, "codescan must stream finding events"
    assert len(completed) == 1

    # every streamed finding carries the Rust-compatible envelope
    for ev in finding_events:
        assert ev["task_id"] == "task-1"
        f = ev["finding"]
        for key in ("id", "severity", "title", "target"):
            assert key in f, f"finding missing {key}: {sorted(f)}"

    done = completed[0]
    assert done["task_id"] == "task-1"
    assert done["request_id"] == "r1"
    result = done["result"]
    assert result["command"] == "codescan"
    assert len(result["findings"]) == len(finding_events)
    assert done["findings"] == result["findings"]
    assert done["state"]["phase"] == "idle"
