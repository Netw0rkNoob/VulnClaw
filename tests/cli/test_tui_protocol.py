from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from vulnclaw.tui_protocol import (
    CLIENT_MESSAGE_TYPES,
    PROTOCOL_VERSION,
    SERVER_EVENT_TYPES,
    JsonlWriter,
    ProtocolError,
    decode_client_message,
    make_event,
)


def test_decode_valid_start_task() -> None:
    message = decode_client_message(
        json.dumps(
            {
                "protocol_version": 1,
                "type": "start_task",
                "request_id": "r1",
                "task_id": "t1",
                "payload": {
                    "task": {"command": "run", "target": "https://example.test"}
                },
            }
        )
    )

    assert message.type == "start_task"
    assert message.request_id == "r1"
    assert message.task_id == "t1"
    assert message.payload["task"]["command"] == "run"
    assert message.payload["task"]["target"] == "https://example.test"


def test_decode_valid_generic_control_request() -> None:
    message = decode_client_message(
        json.dumps(
            {
                "protocol_version": 1,
                "type": "control",
                "request_id": "r-control",
                "payload": {
                    "operation": "example.inspect",
                    "arguments": {"detail": True},
                },
            }
        )
    )

    assert message.type == "control"
    assert message.task_id is None
    assert message.payload["operation"] == "example.inspect"


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("not-json", "invalid_json"),
        (json.dumps([]), "invalid_message"),
        (
            json.dumps(
                {"protocol_version": 99, "type": "initialize", "request_id": "r1"}
            ),
            "unsupported_protocol",
        ),
        (
            json.dumps(
                {"protocol_version": 1, "type": "surprise", "request_id": "r1"}
            ),
            "unsupported_message",
        ),
        (
            json.dumps(
                {"protocol_version": 1, "type": "start_task", "request_id": "r1"}
            ),
            "invalid_message",
        ),
        (
            json.dumps(
                {"protocol_version": 1, "type": "initialize", "request_id": "r1"}
            ),
            "invalid_message",
        ),
    ],
)
def test_decode_rejects_bad_messages(raw: str, code: str) -> None:
    with pytest.raises(ProtocolError) as caught:
        decode_client_message(raw)
    assert caught.value.code == code


def test_writer_emits_one_versioned_json_object_per_line() -> None:
    stream = io.StringIO()
    writer = JsonlWriter(stream)
    state = {
        "target": "example.test",
        "phase": "idle",
        "task_constraints": {},
        "task": {"active": False, "task_id": None},
        "last_run": None,
        "findings": [],
        "evidence": [],
        "constraint_violations": [],
    }

    writer.write(make_event("state", request_id="r1", state=state))

    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == {
        "protocol_version": PROTOCOL_VERSION,
        "type": "state",
        "request_id": "r1",
        "state": state,
    }


def test_runtime_validation_rejects_unknown_fields_in_both_directions() -> None:
    request = {
        "protocol_version": 1,
        "type": "start_task",
        "request_id": "r1",
        "task_id": "t1",
        "payload": {"task": {"command": "run", "target": "example.test"}},
        "unexpected": True,
    }
    with pytest.raises(ProtocolError, match="schema violation"):
        decode_client_message(json.dumps(request))

    stream = io.StringIO()
    with pytest.raises(ValidationError):
        JsonlWriter(stream).write(
            make_event(
                "shutdown_complete",
                request_id="r2",
                unexpected=True,
            )
        )
    assert stream.getvalue() == ""


def test_on_disk_schema_covers_every_v1_message_shape() -> None:
    schema_path = Path(__file__).resolve().parents[2] / "protocol" / "tui-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    constraints = {
        "allowed_ports": [],
        "blocked_ports": [],
        "allowed_hosts": [],
        "blocked_hosts": [],
        "allowed_paths": [],
        "blocked_paths": [],
        "allowed_actions": [],
        "blocked_actions": [],
        "notes": [],
        "strict_mode": False,
    }
    finding = {
        "id": "f1",
        "severity": "high",
        "title": "Example",
        "target": "example.test",
    }
    state = {
        "target": "example.test",
        "phase": "idle",
        "task_constraints": constraints,
        "task": {"active": False, "task_id": None},
        "last_run": None,
        "findings": [finding],
        "evidence": [],
        "constraint_violations": [],
    }
    messages = [
        {
            "protocol_version": 1,
            "type": "initialize",
            "request_id": "r1",
            "payload": {"client": {"name": "test", "version": "1"}, "bootstrap": {}},
        },
        {
            "protocol_version": 1,
            "type": "start_task",
            "request_id": "r2",
            "task_id": "t1",
            "payload": {"task": {"command": "run", "target": "example.test"}},
        },
        {
            "protocol_version": 1,
            "type": "cancel_task",
            "request_id": "r3",
            "task_id": "t1",
            "payload": {},
        },
        {"protocol_version": 1, "type": "get_state", "request_id": "r4", "payload": {}},
        {
            "protocol_version": 1,
            "type": "control",
            "request_id": "r-control",
            "payload": {
                "operation": "example.inspect",
                "arguments": {"detail": True},
            },
        },
        {"protocol_version": 1, "type": "shutdown", "request_id": "r5", "payload": {}},
        {
            "protocol_version": 1,
            "type": "ready",
            "request_id": "r1",
            "backend": {"pid": 123, "version": "0.3.7", "protocol_version": 1},
            "capabilities": {
                "commands": ["run"],
                "control_operations": [],
                "cancellation": True,
                "authoritative_state": True,
            },
            "runtime": {
                "config_ready": True,
                "provider": "test",
                "model": "test-1",
                "mcp_started": 0,
                "skills": [],
            },
            "state": state,
        },
        {"protocol_version": 1, "type": "state", "state": state},
        {
            "protocol_version": 1,
            "type": "task_started",
            "request_id": "r2",
            "task_id": "t1",
            "task": {"command": "run", "target": "example.test"},
            "state": state,
        },
        {"protocol_version": 1, "type": "status", "task_id": "t1", "status": "running"},
        {"protocol_version": 1, "type": "reasoning", "task_id": "t1", "text": "why"},
        {"protocol_version": 1, "type": "log", "task_id": "t1", "message": "line"},
        {
            "protocol_version": 1,
            "type": "tool_call",
            "task_id": "t1",
            "tool": "fetch",
            "arguments": "{}",
        },
        {
            "protocol_version": 1,
            "type": "tool_result",
            "task_id": "t1",
            "result": "ok",
        },
        {"protocol_version": 1, "type": "finding", "task_id": "t1", "finding": finding},
        {
            "protocol_version": 1,
            "type": "approval_required",
            "task_id": "t1",
            "question": "Continue?",
        },
        {
            "protocol_version": 1,
            "type": "task_completed",
            "request_id": "r2",
            "task_id": "t1",
            "result": {"status": "completed", "findings": [finding]},
            "findings": [finding],
            "state": state,
        },
        {
            "protocol_version": 1,
            "type": "task_cancelled",
            "request_id": "r2",
            "task_id": "t1",
            "state": state,
        },
        {
            "protocol_version": 1,
            "type": "task_failed",
            "request_id": "r2",
            "task_id": "t1",
            "error": {"code": "task_failed", "message": "boom"},
            "state": state,
        },
        {
            "protocol_version": 1,
            "type": "control_result",
            "request_id": "r-control",
            "operation": "example.inspect",
            "result": {"ok": True},
            "state": state,
        },
        {
            "protocol_version": 1,
            "type": "error",
            "request_id": "r2",
            "code": "invalid_task",
            "message": "bad task",
        },
        {
            "protocol_version": 1,
            "type": "shutdown_complete",
            "request_id": "r5",
        },
    ]

    for message in messages:
        validator.validate(message)

    assert {message["type"] for message in messages} == (
        CLIENT_MESSAGE_TYPES | SERVER_EVENT_TYPES
    )

    invalid_start = {
        "protocol_version": 1,
        "type": "start_task",
        "request_id": "r2",
        "payload": {"task": {"command": "run", "target": "example.test"}},
    }
    with pytest.raises(ValidationError):
        validator.validate(invalid_start)

    unknown_field = dict(messages[1], unexpected=True)
    with pytest.raises(ValidationError):
        validator.validate(unknown_field)

    incomplete_state = dict(state)
    incomplete_state.pop("phase")
    with pytest.raises(ValidationError):
        validator.validate(
            {"protocol_version": 1, "type": "state", "state": incomplete_state}
        )

    example_path = schema_path.parent / "examples" / "tui-v1-session.jsonl"
    for line in example_path.read_text(encoding="utf-8").splitlines():
        validator.validate(json.loads(line))
