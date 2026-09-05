"""Versioned JSONL protocol shared by the Python TUI backend and clients."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, TextIO

from jsonschema import Draft202012Validator, ValidationError

PROTOCOL_VERSION = 1

CLIENT_MESSAGE_TYPES = frozenset(
    {"initialize", "start_task", "cancel_task", "get_state", "control", "shutdown"}
)
TASK_CLIENT_MESSAGE_TYPES = frozenset({"start_task", "cancel_task"})

SERVER_EVENT_TYPES = frozenset(
    {
        "ready",
        "state",
        "task_started",
        "status",
        "reasoning",
        "log",
        "tool_call",
        "tool_result",
        "finding",
        "approval_required",
        "approval_closed",
        "task_completed",
        "task_cancelled",
        "task_failed",
        "control_result",
        "error",
        "shutdown_complete",
    }
)


@dataclass(frozen=True)
class ClientMessage:
    """A validated client request."""

    type: str
    request_id: str
    task_id: str | None
    payload: dict[str, Any]


class ProtocolError(ValueError):
    """Structured request error safe to return to the protocol client."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        request_id: str | None = None,
        task_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.request_id = request_id
        self.task_id = task_id

    def as_event(self) -> dict[str, Any]:
        return make_event(
            "error",
            request_id=self.request_id,
            task_id=self.task_id,
            code=self.code,
            message=str(self),
        )


def decode_client_message(line: str) -> ClientMessage:
    """Decode and validate one client JSONL request."""

    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError("invalid_json", f"invalid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ProtocolError("invalid_message", "message must be a JSON object")

    request_id = _optional_identifier(raw.get("request_id"))
    task_id = _optional_identifier(raw.get("task_id"))
    version = raw.get("protocol_version")
    if version != PROTOCOL_VERSION:
        raise ProtocolError(
            "unsupported_protocol",
            f"protocol_version must be {PROTOCOL_VERSION}",
            request_id=request_id,
            task_id=task_id,
        )

    kind = raw.get("type")
    if not isinstance(kind, str) or kind not in CLIENT_MESSAGE_TYPES:
        raise ProtocolError(
            "unsupported_message",
            f"unsupported client message type: {kind!r}",
            request_id=request_id,
            task_id=task_id,
        )
    if request_id is None:
        raise ProtocolError("invalid_message", "request_id is required")
    if kind in TASK_CLIENT_MESSAGE_TYPES and task_id is None:
        raise ProtocolError(
            "invalid_message",
            f"task_id is required for {kind}",
            request_id=request_id,
        )

    if "payload" not in raw:
        raise ProtocolError(
            "invalid_message",
            "payload is required",
            request_id=request_id,
            task_id=task_id,
        )
    payload = raw["payload"]
    if not isinstance(payload, dict):
        raise ProtocolError(
            "invalid_message",
            "payload must be a JSON object",
            request_id=request_id,
            task_id=task_id,
        )
    try:
        _protocol_validator().validate(raw)
    except ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path)
        location = f" at {path}" if path else ""
        raise ProtocolError(
            "invalid_message",
            f"protocol schema violation{location}: {exc.message}",
            request_id=request_id,
            task_id=task_id,
        ) from exc
    return ClientMessage(kind, request_id, task_id, payload)


def make_event(
    event_type: str,
    *,
    request_id: str | None = None,
    task_id: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """Build one server event with the required protocol envelope."""

    if event_type not in SERVER_EVENT_TYPES:
        raise ValueError(f"unknown server event type: {event_type}")
    event: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "type": event_type,
    }
    if request_id is not None:
        event["request_id"] = request_id
    if task_id is not None:
        event["task_id"] = task_id
    event.update(fields)
    return event


def encode_message(message: dict[str, Any]) -> str:
    """Serialize a protocol message as one compact JSON line."""

    return json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"


class JsonlWriter:
    """Thread-safe JSONL writer used by async tasks and stream callbacks."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, message: dict[str, Any]) -> None:
        event_type = message.get("type")
        if event_type not in SERVER_EVENT_TYPES:
            raise ValueError(f"writer accepts server events only, got: {event_type!r}")
        _protocol_validator().validate(message)
        line = encode_message(message)
        with self._lock:
            self._stream.write(line)
            self._stream.flush()

    def event(
        self,
        event_type: str,
        *,
        request_id: str | None = None,
        task_id: str | None = None,
        **fields: Any,
    ) -> None:
        self.write(
            make_event(
                event_type,
                request_id=request_id,
                task_id=task_id,
                **fields,
            )
        )


def _optional_identifier(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


@lru_cache(maxsize=1)
def _protocol_validator() -> Draft202012Validator:
    packaged = Path(__file__).with_name("protocol") / "tui-v1.schema.json"
    source = Path(__file__).resolve().parent.parent / "protocol" / "tui-v1.schema.json"
    path = packaged if packaged.exists() else source
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)
