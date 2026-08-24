"""Regression: structured approval_required events must pass the protocol schema.

This is the fix for the ValidationError that swallowed TUI approval prompts
in the first live run (schema only knew the legacy `question` field).
"""

from __future__ import annotations

import io
import json

from vulnclaw.tui_protocol import JsonlWriter


def _emit(fields: dict) -> dict:
    stream = io.StringIO()
    writer = JsonlWriter(stream)
    writer.event("approval_required", task_id="task-1", **fields)
    return json.loads(stream.getvalue().splitlines()[0])


class TestApprovalRequiredSchema:
    def test_structured_payload_passes(self):
        event = _emit(
            {
                "request_hash": "a" * 64,
                "kind": "shell",
                "question": "whoami && ls -la",
                "cwd": "/tmp/target",
                "detail": "auto-review: 'curl' is not in the trusted command table",
                "expires_at": "2026-08-23T06:22:42+00:00",
                "risk": "Executes with current user privileges; not sandboxed.",
            }
        )
        assert event["type"] == "approval_required"
        assert event["request_hash"] == "a" * 64

    def test_legacy_minimal_payload_still_passes(self):
        event = _emit({"question": "legacy ask_user question"})
        assert event["question"] == "legacy ask_user question"

    def test_full_tui_channel_payload_roundtrip(self):
        """The exact payload TuiApprovalChannel emits must serialize cleanly."""
        from vulnclaw.agent.exec_gate import ApprovalView

        view = ApprovalView(
            request_hash="b" * 64,
            kind="python",
            display_escaped="print('x')\\u001b[31m",
            cwd="/home/user/target",
            detail="auto-review: interpreters and shells cannot run in auto-review",
            expires_at="2026-08-23T07:00:00+00:00",
            risk="Executes with current user privileges; not sandboxed.",
        )
        event = _emit(view.to_event_payload())
        assert event["kind"] == "python"
        assert "\\u001b" in event["question"]  # escaped, raw ESC never transmitted
        assert "\x1b" not in json.dumps(event)
