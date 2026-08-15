"""Focused tests for CLI rendering and stream-protocol helpers."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

import vulnclaw.cli._helpers as helpers


def _json_lines(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def test_tui_group_event_round_trips_through_wire_protocol():
    stream = io.StringIO()
    target_console = SimpleNamespace(file=stream)
    environ = {
        helpers.TUI_EVENT_STREAM_ENV: "1",
        helpers.TUI_EVENT_TOKEN_ENV: "secret",
    }

    helpers._emit_tui_event(
        target_console,
        "group_finished",
        {"group_id": "g1", "status": "verified"},
        environ,
    )

    event = helpers._parse_tui_solve_event(
        stream.getvalue(), expected_token="secret"
    )
    assert event == helpers.SubagentTuiEvent(
        kind="group_finished",
        payload={"group_id": "g1", "status": "verified"},
    )


@pytest.mark.parametrize(
    "line, token",
    [
        ("ordinary output", "secret"),
        (f"{helpers.TUI_EVENT_PREFIX}secret:not-json", "secret"),
        (f"{helpers.TUI_EVENT_PREFIX}secret:[]", "secret"),
        (
            f'{helpers.TUI_EVENT_PREFIX}secret:{{"kind":"agent_step","payload":{{}}}}',
            "secret",
        ),
        (
            f'{helpers.TUI_EVENT_PREFIX}secret:{{"kind":"group_created","payload":[]}}',
            "secret",
        ),
        (
            f'{helpers.TUI_EVENT_PREFIX}other:{{"kind":"group_created","payload":{{}}}}',
            "secret",
        ),
        (f'{helpers.TUI_EVENT_PREFIX}:{{"kind":"group_created","payload":{{}}}}', ""),
    ],
)
def test_tui_group_event_parser_rejects_untrusted_lines(line, token):
    assert helpers._parse_tui_solve_event(line, expected_token=token) is None


@pytest.mark.parametrize(
    "environ, kind",
    [
        ({}, "group_created"),
        ({helpers.TUI_EVENT_STREAM_ENV: "1"}, "group_created"),
        (
            {
                helpers.TUI_EVENT_STREAM_ENV: "1",
                helpers.TUI_EVENT_TOKEN_ENV: "secret",
            },
            "agent_step",
        ),
    ],
)
def test_tui_event_emitter_ignores_disabled_or_non_group_events(environ, kind):
    stream = io.StringIO()

    helpers._emit_tui_event(SimpleNamespace(file=stream), kind, {}, environ)

    assert stream.getvalue() == ""


def test_group_projection_includes_progress_and_failure_context():
    projection = helpers._group_console_projection(
        "group_finished",
        {
            "group_id": "g7",
            "status": "verified",
            "member_total": 3,
            "member_done": 2,
            "wave_count": 4,
            "evidence_count": 5,
            "member_task_id": "task-2",
            "member_status": "failed",
            "member_error": "timeout",
            "conclusion": "confirmed",
        },
    )

    assert projection is not None
    prefix, detail, style = projection
    assert "g7" in prefix and "verified" in prefix
    assert all(
        expected in detail
        for expected in (
            "confirmed",
            "timeout",
            "task-2=failed",
            "members 2/3",
            "waves 4",
            "evidence 5",
        )
    )
    assert style == "green"


@pytest.mark.parametrize(
    "kind, status, expected_style",
    [
        ("group_failed", "failed", "red"),
        ("group_cancelled", "cancelled", "yellow"),
        ("group_finished", "completed", "green"),
        ("group_progress", "running", "magenta"),
    ],
)
def test_group_projection_maps_status_to_terminal_style(kind, status, expected_style):
    projection = helpers._group_console_projection(
        kind, {"group_id": "g1", "status": status}
    )

    assert projection is not None
    assert projection[2] == expected_style


def test_group_created_projection_falls_back_to_goal():
    projection = helpers._group_console_projection(
        "group_created",
        {"group_id": "g2", "phase": "initial_recon", "goal": "map the target"},
    )

    assert projection is not None
    assert "initial recon" in projection[0]
    assert projection[1] == "map the target"
    assert helpers._group_console_projection("agent_step", {}) is None


def test_jsonl_stream_sink_preserves_event_order_and_coalesces_tokens():
    stream = io.StringIO()
    sink = helpers.JsonlStreamSink(stream, show_thinking=True)

    sink.on_status("working")
    sink.on_thinking_token("inspect ")
    sink.on_thinking_token("headers")
    sink.on_content_token("port ")
    sink.on_content_token("open")
    sink.on_tool_call("fetch", '{"url":"https://example.com"}')
    sink.on_tool_result("x" * 2000)
    sink.on_stream_end()

    events = _json_lines(stream)
    assert [event["type"] for event in events] == [
        "status",
        "reasoning",
        "log",
        "log",
        "log",
    ]
    assert events[1]["text"] == "inspect headers"
    assert events[2]["message"] == "port open"
    assert "fetch" in events[3]["message"]
    assert "terminal preview collapsed" in events[4]["message"]


def test_jsonl_stream_sink_hides_reasoning_and_uses_stdout_by_default(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr(helpers.sys, "stdout", stream)
    sink = helpers.JsonlStreamSink(show_thinking=False)

    sink.on_thinking_token("")
    sink.on_thinking_token("secret")
    sink.on_content_token("")
    sink.on_content_token("visible")
    sink.on_stream_end()

    assert _json_lines(stream) == [{"type": "log", "message": "visible"}]


def test_emit_complete_event_uses_tui_result_schema():
    stream = io.StringIO()
    findings = [{"id": "v001", "severity": "high", "title": "SQL injection"}]

    helpers.emit_complete_event(stream, summary="goal reached", findings=findings)

    assert _json_lines(stream) == [
        {
            "type": "complete",
            "summary": "goal reached",
            "result": {"findings": findings},
        }
    ]


@pytest.mark.parametrize(
    "kind, payload, expected",
    [
        ("agent_step", {"step": 4}, "4"),
        ("completed", {}, "Goal"),
        ("complete_rejected", {"reason": "needs proof"}, "needs proof"),
        ("ask_user", {"question": "continue?"}, "continue?"),
        ("no_path", {"reason": "blocked"}, "blocked"),
        ("error", {"error": "boom"}, "boom"),
    ],
)
def test_solve_event_printer_renders_each_terminal_state(kind, payload, expected):
    output = io.StringIO()
    printer = helpers._make_solve_event_printer(
        Console(file=output, force_terminal=False, width=200)
    )

    printer(kind, payload)

    assert expected in output.getvalue()


def test_solve_event_printer_emits_machine_and_human_group_updates(monkeypatch):
    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=200)
    monkeypatch.setenv(helpers.TUI_EVENT_STREAM_ENV, "1")
    monkeypatch.setenv(helpers.TUI_EVENT_TOKEN_ENV, "secret")

    helpers._make_solve_event_printer(console)(
        "group_finished", {"group_id": "g9", "status": "verified"}
    )

    rendered = output.getvalue()
    wire_line = next(
        line for line in rendered.splitlines() if line.startswith(helpers.TUI_EVENT_PREFIX)
    )
    assert helpers._parse_tui_solve_event(
        wire_line, expected_token="secret"
    ) == helpers.SubagentTuiEvent(
        kind="group_finished", payload={"group_id": "g9", "status": "verified"}
    )
    assert "g9" in rendered and "verified" in rendered


def test_print_agent_output_handles_visible_and_reasoning_only_text(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(
        helpers, "console", Console(file=output, force_terminal=False, width=200)
    )
    config = SimpleNamespace(session=SimpleNamespace(show_thinking=False))

    helpers._print_agent_output("visible [payload]", config)
    helpers._print_agent_output("<think>secret</think>", config)

    rendered = output.getvalue()
    assert "visible [payload]" in rendered
    assert "hidden reasoning" in rendered
    assert "secret" not in rendered


def test_generate_report_selects_session_target_state_then_empty_session(
    monkeypatch, tmp_path
):
    import vulnclaw.report.generator as report_generator
    import vulnclaw.target_state.store as target_store

    calls: list[tuple] = []
    saved_state = object()
    current_session = SimpleNamespace(findings=[object()], executed_steps=[], notes=[])

    def fake_generate(session, output_path=None, report_format="markdown"):
        calls.append(("session", session, output_path, report_format))
        return tmp_path / "session.md"

    def fake_generate_saved(state, output_path=None):
        calls.append(("saved", state, output_path))
        return tmp_path / "saved.md"

    monkeypatch.setattr(report_generator, "generate_report", fake_generate)
    monkeypatch.setattr(
        report_generator, "generate_report_from_target_state", fake_generate_saved
    )
    monkeypatch.setattr(target_store, "load_target_state", lambda target: saved_state)

    assert helpers._generate_report_for_target(
        "example.com",
        current_session=current_session,
        report_format="json",
        output_path="custom.json",
    ).endswith("session.md")
    assert helpers._generate_report_for_target(
        "example.com", output_path="saved.md"
    ).endswith("saved.md")

    monkeypatch.setattr(target_store, "load_target_state", lambda target: None)
    assert helpers._generate_report_for_target("new.example").endswith("session.md")

    assert calls[0] == ("session", current_session, "custom.json", "json")
    assert calls[1] == ("saved", saved_state, "saved.md")
    assert calls[2][0] == "session"
    assert calls[2][1].target == "new.example"


def test_constraint_compatibility_falls_back_to_legacy_signature(monkeypatch):
    def legacy(prompt, only_port, only_host, only_path):
        return f"{prompt}:{only_port}:{only_host}:{only_path}"

    monkeypatch.setattr(helpers, "_append_cli_constraints", legacy)

    assert helpers._append_cli_constraints_compat(
        "scan", 443, "example.com", "/admin", "blocked.example", "/private"
    ) == "scan:443:example.com:/admin"


def test_constraint_compatibility_does_not_hide_unrelated_type_errors(monkeypatch):
    def broken(*args):
        raise TypeError("bad value")

    monkeypatch.setattr(helpers, "_append_cli_constraints", broken)

    with pytest.raises(TypeError, match="bad value"):
        helpers._append_cli_constraints_compat("scan", None, None, None, None, None)


def test_action_constraints_cover_allowed_blocked_and_empty_inputs():
    assert helpers._append_action_constraints("scan", None, None) == "scan"
    assert helpers._append_action_constraints(
        "scan", "recon,scan", "exploit"
    ) == "scan Only allowed actions: recon,scan Blocked actions: exploit."


def test_manual_command_renders_roff_man_page():
    from vulnclaw.cli.main import app

    result = CliRunner().invoke(app, ["manual", "run", "--format", "man"])

    assert result.exit_code == 0
    assert ".TH VULNCLAW 1" in result.output
    assert ".SS run" in result.output
    assert ".SH COMMON TASK FLAGS" in result.output
    assert "\\-" in result.output


def test_manual_rejects_invalid_render_format():
    from vulnclaw.cli.manual import render_manual

    with pytest.raises(ValueError, match="text, markdown, man"):
        render_manual("html")


def test_run_stream_emits_progress_and_verified_claims(monkeypatch):
    import vulnclaw.cli.main as cli_main
    from vulnclaw.config.schema import VulnClawConfig

    config = VulnClawConfig()
    config.llm.api_key = "test-key"
    config.session.show_thinking = True
    monkeypatch.setattr(cli_main, "load_config", lambda: config)

    summary = {
        "completed": True,
        "steps": 4,
        "evidence": 2,
        "verified_claims": [
            {"id": "claim-1", "claim": "SQL injection confirmed"},
            "non-dict claims are ignored",
        ],
    }

    class FakeAgent:
        session_state = SimpleNamespace(findings=[])
        context = SimpleNamespace(
            state=SimpleNamespace(
                agent_state=SimpleNamespace(get_summary=lambda: summary)
            )
        )

        async def solve(self, prompt, **kwargs):
            sink = kwargs["stream_sink"]
            sink.on_status("working")
            sink.on_thinking_token("reason")
            sink.on_content_token("answer")
            sink.on_stream_end()
            on_event = kwargs["on_event"]
            on_event("agent_step", {"step": 4})
            on_event("error", {"error": "retryable"})
            on_event("ask_user", {"question": "continue?"})
            on_event("no_path", {"reason": "none left"})
            on_event("completed", {})
            return []

    async def fake_orchestrated(*, runner, **kwargs):
        await runner(FakeAgent(), config)
        return SimpleNamespace(summary={"findings_count": 0})

    monkeypatch.setattr(
        cli_main, "_run_cli_orchestrated_task", fake_orchestrated
    )

    result = CliRunner().invoke(cli_main.app, ["run", "example.com", "--stream"])

    assert result.exit_code == 0, result.exception
    events = [
        json.loads(line)
        for line in result.output.splitlines()
        if line.startswith("{")
    ]
    assert any(event == {"type": "reasoning", "text": "reason"} for event in events)
    assert any(event == {"type": "log", "message": "answer"} for event in events)
    assert any(event.get("message") == "turn 4" for event in events)
    assert any(event.get("status") == "goal reached" for event in events)
    complete = next(event for event in events if event["type"] == "complete")
    assert complete["result"]["findings"] == [
        {
            "id": "claim-1",
            "severity": "high",
            "title": "SQL injection confirmed",
            "target": "example.com",
        }
    ]
