"""CLI shared helper functions."""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from rich.console import Console
from rich.text import Text

from vulnclaw import __version__
from vulnclaw.config.text_utils import format_think_tags, strip_think_tags
from vulnclaw.i18n import _

console = Console()
err_console = Console(stderr=True)

TERMINAL_TOOL_RESULT_PREVIEW_CHARS = 1200
TUI_EVENT_STREAM_ENV = "VULNCLAW_TUI_EVENT_STREAM"
TUI_EVENT_TOKEN_ENV = "VULNCLAW_TUI_EVENT_TOKEN"
TUI_EVENT_PREFIX = "__VULNCLAW_TUI_EVENT__:"


@dataclass(frozen=True)
class SubagentTuiEvent:
    kind: str
    payload: dict[str, Any]


def _emit_tui_event(
    target_console: Any,
    kind: str,
    payload: dict[str, Any],
    environ: Mapping[str, str],
) -> None:
    token = environ.get(TUI_EVENT_TOKEN_ENV, "")
    if (
        environ.get(TUI_EVENT_STREAM_ENV) != "1"
        or not token
        or not kind.startswith("group_")
    ):
        return
    envelope = json.dumps(
        {"kind": kind, "payload": payload},
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    target_console.file.write(f"{TUI_EVENT_PREFIX}{token}:{envelope}\n")
    target_console.file.flush()


def _parse_tui_solve_event(
    line: str, *, expected_token: str
) -> SubagentTuiEvent | None:
    raw = str(line or "").rstrip("\r\n")
    event_prefix = f"{TUI_EVENT_PREFIX}{expected_token}:"
    if not expected_token or not raw.startswith(event_prefix):
        return None
    try:
        envelope = json.loads(raw[len(event_prefix) :])
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(envelope, dict):
        return None
    kind = str(envelope.get("kind") or "")
    payload = envelope.get("payload")
    if not kind.startswith("group_") or not isinstance(payload, dict):
        return None
    return SubagentTuiEvent(kind=kind, payload=payload)


def _group_console_projection(
    kind: str,
    payload: dict[str, Any],
) -> tuple[str, str, str] | None:
    if not kind.startswith("group_"):
        return None
    group_id = str(payload.get("group_id") or "?")
    phase = str(
        payload.get("phase") or kind.removeprefix("group_")
    ).replace("_", " ")
    status = str(payload.get("status") or "")
    details: list[str] = []
    member_total = int(payload.get("member_total") or 0)
    member_done = int(payload.get("member_done") or 0)
    if member_total:
        details.append(f"members {member_done}/{member_total}")
    wave_count = int(payload.get("wave_count") or 0)
    if wave_count:
        details.append(f"waves {wave_count}")
    evidence_count = int(payload.get("evidence_count") or 0)
    if evidence_count:
        details.append(f"evidence {evidence_count}")
    member_task_id = str(payload.get("member_task_id") or "")
    if member_task_id:
        details.insert(
            0,
            f"member {member_task_id}={payload.get('member_status') or 'unknown'}",
        )
    member_error = str(payload.get("member_error") or "")
    if member_error:
        details.insert(0, member_error)
    conclusion = str(payload.get("conclusion") or "").strip()
    goal = str(payload.get("goal") or "").strip()
    detail = " · ".join(item for item in [conclusion, *details] if item)
    if not detail and kind == "group_created":
        detail = goal
    label = (
        status
        if status
        and kind in {"group_finished", "group_cancelled", "group_failed"}
        else phase
    )
    style = (
        "green"
        if status in {"verified", "completed"}
        else "red"
        if status == "failed"
        else "yellow"
        if status in {"cancelled", "budget_exhausted", "no_path"}
        else "magenta"
    )
    return f"◈ [{group_id}] {label}: ", detail, style


def _collapse_terminal_text(text: str, limit: int = TERMINAL_TOOL_RESULT_PREVIEW_CHARS) -> tuple[str, bool]:
    """Return a human-sized terminal preview without changing model-visible content."""

    value = str(text or "")
    if limit <= 0 or len(value) <= limit:
        return value, False
    marker = f"\n...[terminal preview collapsed {len(value) - limit} chars]...\n"
    head = max(1, int(limit * 0.7))
    tail = max(1, limit - head)
    return f"{value[:head].rstrip()}{marker}{value[-tail:].lstrip()}", True


def _extract_evidence_id(text: str) -> str:
    match = re.search(r"\[evidence:(e\d+)\]", str(text or ""))
    return match.group(1) if match else ""


def _print_styled_plain(console_obj: Console, prefix: str, body: str, *, style: str = "dim") -> None:
    """Print dynamic text as Rich Text so payloads are never parsed as markup."""

    rendered = Text(prefix, style=style)
    rendered.append(str(body or ""))
    console_obj.print(rendered, soft_wrap=True)


def _emit_tui_solve_event(
    target_console: Console, kind: str, payload: dict[str, Any]
) -> None:
    _emit_tui_event(target_console, kind, payload, os.environ)


class TerminalStreamSink:
    """CLI terminal stream renderer."""

    def __init__(self, console: Console, show_thinking: bool = False) -> None:
        self._console = console
        self._show_thinking = show_thinking
        self._status_printed = False

    def on_status(self, message: str) -> None:
        self._console.print(Text(f"{message} ", style="dim"), end="", soft_wrap=True)
        self._status_printed = True

    def on_thinking_token(self, token: str) -> None:
        if self._show_thinking:
            self._console.print(Text(str(token or ""), style="dim italic"), end="", soft_wrap=True)

    def on_content_token(self, token: str) -> None:
        if self._status_printed:
            self._console.print()
            self._status_printed = False
        self._console.print(Text(str(token or "")), end="", soft_wrap=True)

    def on_tool_call(self, tool_name: str, args: str) -> None:
        self._console.print()
        call_text = Text(f"{_('cli.tool_calling')} {tool_name} ", style="bold cyan")
        call_text.append(str(args or "")[:100])
        self._console.print(call_text, soft_wrap=True)
        self._status_printed = False

    def on_tool_result(self, result_summary: str) -> None:
        self._console.print()
        preview, collapsed = _collapse_terminal_text(result_summary)
        if collapsed:
            evidence_id = _extract_evidence_id(result_summary)
            hint = (
                f"\n[terminal-only preview: {len(preview)}/{len(str(result_summary or ''))} chars shown; "
                "full output is stored as evidence"
            )
            if evidence_id:
                hint += f"; saved as {evidence_id}, use evidence_search/evidence_view to revisit"
            hint += "]"
            preview = f"{preview}{hint}"
        _print_styled_plain(self._console, _("cli.tool_result"), preview)

    def on_stream_end(self) -> None:
        self._status_printed = False
        self._console.print()


class JsonlStreamSink:
    """Rust ratatui TUI protocol stream sink (newline-delimited JSON).

    Emits the same event vocabulary the ``vulnclaw-tui-native`` workbench
    parses: ``status`` / ``log`` / ``reasoning`` lines on stdout. Findings are
    delivered by the caller in the final ``complete`` event (VulnClaw records
    evidence, not a live finding stream).
    """

    def __init__(self, stream: Any = None, show_thinking: bool = False) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._show_thinking = show_thinking
        self._status_printed = False
        # Token buffers: LLM streaming emits thinking/content one delta at a
        # time (often a single word). Accumulate them and flush whole chunks so
        # the TUI renders one coherent paragraph per `reasoning`/`log` event
        # instead of one line per token.
        self._thinking_buffer = ""
        self._content_buffer = ""

    def _emit(self, event: dict) -> None:
        self._stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        self._stream.flush()

    def _flush_thinking(self) -> None:
        if self._thinking_buffer:
            if self._show_thinking:
                self._emit({"type": "reasoning", "text": self._thinking_buffer})
            self._thinking_buffer = ""

    def _flush_content(self) -> None:
        if self._content_buffer:
            self._emit({"type": "log", "message": self._content_buffer})
            self._content_buffer = ""
            self._status_printed = False

    def _flush_all(self) -> None:
        self._flush_thinking()
        self._flush_content()

    def on_status(self, message: str) -> None:
        self._flush_all()
        self._emit({"type": "status", "status": str(message or "")})
        self._status_printed = True

    def on_thinking_token(self, token: str) -> None:
        if not token:
            return
        # Thinking and content never interleave mid-stream from the LLM, but
        # flush the other buffer first so ordering stays correct if they do.
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
        self._emit({"type": "log", "message": f"→ tool: {tool_name} {str(args or '')[:100]}"})
        self._status_printed = False

    def on_tool_result(self, result_summary: str) -> None:
        self._flush_all()
        preview, _collapsed = _collapse_terminal_text(result_summary)
        self._emit({"type": "log", "message": f"→ result: {preview}"})

    def on_stream_end(self) -> None:
        self._flush_all()
        self._status_printed = False


def emit_complete_event(
    stream: Any,
    *,
    summary: str,
    findings: list[dict[str, Any]],
) -> None:
    """Emit the terminal ``complete`` event of the Rust TUI protocol."""
    stream.write(
        json.dumps(
            {"type": "complete", "summary": summary, "result": {"findings": findings}},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    stream.flush()


ASCII_LOGO = (
    " _    __      __      ________\n"
    "| |  / /_  __/ /___  / ____/ /___ __      __\n"
    "| | / / / / / / __ \\/ /   / / __ `/ | /| / /\n"
    "| |/ / /_/ / / / / / /___/ / /_/ /| |/ |/ /\n"
    "|___/\\__,_/_/_/ /_/\\____/_/\\__,_/ |__/|__/\n"
)

BANNER_SUBTITLE = f"VulnClaw v{__version__} - AI-powered penetration testing CLI"


def _print_banner() -> None:
    """Print the VulnClaw ASCII banner."""

    console.print(Text(ASCII_LOGO, style="bold red"))
    console.print(Text(BANNER_SUBTITLE))
    console.print()


def _print_agent_output(output: str, config: Any) -> None:
    """Print agent output with think-tag filtering based on config."""

    from rich.markup import escape as rich_escape

    formatted = format_think_tags(output, show=config.session.show_thinking)
    if formatted:
        console.print(rich_escape(formatted))
    elif not config.session.show_thinking:
        stripped = strip_think_tags(output)
        if (stripped != output) and not stripped:
            console.print("[dim](LLM returned only hidden reasoning and no visible answer.)[/dim]")


def _make_solve_event_printer(target_console: Console) -> Any:
    """Return an on_event callback that prints model-led solve progress."""

    def on_event(kind: str, payload: dict) -> None:
        _emit_tui_solve_event(target_console, kind, payload)
        if projection := _group_console_projection(kind, payload):
            prefix, detail, style = projection
            _print_styled_plain(
                target_console,
                prefix,
                detail,
                style=style,
            )
        elif kind == "agent_step":
            target_console.print(f"[cyan]◆ Turn {payload.get('step', '?')}[/cyan]")
        elif kind == "agent_observation":
            reason = payload.get("reason") or _("cli.auto_continue")
            tools = ", ".join(payload.get("tools") or []) or _("cli.none_short")
            evidence = (payload.get("evidence") or "").strip()
            _print_styled_plain(target_console, _("cli.reason"), str(reason)[:120], style="yellow")
            _print_styled_plain(target_console, _("cli.tools"), tools, style="magenta")
            if evidence:
                _print_styled_plain(target_console, _("cli.evidence"), evidence[:220], style="green")
        elif kind == "completed":
            target_console.print(f"[green]{_('cli.goal_completed')}[/green]")
        elif kind == "complete_rejected":
            _print_styled_plain(target_console, _("cli.complete_rejected"), str(payload.get("reason", ""))[:90], style="red")
        elif kind == "ask_user":
            _print_styled_plain(target_console, _("cli.ask_user"), str(payload.get("question", ""))[:160], style="yellow")
        elif kind == "no_path":
            _print_styled_plain(target_console, _("cli.no_path"), str(payload.get("reason", ""))[:160], style="yellow")
        elif kind == "error":
            _print_styled_plain(target_console, "error: ", str(payload.get("error", ""))[:160], style="red")

    return on_event


def _generate_report_for_target(
    target: str,
    *,
    current_session: Any = None,
    report_format: str = "markdown",
    output_path: Optional[str] = None,
) -> str:
    """Generate a report for a target using the best available source data."""

    from vulnclaw.agent.context import SessionState
    from vulnclaw.report.generator import generate_report, generate_report_from_target_state
    from vulnclaw.target_state.store import load_target_state

    if current_session is not None and (
        current_session.findings or current_session.executed_steps or current_session.notes
    ):
        path = generate_report(current_session, output_path, report_format=report_format)
        return str(path)

    state = load_target_state(target)
    if state:
        path = generate_report_from_target_state(state, output_path=output_path)
        return str(path)

    session = SessionState(target=target)
    path = generate_report(session, output_path, report_format=report_format)
    return str(path)


def _append_cli_constraints(
    prompt: str,
    only_port: Optional[int],
    only_host: Optional[str],
    only_path: Optional[str],
    blocked_host: Optional[str] = None,
    blocked_path: Optional[str] = None,
) -> str:
    """Append scope constraints to the task prompt."""

    constraints = []
    if only_port is not None:
        constraints.append(f"Only test port {only_port}")
    if only_host:
        constraints.append(f"Only test host {only_host}")
    if only_path:
        constraints.append(f"Only test path {only_path}")
    if blocked_host:
        constraints.append(f"Blocked host {blocked_host}")
    if blocked_path:
        constraints.append(f"Blocked path {blocked_path}")
    if not constraints:
        return prompt
    return f"{prompt} {' '.join(constraints)}."


def _append_cli_constraints_compat(
    prompt: str,
    only_port: Optional[int],
    only_host: Optional[str],
    only_path: Optional[str],
    blocked_host: Optional[str],
    blocked_path: Optional[str],
) -> str:
    """Append scope constraints while preserving older monkeypatch call shapes."""

    try:
        return _append_cli_constraints(
            prompt, only_port, only_host, only_path, blocked_host, blocked_path
        )
    except TypeError as exc:
        if "positional" not in str(exc) and "argument" not in str(exc):
            raise
        return _append_cli_constraints(prompt, only_port, only_host, only_path)


def _append_action_constraints(
    prompt: str, allow_actions: Optional[str], block_actions: Optional[str]
) -> str:
    """Append action constraints to the task prompt."""

    constraints = []
    if allow_actions:
        constraints.append(f"Only allowed actions: {allow_actions}")
    if block_actions:
        constraints.append(f"Blocked actions: {block_actions}")
    if not constraints:
        return prompt
    return f"{prompt} {' '.join(constraints)}."


async def _run_cli_orchestrated_task(
    *,
    command: str,
    target: str,
    resume: bool,
    snapshot: Optional[str],
    runner: Any,
    **run_context: Any,
) -> Any:
    """Run a CLI task through the shared orchestrator helpers."""

    from vulnclaw.agent.core import AgentCore
    from vulnclaw.cli.approval_channel import install_cli_approval_channel
    from vulnclaw.config.settings import load_config
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager
    from vulnclaw.orchestrator import run_agent_task

    config = load_config()
    install_cli_approval_channel(config)
    mcp_manager = MCPLifecycleManager(config)
    mcp_manager.start_enabled_servers()
    agent = AgentCore(config, mcp_manager)

    try:
        def on_restored(restore_result: Any) -> None:
            console.print(
                f"[*] Restored saved target state: [bold]{restore_result.target or target}[/]"
            )

        return await run_agent_task(
            agent=agent,
            command=command,
            target=target,
            resume=resume,
            snapshot_id=snapshot,
            on_restored=on_restored,
            runner=lambda shared_agent: runner(shared_agent, config),
            **run_context,
        )
    finally:
        import signal

        signal.signal(signal.SIGINT, signal.SIG_IGN)
        mcp_manager.stop_all()
