"""Trusted CLI approval channel — real-TTY synchronous y/N prompts.

Installed only when both stdin and stdout are TTYs. Anything else
(headless runs, Web tasks, subagents) gets no channel and the gate refuses.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from vulnclaw.agent.exec_gate import ApprovalView, ExecutionGate, get_execution_gate

_PROMPT_WIDTH = 72


def _hr(char: str = "-") -> str:
    return char * _PROMPT_WIDTH


class CliTtyApprovalChannel:
    """Synchronous y/N prompt rendered on the controlling terminal."""

    def __init__(self) -> None:
        self._input_lock = asyncio.Lock()

    async def request_approval(self, view: ApprovalView) -> str:
        lines = [
            "",
            _hr("="),
            f"Execution approval required  [{view.kind}]  hash={view.request_hash[:12]}",
            _hr(),
        ]
        if view.cwd:
            lines.append(f"cwd: {view.cwd}")
        if view.detail:
            lines.append(f"detail: {view.detail}")
        lines.append("command/code:")
        for raw in view.display_escaped.splitlines() or ["(empty)"]:
            lines.append(f"  | {raw}")
        if view.expires_at:
            lines.append(f"expires: {view.expires_at}")
        lines.append(f"risk: {view.risk or 'executes with current user privileges'}")
        lines.append(_hr())
        print("\n".join(lines), file=sys.stdout, flush=True)

        async with self._input_lock:
            try:
                answer = await asyncio.to_thread(
                    input, "Approve this execution? [y/N] "
                )
            except (EOFError, KeyboardInterrupt):
                answer = ""
        print(_hr(), file=sys.stdout, flush=True)
        return "approve" if answer.strip().lower() in {"y", "yes"} else "deny"


def tty_available() -> bool:
    """A trusted local operator can only exist on a real terminal."""
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def install_cli_approval_channel(config: Any = None) -> bool:
    """Install the TTY channel on the process gate when interactive.

    Returns True when a channel is available after the call.
    """
    gate: ExecutionGate = get_execution_gate(config)
    if not tty_available():
        return gate.has_trusted_channel()
    if not isinstance(gate.channel, CliTtyApprovalChannel):
        gate.install_channel(CliTtyApprovalChannel())

    # Legacy sync surface (report verifier PoC): reuse the same prompt.
    def _sync_confirm(view: ApprovalView) -> bool:
        if not tty_available():
            return False
        channel = CliTtyApprovalChannel()
        decision = asyncio.new_event_loop().run_until_complete(
            channel.request_approval(view)
        )
        return decision == "approve"

    gate.install_sync_confirm_hook(_sync_confirm)
    return True
