"""ExecutionGate — per-request operator approval for dangerous tools.

C-1/C-2 fix, lightweight edition: dangerous tools stay registered (they are
the agent's core capability), but every spawn request is bound to one
explicit operator decision. There is deliberately no session-level allow,
no prefix wildcards and no grant tokens: a decision approves exactly one
canonical request, identified by the SHA-256 of its full content.

Trusted channels are installed by the local control plane only:

- interactive CLI/REPL on a real TTY (synchronous y/N prompt);
- native TUI via the ``execution.approval.resolve`` control operation;
- an optional synchronous confirm hook for legacy sync callers
  (report verifier) that cannot await.

Model text, tool results and MCP returns can never resolve a pending
request. Without any channel the gate refuses with a stable error.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

# ── Display escaping ─────────────────────────────────────────────────────

_BIDI_RANGES = (
    (0x202A, 0x202E),
    (0x2066, 0x2069),
    (0x200E, 0x200F),
    (0x061C, 0x061C),
)
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}


def visualize_for_display(text: str) -> str:
    """Render untrusted text safely: control/bidi/zero-width chars escaped."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char in ("\t", "\n"):
            out.append(char)
        elif code == 0x1B or code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            out.append(f"\\u{code:04x}")
        elif code in _ZERO_WIDTH or any(lo <= code <= hi for lo, hi in _BIDI_RANGES):
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    return "".join(out)


def visualize_single_line_for_display(text: str) -> str:
    """Escape untrusted text that must not create extra terminal rows."""
    return visualize_for_display(text).replace("\t", "\\t").replace("\n", "\\n")


# ── Request / view ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class GateRequest:
    """One canonical, content-addressed execution request."""

    kind: str  # "shell" | "python" | "php_diff" | "poc"
    display: str  # raw command or source code
    cwd: str = ""
    detail: str = ""  # extra context shown under the command
    # Model self-assessment (codex on-request style). One-way escalation
    # only: "review" forces the human path even for allowlisted commands;
    # it can never downgrade a prompt-class command.
    model_risk: str = ""  # "" | "safe" | "review"
    model_reason: str = ""

    def request_hash(self) -> str:
        payload = json.dumps(
            {
                "kind": self.kind,
                "display": self.display,
                "cwd": self.cwd,
                "detail": self.detail,
                "model_risk": self.model_risk,
                "model_reason": self.model_reason,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalView:
    """Operator-facing description of one pending request."""

    request_hash: str
    kind: str
    display_escaped: str
    cwd: str
    detail: str
    expires_at: str
    expires_in_seconds: int
    risk: str = ""

    def to_event_payload(self) -> dict[str, Any]:
        return {
            "request_hash": self.request_hash,
            "kind": self.kind,
            "question": self.display_escaped,
            "cwd": self.cwd,
            "detail": self.detail,
            "expires_at": self.expires_at,
            "expires_in_seconds": self.expires_in_seconds,
            "risk": self.risk,
        }


class TrustedApprovalChannel(Protocol):
    async def request_approval(self, view: ApprovalView) -> str:
        """Return "approve" or "deny"."""
        ...


SyncConfirmHook = Any  # Callable[[ApprovalView], bool] for legacy sync callers


# ── Outcome ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class GateOutcome:
    approved: bool
    status: str  # approved|denied|expired|cancelled|no_channel|already_pending|channel_error
    message: str = ""  # model-visible refusal text when not approved

    def refusal_text(self, tool_label: str) -> str:
        if self.message:
            return f"[!] {tool_label} execution refused ({self.status}): {self.message}"
        return f"[!] {tool_label} execution refused ({self.status})."


class _Pending:
    __slots__ = ("view", "future", "state")

    def __init__(self, view: ApprovalView) -> None:
        self.view = view
        self.future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self.state = "pending"


# ── The gate ─────────────────────────────────────────────────────────────


class ExecutionGate:
    VALID_MODES = ("ask", "auto_review", "full_access")

    def __init__(
        self,
        timeout_seconds: int = 300,
        *,
        mode: str = "ask",
        trusted_commands: tuple[tuple[str, ...], ...] = (),
    ) -> None:
        self.timeout_seconds = max(1, int(timeout_seconds))
        if mode not in self.VALID_MODES:
            raise ValueError(f"invalid permission mode: {mode!r}")
        self.mode: str = mode
        self.trusted_commands = tuple(trusted_commands)
        self.channel: TrustedApprovalChannel | None = None
        self.sync_confirm_hook: SyncConfirmHook | None = None
        self._lock = asyncio.Lock()
        self._approval_lock = asyncio.Lock()
        self._inflight_hashes: set[str] = set()
        self._pending_by_hash: dict[str, _Pending] = {}
        self.stats: dict[str, int] = {
            "requested": 0,
            "approved": 0,
            "denied": 0,
            "expired": 0,
            "cancelled": 0,
        }

    # ── Control plane wiring ─────────────────────────────────────────────

    def install_channel(self, channel: TrustedApprovalChannel) -> None:
        self.channel = channel

    def uninstall_channel(self) -> None:
        self.channel = None
        self.expire_all_pending("cancelled")

    def has_trusted_channel(self) -> bool:
        return self.channel is not None or self.sync_confirm_hook is not None

    def install_sync_confirm_hook(self, hook: SyncConfirmHook) -> None:
        self.sync_confirm_hook = hook

    # ── Mode management ──────────────────────────────────────────────────

    def set_mode(self, mode: str, *, source: str = "local") -> str:
        """Switch the active policy. Validation only — nothing is recorded."""
        normalized = str(mode or "").strip().lower()
        if normalized not in self.VALID_MODES:
            raise ValueError(
                f"invalid permission mode {mode!r}; expected one of {', '.join(self.VALID_MODES)}"
            )
        self.mode = normalized
        return self.mode

    async def _notify_closed(self, request_hash: str, status: str) -> None:
        """Tell the channel the pending left the queue (modal cleanup hook).

        Active channels (CLI y/N) have no use for it; the passive TUI channel
        uses it to dismiss the blocking modal on expiry/cancellation.
        """
        closer = getattr(self.channel, "notify_closed", None)
        if closer is None:
            return
        try:
            await closer(request_hash=request_hash, status=status)
        except Exception:
            return

    # ── Resolution from trusted control ops ──────────────────────────────

    async def resolve(self, request_hash: str, decision: str) -> dict[str, str]:
        """Apply a trusted decision. Idempotent; hash-keyed; status-only.

        ``request_hash`` is the sole correlation key: identical concurrent
        requests are deduped into one pending, so the hash uniquely
        identifies a live request without any receipt number.
        """
        normalized = str(decision or "").strip().lower()
        if normalized not in ("approve", "deny"):
            return {"status": "invalid_decision"}
        async with self._lock:
            pending = self._pending_by_hash.get(request_hash)
            if pending is None:
                return {"status": "unknown_request"}
            if pending.state != "pending" or pending.future.done():
                return {"status": "already_resolved"}
            pending.state = "approved" if normalized == "approve" else "denied"
            pending.future.set_result(normalized)
            return {"status": "resolved"}

    def expire_all_pending(self, reason: str = "expired") -> int:
        count = 0
        for pending in list(self._pending_by_hash.values()):
            if pending.state == "pending" and not pending.future.done():
                pending.state = reason
                pending.future.set_result("deny")
                count += 1
        return count

    async def wait_decision(self, request_hash: str) -> str:
        """Await the trusted resolution of one pending request.

        Passive channels (native TUI control path) emit the approval event
        and then await here; ``resolve()`` completes the future. Returns
        "deny" if the pending vanished (expired/cancelled first).
        """
        async with self._lock:
            pending = self._pending_by_hash.get(request_hash)
            if pending is None or pending.state != "pending":
                return "deny"
            future = pending.future
        return await asyncio.shield(future)

    # ── Model-facing entry ───────────────────────────────────────────────

    async def authorize(self, request: GateRequest, *, run_id: str = "") -> GateOutcome:
        self.stats["requested"] += 1

        # ── full_access: everything runs unattended ──────────────────────
        if self.mode == "full_access":
            return GateOutcome(True, "approved")

        # ── auto_review: Codex-style command classification ───────────────
        # Shell commands matching the read-only table or operator trusted
        # prefixes run unattended; everything else degrades to the normal
        # per-request approval flow (interactive channel or stable refusal).
        # Non-shell kinds (python/php/poc) are interpreters by definition and
        # always take the approval path in this mode.
        #
        # Model self-assessment rides on top, one-way only: a "review" tag
        # forces the human path even for allowlisted commands. A "safe" tag
        # is ignored — the local classifier remains the sole authority for
        # running without approval.
        flagged_review = request.model_risk == "review"
        classifier_reason = ""
        if self.mode == "auto_review" and request.kind == "shell" and not flagged_review:
            from vulnclaw.agent.command_classifier import classify_shell_command

            verdict = classify_shell_command(request.display, self.trusted_commands)
            if verdict.decision == "allow":
                return GateOutcome(True, "approved")
            classifier_reason = verdict.reason

        notes: list[str] = []
        if flagged_review:
            notes.append(
                "model self-assessment: needs review"
                + (f"\n{request.model_reason}" if request.model_reason else "")
            )
        if classifier_reason:
            notes.append(classifier_reason)
        if notes and self.mode != "full_access":
            extra = " | ".join(notes)
            request = replace(
                request,
                detail=f"{request.detail} | {extra}" if request.detail else extra,
            )
            # fall through to the interactive flow below

        if self.channel is None:
            return GateOutcome(
                False,
                "no_channel",
                message=(
                    "no trusted approval channel is installed. Run interactively "
                    "(CLI/TUI) to approve executions, or configure "
                    "safety.permission_mode explicitly."
                ),
            )

        request_hash = request.request_hash()

        async with self._lock:
            if request_hash in self._inflight_hashes:
                return GateOutcome(
                    False,
                    "already_pending",
                    message=(
                        "an identical request is already awaiting approval; "
                        f"command: {request.display[:80]}"
                    ),
                )
            self._inflight_hashes.add(request_hash)

        pending: _Pending | None = None
        try:
            async with self._approval_lock:
                # The channel may have been removed while this request waited
                # behind another approval. Re-check immediately before exposing
                # the request and fail closed without starting a stale timeout.
                channel = self.channel
                if channel is None:
                    return GateOutcome(
                        False,
                        "no_channel",
                        message=(
                            "no trusted approval channel is installed. Run interactively "
                            "(CLI/TUI) to approve executions, or configure "
                            "safety.permission_mode explicitly."
                        ),
                    )

                view = ApprovalView(
                    request_hash=request_hash,
                    kind=request.kind,
                    display_escaped=visualize_for_display(request.display),
                    cwd=visualize_single_line_for_display(request.cwd),
                    detail=visualize_for_display(request.detail),
                    expires_at=(
                        datetime.now(timezone.utc) + timedelta(seconds=self.timeout_seconds)
                    ).isoformat(timespec="seconds"),
                    expires_in_seconds=self.timeout_seconds,
                    risk="Executes with current user privileges; not sandboxed.",
                )
                pending = _Pending(view)
                async with self._lock:
                    self._pending_by_hash[request_hash] = pending

                decision: str | None = None
                try:
                    decision = await asyncio.wait_for(
                        channel.request_approval(view), timeout=self.timeout_seconds
                    )
                except asyncio.TimeoutError:
                    decision = "expired"
                except asyncio.CancelledError:
                    await self._settle(pending, request_hash, "cancelled")
                    self.stats["cancelled"] += 1
                    await self._notify_closed(request_hash, "cancelled")
                    raise
                except Exception as exc:  # channel malfunction must never auto-approve
                    await self._settle(pending, request_hash, "cancelled")
                    self.stats["cancelled"] += 1
                    await self._notify_closed(request_hash, "cancelled")
                    return GateOutcome(
                        False,
                        "channel_error",
                        message=f"approval channel failed: {exc.__class__.__name__}",
                    )

                # A resolution applied through gate.resolve() is authoritative
                # for passive channels. Active channels settle from their return
                # value. Either path updates the same pending before cleanup.
                async with self._lock:
                    if pending.state == "pending":
                        pending.state = {
                            "approve": "approved",
                            "deny": "denied",
                        }.get(str(decision), "expired")
                    status = pending.state
                self.stats[status] = self.stats.get(status, 0) + 1
                await self._notify_closed(request_hash, status)
                if status != "approved":
                    return GateOutcome(False, status)
                return GateOutcome(True, "approved")
        finally:
            async with self._lock:
                if pending is not None and self._pending_by_hash.get(request_hash) is pending:
                    self._pending_by_hash.pop(request_hash, None)
                self._inflight_hashes.discard(request_hash)

    async def _settle(self, pending: _Pending, request_hash: str, state: str) -> None:
        async with self._lock:
            if pending.state == "pending" and not pending.future.done():
                pending.state = state
                pending.future.set_result("deny")
            self._pending_by_hash.pop(request_hash, None)

    # ── Legacy synchronous bridge (report verifier) ──────────────────────

    def confirm_sync(self, request: GateRequest) -> bool:
        """Synchronous confirmation for callers that cannot await.

        Full-access mode returns immediately. Other modes use the sync confirm
        hook when installed and refuse inside a running loop rather than
        blocking it.
        """
        if self.mode == "full_access":
            return True
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            return False  # inside a running loop: refuse rather than deadlock
        hook = self.sync_confirm_hook
        if hook is None:
            return False
        view = ApprovalView(
            request_hash=request.request_hash(),
            kind=request.kind,
            display_escaped=visualize_for_display(request.display),
            cwd=visualize_single_line_for_display(request.cwd),
            detail=visualize_for_display(request.detail),
            expires_at="(sync)",
            expires_in_seconds=self.timeout_seconds,
            risk="Executes with current user privileges; not sandboxed.",
        )
        try:
            return bool(hook(view))
        except Exception:
            return False


# ── Process-level singleton ──────────────────────────────────────────────

_default_gate: ExecutionGate | None = None


def get_execution_gate(config: Any = None) -> ExecutionGate:
    """Return the process-wide gate, creating it with config-derived settings."""
    global _default_gate
    if _default_gate is None:
        timeout = 300
        mode = "ask"
        trusted: tuple[tuple[str, ...], ...] = ()
        warnings: list[str] = []
        safety = getattr(config, "safety", None)
        if safety is not None:
            timeout = int(getattr(safety, "approval_timeout_seconds", 300) or 300)
            mode = str(getattr(safety, "permission_mode", "ask") or "ask").strip().lower()
            from vulnclaw.agent.command_classifier import parse_trusted_commands

            trusted, warnings = parse_trusted_commands(
                list(getattr(safety, "trusted_commands", []) or [])
            )
        try:
            _default_gate = ExecutionGate(
                timeout_seconds=timeout,
                mode=mode,
                trusted_commands=trusted,
            )
        except ValueError:
            # Unknown persisted value: fail safe to per-request approval.
            _default_gate = ExecutionGate(timeout_seconds=timeout)
        if warnings:
            import sys

            for warning in warnings:
                print(f"[!] {warning}", file=sys.stderr)
    return _default_gate


def reset_execution_gate() -> None:
    """Test helper: drop the singleton so tests get a fresh gate."""
    global _default_gate
    _default_gate = None
