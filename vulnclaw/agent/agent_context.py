"""The typed seam between :class:`~vulnclaw.agent.core.AgentCore` and its helpers.

Helper modules (``loop_controller``, ``llm_client``, ``builtin_tools``,
``solver``, ``recon_tools`` …) are handed the agent and reach into its state and
a handful of its methods. Historically that handle was typed ``agent: Any``,
which hid the real contract and let the seam leak. :class:`AgentContext` names
that contract exactly: the members those helpers actually touch, and nothing
more.

The protocol is deliberately faithful to the surface as it stands today —
including the underscore-prefixed callbacks (``_get_client``,
``_execute_mcp_tool`` …) that helpers still lean on. Those are internal agent
machinery a helper reaches back into; typing them honestly documents the
coupling rather than hiding it. Giving them real public homes is a later,
larger change (extracting a concrete context object / role-specific ports), not
part of hardening this seam.

This module imports neither ``core`` nor the helpers, so it can be referenced
from either side without an import cycle. The concrete types below are only
needed for annotations, so they live under ``TYPE_CHECKING``; with
``from __future__ import annotations`` every annotation is a lazy string and is
never resolved at runtime. ``@runtime_checkable`` therefore verifies member
*presence* (which is what the conformance test asserts), not signatures.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from vulnclaw.agent.context import ContextManager, PentestPhase, SessionState
    from vulnclaw.agent.llm_client import StreamSink
    from vulnclaw.agent.response_observations import ResponseObservationParser
    from vulnclaw.agent.runtime_state import AgentResult, RuntimeState
    from vulnclaw.agent.subagent.models import SubagentContext
    from vulnclaw.config.schema import VulnClawConfig


@runtime_checkable
class AgentContext(Protocol):
    """The surface a helper module may rely on when handed the agent.

    Any object passed to a helper as ``agent`` is expected to satisfy this
    protocol. :class:`~vulnclaw.agent.core.AgentCore` satisfies it structurally;
    a ``test_agent_context_protocol`` conformance test guards against drift.
    Focused test doubles are intentionally *not* required to conform — they may
    implement only the slice their unit under test exercises.
    """

    # ── Data the helpers read (and, for runtime/context, mutate) ──────────
    runtime: RuntimeState
    context: ContextManager
    config: VulnClawConfig
    mcp_manager: Any
    active_role: str | None
    _observation_parser: ResponseObservationParser
    _kb_retriever: Any
    _kb_context_cache: dict[Any, str]
    _subagent_ctx: SubagentContext

    @property
    def session_state(self) -> SessionState:
        """The current session state (shorthand for ``context.state``)."""
        ...

    # ── LLM client / credential plumbing ─────────────────────────────────
    def _get_client(self) -> Any:
        """Return the lazily-built, credential-resolved LLM client."""
        ...

    def _child_factory(self) -> AgentContext:
        """Build a fresh isolated child agent."""
        ...

    def rotate_api_key(self) -> bool:
        """Advance to the next key in the failover pool; ``False`` if none."""
        ...

    # ── Tool + prompt construction the helpers call back into ────────────
    def _build_openai_tools(self) -> list[dict]:
        """Assemble the OpenAI function-calling schema (MCP + built-in)."""
        ...

    async def _execute_mcp_tool(self, tool_name: str, args: dict) -> str:
        """Execute a tool via the MCP manager or the built-in tools."""
        ...

    def _build_system_prompt(
        self,
        target: Optional[str] = None,
        auto_mode: bool = False,
        user_input: Optional[str] = None,
    ) -> str:
        """Build the dynamic system prompt for the current turn."""
        ...

    def _build_round_context(self, round_num: int, max_rounds: int) -> str:
        """Build the per-round context string for the auto loop."""
        ...

    # ── Input / output analysis callbacks ────────────────────────────────
    def _detect_target(self, user_input: str) -> Optional[str]:
        """Extract a target from user input, if any."""
        ...

    def _detect_phase(self, user_input: str) -> Optional[PentestPhase]:
        """Detect the pentest phase implied by user input."""
        ...

    def _detect_phase_from_output(self, output: str) -> Optional[PentestPhase]:
        """Detect a phase-transition signal in LLM output."""
        ...

    def _detect_attack_path(self, output: str) -> Optional[str]:
        """Detect the canonical attack path/technique in LLM output."""
        ...

    def _is_meaningful_step(self, step: str) -> bool:
        """Whether a step represents real progress (not a pure failure)."""
        ...

    def _is_completion_signal(self, output: str) -> bool:
        """Whether LLM output signals task completion."""
        ...

    def _track_failed_target(self, response_text: str) -> Optional[str]:
        """Record target-level failures; return a blocked hostname if any."""
        ...

    def _update_recon_dimension_completion(self, response: str) -> None:
        """Auto-detect which recon dimensions have been explored."""
        ...

    async def _generate_attack_summary(self) -> str:
        """Generate the attack-chain narrative for a cycle report."""
        ...

    # ── Runtime / reflexion lifecycle ────────────────────────────────────
    def _reset_runtime_state(
        self,
        user_input: str = "",
        detected_phase: Optional[PentestPhase] = None,
    ) -> None:
        """Reset per-run runtime state to avoid cross-run contamination."""
        ...

    def _save_reflexion_snapshot(self) -> None:
        """Persist the current reflexion state onto the session snapshot."""
        ...

    # ── Loop entry point some helpers re-enter ───────────────────────────
    async def auto_pentest(
        self,
        user_input: str,
        target: Optional[str] = None,
        max_rounds: int = 15,
        on_step: Optional[Callable[[int, AgentResult], None]] = None,
        *,
        stream_sink: Optional[StreamSink] = None,
    ) -> list[AgentResult]:
        """Run the autonomous penetration-test loop."""
        ...
