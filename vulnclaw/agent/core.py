"""VulnClaw Agent Core — the main AI agent loop with tool calling."""

from __future__ import annotations

from typing import Any, Callable, Optional

from vulnclaw.agent.anti_loop import (
    detect_attack_path,
    detect_phase_from_output,
    is_completion_signal,
    is_meaningful_step,
    track_failed_target,
)
from vulnclaw.agent.builtin_tools import (
    BLOCKED_PATTERNS,
    RESERVED_IP_RANGES,
    build_openai_tools,
    execute_mcp_tool,
    execute_nmap,
    execute_python,
    is_reserved_ip,
    parse_nmap_xml,
    validate_scan_target,
)
from vulnclaw.agent.context import ContextManager, PentestPhase, SessionState, TaskConstraints
from vulnclaw.agent.ctf_mode import detect_flag_claim
from vulnclaw.agent.finding_parser import FindingParser
from vulnclaw.agent.input_analysis import (
    detect_phase,
    detect_target,
    extract_task_constraints,
    extract_user_vuln_hint,
    get_payload_examples,
)
from vulnclaw.agent.kb_context import build_kb_context
from vulnclaw.agent.llm_client import StreamSink, call_llm
from vulnclaw.agent.loop_controller import auto_pentest as run_auto_pentest
from vulnclaw.agent.loop_controller import persistent_pentest as run_persistent_pentest
from vulnclaw.agent.prompt_context import build_round_context, generate_attack_summary
from vulnclaw.agent.recon_tracker import update_recon_dimension_completion
from vulnclaw.agent.runtime_state import AgentResult, PersistentCycleResult, RuntimeState
from vulnclaw.agent.skill_context import get_active_skill_context
from vulnclaw.agent.system_prompt import build_dynamic_system_prompt
from vulnclaw.agent.tool_call_manager import safe_parse_tool_args
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.target_state.store import save_target_state

# Optional KB integration — gracefully degrade if KB data is unavailable
try:
    from vulnclaw.kb.retriever import KnowledgeRetriever
except Exception:
    KnowledgeRetriever = None


class AgentCore:
    """Core AI agent that orchestrates LLM calls and tool execution."""

    def __init__(self, config: VulnClawConfig, mcp_manager: Any = None) -> None:
        self.config = config
        self.mcp_manager = mcp_manager
        self.context = ContextManager()
        self._client = None
        self.runtime = RuntimeState()
        self._reset_runtime_state()
        # Optional KB retriever — lazily initialized on first use
        self._kb_retriever: Any = None
        self._finding_parser = FindingParser(self.context, self.runtime)

    def _maybe_auto_save_session(self) -> None:
        """Persist session state when auto-save is enabled."""
        if self.config.session.auto_save:
            session_path = self.context.state.save()
            if self.context.state.target:
                save_target_state(
                    self.context.state.target,
                    self.context.state,
                    command="auto",
                    session_file=str(session_path),
                    runtime=self.runtime,
                )

    @property
    def session_state(self) -> SessionState:
        """Access current session state."""
        return self.context.state

    def reset_context(self) -> None:
        """Reset agent context and runtime loop state."""
        self.context.reset()
        self._reset_runtime_state()

    def _reset_runtime_state(
        self,
        user_input: str = "",
        detected_phase: Optional[PentestPhase] = None,
    ) -> None:
        """Reset per-run runtime state to avoid cross-run contamination."""
        user_lower = user_input.lower() if user_input else ""
        existing_constraints = self.context.state.task_constraints
        parsed_constraints = (
            extract_task_constraints(user_input)
            if user_input
            else self.context.state.task_constraints
        )
        if (
            user_input
            and "[Persistent Cycle " in user_input
            and parsed_constraints.allowed_ports == []
            and parsed_constraints.blocked_ports == []
            and parsed_constraints.allowed_actions == []
            and parsed_constraints.blocked_actions == []
            and parsed_constraints.allowed_paths == []
            and parsed_constraints.blocked_paths == []
        ):
            parsed_constraints = existing_constraints
        elif parsed_constraints.is_empty():
            parsed_constraints = self.context.state.task_constraints
        self.runtime = RuntimeState(
            auto_skill_input=user_input,
            user_vuln_hint=self._extract_user_vuln_hint(user_input) if user_input else "",
            task_constraints=parsed_constraints,
            is_recon_phase=detected_phase == PentestPhase.RECON,
            is_ctf_mode=any(
                kw in user_lower for kw in ["ctf", "flag", "夺旗", "解题", "找flag", "找出flag"]
            ),
        )
        self.runtime.user_vuln_hint_rounds = 3 if self.runtime.user_vuln_hint else 0
        self.context.state.task_constraints = self.runtime.task_constraints
        if self.mcp_manager and hasattr(self.mcp_manager, "set_task_constraints"):
            self.mcp_manager.set_task_constraints(self.context.state.task_constraints)

        self.context.state.recon_dimensions_completed = {
            "server": False,
            "website": False,
            "domain": False,
            "personnel": False,
        }
        social_engineering_keywords = [
            "社会工程",
            "社工",
            "人员信息",
            "作者追踪",
            "人物追踪",
            "人物画像",
            "osint",
            "情报",
            "作者",
            "调查",
        ]
        self.context.state.recon_dimension4_active = self.runtime.is_recon_phase and any(
            kw in user_lower for kw in social_engineering_keywords
        )
        # Re-bind finding parser to the new runtime object
        self._finding_parser = FindingParser(self.context, self.runtime)

    def _get_client(self):
        """Lazy-initialize OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI

                self._client = OpenAI(
                    api_key=self.config.llm.api_key,
                    base_url=self.config.llm.base_url,
                )
            except ImportError:
                raise RuntimeError("请安装 openai 包: pip install openai")
        return self._client

    @staticmethod
    def _extract_response(message: Any) -> str:
        """Compatibility wrapper for old tests and call sites."""
        from vulnclaw.agent.llm_client import extract_response

        return extract_response(message)

    def _build_system_prompt(
        self,
        target: Optional[str] = None,
        auto_mode: bool = False,
        user_input: Optional[str] = None,
    ) -> str:
        """Build the dynamic system prompt for this turn."""
        # Collect MCP tools if available
        mcp_tools = []
        if self.mcp_manager:
            mcp_tools = self.mcp_manager.get_tool_schemas()

        # Collect skill context — dynamically dispatch based on user input
        skill_context = self._get_active_skill_context(user_input=user_input)

        phase = (
            self.context.state.phase.value
            if self.context.state.phase != PentestPhase.IDLE
            else None
        )
        personnel_keywords = [
            "社会工程",
            "社工",
            "人员信息",
            "作者追踪",
            "人物追踪",
            "人物画像",
            "osint",
            "情报",
            "调查",
            "作者",
        ]
        enable_personnel = any(kw in (user_input or "").lower() for kw in personnel_keywords)
        if (
            hasattr(self.context.state, "recon_dimension4_active")
            and self.context.state.recon_dimension4_active
        ):
            enable_personnel = True

        kb_context = self._build_kb_context(user_input)

        return build_dynamic_system_prompt(
            target=target or self.context.state.target,
            phase=phase,
            skill_context=skill_context,
            mcp_tools=mcp_tools,
            enable_personnel_dim=enable_personnel,
            auto_mode=auto_mode,
            user_input=user_input,
            kb_context=kb_context,
        )

    def _get_active_skill_context(self, user_input: Optional[str] = None) -> Optional[str]:
        return get_active_skill_context(user_input)

    def _build_kb_context(self, user_input: Optional[str] = None) -> str:
        return build_kb_context(self, user_input)

    def _detect_phase(self, user_input: str) -> Optional[PentestPhase]:
        """Detect pentest phase from user input using keyword matching."""
        return detect_phase(user_input)

    def _extract_user_vuln_hint(self, user_input: str) -> str:
        """Extract explicit vulnerability hints from user input.

        When the user says "这个点有SQL注入，测试一下" or "帮我测一下XSS"，
        returns a directive telling LLM to test that specific vuln immediately.
        Returns "" if no explicit hint found.
        """
        return extract_user_vuln_hint(user_input)

    @staticmethod
    def _get_payload_examples(found_vulns: list[str], target: str) -> str:
        """Return concrete PoC payload examples for the given vulnerability types."""
        return get_payload_examples(found_vulns, target)

    def _detect_target(self, user_input: str) -> Optional[str]:
        """Extract target from user input."""
        return detect_target(user_input)

    # ── Single-turn chat (for manual REPL interaction) ──────────────

    async def chat(
        self,
        user_input: str,
        target: Optional[str] = None,
        *,
        stream_sink: Optional["StreamSink"] = None,
    ) -> AgentResult:
        """Process a user message and return agent response (single turn).

        For multi-step tasks with targets, use auto_pentest() instead.
        Chat mode is for quick Q&A and simple single-step queries.
        """
        result = AgentResult()

        # Chat mode is free-form — don't inherit constraints from previous sessions
        self.context.state.task_constraints = TaskConstraints()

        # Detect target and phase from input
        detected_target = target or self._detect_target(user_input)
        detected_phase = self._detect_phase(user_input)

        # Update session state
        if detected_target:
            self.context.state.target = detected_target
            result.target = detected_target

        if detected_phase:
            self.context.state.advance_phase(detected_phase)
            result.phase = detected_phase.value

        # Add user message to context
        self.context.add_user_message(user_input)

        # Build system prompt — pass user_input for dynamic Skill dispatch
        system_prompt = self._build_system_prompt(
            detected_target, auto_mode=False, user_input=user_input
        )

        # Call LLM
        try:
            response_text = await call_llm(self, system_prompt, stream_sink=stream_sink)
            result.output = response_text

            # Add assistant response to context
            self.context.add_assistant_message(response_text)

            # Parse any structured findings from the response
            self._finding_parser.parse(response_text)

            # Auto-save session when enabled
            self._maybe_auto_save_session()

        except Exception as e:
            result.output = f"[!] Agent 错误: {e}"

        return result

    # ── Autonomous pentest loop ─────────────────────────────────────

    async def auto_pentest(
        self,
        user_input: str,
        target: Optional[str] = None,
        max_rounds: int = 15,
        on_step: Optional[Callable[[int, AgentResult], None]] = None,
        on_token: Optional[Callable[[str], None]] = None,
        on_tool_call: Optional[Callable[[dict], None]] = None,
        on_tool_result: Optional[Callable[[dict], None]] = None,
    ) -> list[AgentResult]:
        """Autonomous penetration test loop."""
        return await run_auto_pentest(
            self, user_input, target, max_rounds, on_step,
            on_token=on_token, on_tool_call=on_tool_call, on_tool_result=on_tool_result,
        )

    def _build_round_context(self, round_num: int, max_rounds: int) -> str:
        """Build context string for the current round in auto loop."""
        return build_round_context(self, round_num, max_rounds)

    # ── Persistent pentest loop ──────────────────────────────────────

    async def persistent_pentest(
        self,
        user_input: str,
        target: Optional[str] = None,
        rounds_per_cycle: int = 100,
        max_cycles: int = 10,
        auto_report: bool = True,
        on_cycle_step: Optional[Callable[[int, int, AgentResult], None]] = None,
        on_cycle_complete: Optional[Callable[[int, "PersistentCycleResult"], None]] = None,
    ) -> list["PersistentCycleResult"]:
        """Persistent penetration test — runs cycles of auto_pentest until stopped."""
        return await run_persistent_pentest(
            self,
            user_input,
            target,
            rounds_per_cycle,
            max_cycles,
            auto_report,
            on_cycle_step,
            on_cycle_complete,
        )

    def _detect_phase_from_output(self, output: str) -> Optional[PentestPhase]:
        """Detect phase transition signals from LLM output."""
        return detect_phase_from_output(output)

    def _is_completion_signal(self, output: str) -> bool:
        """Check if the LLM output signals task completion."""
        return is_completion_signal(output)

    def _detect_flag_claim(self, output: str) -> Optional[str]:
        """Detect if the LLM claims to have found a flag, return the claimed flag or None.

        This is used to trigger automatic verification — if the LLM claims
        a flag but we can't verify it independently, we should NOT stop.
        """
        return detect_flag_claim(output)

    def _track_failed_target(self, response_text: str) -> Optional[str]:
        """Track target-level failures and detect repeatedly failed targets.

        Returns the hostname of a blocked target if one is detected, else None.
        """
        return track_failed_target(self, response_text)

    def _is_meaningful_step(self, step: str) -> bool:
        """Check if a step represents meaningful progress (not just a failed retry).

        Only steps with actual discoveries or confirmations count as progress.
        A step is considered NOT meaningful only when it is a PURE failure —
        i.e., it mentions failure indicators AND has no progress indicators at all.
        If a step has BOTH failure and progress keywords (e.g. "XSS测试超时但发现新路径"),
        it is still meaningful because progress was made.
        """
        return is_meaningful_step(step)

    def _detect_attack_path(self, output: str) -> Optional[str]:
        """Detect the current attack path/technique from LLM output.

        Returns a canonical path name like "regex_bypass", "rce", "file_inclusion", etc.
        Used to track whether the agent is stuck on the same approach.
        """
        return detect_attack_path(output)

    async def _generate_attack_summary(self) -> str:
        """Generate a detailed attack path summary for the cycle report.

        Provides all execution steps, notes, and findings to the LLM and asks
        for a detailed narrative of the attack chain with specific URLs/techniques.
        """
        return await generate_attack_summary(self)

    @staticmethod
    def _safe_parse_tool_args(arguments: Optional[str]) -> dict:
        """Safely parse tool call arguments JSON, with fallback for malformed input."""
        return safe_parse_tool_args(arguments)

    async def _execute_mcp_tool(self, tool_name: str, args: dict) -> str:
        """Execute a tool call via MCP manager or built-in tools."""
        return await execute_mcp_tool(self, tool_name, args)

    def _build_openai_tools(self) -> list[dict]:
        """Build OpenAI function calling schema from MCP tools + built-in tools."""
        return build_openai_tools(self.mcp_manager)

    # ── Python code executor ─────────────────────────────────────────

    _BLOCKED_PATTERNS = BLOCKED_PATTERNS

    async def _execute_nmap(self, args: dict) -> str:
        return await execute_nmap(self, args)

    # ── Reserved IP detection helpers ─────────────────────────────────

    _RESERVED_IP_RANGES = RESERVED_IP_RANGES

    def _is_reserved_ip(self, ip: str) -> tuple[bool, str]:
        return is_reserved_ip(ip)

    def _validate_scan_target(self, target: str) -> str:
        return validate_scan_target(target)

    def _parse_nmap_xml(self, xml_output: str, target: str) -> str:
        return parse_nmap_xml(xml_output, target)

    async def _execute_python(self, args: dict) -> str:
        return await execute_python(self, args)

    def _update_recon_dimension_completion(self, response: str) -> None:
        """Auto-detect which recon dimensions have been explored."""
        update_recon_dimension_completion(self, response)
