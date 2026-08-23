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
from vulnclaw.agent.memory import MemoryStore
from vulnclaw.agent.prompt_context import build_round_context, generate_attack_summary
from vulnclaw.agent.recon_tracker import update_recon_dimension_completion
from vulnclaw.agent.roles import role_prompt_block
from vulnclaw.agent.runtime_state import AgentResult, PersistentCycleResult, RuntimeState
from vulnclaw.agent.skill_context import apply_skill_selection
from vulnclaw.agent.subagent.models import SubagentContext
from vulnclaw.agent.system_prompt import build_dynamic_system_prompt
from vulnclaw.agent.tool_call_manager import safe_parse_tool_args
from vulnclaw.config.schema import VulnClawConfig, resolve_engine
from vulnclaw.config.settings import make_openai_client
from vulnclaw.i18n import _
from vulnclaw.target_state.store import save_target_state

# Optional KB integration — gracefully degrade if KB data is unavailable
try:
    from vulnclaw.kb.retriever import KnowledgeRetriever, RetrieverStatus
except Exception:
    KnowledgeRetriever = None
    RetrieverStatus = None


class AgentCore:
    """Core AI agent that orchestrates LLM calls and tool execution."""

    def __init__(self, config: VulnClawConfig, mcp_manager: Any = None) -> None:
        self.config = config
        self.mcp_manager = mcp_manager
        memory_dir = config.session.output_dir / "memory"
        self.context = ContextManager(
            max_history=config.session.context_hot_max_messages,
            max_tokens=config.session.context_hot_max_tokens,
            search_max_chars=config.session.memory_search_max_chars,
            memory_store=MemoryStore(
                store_dir=memory_dir,
                archive_max_bytes=config.session.memory_archive_max_bytes,
                archive_max_files=config.session.memory_archive_max_files,
            ),
        )
        # Wire the vault to the run output directory so archiving can persist.
        self.context.vault_output_dir = config.session.output_dir
        self.active_role: str | None = None
        self._subagent_ctx = SubagentContext()
        self._client = None
        # Failover key pool: prefer llm.api_keys, else the single llm.api_key.
        self._key_pool = config.llm.key_pool()
        self._key_index = 0
        self.runtime = RuntimeState()
        self._reset_runtime_state()
        # Optional KB retriever — lazily initialized on first use
        self._kb_retriever: Any = None
        self._kb_context_cache: dict[Any, str] = {}
        self._finding_parser = FindingParser(self.context, self.runtime)
        self._report_kb_status()

    def _child_factory(self) -> "AgentCore":
        """Build an isolated child; subclasses may override this explicit seam."""

        return AgentCore(self.config, self.mcp_manager)

    def _report_kb_status(self) -> None:
        """Print the knowledge-base backend status once at startup."""
        if KnowledgeRetriever is None:
            return
        try:
            self._kb_retriever = KnowledgeRetriever()
            status = self._kb_retriever.get_status()
            # Auto-seed when KB is empty
            if status == RetrieverStatus.DISABLED:
                from vulnclaw.kb.updater import seed_knowledge_base

                seed_knowledge_base(self._kb_retriever.store)
                self._kb_retriever = KnowledgeRetriever()
                status = self._kb_retriever.get_status()
        except Exception:
            return

        try:
            from rich.console import Console

            console = Console()
        except Exception:
            return

        if RetrieverStatus is None:
            return
        if status == RetrieverStatus.CHROMADB_ACTIVE:
            console.print(f"[green]{_('agent.kb_enabled')}[/green]")
        elif status == RetrieverStatus.KEYWORD_FALLBACK:
            console.print(f"[yellow]{_('agent.kb_fallback')}[/yellow]")
        else:
            console.print(f"[red]{_('agent.kb_disabled')}[/red]")

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

    def apply_config(self, config: VulnClawConfig) -> None:
        """Adopt an updated config (e.g. after the in-REPL config editor).

        The cached OpenAI client is bound to a specific ``base_url``, so drop it
        and rebuild the failover key pool; the next call re-creates the client
        with the new provider / model / key.
        """
        self.config = config
        self._client = None
        self._key_pool = config.llm.key_pool()
        self._key_index = 0
        context = getattr(self, "context", None)
        if context is not None:
            context.max_history = config.session.context_hot_max_messages
            context.max_tokens = config.session.context_hot_max_tokens
            context.search_max_chars = config.session.memory_search_max_chars
            memory_store = getattr(context, "memory_store", None)
            if memory_store is not None:
                memory_store.archive_max_bytes = config.session.memory_archive_max_bytes
                memory_store.archive_max_files = config.session.memory_archive_max_files
            context._trim()

    def _reset_runtime_state(
        self,
        user_input: str = "",
        detected_phase: Optional[PentestPhase] = None,
    ) -> None:
        """Reset per-run runtime state to avoid cross-run contamination."""
        user_lower = user_input.lower() if user_input else ""
        # A persistent-mode cycle re-enters this reset every cycle for the SAME
        # engagement (its prompt carries the "[Persistent Cycle N]" marker). Such
        # a cycle is a continuation, not a fresh task, so accumulated per-target
        # progress (recon dimensions, dimension-4 activation) must survive the
        # reset — mirroring how reflexion memory is restored below.
        is_persistent_cycle = bool(user_input and "[Persistent Cycle " in user_input)
        existing_constraints = self.context.state.task_constraints
        parsed_constraints = (
            extract_task_constraints(user_input)
            if user_input
            else self.context.state.task_constraints
        )
        if (
            is_persistent_cycle
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

        # Preserve accumulated recon progress across persistent cycles; only a
        # genuinely fresh task (or first cycle) starts the four dimensions over.
        if not is_persistent_cycle:
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

        # 跨周期恢复反思记忆（persistent 模式）：保留失败路径/历史/归因，重置本周期 stuck 计数
        self._restore_reflexion_history()

    # ── Reflexion 跨周期持久化 ───────────────────────────────────────
    _REFLEXION_ATTEMPT_MEMORY = 50  # 跨周期最多携带的 attempt 条数，限制内存与归因开销

    def _restore_reflexion_history(self) -> None:
        """从 SessionState 快照恢复反思的记忆部分，但重置每周期 stuck 计数。"""
        if not getattr(self.config.session, "reflexion_enabled", True):
            return
        snapshot = getattr(self.context.state, "reflexion_snapshot", None)
        reflexion = getattr(self.runtime, "reflexion", None)
        if not snapshot or reflexion is None:
            return
        try:
            from vulnclaw.agent.reflexion import ReflexionState

            restored = ReflexionState.model_validate(snapshot)
        except Exception:
            return
        # 记忆：失败路径 / 归因素材 / 最近 attempts / 已知障碍
        reflexion.state.failed_paths = restored.failed_paths
        reflexion.state.constraints = restored.constraints
        reflexion.state.attempts = restored.attempts[-self._REFLEXION_ATTEMPT_MEMORY :]
        reflexion.state.last_vuln_type = restored.last_vuln_type
        # 每周期重置：连败计数 / 同类失败计数 / 升级驱动（reflections）
        reflexion.state.consecutive_failures = 0
        reflexion.state.vuln_type_fail_count = 0
        reflexion.state.reflections = []

    def _save_reflexion_snapshot(self) -> None:
        """把当前反思状态写回 SessionState 快照，供下个周期/同目标恢复时复用。"""
        if not getattr(self.config.session, "reflexion_enabled", True):
            return
        reflexion = getattr(self.runtime, "reflexion", None)
        if reflexion is None:
            return
        try:
            self.context.state.reflexion_snapshot = reflexion.state.model_dump(mode="json")
        except Exception:
            pass

    def _current_api_key(self) -> str:
        """Return the static API key currently selected from the failover pool."""
        if self._key_pool:
            return self._key_pool[self._key_index]
        return self.config.llm.api_key

    def rotate_api_key(self) -> bool:
        """Advance to the next key in the failover pool.

        Invalidates the cached client so the next call rebuilds with the new
        key. Returns False (no-op) when there is nothing to rotate to.
        """
        if len(self._key_pool) <= 1:
            return False
        self._key_index = (self._key_index + 1) % len(self._key_pool)
        self._client = None
        return True

    def _get_client(self):
        """Lazy-initialize OpenAI client with dynamic credential resolution.

        Supports static API keys as well as keyless / short-lived bearer tokens
        (env / file / command / WIF). The token is re-resolved on every call so
        rotated or just-minted access tokens are picked up without rebuilding the
        client; ``client.api_key`` becomes the ``Authorization: Bearer`` value.
        """
        from vulnclaw.config.token_provider import load_oauth_tokens, resolve_llm_token

        llm = self.config.llm

        # ── ChatGPT subscription: auto-start the built-in bridge proxy ──
        # The subscription token only works against the ChatGPT backend, so we
        # transparently route VulnClaw's chat.completions through an in-process
        # proxy instead of requiring the user to run one.
        if (
            getattr(llm, "chatgpt_auto_proxy", False)
            and str(getattr(llm, "auth_mode", "") or "").lower() == "oauth"
            and str(load_oauth_tokens().get("flow") or "") == "chatgpt"
        ):
            from vulnclaw.agent.chatgpt_proxy import ensure_proxy_running

            proxy_base = ensure_proxy_running()
            if self._client is None:
                try:
                    self._client = make_openai_client(
                        api_key="local-proxy", base_url=proxy_base
                    )
                except ImportError:
                    raise RuntimeError("请安装 openai 包: pip install openai")
            return self._client

        auth_mode = str(getattr(llm, "auth_mode", "") or "static").strip().lower()
        if auth_mode in ("", "static"):
            # Respect the failover rotation index rather than always resolving
            # the primary key, so rotate_api_key() actually switches keys.
            token = self._current_api_key()
        else:
            token = resolve_llm_token(llm)
        if self._client is None:
            try:
                self._client = make_openai_client(
                    api_key=token or "placeholder",
                    base_url=llm.base_url,
                )
            except ImportError:
                raise RuntimeError("请安装 openai 包: pip install openai")
        elif token:
            # Refresh the bearer token in place for rotating / short-lived creds.
            self._client.api_key = token
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
            self.context.state.phase
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

        prompt = build_dynamic_system_prompt(
            target=target or self.context.state.target,
            phase=phase,
            skill_context=skill_context,
            mcp_tools=mcp_tools,
            enable_personnel_dim=enable_personnel,
            auto_mode=auto_mode,
            user_input=user_input,
            kb_context=kb_context,
            task_constraints=self.context.state.task_constraints,
        )
        active_role_prompt = role_prompt_block(self.active_role)
        if active_role_prompt:
            prompt = f"{prompt}\n\n{active_role_prompt}"
        return prompt

    def _get_active_skill_context(self, user_input: Optional[str] = None) -> Optional[str]:
        # Resolve the bundle once, record its provenance on the session (so
        # findings created this turn inherit it), and return the same bundle's
        # context. All derivation lives in the skill_context helper.
        return apply_skill_selection(self.context.state, user_input)

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
        task_constraints: Optional[TaskConstraints] = None,
    ) -> AgentResult:
        """Process a user message and return agent response (single turn).

        For multi-step tasks with targets, use auto_pentest() instead.
        Chat mode is for quick Q&A and simple single-step queries.
        """
        result = AgentResult()

        # Chat is free-form by default, but protocol/API callers can provide an
        # already parsed scope.  This keeps the Python core authoritative instead
        # of forcing presentation clients to encode constraints back into prose.
        self.apply_task_constraints(task_constraints or TaskConstraints())

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
        *,
        stream_sink: Optional["StreamSink"] = None,
        engine: Optional[str] = None,
        task_constraints: Optional[TaskConstraints] = None,
    ) -> list[AgentResult]:
        """Autonomous penetration test loop.

        Return-value contract (important for callers): only the legacy ``rounds``
        engine returns a populated ``list[AgentResult]`` — one per round. The
        ``solve`` and ``team`` engines persist their outcome on
        ``self.session_state`` (findings, steps, agent_state) and return an
        **empty list**. Callers that need results must read ``session_state``
        rather than the return value; those (like the orchestrator) already do.
        """
        selected_engine = resolve_engine(self.config, engine)
        if selected_engine == "solve":
            await self.solve(
                user_input,
                target=target,
                max_steps=getattr(self.config.session, "solve_max_steps", max_rounds),
                max_tool_rounds=getattr(self.config.session, "solve_max_tool_rounds", 6),
                stream_sink=stream_sink,
                task_constraints=task_constraints,
            )
            return []
        if selected_engine == "team":
            from vulnclaw.agent.team import run_team_pentest

            if task_constraints is not None:
                self.apply_task_constraints(task_constraints)

            await run_team_pentest(
                self,
                user_input=user_input,
                target=target,
                max_steps=getattr(self.config.session, "solve_max_steps", max_rounds),
                max_directions=getattr(self.config.session, "solve_max_directions", 3),
                max_tool_rounds=getattr(self.config.session, "solve_max_tool_rounds", 4),
                max_parallel=getattr(self.config.session, "solve_max_parallel", 3),
                stream_sink=stream_sink,
            )
            return []
        return await run_auto_pentest(
            self,
            user_input,
            target,
            max_rounds,
            on_step,
            stream_sink=stream_sink,
            task_constraints=task_constraints,
        )

    def _build_round_context(self, round_num: int, max_rounds: int) -> str:
        """Build context string for the current round in auto loop."""
        return build_round_context(self, round_num, max_rounds)

    # ── 模型主导自主引擎（AgentState 证据记忆 + 证据闸门）────────────────

    async def solve(
        self,
        user_input: str,
        target: Optional[str] = None,
        *,
        goal: Optional[str] = None,
        max_steps: int = 80,
        max_tool_rounds: int = 6,
        stream_sink: Optional["StreamSink"] = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
        task_constraints: Optional[TaskConstraints] = None,
    ) -> Any:
        """运行模型主导 solve。"""
        from vulnclaw.agent.solver import solve as run_solve

        detected_target = target or self._detect_target(user_input)
        if detected_target:
            self.context.state.target = detected_target
        self._reset_runtime_state(user_input=user_input)
        if task_constraints is not None:
            self.apply_task_constraints(task_constraints)
        self.context.add_user_message(user_input)

        resolved_goal = goal or user_input
        origin = detected_target or self.context.state.target or user_input
        return await run_solve(
            self,
            origin=origin,
            goal=resolved_goal,
            max_steps=max_steps,
            max_tool_rounds=max_tool_rounds,
            stream_sink=stream_sink,
            on_event=on_event,
        )

    def apply_task_constraints(self, constraints: TaskConstraints) -> None:
        """Install one authoritative constraint object across the runtime."""

        self.context.state.task_constraints = constraints
        self.runtime.task_constraints = constraints
        if self.mcp_manager and hasattr(self.mcp_manager, "set_task_constraints"):
            self.mcp_manager.set_task_constraints(constraints)

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
        *,
        # stream_sink 由 main.py 传入，逐级透传到 call_llm_auto_stream 实现流式输出
        stream_sink: Optional["StreamSink"] = None,
        task_constraints: Optional[TaskConstraints] = None,
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
            stream_sink=stream_sink,
            task_constraints=task_constraints,
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
        cfg = getattr(self.config, "subagent", None)
        session_kind = str(
            getattr(getattr(self.context, "state", None), "session_kind", "")
            or ""
        )
        include_subagent_tool = bool(
            cfg
            and cfg.enabled
            and (
                self._subagent_ctx.depth == 0
                or session_kind == "group_leader"
            )
        )
        return build_openai_tools(
            self.mcp_manager,
            active_role=self.active_role,
            include_subagent_tool=include_subagent_tool,
        )

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
