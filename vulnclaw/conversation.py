"""Shared conversation decisions, scope and report requirements."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from vulnclaw.target_state.store import apply_target_state_to_agent

if TYPE_CHECKING:
    from vulnclaw.task_service import PreparedTask

_AFFIRMATIVE = frozenset(
    {
        "y",
        "yes",
        "yeah",
        "yep",
        "yup",
        "ok",
        "okay",
        "sure",
        "go",
        "go ahead",
        "proceed",
        "continue",
        "start",
        "begin",
        "do it",
        "let's go",
        "lets go",
        "ship it",
        "好",
        "好的",
        "行",
        "可以",
        "是",
        "是的",
        "继续",
        "确认",
        "确认继续",
        "开始",
        "干",
        "搞起",
    }
)

_READINESS_RE = re.compile(
    r"(ready\s+to|are\s+(we|you)\s+ready|shall\s+we|should\s+we|"
    r"can\s+we\s+(begin|start)|want\s+to\s+(begin|start)|good\s+to\s+go|"
    r"all\s+set\??|"
    r"准备好|可以开始|开始吗|开始么|开始了吗|要开始|开不开)",
    re.IGNORECASE,
)

_URL_OR_IP_RE = re.compile(r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE)

_IMPERATIVE_START_RE = re.compile(
    r"^(?:please\s+)?(?:"
    r"go|start|continue|resume|scan|recon(?:naissance)?|test|pentest|"
    r"exploit|enumerate|probe|fetch|check|run|do|"
    r"扫描|测试|渗透|侦察|继续|开始"
    r")\b",
    re.IGNORECASE,
)

# An operational directive names a testing action, even when it is politely
# phrased as a question and carries no URL ("can you test the login for SQLi?").
# Readiness/meta questions are filtered out before this runs, so matching an
# action verb anywhere in the turn is a signal to keep it on the work path.
_OPERATIONAL_ACTION_RE = re.compile(
    r"\b(?:scan|test|pentest|exploit|enumerate|probe|fuzz|attack|inject|"
    r"brute(?:force|-force)?|recon(?:naissance)?)\b|"
    # A named vulnerability class is itself a testing directive, so it keeps
    # the turn operational even when the verb is a soft one like "check".
    r"\b(?:sql\s*injection|sqli|xss|idor|ssrf|rce|csrf|lfi|rfi|xxe|ssti|"
    r"open\s*redirect|path\s*traversal|command\s*injection)\b|"
    r"扫描|测试|渗透|侦察|利用|爆破|枚举|注入",
    re.IGNORECASE,
)


def is_affirmative_continue(user_input: str) -> bool:
    """True when the user is green-lighting the next autonomous step."""
    text = " ".join((user_input or "").strip().lower().split())
    return text in _AFFIRMATIVE


def is_conversational_checkin(user_input: str) -> bool:
    """True when the user is asking a readiness/meta question, not issuing work.

    Example: ``ready to begin bug hunting?`` should get a spoken status first,
    not an immediate ``agent_run`` recon wave.
    """
    text = (user_input or "").strip()
    if not text or is_affirmative_continue(text):
        return False
    if re.match(
        r"^(?:请)?(?:解释|总结|汇总|说明|生成报告|导出报告|不要.*报告|不用.*报告|"
        r"explain\b|summari[sz]e\b|export\b|report\b)",
        text,
        re.IGNORECASE,
    ):
        return True

    if _READINESS_RE.search(text):
        return True

    is_question = "?" in text or text.endswith("？") or text.endswith("吗") or text.endswith("么")
    if not is_question:
        return False

    # Operational questions with a concrete host stay on the work path.
    if _URL_OR_IP_RE.search(text):
        return False

    # Short "scan it?"-style commands are not check-ins.
    if _IMPERATIVE_START_RE.match(text) and len(text) <= 40:
        return False

    # A concrete testing directive stays on the work path even without a host
    # and even when phrased as a question ("can you test X for SQLi?").
    if _OPERATIONAL_ACTION_RE.search(text):
        return False

    # Short open questions → answer first (status, plan, clarification).
    return len(text) <= 120


def continue_task_prompt(last_auto_input: str, current_target: str | None = None) -> str:
    """Rewrite a terse affirmative into a full continue-task goal."""
    prior = (last_auto_input or "").strip()
    target = (current_target or "").strip()
    if prior and not is_affirmative_continue(prior) and not is_conversational_checkin(prior):
        return f"User confirmed: continue the prior autonomous engagement.\nPrior task: {prior}" + (
            f"\nTarget: {target}" if target else ""
        )
    if target:
        return (
            f"User confirmed: begin or continue authorized recon and bug hunting "
            f"on in-scope target {target}."
        )
    return "User confirmed: continue the current authorized engagement."


def should_auto_pentest(user_input: str, current_target: Optional[str]) -> bool:
    """Determine if user input should trigger autonomous pentest loop.

    Triggers when:
    - User explicitly asks for a full pentest with a target
    - User mentions a target plus action keywords like "渗透测试" or "打一下"
    - User asks to solve a CTF / find a flag with a target
    - User asks for information gathering / recon / OSINT with a target
    - A target is present + multi-step task indicators
    """
    # Readiness / meta questions (e.g. "ready to begin bug hunting?") get a
    # spoken answer first — never jump straight into the solve tool loop.
    if is_conversational_checkin(user_input):
        return False

    input_lower = user_input.lower()

    # Explicit auto-mode triggers
    auto_keywords = [
        "渗透测试",
        "进行渗透",
        "做渗透",
        "打一下",
        "全面测试",
        "pentest",
        "full test",
        "auto",
        "自主渗透模式",
        "自主模式",
        "找出flag",
        "找到flag",
        "拿flag",
        "get flag",
        "find flag",
        "解题",
        "做题",
        "挑战",
        "challenge",
        "ctf",
        "弱口令",
        "爆破",
        "绕过",
        "bypass",
        "brute",
        "搜集",
        "收集",
        "信息收集",
        "侦察",
        "recon",
        "reconnaissance",
        "社工",
        "osint",
        "情报",
        "intelligence",
        "分析目标",
        "目标分析",
        "资产发现",
        "目录扫描",
        "探测",
        "探索",
        "调查",
        "investigate",
        "enumerate",
        "全面分析",
        "深度分析",
        "详细分析",
        "全面扫描",
        "子域名",
        "subdomain",
    ]

    # Single-step queries should NOT trigger auto mode
    single_step_keywords = [
        "生成报告",
        "report",
        "help",
        "帮助",
    ]

    # If it's clearly a single-step query, don't auto-loop
    # But if it also has auto keywords, still go auto (e.g. "收集信息并生成报告")
    if any(kw in input_lower for kw in single_step_keywords) and not any(
        kw in input_lower for kw in auto_keywords
    ):
        return False

    # If it has auto-mode keywords, trigger auto loop
    if any(kw in input_lower for kw in auto_keywords):
        # Must have a target (either in input or already set)
        has_target = bool(current_target) or bool(extract_target_from_input(user_input))
        return has_target

    # Fallback: has target + multi-step task -> auto
    has_target = bool(current_target) or bool(extract_target_from_input(user_input))
    if has_target:
        multi_step_indicators = [
            "并",
            "然后",
            "输出",
            "保存",
            "写到",
            "导出",
            "所有",
            "全部",
            "完整",
            "详细",
        ]
        if any(ind in input_lower for ind in multi_step_indicators):
            return True

    return False


def extract_target_from_input(user_input: str) -> Optional[str]:
    """Extract target from user input string."""
    # Try to find URL (with optional port)
    url_match = re.search(r"(https?://[a-zA-Z0-9][-a-zA-Z0-9.:]*)", user_input)
    if url_match:
        return url_match.group(1).rstrip("/")
    # Try to find IP address
    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", user_input)
    if ip_match:
        return ip_match.group(1)
    # Try to find domain
    domain_match = re.search(
        r"([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", user_input
    )
    if domain_match:
        return domain_match.group(1)
    return None


@dataclass
class ReportRequest:
    kind: str = "security"
    preference: str = "default"
    output: str | None = None
    exported: bool = False


@dataclass(frozen=True)
class ConversationTurn:
    text: str
    auto: bool
    exited_auto: bool = False
    previous_target: str | None = None
    answering: bool = False


@dataclass
class ConversationState:
    """Conversation decisions independent of terminal input widgets."""

    agent: Any
    target: str | None = None
    phase: str = "Ready"
    auto_mode: bool = False
    last_auto_input: str = ""
    report: ReportRequest = field(default_factory=ReportRequest)
    engagement_completed: bool = False
    task: PreparedTask | None = None

    @property
    def pending_questions(self) -> list[str]:
        state = getattr(getattr(self.agent, "session_state", None), "agent_state", None)
        return getattr(state, "pending_questions", [])

    def prepare_target(self, requested_target: str) -> bool:
        target = requested_target.strip()
        if not target:
            return False
        if self.target and self.target != target:
            self.agent.reset_context()
            self.report = ReportRequest()
            self.task = None
        restored = apply_target_state_to_agent(self.agent, target)
        self.target = target
        self.phase = restored.phase or self.agent.session_state.phase.value
        return restored.restored

    def clear(self) -> None:
        self.target = None
        self.phase = "Ready"
        self.auto_mode = False
        self.last_auto_input = ""
        self.agent.reset_context()
        self.report = ReportRequest()
        self.engagement_completed = False
        self.task = None

    def prepare_turn(self, text: str) -> ConversationTurn:
        answering = self.auto_mode and bool(self.pending_questions)
        exited = self.auto_mode and text.lower().strip() in (
            "chat",
            "manual",
            "exit auto",
            "单轮",
            "手动",
        )
        if exited:
            self.auto_mode = False
            self.last_auto_input = ""
            self.task = None
            auto = False
            answering = False
        elif answering:
            auto = True
        elif self.auto_mode:
            auto = not is_conversational_checkin(text) and (
                is_affirmative_continue(text)
                or should_auto_pentest(text, self.target)
                or bool(_OPERATIONAL_ACTION_RE.search(text))
            )
        else:
            auto = should_auto_pentest(text, self.target)
        previous = None
        # Only new user text can select a target. An answer belongs to the
        # waiting task, even when it supplies a URL or other concrete details.
        detected = None if answering else extract_target_from_input(text)
        if detected and self.target and detected != self.target:
            previous = self.target
            self.target = detected
            self.phase = "Recon"
            self.agent.reset_context()
            self.auto_mode = False
            self.last_auto_input = ""
            self.report = ReportRequest()
            self.task = None
        if detected:
            self.target = detected
        if answering:
            prior = self.task.prompt if self.task else self.last_auto_input
            text = (
                f"Continue the prior task.\nPrior task: {prior}\n\n"
                + "Pending questions:\n"
                + "\n".join(self.pending_questions)
                + f"\n\nUser reply: {text}"
            )
        elif auto and is_affirmative_continue(text):
            text = continue_task_prompt(self.last_auto_input, self.target)
        if auto:
            self.last_auto_input = text
        return ConversationTurn(text, auto, exited, previous, answering)


async def run_conversation(application: Any, text: str, sink: Any) -> dict[str, Any]:
    """Shared conversational execution, independent of terminal rendering."""
    from vulnclaw.agent.execution_context import ExecutionContext, execution_context
    from vulnclaw.agent.input_analysis import _is_self_discovering_skill_launch
    from vulnclaw.config.domain_models import TaskConstraints
    from vulnclaw.report_service import export_report
    from vulnclaw.task_service import build_scope_constraints

    agent = application.agent
    config = application.config
    conversation = application.conversation
    turn = conversation.prepare_turn(text)
    if turn.auto and conversation.engagement_completed:
        conversation.report = ReportRequest()
        conversation.engagement_completed = False
    if turn.previous_target or not application.current_target:
        scope_target = "" if _is_self_discovering_skill_launch(turn.text) else conversation.target
        application.current_constraints = build_scope_constraints(
            scope_target or "",
            application.bootstrap,
        ).model_dump()
    constraints = _turn_constraints(
        TaskConstraints.model_validate(application.current_constraints), text
    )
    application.current_constraints = constraints.model_dump()
    application.current_target = conversation.target or application.current_target
    agent.apply_task_constraints(constraints)
    reports: list[dict[str, str]] = []

    async def report_action(arguments: dict[str, Any]) -> dict[str, Any]:
        action = arguments.get("action")
        kind = arguments.get("kind", conversation.report.kind)
        if application.permission_mode == "read_only":
            raise ValueError("Read-Only does not export reports")
        if action not in {"default", "required", "suppress", "export"}:
            raise ValueError("report action must be default, required, suppress or export")
        if kind not in {"security", "replay"}:
            raise ValueError("report kind must be security or replay")
        request = conversation.report
        request.kind = kind
        request.output = arguments.get("output") or request.output
        if action != "export":
            # Classifying a continuation must not discard an earlier requirement.
            if action != "default" or request.preference == "default":
                request.preference = action
            return {"report": request.preference, "kind": kind}
        try:
            report = await export_report(
                agent,
                config,
                kind=kind,
                output=request.output,
                partial=not conversation.engagement_completed,
            )
        except Exception as exc:
            return {"report_error": str(exc)}
        reports.append(report)
        request.exported = True
        return report

    def on_event(kind: str, payload: dict[str, Any]) -> None:
        if kind == "subagent":
            sink._event("subagent", **payload)
        elif kind == "subagent_stream":
            event = dict(payload)
            event_type = event.pop("type")
            if sink.accepts(event_type):
                sink._event(event_type, **event)
        elif kind == "ask_user":
            sink.on_content_token(str(payload.get("question", "")))
            application.question_ready()
        elif kind in {"error", "no_path", "agent_step", "completed"}:
            sink.on_status(f"{kind}: {payload}")

    with execution_context(ExecutionContext(report=report_action)):
        if application.permission_mode == "read_only" or not turn.auto:
            result = await agent.chat(
                turn.text,
                target=conversation.target,
                stream_sink=sink,
                task_constraints=constraints,
            )
            completed = False
        else:
            conversation.auto_mode = True
            from vulnclaw.config.schema import resolve_engine

            engine = resolve_engine(config)
            if turn.answering:
                # The reply is recorded by solve in the normal message history.
                # Consume the waiting state only after scope validation succeeds.
                conversation.pending_questions.clear()
            if conversation.task is not None:
                from vulnclaw.task_service import PreparedTask, run_task_action

                task = conversation.task
                result = await run_task_action(
                    agent, PreparedTask(task.request, turn.text, constraints),
                    stream_sink=sink, on_event=on_event,
                )
                completed = bool(
                    getattr(result, "completed", False) or agent.session_state.agent_state.completed
                )
                if isinstance(result, list) and result:
                    completed = completed or not getattr(result[-1], "should_continue", True)
            elif engine == "solve":
                result = await agent.solve(
                    turn.text,
                    target=conversation.target,
                    max_steps=config.session.solve_max_steps,
                    max_tool_rounds=config.session.solve_max_tool_rounds,
                    stream_sink=sink,
                    on_event=on_event,
                    task_constraints=constraints,
                )
                completed = bool(getattr(result, "completed", False))
            else:
                result = await agent.auto_pentest(
                    turn.text,
                    target=conversation.target,
                    max_rounds=config.session.max_rounds,
                    stream_sink=sink,
                    engine=engine,
                    task_constraints=constraints,
                )
                state = agent.session_state.agent_state
                completed = bool(state.completed) or bool(
                    result and not getattr(result[-1], "should_continue", True)
                )
            conversation.auto_mode = not completed

    state = agent.session_state
    if application.permission_mode != "read_only":
        from vulnclaw.findings.verification import verify_findings

        await verify_findings(
            state,
            config=config,
            poc_verify=conversation.task.request.options.poc_verify if conversation.task else None,
        )
    conversation.target = state.target or conversation.target
    phase = getattr(state.phase, "value", state.phase)
    conversation.phase = str(phase)
    application.current_target = conversation.target or ""
    report_error = None
    request = conversation.report
    enabled = (
        config.session.solve_auto_report
        if request.kind == "replay"
        else config.session.conversation_auto_report
    )
    if (
        completed
        and not request.exported
        and request.preference != "suppress"
        and (enabled or request.preference == "required")
    ):
        try:
            reports.append(
                await export_report(
                    agent,
                    config,
                    kind=request.kind,
                    output=request.output,
                )
            )
            request.exported = True
        except Exception as exc:
            report_error = str(exc)
    if completed:
        # Keep the last kind for /report; next engagement starts with defaults.
        request.preference = "default"
        conversation.engagement_completed = True
        conversation.task = None
    output = str(getattr(result, "output", "") or "")
    return {
        "output": output,
        "completed": completed,
        "reports": reports,
        "report_error": report_error,
        "target": application.current_target,
    }


def _turn_constraints(current: Any, text: str) -> Any:
    """A turn may narrow inherited scope; an empty intersection is never unrestricted."""
    from fnmatch import fnmatchcase

    from vulnclaw.agent.input_analysis import extract_task_constraints

    requested = extract_task_constraints(text)
    constraints = current.model_copy(deep=True)
    for name in ("allowed_hosts", "allowed_ports", "allowed_paths", "allowed_actions"):
        proposed = getattr(requested, name)
        if not proposed:
            continue
        allowed = getattr(current, name)
        if not allowed:
            narrowed = proposed
        elif name == "allowed_hosts":
            narrowed = [
                host for host in proposed if any(fnmatchcase(host, pattern) for pattern in allowed)
            ]
        elif name == "allowed_paths":
            narrowed = []
            for path in proposed:
                for parent in allowed:
                    if path == parent or path.startswith(parent.rstrip("/") + "/"):
                        narrowed.append(path)
                    elif parent.startswith(path.rstrip("/") + "/"):
                        narrowed.append(parent)
        else:
            narrowed = [value for value in proposed if value in allowed]
        if not narrowed:
            raise ValueError(
                f"Requested {name} do not overlap the current scope; use /scope to change it"
            )
        setattr(constraints, name, list(dict.fromkeys(narrowed)))
    for name in ("blocked_hosts", "blocked_ports", "blocked_paths", "blocked_actions", "notes"):
        setattr(
            constraints,
            name,
            list(dict.fromkeys(getattr(current, name) + getattr(requested, name))),
        )
    constraints.strict_mode = not constraints.is_empty()
    return constraints
