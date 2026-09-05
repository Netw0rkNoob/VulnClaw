"""Autonomous / persistent loop helpers for AgentCore."""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


from vulnclaw.agent.constraint_policy import validate_phase_transition
from vulnclaw.agent.context import PentestPhase, TaskConstraints
from vulnclaw.agent.ctf_mode import update_ctf_state
from vulnclaw.agent.llm_client import call_llm_auto
from vulnclaw.agent.reasoning_state import (
    ConstraintCategory,
    ConstraintSeverity,
    PathStatus,
)
from vulnclaw.agent.reflexion import FailureCategory, classify_failure
from vulnclaw.agent.runtime_state import AgentResult, PersistentCycleResult
from vulnclaw.config.schema import resolve_engine
from vulnclaw.i18n import _

RECON_MIN_ROUNDS = 8


def _reasoning_enabled(agent: AgentContext) -> bool:
    return getattr(getattr(agent.config, "session", None), "reasoning_state_enabled", True)


def _sync_reasoning_path(agent: AgentContext, path_name: str, *, success: bool) -> None:
    """把识别到的攻击路径落进结构化推理状态，并刷新优先级。"""
    if not path_name or not _reasoning_enabled(agent):
        return
    reasoning = getattr(agent.context.state, "reasoning", None)
    if reasoning is None or not hasattr(reasoning, "add_path"):
        return
    existing = next((p for p in reasoning.paths if p.name == path_name), None)
    if existing is None:
        existing = reasoning.add_path(path_name, steps=[], priority=1)
    if success:
        existing.status = PathStatus.SUCCESS
        existing.result = "取得进展"
    elif existing.status != PathStatus.SUCCESS:
        existing.status = PathStatus.FAILED
    reasoning.auto_prioritize()


def _sync_reasoning_constraint(agent: AgentContext, path_name: str, category: FailureCategory) -> None:
    """把识别到的障碍（WAF/过滤等）落进结构化推理状态，描述保持稳定以便去重。"""
    if not _reasoning_enabled(agent):
        return
    reasoning = getattr(agent.context.state, "reasoning", None)
    if reasoning is None or not hasattr(reasoning, "add_constraint"):
        return
    mapping = {
        FailureCategory.ENV_CONSTRAINT: ConstraintCategory.WAF,
        FailureCategory.PARAM_ERROR: ConstraintCategory.FILTER,
    }
    category_value = mapping.get(category)
    if category_value is None:
        return
    reasoning.add_constraint(
        description=f"{path_name or '当前路径'} 被 {category_value.value} 阻断",
        category=category_value,
        severity=ConstraintSeverity.HIGH,
        source="auto_pentest",
    )


def _configure_reflexion(agent: AgentContext) -> None:
    reflexion = getattr(agent.runtime, "reflexion", None)
    session = getattr(agent.config, "session", None)
    if not reflexion or not session:
        return

    for attr, config_attr in (
        ("max_same_vuln_fails", "reflexion_max_same_vuln_fails"),
        ("max_total_no_progress", "reflexion_max_total_no_progress"),
        ("escalation_max_level", "escalation_max_level"),
    ):
        if hasattr(reflexion, attr) and hasattr(session, config_attr):
            setattr(reflexion, attr, getattr(session, config_attr))


async def auto_pentest(
    agent: AgentContext,
    user_input: str,
    target: str | None = None,
    max_rounds: int = 15,
    on_step: Callable[[int, AgentResult], None] | None = None,
    *,
    stream_sink: Any = None,
    task_constraints: TaskConstraints | None = None,
) -> list[AgentResult]:
    results: list[AgentResult] = []

    detected_target = target or agent._detect_target(user_input)
    detected_phase = agent._detect_phase(user_input) or PentestPhase.RECON

    if detected_target:
        agent.context.state.target = detected_target
    if detected_phase:
        agent.context.state.advance_phase(detected_phase)

    agent.context.add_user_message(user_input)
    agent._reset_runtime_state(user_input=user_input, detected_phase=detected_phase)
    if task_constraints is not None:
        agent.apply_task_constraints(task_constraints)
    _configure_reflexion(agent)

    for round_num in range(1, max_rounds + 1):
        result = AgentResult()
        result.target = agent.context.state.target
        result.phase = agent.context.state.phase.value

        system_prompt = agent._build_system_prompt(
            agent.context.state.target,
            auto_mode=True,
            user_input=agent.runtime.auto_skill_input or user_input,
        )
        round_context = agent._build_round_context(round_num, max_rounds)

        try:
            response_text = await call_llm_auto(agent, system_prompt, round_context, stream_sink=stream_sink)
            result.output = response_text
            agent.context.add_assistant_message(
                _("agent.loop.round_analysis", round=round_num, response=response_text)
            )
            agent._finding_parser.parse(response_text)

            if agent.runtime.is_recon_phase:
                agent._update_recon_dimension_completion(response_text)

            new_phase = agent._detect_phase_from_output(response_text)
            phase_violation = None
            if new_phase and new_phase != agent.context.state.phase:
                phase_violation = validate_phase_transition(
                    new_phase, agent.context.state.task_constraints
                )
                if phase_violation:
                    agent.context.state.add_constraint_violation_event(
                        source="phase",
                        action="exploit" if new_phase == PentestPhase.EXPLOITATION else "",
                        code="phase_transition_blocked",
                        severity="high",
                        summary=phase_violation,
                        detail=response_text[:500],
                    )
                    result.output = f"{response_text}\n[!] {phase_violation}"
                    result.should_continue = False
                else:
                    agent.context.state.advance_phase(new_phase)
                    result.phase = new_phase.value

            if phase_violation is None:
                result.should_continue = not agent._is_completion_signal(response_text)

            result.should_continue = update_ctf_state(agent, response_text, result.should_continue)

            if (
                agent.runtime.is_recon_phase
                and not result.should_continue
                and phase_violation is None
            ):
                if (
                    agent.runtime.is_ctf_mode
                    and agent.runtime.flag_verified
                    and agent.runtime.claimed_flag
                ):
                    pass
                elif round_num < RECON_MIN_ROUNDS:
                    result.should_continue = True
                elif not agent.context.state.is_recon_complete():
                    result.should_continue = True

            step_raw = f"Round {round_num}: {response_text[:100]}..."
            sig = re.sub(r"Round\s*\d+:", "", step_raw).strip()[:60].lower()
            sig = re.sub(r"\s+", "_", sig)
            sig = re.sub(r"[^\w]", "", sig)

            if sig not in agent.runtime.seen_step_signatures:
                agent.runtime.seen_step_signatures.add(sig)
                agent.context.state.add_step(step_raw)

            agent._track_failed_target(response_text)

            current_findings = len(agent.context.state.findings)
            current_notes = len(agent.context.state.notes)
            current_steps = len(agent.context.state.executed_steps)

            is_spinning = False
            recent_notes = agent.context.state.notes[-5:]
            if recent_notes:
                all_words: list[str] = []
                for note in recent_notes:
                    all_words.extend(re.findall(r"[\u4e00-\u9fff]+", note))
                if all_words:
                    word_counts = Counter(all_words)
                    if word_counts.most_common(1)[0][1] >= 3:
                        is_spinning = True

            last_step = (
                agent.context.state.executed_steps[-1] if agent.context.state.executed_steps else ""
            )
            is_meaningful = agent._is_meaningful_step(last_step)

            has_new_progress = (
                current_findings > agent.runtime.last_findings_count
                or (current_notes > agent.runtime.last_notes_count and not is_spinning)
                or (current_steps > agent.runtime.last_steps_count + 1 and is_meaningful)
            )

            if has_new_progress:
                agent.runtime.rounds_without_progress = 0
                agent.runtime.python_timeout_rounds = 0
            else:
                agent.runtime.rounds_without_progress += 1

            agent.runtime.last_findings_count = current_findings
            agent.runtime.last_notes_count = current_notes
            agent.runtime.last_steps_count = current_steps

            detected_path = agent._detect_attack_path(response_text)
            reflexion = getattr(agent.runtime, "reflexion", None)
            reflexion_on = getattr(agent.config.session, "reflexion_enabled", True) and hasattr(
                reflexion, "record_attempt"
            )
            failure_category = None if has_new_progress else classify_failure(response_text)
            if reflexion_on:
                reflexion.record_attempt(
                    path=detected_path or agent.runtime.current_attack_path or "unknown",
                    success=has_new_progress,
                    category=failure_category,
                    details=response_text[:200],
                    vuln_type=detected_path or "",
                )

            # 把攻击路径与障碍同步进结构化推理状态
            _sync_reasoning_path(agent, detected_path, success=has_new_progress)
            if failure_category is not None:
                _sync_reasoning_constraint(agent, detected_path, failure_category)

            if not has_new_progress and not agent.runtime.path_switch_forced:
                if detected_path:
                    if detected_path == agent.runtime.current_attack_path:
                        agent.runtime.same_path_fail_count += 1
                    else:
                        # 卡住后切换了攻击路径 = 一次反思事件，记录以闭合升级环
                        if (
                            reflexion_on
                            and agent.runtime.current_attack_path
                            and reflexion.should_reflect()
                        ):
                            reflexion.record_reflection(
                                old_path=agent.runtime.current_attack_path,
                                new_path=detected_path,
                                reasoning=response_text[:200],
                            )
                        agent.runtime.current_attack_path = detected_path
                        agent.runtime.same_path_fail_count = 0
                        agent.runtime.path_switch_forced = False
            elif has_new_progress:
                agent.runtime.same_path_fail_count = 0
                agent.runtime.path_switch_forced = False

            agent.context.state.save()

        except Exception as e:
            result.output = _("agent.loop.round_error", round=round_num, error=e)
            agent.runtime.consecutive_errors += 1
            await asyncio.sleep(min(2 ** (agent.runtime.consecutive_errors - 1), 8))
            if agent.runtime.consecutive_errors >= 3:
                result.should_continue = False
            else:
                result.should_continue = True
                agent.context.trim_messages(max_messages=20)
        else:
            agent.runtime.consecutive_errors = 0

        results.append(result)
        if on_step:
            on_step(round_num, result)
        if not result.should_continue:
            break

    # 把本周期反思记忆写回 SessionState 快照，供下个周期/同目标恢复时复用
    if hasattr(agent, "_save_reflexion_snapshot"):
        agent._save_reflexion_snapshot()
        agent.context.state.save()

    return results


async def persistent_pentest(
    agent: AgentContext,
    user_input: str,
    target: str | None = None,
    rounds_per_cycle: int = 100,
    max_cycles: int = 10,
    auto_report: bool = True,
    on_cycle_step: Callable[[int, int, AgentResult], None] | None = None,
    on_cycle_complete: Callable[[int, PersistentCycleResult], None] | None = None,
    *,
    # stream_sink 由 core.py 透传入，传给 agent.auto_pentest() 实现流式输出
    stream_sink: Any = None,
    task_constraints: TaskConstraints | None = None,
) -> list[PersistentCycleResult]:
    cycle_results: list[PersistentCycleResult] = []

    detected_target = target or agent._detect_target(user_input)
    if detected_target:
        agent.context.state.target = detected_target

    agent.context.add_user_message(user_input)
    agent._reset_runtime_state(user_input=user_input)
    if task_constraints is not None:
        agent.apply_task_constraints(task_constraints)

    findings_at_cycle_start = len(agent.context.state.findings)
    cycle_num = 0
    should_stop = False

    while not should_stop:
        cycle_num += 1
        if max_cycles > 0 and cycle_num > max_cycles:
            should_stop = True
            break

        cycle_results_list: list[AgentResult] = []

        # Snapshot which findings were already verified before this cycle runs, so
        # the cycle report can label only genuinely-new verified findings.
        prev_verified_ids = {
            f.finding_id for f in agent.context.state.get_verified_findings()
        }

        def _make_step_callback(cycle: int):
            def _on_step(round_num: int, result: AgentResult) -> None:
                cycle_results_list.append(result)
                if on_cycle_step:
                    on_cycle_step(round_num, cycle, result)

            return _on_step

        try:
            constraints_block = ""
            if getattr(agent.context.state, "task_constraints", None):
                rendered = agent.context.state.task_constraints.to_prompt_block()
                if rendered:
                    constraints_block = f"\n\n{rendered}"
            selected_engine = resolve_engine(agent.config)
            results = await agent.auto_pentest(
                user_input=(
                    _(
                        "agent.loop.persistent_cycle",
                        cycle=cycle_num,
                        target=agent.context.state.target or _("agent.loop.unknown"),
                    )
                    + constraints_block
                    if cycle_num > 1
                    else user_input
                ),
                target=agent.context.state.target,
                max_rounds=rounds_per_cycle,
                on_step=_make_step_callback(cycle_num),
                # 透传 stream_sink，使 persistent 模式也支持流式输出
                stream_sink=stream_sink,
                task_constraints=agent.context.state.task_constraints,
            )
            cycle_results_list = results if results else cycle_results_list
            if selected_engine == "solve":
                agent_state = agent.context.state.agent_state
                should_stop = bool(agent_state.completed or agent_state.pending_questions)
        except KeyboardInterrupt:
            should_stop = True
            cycle_results_list = cycle_results_list or []

        total_findings = len(agent.context.state.findings)
        total_steps = len(agent.context.state.executed_steps)
        new_findings = total_findings - findings_at_cycle_start
        findings_at_cycle_start = total_findings

        llm_summary = ""
        try:
            llm_summary = await agent._generate_attack_summary()
        except Exception:
            pass

        report_path = None
        if auto_report:
            try:
                from vulnclaw.report.generator import generate_persistent_cycle_report

                report_path = generate_persistent_cycle_report(
                    session=agent.context.state,
                    cycle_num=cycle_num,
                    total_findings=total_findings,
                    new_findings=new_findings,
                    total_steps=total_steps,
                    rounds_per_cycle=rounds_per_cycle,
                    llm_attack_summary=llm_summary,
                    prev_verified_ids=prev_verified_ids,
                )
            except Exception as e:
                report_path = _("agent.loop.report_failed", error=e)

        cycle_result = PersistentCycleResult(
            cycle_num=cycle_num,
            results=cycle_results_list,
            report_path=str(report_path) if report_path else None,
            total_findings=total_findings,
            total_steps=total_steps,
            stopped_early=should_stop,
        )
        cycle_results.append(cycle_result)

        if on_cycle_complete:
            on_cycle_complete(cycle_num, cycle_result)

        if cycle_results_list and not should_stop:
            last_result = cycle_results_list[-1]
            if not last_result.should_continue:
                if new_findings == 0 and total_findings > 0:
                    should_stop = True

    return cycle_results
