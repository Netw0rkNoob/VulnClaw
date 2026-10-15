"""Prompt/round-context helpers for AgentCore."""

from __future__ import annotations

from typing import TYPE_CHECKING

from vulnclaw.i18n import _
from vulnclaw.i18n.phases import localized_phase_name

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext



def build_round_context(agent: AgentContext, round_num: int, max_rounds: int) -> str:
    """Build context string for the current round in auto loop."""
    state = agent.context.state
    constraints_summary = ""
    constraints_block = (
        state.get_constraints_prompt_block()
        if hasattr(state, "get_constraints_prompt_block")
        else ""
    )
    if constraints_block:
        constraints_summary = f"\n\n{constraints_block}"

    reasoning_summary = ""
    session_config = getattr(agent.config, "session", None)
    reasoning_enabled = getattr(session_config, "reasoning_state_enabled", True)
    if reasoning_enabled:
        reasoning = getattr(state, "reasoning", None)
        reasoning_block = (
            reasoning.to_prompt_block()
            if hasattr(reasoning, "to_prompt_block")
            else ""
        )
        if reasoning_block:
            reasoning_summary = f"\n\n{reasoning_block}"

    reflexion_summary = ""
    reflexion_enabled = getattr(session_config, "reflexion_enabled", True)
    reflexion = getattr(agent.runtime, "reflexion", None)
    if reflexion_enabled and hasattr(reflexion, "to_prompt_block"):
        reflexion_block = reflexion.to_prompt_block()
        if reflexion_block:
            reflexion_summary = f"\n\n{reflexion_block}"
        if hasattr(reflexion, "to_reflection_prompt"):
            reflection_block = reflexion.to_reflection_prompt()
            if reflection_block:
                reflexion_summary += f"\n\n{reflection_block}"

    findings_summary = ""
    if state.findings:
        findings_summary = _("agent.runtime.findings_summary", count=len(state.findings))
        for finding in state.findings[-5:]:
            findings_summary += (
                f"\n  - [{finding.severity}] {finding.title}: {finding.evidence[:100]}"
            )

    user_hint_directive = ""
    if round_num <= agent.runtime.user_vuln_hint_rounds and agent.runtime.user_vuln_hint:
        user_hint_directive = (
            f"\n\n{'=' * 50}\n"
            f"{_('agent.runtime.user_hint_header', round=round_num, total=agent.runtime.user_vuln_hint_rounds)}\n"
            f"{agent.runtime.user_vuln_hint}\n"
            f"{'=' * 50}\n"
        )
        agent.runtime.user_vuln_hint_rounds -= 1

    steps_summary = ""
    if state.executed_steps:
        recent_steps = state.executed_steps[-8:]
        steps_summary = _("agent.runtime.recent_steps", count=len(state.executed_steps))
        for step in recent_steps:
            steps_summary += f"\n  - {step[:150]}"

    failed_summary = ""
    if state.executed_steps:
        failed_attempts = []
        failure_markers = [
            "失败",
            "没有",
            "返回相同",
            "被拦截",
            "404",
            "no",
            "未成功",
            "无效",
            "error",
            "failed",
            "still",
            "未发现",
            "无结果",
            "timeout",
            "禁止",
            "denied",
            "不存在",
            "无法",
            "不能",
            "不对",
        ]
        for step in state.executed_steps:
            if any(marker in step.lower() for marker in failure_markers):
                failed_attempts.append(step[:150])
        if failed_attempts:
            failed_summary = _("agent.runtime.failure_history")
            for failure in failed_attempts[-10:]:
                failed_summary += f"\n  ❌ {failure}"

    recon_summary = ""
    if state.recon_data:
        recon_summary = _("agent.runtime.recon_data", keys=list(state.recon_data.keys()))

    resume_summary = ""
    if getattr(state, "resume_summary", ""):
        resume_summary = f"\n\n{state.resume_summary}"

    notes_summary = ""
    if state.notes:
        notes_summary = _("agent.runtime.important_notes", notes="; ".join(state.notes[-5:]))

    facts_summary = ""
    if hasattr(state, "confirmed_facts") and state.confirmed_facts:
        facts_summary = _("agent.runtime.confirmed_facts")
        for fact in state.confirmed_facts[-8:]:
            facts_summary += f"\n  ✅ {fact[:150]}"

    assumptions_summary = ""
    if hasattr(state, "unverified_assumptions") and state.unverified_assumptions:
        assumptions_summary = _("agent.runtime.unverified_assumptions")
        for assumption in state.unverified_assumptions[-5:]:
            assumptions_summary += f"\n  ❓ {assumption[:150]}"
        assumptions_summary += _("agent.runtime.assumption_caution")

    path_warning = ""
    same_path_fails = agent.runtime.same_path_fail_count

    if state.executed_steps:
        recent = state.executed_steps[-8:]
        if len(recent) >= 5:
            recent_text = " ".join(recent).lower()
            stuck_indicators = ["get=", "post=", "payload", "参数", "尝试"]
            stuck_count = sum(
                1 for indicator in stuck_indicators if recent_text.count(indicator) >= 3
            )
            if stuck_count >= 1:
                path_warning = _("agent.runtime.path_stuck_warning")

    path_switch_warning = ""
    if not reflexion_enabled and same_path_fails >= 3:
        path_switch_warning = _("agent.runtime.path_switch_warning", count=same_path_fails)
        agent.runtime.same_path_fail_count = 0
        agent.runtime.path_switch_forced = True

    assumption_reminder = ""
    if round_num > 2 and round_num % 3 == 0:
        assumption_reminder = _("agent.runtime.assumption_checkpoint")

    python_timeout_warning = ""
    python_timeout_rounds = agent.runtime.python_timeout_rounds
    if python_timeout_rounds >= 1:
        python_timeout_warning = _("agent.runtime.python_timeout_warning")

    dead_loop_warning = ""
    rounds_no_progress = agent.runtime.rounds_without_progress
    stale_threshold = agent.config.session.stale_rounds_threshold

    blocked_targets_warning = ""
    blocked_targets = agent.runtime.blocked_targets
    if blocked_targets:
        target_lines = "\n".join(
            _("agent.runtime.blocked_target_item", target=target) for target in blocked_targets
        )
        blocked_targets_warning = _(
            "agent.runtime.blocked_targets_warning", targets=target_lines
        )

    if rounds_no_progress >= stale_threshold:
        dead_loop_warning = _("agent.runtime.dead_loop_severe", count=rounds_no_progress)
    elif rounds_no_progress >= max(stale_threshold // 2, 2):
        dead_loop_warning = _("agent.runtime.dead_loop_warning", count=rounds_no_progress)

    flag_warning = ""
    claimed_flag = agent.runtime.claimed_flag
    flag_verified = agent.runtime.flag_verified
    if claimed_flag and flag_verified:
        flag_warning = _("agent.runtime.flag_verified", flag=claimed_flag)
    elif claimed_flag and not flag_verified:
        flag_warning = _("agent.runtime.flag_unverified", flag=claimed_flag)

    ctf_mode_warning = ""
    is_ctf = agent.runtime.is_ctf_mode
    if is_ctf and not claimed_flag:
        ctf_mode_warning = _("agent.runtime.ctf_no_flag")
    elif is_ctf and claimed_flag and not flag_verified:
        ctf_mode_warning = _("agent.runtime.ctf_unverified_flag")

    recon_dim_status = ""
    if agent.runtime.is_recon_phase:
        dim_status_text = state.get_recon_status_text()
        is_complete = state.is_recon_complete()
        rounds_no_progress = agent.runtime.rounds_without_progress

        recon_dim_status = _("agent.runtime.recon_dimension_status", status=dim_status_text)
        if not is_complete:
            recon_dim_status += _("agent.runtime.recon_incomplete")
        elif (is_complete and rounds_no_progress >= 3) or (rounds_no_progress >= 8 + 5):
            output_dir = str(agent.config.session.output_dir.resolve())
            if is_complete:
                trigger_reason = _(
                    "agent.runtime.recon_trigger_complete", count=rounds_no_progress
                )
            else:
                trigger_reason = _(
                    "agent.runtime.recon_trigger_safety", count=rounds_no_progress
                )
            recon_dim_status += _(
                "agent.runtime.recon_force_switch",
                reason=trigger_reason,
                output_dir=output_dir,
            )
        if round_num < 8:
            recon_dim_status += _("agent.runtime.recon_min_rounds", round=round_num)

    return (
        _("agent.runtime.loop_header", round=round_num, total=max_rounds)
        + _("agent.runtime.current_target", target=state.target or _("agent.common.not_set"))
        + _("agent.runtime.current_phase", phase=localized_phase_name(state.phase))
        + _("agent.runtime.output_dir", path=agent.config.session.output_dir.resolve())
        + constraints_summary
        + reasoning_summary
        + reflexion_summary
        + user_hint_directive
        + findings_summary
        + facts_summary
        + assumptions_summary
        + steps_summary
        + failed_summary
        + recon_summary
        + resume_summary
        + notes_summary
        + path_warning
        + path_switch_warning
        + assumption_reminder
        + python_timeout_warning
        + blocked_targets_warning
        + dead_loop_warning
        + flag_warning
        + ctf_mode_warning
        + recon_dim_status
        + _("agent.runtime.next_action_instruction")
    )


async def generate_attack_summary(agent: AgentContext) -> str:
    """Generate a detailed attack path summary for the cycle report."""
    state = agent.context.state

    steps = state.executed_steps[-30:] if state.executed_steps else []
    steps_text = (
        "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps))
        if steps
        else _("agent.summary.no_steps")
    )

    notes = state.notes[-20:] if state.notes else []
    notes_text = (
        "\n".join(f"- {note}" for note in notes) if notes else _("agent.summary.no_notes")
    )

    findings = state.findings
    if findings:
        lines = []
        for finding in findings:
            evidence = (finding.evidence or "")[:150].strip()
            lines.append(
                _(
                    "agent.summary.finding",
                    severity=finding.severity,
                    title=finding.title,
                    evidence=evidence or _("agent.common.none"),
                    outcome=finding.assessment.outcome if finding.assessment else "pending",
                )
            )
        findings_text = "\n".join(lines)
    else:
        findings_text = _("agent.common.none")

    prompt = _(
        "agent.summary.prompt",
        target=state.target or "?",
        phase=localized_phase_name(state.phase),
        steps=steps_text,
        notes=notes_text,
        findings=findings_text,
    )

    try:
        client = agent._get_client()
        messages = [{"role": "user", "content": prompt}]
        from vulnclaw.agent.llm_client import _fit_context_window, build_chat_completion_kwargs

        messages = _fit_context_window(agent, messages, [], purpose="persistent_summary")

        response = client.chat.completions.create(
            **build_chat_completion_kwargs(
                agent,
                messages,
                max_tokens=800,
                temperature=0.3,
            )
        )
        if response and response.choices:
            raw = response.choices[0].message.content or ""
            from vulnclaw.agent.think_filter import strip_think_tags

            return strip_think_tags(raw).strip()
    except Exception:
        pass
    return ""
