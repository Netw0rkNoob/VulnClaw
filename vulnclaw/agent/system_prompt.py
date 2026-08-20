"""Dynamic system prompt assembly for AgentCore."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from vulnclaw.agent.prompts import (
    build_system_prompt,
    get_auto_pentest_instruction,
    get_recon_instruction,
)

if TYPE_CHECKING:
    from vulnclaw.agent.context import TaskConstraints


def build_dynamic_system_prompt(
    *,
    target: Optional[str],
    phase: Optional[str],
    skill_context: Optional[str],
    mcp_tools: list[dict],
    enable_personnel_dim: bool,
    auto_mode: bool,
    user_input: Optional[str],
    kb_context: str,
    experience_context: str = "",
    task_constraints: Optional["TaskConstraints"] = None,
) -> str:
    """Build the dynamic system prompt for one turn."""
    prompt = build_system_prompt(
        target=target,
        phase=phase,
        skill_context=skill_context,
        mcp_tools=mcp_tools,
        enable_personnel_dim=enable_personnel_dim,
    )

    if auto_mode:
        prompt += "\n\n" + get_auto_pentest_instruction()

    if user_input:
        recon_triggers = [
            # Chinese triggers
            "搜集",
            "收集",
            "信息收集",
            "侦察",
            "社会工程",
            "社工",
            "调查",
            "作者",
            "人物",
            "情报",
            "分析目标",
            "目标分析",
            "资产发现",
            "子域名",
            # English triggers
            "recon",
            "osint",
            "reconnaissance",
            "gather info",
            "information gathering",
            "enumerat",
            "subdomain",
            "asset discovery",
            "social engineer",
            "footprint",
        ]
        if any(trigger in user_input.lower() for trigger in recon_triggers):
            prompt += "\n\n" + get_recon_instruction(enable_personnel_dim)

    if kb_context:
        prompt += "\n\n" + kb_context

    if experience_context:
        prompt += "\n\n" + experience_context

    if task_constraints is not None:
        constraints_block = task_constraints.to_prompt_block()
        if constraints_block:
            prompt += "\n\n" + constraints_block

    return prompt
