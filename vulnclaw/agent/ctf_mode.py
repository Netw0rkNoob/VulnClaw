"""CTF flag state-machine helpers for AgentCore."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext



def detect_flag_claim(output: str) -> Optional[str]:
    """Detect if the LLM claims to have found a flag."""
    flag_patterns = [
        r"(NSSCTF\{[^}]+\})",
        r"(CTF\{[^}]+\})",
        r"(flag\{[^}]+\})",
        r"(Flag\{[^}]+\})",
        r"(FLAG\{[^}]+\})",
    ]
    for pattern in flag_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def update_ctf_state(agent: AgentContext, response_text: str, result_should_continue: bool) -> bool:
    """Update flag claim/verification state and return should_continue."""
    if agent.runtime.claimed_flag and not agent.runtime.flag_verified:
        verification_markers = [
            "验证成功",
            "验证通过",
            "已验证",
            "复现成功",
            "确认flag",
            "verified",
            "confirmed",
            "flag正确",
            "提交成功",
            "flag 获取成功",
            "flag获取成功",
            "获取成功",
            "找到flag",
            "flag found",
            "成功获取",
            "获取了flag",
            "拿到了flag",
            "成功拿到",
            "成功找到",
            "解题完成",
            "解题成功",
            "verification successful",
            "verification passed",
            "flag verified",
            "flag confirmed",
            "submission successful",
            "flag acquired",
            "successfully obtained",
            "solved the challenge",
            "challenge solved",
            "got the flag",
            "obtained the flag",
        ]
        if any(marker in response_text.lower() for marker in verification_markers):
            agent.runtime.flag_verified = True

    if agent.runtime.is_ctf_mode and agent.runtime.claimed_flag and not agent.runtime.flag_verified:
        flag_in_notes_count = sum(
            1 for note in agent.context.state.notes if agent.runtime.claimed_flag in note
        )
        if flag_in_notes_count >= 2:
            agent.runtime.flag_verified = True
        elif flag_in_notes_count >= 1 and agent.runtime.claimed_flag in response_text:
            agent.runtime.flag_verified = True

    claimed_flag = detect_flag_claim(response_text)
    if claimed_flag:
        if not agent.runtime.claimed_flag:
            agent.runtime.claimed_flag = claimed_flag
            agent.runtime.flag_verified = False
            result_should_continue = True
        elif agent.runtime.claimed_flag == claimed_flag and not agent.runtime.flag_verified:
            agent.runtime.flag_claim_count += 1
            if agent.runtime.flag_claim_count >= 3:
                agent.runtime.flag_verified = True
            else:
                result_should_continue = True

    if agent.runtime.is_ctf_mode and not result_should_continue:
        if not agent.runtime.flag_verified or not agent.runtime.claimed_flag:
            result_should_continue = True

    if agent.runtime.flag_verified and agent.runtime.claimed_flag:
        agent.runtime.post_flag_rounds += 1
        if agent.runtime.post_flag_rounds >= 2:
            result_should_continue = False
    if agent.runtime.flag_verified and agent.runtime.claimed_flag and result_should_continue:
        # Once the flag is verified, allow only a short wrap-up window.
        if agent.runtime.post_flag_rounds >= 1 and "[done]" not in response_text.lower():
            result_should_continue = False

    return result_should_continue
