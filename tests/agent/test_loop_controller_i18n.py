from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from vulnclaw.agent import loop_controller
from vulnclaw.agent.core import AgentCore
from vulnclaw.agent.runtime_state import AgentResult
from vulnclaw.config.schema import VulnClawConfig


def _agent(tmp_path) -> AgentCore:
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    return AgentCore(config)


@pytest.mark.asyncio
async def test_auto_pentest_renders_round_errors_in_english(
    tmp_path, monkeypatch, i18n_language
):
    agent = _agent(tmp_path)

    async def fail_llm(*args, **kwargs):
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(loop_controller, "call_llm_auto", fail_llm)
    i18n_language("en")
    results = await loop_controller.auto_pentest(agent, "scan example.com", max_rounds=1)

    assert results[0].output == "[!] Round 1 error: provider unavailable"


@pytest.mark.asyncio
async def test_persistent_pentest_localizes_cycle_narration_and_report_errors(
    tmp_path, monkeypatch, i18n_language
):
    agent = _agent(tmp_path)
    prompts: list[str] = []

    async def fake_auto_pentest(*, user_input, **kwargs):
        prompts.append(user_input)
        return [AgentResult(output="ok", should_continue=True)]

    async def fake_summary():
        return ""

    def fail_report(**kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(agent, "auto_pentest", fake_auto_pentest)
    monkeypatch.setattr(agent, "_generate_attack_summary", fake_summary)
    monkeypatch.setattr(
        "vulnclaw.report.generator.generate_persistent_cycle_report", AsyncMock(side_effect=fail_report)
    )

    i18n_language("en")
    results = await loop_controller.persistent_pentest(
        agent,
        "scan example.com",
        target="example.com",
        rounds_per_cycle=1,
        max_cycles=2,
    )

    assert prompts[1].startswith(
        "[Persistent Cycle 2] Continue penetration testing target example.com."
    )
    assert results[0].report_path == "Report generation failed: disk full"
