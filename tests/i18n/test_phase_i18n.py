"""Bilingual regression tests for phase headings in prompts and reports."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnclaw.agent.context import PentestPhase, SessionState
from vulnclaw.agent.prompts import build_system_prompt
from vulnclaw.i18n import current_lang, init_i18n
from vulnclaw.i18n.phases import canonical_phase_id, localized_phase_name
from vulnclaw.report.generator import generate_persistent_cycle_report, generate_report


@pytest.mark.parametrize(
    ("phase", "phase_id"),
    [
        (PentestPhase.IDLE, "idle"),
        (PentestPhase.RECON, "recon"),
        (PentestPhase.VULN_DISCOVERY, "vuln_discovery"),
        (PentestPhase.EXPLOITATION, "exploitation"),
        (PentestPhase.POST_EXPLOITATION, "post_exploitation"),
        (PentestPhase.REPORTING, "reporting"),
    ],
)
def test_phase_lookup_uses_canonical_id_for_enum_and_legacy_value(phase, phase_id):
    assert canonical_phase_id(phase) == phase_id
    assert canonical_phase_id(phase.value) == phase_id


@pytest.mark.parametrize(
    ("language", "expected_names"),
    [
        (
            "en",
            {
                PentestPhase.RECON: "Recon",
                PentestPhase.VULN_DISCOVERY: "Vulnerability Discovery",
                PentestPhase.EXPLOITATION: "Exploitation",
                PentestPhase.POST_EXPLOITATION: "Post-exploitation",
                PentestPhase.REPORTING: "Reporting",
            },
        ),
        (
            "zh",
            {
                PentestPhase.RECON: "信息收集",
                PentestPhase.VULN_DISCOVERY: "漏洞发现",
                PentestPhase.EXPLOITATION: "漏洞利用",
                PentestPhase.POST_EXPLOITATION: "后渗透",
                PentestPhase.REPORTING: "报告生成",
            },
        ),
    ],
)
def test_all_prompt_phase_headings_follow_explicit_language(language, expected_names, monkeypatch):
    previous_lang = current_lang()
    monkeypatch.setenv("LANG", "fr_FR.UTF-8")
    init_i18n(lang=language)
    try:
        for phase, expected_name in expected_names.items():
            prompt = build_system_prompt(phase=phase)
            if language == "en":
                assert f"## Current Phase: {expected_name}" in prompt
                assert "## 当前阶段：" not in prompt
            else:
                assert f"## 当前阶段：{expected_name}" in prompt
                assert "## Current Phase:" not in prompt
            assert localized_phase_name(phase.name.lower()) == expected_name
    finally:
        init_i18n(lang=previous_lang)


@pytest.mark.parametrize(
    ("language", "expected_headings", "unexpected_heading"),
    [
        (
            "en",
            ("### Recon (1 step)", "### Exploitation (2 steps)"),
            "### 漏洞利用（共 2 步）",
        ),
        (
            "zh",
            ("### 信息收集（共 1 步）", "### 漏洞利用（共 2 步）"),
            "### Exploitation (2 steps)",
        ),
    ],
)
async def test_standard_and_cycle_report_phase_headings_follow_explicit_language(
    language, expected_headings, unexpected_heading, monkeypatch, tmp_path
):
    previous_lang = current_lang()
    monkeypatch.setenv("LANG", "fr_FR.UTF-8")
    monkeypatch.setattr(
        "vulnclaw.report.generator._generate_attack_summary_from_session",
        lambda session: "",
    )
    init_i18n(lang=language)
    try:
        session = SessionState(target="https://example.test")
        for phase in (
            PentestPhase.RECON,
            PentestPhase.VULN_DISCOVERY,
            PentestPhase.EXPLOITATION,
        ):
            session.advance_phase(phase)
        session.add_step("verified exploit", action="verify exploit", result="confirmed")

        report_path = await generate_report(session, str(tmp_path / "report.md"))
        cycle_path = await generate_persistent_cycle_report(
            session,
            cycle_num=1,
            output_path=str(tmp_path / "cycle.md"),
        )

        for output_path in (report_path, cycle_path):
            content = Path(output_path).read_text(encoding="utf-8")
            for expected_heading in expected_headings:
                assert expected_heading in content
            assert unexpected_heading not in content
    finally:
        init_i18n(lang=previous_lang)


def _has_chinese(text: str) -> bool:
    return any("一" <= ch <= "鿿" for ch in text)


@pytest.mark.parametrize(
    ("language", "expected_action", "expected_step_fragment"),
    [
        ("en", "Phase transition", "Phase transition"),
        ("zh", "阶段切换", "阶段切换"),
    ],
)
def test_phase_transition_step_record_follows_explicit_language(
    language, expected_action, expected_step_fragment, monkeypatch
):
    previous_lang = current_lang()
    monkeypatch.setenv("LANG", "fr_FR.UTF-8")
    init_i18n(lang=language)
    try:
        session = SessionState(target="https://example.test")
        session.advance_phase(PentestPhase.RECON)
        record = session.step_records[-1]
        step_text = session.executed_steps[-1]

        assert record.action == expected_action
        assert expected_step_fragment in step_text
        if language == "en":
            assert not _has_chinese(step_text)
            assert not _has_chinese(record.action)
            assert not _has_chinese(record.result)
    finally:
        init_i18n(lang=previous_lang)
