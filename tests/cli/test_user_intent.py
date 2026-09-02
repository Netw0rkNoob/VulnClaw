"""Tests for conversational check-in routing helpers."""

from vulnclaw.cli.main import _should_auto_pentest
from vulnclaw.cli.user_intent import (
    continue_task_prompt,
    is_affirmative_continue,
    is_conversational_checkin,
)


class TestIsConversationalCheckin:
    def test_ready_to_begin_bug_hunting(self):
        assert is_conversational_checkin("ready to begin bug hunting?") is True

    def test_are_we_ready(self):
        assert is_conversational_checkin("are we ready?") is True

    def test_zh_readiness(self):
        assert is_conversational_checkin("准备好开始了吗？") is True

    def test_short_meta_question(self):
        assert is_conversational_checkin("what's the plan?") is True

    def test_affirmative_not_checkin(self):
        assert is_conversational_checkin("yes") is False
        assert is_affirmative_continue("yes") is True

    def test_operational_with_url_not_checkin(self):
        assert is_conversational_checkin("scan https://example.com for XSS?") is False

    def test_imperative_start_not_checkin(self):
        assert is_conversational_checkin("start recon") is False
        assert is_conversational_checkin("scan it") is False

    def test_plain_work_order_not_checkin(self):
        assert is_conversational_checkin("recon crypto.com") is False

    def test_operational_request_phrased_as_question_not_checkin(self):
        # A concrete testing directive must still run, even without a URL and
        # even when politely phrased as a question.
        assert is_conversational_checkin("Can you test the login for SQL injection?") is False
        assert is_conversational_checkin("could you check the upload form for XSS?") is False
        assert is_conversational_checkin("能帮我测一下登录框的 SQL 注入吗？") is False

    def test_readiness_question_still_checkin_even_with_action_word(self):
        assert is_conversational_checkin("ready to begin bug hunting?") is True
        assert is_conversational_checkin("should we start scanning now?") is True


class TestShouldAutoPentestRespectsCheckin:
    def test_checkin_never_enters_auto_even_with_target(self):
        assert _should_auto_pentest("ready to begin bug hunting?", "https://hackerone.com") is False

    def test_explicit_recon_still_auto(self):
        assert _should_auto_pentest("start recon", "https://api.example.com") is True


class TestContinueTaskPrompt:
    def test_uses_prior_task(self):
        prompt = continue_task_prompt("/hackerone crypto", "https://hackerone.com")
        assert "Prior task" in prompt
        assert "crypto" in prompt

    def test_fallback_to_target(self):
        prompt = continue_task_prompt("yes", "https://web.crypto.com")
        assert "web.crypto.com" in prompt
