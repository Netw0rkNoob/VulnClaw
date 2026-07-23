"""Tests for multi-key failover rotation in the LLM call retry loop."""

import sys
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from types import ModuleType, SimpleNamespace

import pytest

from vulnclaw.agent.llm_client import (
    OPENROUTER_MAX_TRANSIENT_ATTEMPTS,
    OpenRouterResponseError,
    _call_with_persistent_retries,
    _is_key_exhausted_error,
    _parse_retry_after,
)


class FakeAgent:
    """Minimal stand-in exposing the key-pool surface the retry loop uses."""

    def __init__(self, keys):
        self._key_pool = list(keys)
        self._key_index = 0

    def current_key(self):
        return self._key_pool[self._key_index]

    def rotate_api_key(self) -> bool:
        if len(self._key_pool) > 1:
            self._key_index = (self._key_index + 1) % len(self._key_pool)
            return True
        return False


class OpenRouterFakeAgent(FakeAgent):
    config = SimpleNamespace(llm=SimpleNamespace(provider="openrouter"))


class FakeHTTPError(RuntimeError):
    def __init__(
        self,
        status_code: int,
        *,
        retry_after: str | None = None,
        secret: str = "fake-secret-in-upstream-body",
    ):
        super().__init__(f"upstream returned {status_code}: {secret}")
        self.status_code = status_code
        headers = {"x-request-id": "req_safe_123"}
        if retry_after is not None:
            headers["retry-after"] = retry_after
        self.response = SimpleNamespace(status_code=status_code, headers=headers)
        self.body = {
            "error": {
                "message": f"unsafe detail {secret}",
                "metadata": {"error_type": "provider_error"},
            }
        }


def _ok_response():
    return SimpleNamespace(choices=[object()])


def _full_ok_response():
    message = SimpleNamespace(content="ok", tool_calls=None, reasoning_content=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class TestIsKeyExhaustedError:
    def test_detects_rate_limit_and_quota_signals(self):
        for text in [
            "error code: 429 too many requests",
            "rate limit exceeded",
            "rate_limit_exceeded",
            "your quota has been exhausted",
            "deepseek: insufficient balance (402)",
            "账户余额不足",
            "code 1302 concurrency limit",
            "code 1113 balance",
        ]:
            assert _is_key_exhausted_error(text.lower()) is True, text

    def test_ignores_unrelated_errors(self):
        for text in [
            "connection reset by peer",
            "model not found",
            "invalid function arguments json string",
        ]:
            assert _is_key_exhausted_error(text.lower()) is False, text


class TestRotateApiKey:
    def test_rotate_advances_index(self):
        agent = FakeAgent(["k1", "k2"])
        assert agent.current_key() == "k1"
        assert agent.rotate_api_key() is True
        assert agent.current_key() == "k2"

    def test_rotate_single_key_is_noop(self):
        agent = FakeAgent(["only"])
        assert agent.rotate_api_key() is False
        assert agent.current_key() == "only"


class TestFailover:
    async def test_rotates_past_rate_limited_key(self):
        agent = FakeAgent(["bad", "good"])

        def request_fn():
            if agent.current_key() == "bad":
                raise RuntimeError("Error code: 429 - rate limit exceeded")
            return _ok_response()

        response, _ = await _call_with_persistent_retries(agent, request_fn, "test")
        assert response.choices
        assert agent.current_key() == "good"

    async def test_rotates_past_invalid_key_then_succeeds(self):
        agent = FakeAgent(["bad", "good"])

        def request_fn():
            if agent.current_key() == "bad":
                raise RuntimeError("invalid api key provided")
            return _ok_response()

        response, _ = await _call_with_persistent_retries(agent, request_fn, "test")
        assert response.choices
        assert agent.current_key() == "good"

    async def test_raises_when_all_keys_invalid(self):
        agent = FakeAgent(["bad1", "bad2"])

        def request_fn():
            raise RuntimeError("invalid api key provided")

        with pytest.raises(RuntimeError):
            await _call_with_persistent_retries(agent, request_fn, "test")

    async def test_single_key_auth_error_raises_fast(self):
        agent = FakeAgent(["only"])

        def request_fn():
            raise RuntimeError("unauthorized: invalid api key")

        with pytest.raises(RuntimeError):
            await _call_with_persistent_retries(agent, request_fn, "test")


class TestOpenRouterFailover:
    async def test_401_rotates_to_each_other_static_key_once(self):
        agent = OpenRouterFakeAgent(["bad", "good"])
        calls = []

        def request_fn():
            calls.append(agent.current_key())
            if agent.current_key() == "bad":
                raise FakeHTTPError(401)
            return _ok_response()

        response, retries = await _call_with_persistent_retries(
            agent, request_fn, "openrouter"
        )

        assert response.choices
        assert retries == 1
        assert calls == ["bad", "good"]
        assert agent.current_key() == "good"

    async def test_401_fails_after_one_pass_without_leaking_secret(self, capsys):
        agent = OpenRouterFakeAgent(["bad-1", "bad-2", "bad-3"])
        calls = 0

        def request_fn():
            nonlocal calls
            calls += 1
            raise FakeHTTPError(401, secret="sk-never-print")

        with pytest.raises(OpenRouterResponseError) as caught:
            await _call_with_persistent_retries(agent, request_fn, "openrouter")

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert calls == 3
        assert "sk-never-print" not in str(caught.value)
        assert "sk-never-print" not in output
        assert "req_safe_123" in str(caught.value)

    async def test_401_stops_if_key_rotation_cannot_advance(self):
        agent = OpenRouterFakeAgent(["bad-1", "bad-2"])
        agent.rotate_api_key = lambda: False
        calls = 0

        def request_fn():
            nonlocal calls
            calls += 1
            raise FakeHTTPError(401)

        with pytest.raises(OpenRouterResponseError):
            await _call_with_persistent_retries(agent, request_fn, "openrouter")

        assert calls == 1

    async def test_402_is_terminal_and_does_not_rotate(self):
        agent = OpenRouterFakeAgent(["first", "second"])
        calls = 0

        def request_fn():
            nonlocal calls
            calls += 1
            raise FakeHTTPError(402)

        with pytest.raises(OpenRouterResponseError, match="credits"):
            await _call_with_persistent_retries(agent, request_fn, "openrouter")

        assert calls == 1
        assert agent.current_key() == "first"

    @pytest.mark.parametrize("status_code", [429, 503])
    async def test_transient_statuses_are_bounded_without_key_rotation(
        self, monkeypatch, status_code
    ):
        agent = OpenRouterFakeAgent(["first", "second"])
        calls = 0
        sleeps = []

        def request_fn():
            nonlocal calls
            calls += 1
            raise FakeHTTPError(status_code, retry_after="0")

        async def fake_sleep(delay):
            sleeps.append(delay)

        monkeypatch.setattr(
            "vulnclaw.agent.llm_client.asyncio.sleep",
            fake_sleep,
        )

        with pytest.raises(OpenRouterResponseError):
            await _call_with_persistent_retries(agent, request_fn, "openrouter")

        assert calls == OPENROUTER_MAX_TRANSIENT_ATTEMPTS
        assert len(sleeps) == OPENROUTER_MAX_TRANSIENT_ATTEMPTS - 1
        assert agent.current_key() == "first"

    async def test_retry_after_delta_seconds_is_honored(self, monkeypatch):
        agent = OpenRouterFakeAgent(["first", "second"])
        calls = 0
        sleeps = []

        def request_fn():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise FakeHTTPError(429, retry_after="7")
            return _ok_response()

        async def fake_sleep(delay):
            sleeps.append(delay)

        monkeypatch.setattr(
            "vulnclaw.agent.llm_client.asyncio.sleep",
            fake_sleep,
        )

        await _call_with_persistent_retries(agent, request_fn, "openrouter")

        assert sleeps == [7.0]
        assert agent.current_key() == "first"

    async def test_in_band_error_is_rejected_before_response_acceptance(self):
        agent = OpenRouterFakeAgent(["only"])
        response = SimpleNamespace(
            error={
                "code": 402,
                "message": "unsafe fake-secret-in-upstream-body",
                "metadata": {"error_type": "payment_required"},
            },
            choices=[SimpleNamespace(finish_reason="error")],
        )

        with pytest.raises(OpenRouterResponseError, match="credits") as caught:
            await _call_with_persistent_retries(
                agent,
                lambda: response,
                "openrouter",
            )

        assert "fake-secret-in-upstream-body" not in str(caught.value)

    @pytest.mark.parametrize(
        "response",
        [
            SimpleNamespace(error={}, choices=[SimpleNamespace()]),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        error={},
                        finish_reason=None,
                    )
                ]
            ),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(error={}),
                        finish_reason=None,
                    )
                ]
            ),
        ],
    )
    async def test_explicit_empty_error_fails_closed(self, response):
        agent = OpenRouterFakeAgent(["only"])

        with pytest.raises(OpenRouterResponseError):
            await _call_with_persistent_retries(
                agent,
                lambda: response,
                "openrouter",
            )

    @pytest.mark.parametrize(
        "response",
        [
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        error={"code": 402, "message": "unsafe choice error"},
                        finish_reason=None,
                    )
                ]
            ),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        error=None,
                        finish_reason="error",
                    )
                ]
            ),
        ],
    )
    async def test_error_choice_and_error_finish_reason_fail_closed(self, response):
        agent = OpenRouterFakeAgent(["only"])

        with pytest.raises(OpenRouterResponseError):
            await _call_with_persistent_retries(
                agent,
                lambda: response,
                "openrouter",
            )


class TestOpenRouterCallPaths:
    @staticmethod
    def _agent(responses):
        captured_kwargs = []

        class DummyClient:
            def __init__(self):
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self.create)
                )

            def create(self, **kwargs):
                captured_kwargs.append(kwargs)
                return responses.pop(0)

        class DummyAgent:
            _key_pool = ["fake-key"]
            _key_index = 0

            config = SimpleNamespace(
                llm=SimpleNamespace(
                    provider="openrouter",
                    model="openai/gpt-4o",
                    max_tokens=256,
                    temperature=0.1,
                    reasoning_effort="high",
                )
            )
            context = SimpleNamespace(get_messages=lambda: [])

            @staticmethod
            def _build_openai_tools():
                return []

            def __init__(self):
                self.client = DummyClient()

            def _get_client(self):
                return self.client

        return DummyAgent(), captured_kwargs

    async def test_call_llm_rejects_in_band_error(self):
        from vulnclaw.agent.llm_client import call_llm

        response = SimpleNamespace(
            error={"code": 402, "message": "unsafe upstream detail"},
            choices=[SimpleNamespace(finish_reason="error")],
        )
        agent, captured = self._agent([response])

        with pytest.raises(OpenRouterResponseError):
            await call_llm(agent, "system")

        assert captured[0]["extra_body"]["provider"]["require_parameters"] is True

    async def test_tool_summary_rejects_error_and_reuses_request_guard(
        self, monkeypatch
    ):
        from vulnclaw.agent import llm_client

        tool_call = SimpleNamespace(
            id="call_1",
            function=SimpleNamespace(name="test_tool", arguments="{}"),
        )
        initial = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="", tool_calls=[tool_call])
                )
            ]
        )
        summary_error = SimpleNamespace(
            error={"code": 402, "message": "unsafe upstream detail"},
            choices=[SimpleNamespace(finish_reason="error")],
        )
        agent, captured = self._agent([initial, summary_error])

        async def fake_tool_results(agent_obj, message):
            return [
                {
                    "tool_call": message.tool_calls[0],
                    "tool_call_id": "call_1",
                    "content": "tool output",
                }
            ], []

        monkeypatch.setattr(
            llm_client,
            "handle_tool_calls_with_results",
            fake_tool_results,
        )

        with pytest.raises(OpenRouterResponseError):
            await llm_client.call_llm_auto(agent, "system", "round")

        assert len(captured) == 2
        assert all(
            item["extra_body"]["provider"]["require_parameters"] is True
            for item in captured
        )


class TestRetryAfter:
    def test_parses_delta_seconds_and_caps_large_values(self):
        assert _parse_retry_after("5") == 5.0
        assert _parse_retry_after("999") == 60.0

    def test_parses_http_date(self):
        now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
        value = format_datetime(now + timedelta(seconds=25), usegmt=True)

        assert _parse_retry_after(value, now=now) == 25.0

    @pytest.mark.parametrize("value", ["", "not-a-date", "-1", "-3.5"])
    def test_rejects_malformed_or_negative_values(self, value):
        assert _parse_retry_after(value) is None


class TestCallLlmUsesRotatedClient:
    """Regression test: call_llm/call_llm_auto must not close over a stale client.

    rotate_api_key() invalidates agent._client so the *next* _get_client() call
    rebuilds with the new key. If call_llm_auto captured `client =
    agent._get_client()` once and reused it across retries, every retry after a
    rotation would still hit the old (failed) key's client. The retry loop must
    call agent._get_client() fresh on every attempt.
    """

    async def test_call_llm_auto_retries_with_freshly_rotated_client(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            async def run_in_executor(self, executor, fn):
                return fn()

        class DummyClient:
            def __init__(self, key):
                self.key = key
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self._create)
                )

            def _create(self, **kwargs):
                if self.key == "bad":
                    raise RuntimeError("Error code: 429 - rate limit exceeded")
                return _full_ok_response()

        class DummyAgent:
            _key_pool = ["bad", "good"]
            _key_index = 0

            class _Config:
                class _LLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return []

                @staticmethod
                def add_assistant_message(text):
                    return None

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                # Mirrors AgentCore._get_client(): reflects the *current*
                # rotation index, not whatever was current when first called.
                return DummyClient(self._key_pool[self._key_index])

            def rotate_api_key(self) -> bool:
                if len(self._key_pool) > 1:
                    self._key_index = (self._key_index + 1) % len(self._key_pool)
                    return True
                return False

        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())

        result = await llm_client.call_llm_auto(dummy, "sys", "round")

        assert dummy._key_index == 1
        assert "ok" in result

    async def test_call_llm_retries_with_freshly_rotated_client(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            async def run_in_executor(self, executor, fn):
                return fn()

        class DummyClient:
            def __init__(self, key):
                self.key = key
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self._create)
                )

            def _create(self, **kwargs):
                if self.key == "bad":
                    raise RuntimeError("invalid api key provided")
                return _full_ok_response()

        class DummyAgent:
            _key_pool = ["bad", "good"]
            _key_index = 0

            class _Config:
                class _LLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return []

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return DummyClient(self._key_pool[self._key_index])

            def rotate_api_key(self) -> bool:
                if len(self._key_pool) > 1:
                    self._key_index = (self._key_index + 1) % len(self._key_pool)
                    return True
                return False

        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())

        await llm_client.call_llm(dummy, "sys")

        assert dummy._key_index == 1


class TestAgentCoreRotation:
    def _agent(self, **llm):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        for k, v in llm.items():
            setattr(config.llm, k, v)
        return AgentCore(config)

    def test_pool_from_api_keys(self):
        agent = self._agent(api_keys=["k1", "k2"])
        assert agent._key_pool == ["k1", "k2"]
        assert agent._current_api_key() == "k1"

    def test_pool_falls_back_to_single_key(self):
        agent = self._agent(api_key="solo")
        assert agent._key_pool == ["solo"]
        assert agent.rotate_api_key() is False

    def test_rotate_advances_and_invalidates_client(self, monkeypatch):
        fake_openai = ModuleType("openai")

        class FakeOpenAI:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        fake_openai.OpenAI = FakeOpenAI
        monkeypatch.setitem(sys.modules, "openai", fake_openai)

        agent = self._agent(api_keys=["k1", "k2"])
        agent._get_client()
        assert agent._client is not None
        assert agent.rotate_api_key() is True
        assert agent._client is None
        assert agent._current_api_key() == "k2"
