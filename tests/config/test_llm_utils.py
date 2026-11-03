"""Tests for fixed-temperature model handling in build_chat_completion_kwargs.

Kimi K2.5 and later pin temperature server-side and reject requests that
send any other value, so the kwargs builder must omit the field entirely
for those models — including call-site overrides such as the doctor probe's
hard-coded 0.0 and gateway-prefixed model ids like ``moonshotai/kimi-k3``.
"""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.config.llm_utils import build_chat_completion_kwargs

_MESSAGES = [{"role": "user", "content": "hi"}]


def _llm_config(model: str, provider: str = "moonshot", temperature: float | None = 0.1):
    return SimpleNamespace(
        provider=provider,
        model=model,
        max_tokens=4096,
        temperature=temperature,
        reasoning_effort=None,
    )


def test_moonshot_preset_model_omits_config_temperature():
    kwargs = build_chat_completion_kwargs(_llm_config("kimi-k3"), _MESSAGES)
    assert "temperature" not in kwargs


def test_probe_style_override_temperature_is_omitted():
    # `vulnclaw doctor --probe-llm` passes temperature=0.0 explicitly.
    kwargs = build_chat_completion_kwargs(
        _llm_config("kimi-k3"), _MESSAGES, max_tokens=200, temperature=0.0
    )
    assert "temperature" not in kwargs
    assert kwargs["max_tokens"] == 200


def test_gateway_prefixed_model_id_is_covered():
    kwargs = build_chat_completion_kwargs(_llm_config("moonshotai/kimi-k2.6"), _MESSAGES)
    assert "temperature" not in kwargs


def test_fixed_temperature_version_matrix():
    from vulnclaw.config.llm_utils import _has_fixed_temperature

    for model in ("kimi-k2.5", "kimi-k2.6", "kimi-k2.7", "kimi-k3", "moonshotai/kimi-k3"):
        assert _has_fixed_temperature(model), model
    for model in ("kimi-k2", "kimi-k2-0711-preview", "moonshot-v1-8k", "gpt-4o", ""):
        assert not _has_fixed_temperature(model), model


def test_older_kimi_keeps_temperature():
    kwargs = build_chat_completion_kwargs(_llm_config("kimi-k2"), _MESSAGES)
    assert kwargs["temperature"] == 0.1


def test_unrelated_model_request_shape_unchanged():
    kwargs = build_chat_completion_kwargs(_llm_config("gpt-4o", provider="openai"), _MESSAGES)
    assert kwargs["temperature"] == 0.1
    assert kwargs["max_tokens"] == 4096
