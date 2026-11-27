"""Tests for provider-compatible Chat Completions kwargs."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.config.llm_utils import build_chat_completion_kwargs

_MESSAGES = [{"role": "user", "content": "hi"}]


def _llm(model: str, *, provider: str = "moonshot", temperature: float = 0.1):
    return SimpleNamespace(
        provider=provider,
        model=model,
        max_tokens=4096,
        temperature=temperature,
        reasoning_effort=None,
    )


@pytest.mark.parametrize(
    "model",
    [
        "kimi-k2.5",
        "kimi-k2.6",
        "kimi-k2.7",
        "kimi-k3",
        "Kimi-K3-0905",
        "moonshotai/kimi-k3",
        "moonshot/kimi-k2.6-turbo",
    ],
)
def test_kimi_models_with_fixed_temperature_omit_the_field(model):
    kwargs = build_chat_completion_kwargs(_llm(model), _MESSAGES)

    assert "temperature" not in kwargs
    assert kwargs["model"] == model
    assert kwargs["max_tokens"] == 4096


def test_explicit_temperature_override_is_also_omitted_for_kimi():
    kwargs = build_chat_completion_kwargs(
        _llm("kimi-k3"),
        _MESSAGES,
        max_tokens=200,
        temperature=0.0,
    )

    assert "temperature" not in kwargs
    assert kwargs["max_tokens"] == 200


def test_fixed_temperature_is_matched_across_providers():
    kwargs = build_chat_completion_kwargs(
        _llm("moonshotai/kimi-k3", provider="openrouter"), _MESSAGES
    )

    assert "temperature" not in kwargs


@pytest.mark.parametrize(
    "model",
    ["kimi-k2", "kimi-k2-0905", "moonshot-v1-8k", "deepseek-chat", "gpt-4o"],
)
def test_other_models_keep_the_configured_temperature(model):
    kwargs = build_chat_completion_kwargs(
        _llm(model, provider="custom", temperature=0.3), _MESSAGES
    )

    assert kwargs["temperature"] == 0.3
