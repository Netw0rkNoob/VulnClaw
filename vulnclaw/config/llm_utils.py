"""LLM utility functions — shared across all layers.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V2 残留 — build_chat_completion_kwargs 原依赖 AgentContext 协议，
         此处重构为接受 llm_config 对象的纯函数，消除 agent/ 依赖。
"""

from __future__ import annotations

import re
from typing import Any

_KIMI_FIXED_TEMPERATURE_RE = re.compile(r"kimi-k(\d+)(?:\.(\d+))?", re.IGNORECASE)
_KIMI_FIXED_TEMPERATURE_MIN = (2, 5)


def _is_openai_reasoning_model(provider: str, model: str) -> bool:
    """Return True for OpenAI models that use the newer reasoning parameter set."""
    if provider.lower() != "openai":
        return False
    normalized = model.lower()
    return normalized.startswith(("o1", "o3", "o4", "gpt-5"))


def _has_fixed_temperature(model: str) -> bool:
    """Return True when the model pins ``temperature`` server-side.

    Moonshot's Kimi K2.5 and later (K2.5/K2.6/K2.7/K3) reject requests that
    pass an explicit temperature, so callers must omit the field and let the
    service apply its fixed value. Match the model name rather than the
    provider so vendor-prefixed IDs on gateways (``moonshotai/kimi-k3``) are
    covered too.
    """
    name = str(model or "").rsplit("/", 1)[-1]
    match = _KIMI_FIXED_TEMPERATURE_RE.match(name)
    if not match:
        return False
    version = (int(match.group(1)), int(match.group(2) or 0))
    return version >= _KIMI_FIXED_TEMPERATURE_MIN


def build_chat_completion_kwargs(
    llm_config: Any,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> dict[str, Any]:
    """Build provider-compatible Chat Completions kwargs.

    OpenAI reasoning/GPT-5 models reject the legacy max_tokens field and expect
    max_completion_tokens instead. Other OpenAI-compatible providers may still
    require the older field, so keep the switch scoped to OpenAI's newer model
    families.

    Models that pin temperature server-side (Kimi K2.5+) reject any explicit
    value, so the field is omitted for them.

    Args:
        llm_config: An object with attributes: provider, model, max_tokens,
                    temperature, reasoning_effort (typically config.llm).
        messages: Chat messages list.
        tools: Optional OpenAI tool schemas.
        max_tokens: Override for max tokens.
        temperature: Override for temperature.
    """
    provider = str(getattr(llm_config, "provider", "") or "").lower()
    model = str(getattr(llm_config, "model", "") or "")
    token_limit = max_tokens if max_tokens is not None else getattr(llm_config, "max_tokens", None)
    temp = temperature if temperature is not None else getattr(llm_config, "temperature", None)
    uses_reasoning_params = _is_openai_reasoning_model(provider, model)
    has_fixed_temperature = _has_fixed_temperature(model)

    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    if token_limit is not None:
        if uses_reasoning_params:
            kwargs["max_completion_tokens"] = token_limit
        else:
            kwargs["max_tokens"] = token_limit
    if temp is not None and not uses_reasoning_params and not has_fixed_temperature:
        kwargs["temperature"] = temp
    if tools:
        kwargs["tools"] = tools
    if uses_reasoning_params:
        reasoning_effort = getattr(llm_config, "reasoning_effort", None)
        if reasoning_effort:
            kwargs["reasoning_effort"] = reasoning_effort
    return kwargs
