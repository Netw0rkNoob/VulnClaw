"""LLM utility functions — shared across all layers.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V2 残留 — build_chat_completion_kwargs 原依赖 AgentContext 协议，
         此处重构为接受 llm_config 对象的纯函数，消除 agent/ 依赖。
"""

from __future__ import annotations

from typing import Any


def _is_openai_reasoning_model(provider: str, model: str) -> bool:
    """Return True for OpenAI models that use the newer reasoning parameter set."""
    if provider.lower() != "openai":
        return False
    normalized = model.lower()
    return normalized.startswith(("o1", "o3", "o4", "gpt-5"))


def build_chat_completion_kwargs(
    llm_config: Any,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
    extra_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build provider-compatible Chat Completions kwargs.

    OpenAI reasoning/GPT-5 models reject the legacy max_tokens field and expect
    max_completion_tokens instead. Other OpenAI-compatible providers may still
    require the older field, so keep the switch scoped to OpenAI's newer model
    families.

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

    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    if token_limit is not None:
        if uses_reasoning_params:
            kwargs["max_completion_tokens"] = token_limit
        else:
            kwargs["max_tokens"] = token_limit
    if temp is not None and not uses_reasoning_params:
        kwargs["temperature"] = temp
    if tools:
        kwargs["tools"] = tools
    if uses_reasoning_params:
        reasoning_effort = getattr(llm_config, "reasoning_effort", None)
        if reasoning_effort:
            kwargs["reasoning_effort"] = reasoning_effort
    if extra_body:
        kwargs["extra_body"] = dict(extra_body)
    if provider == "openrouter":
        merged_extra_body = dict(extra_body or {})
        raw_provider_policy = merged_extra_body.get("provider")
        provider_policy = (
            dict(raw_provider_policy) if isinstance(raw_provider_policy, dict) else {}
        )
        provider_policy["require_parameters"] = True
        merged_extra_body["provider"] = provider_policy
        kwargs["extra_body"] = merged_extra_body
    return kwargs
