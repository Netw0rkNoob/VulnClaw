"""LLM client helpers for AgentCore."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Optional, Protocol, runtime_checkable

from vulnclaw.agent.subagent.budget import (
    fail_request as _fail_subagent_llm_admission,
)
from vulnclaw.agent.subagent.budget import (
    fit_messages as _hard_fit_subagent_messages,
)
from vulnclaw.agent.subagent.budget import (
    is_subagent as _is_subagent,
)
from vulnclaw.agent.subagent.budget import (
    prepare_request as _prepare_subagent_llm_request,
)
from vulnclaw.agent.subagent.budget import (
    record_usage as _record_subagent_llm_usage,
)
from vulnclaw.agent.subagent.budget import (
    reserve_request as _reserve_subagent_llm_request,
)
from vulnclaw.agent.subagent.budget import (
    settle_request as _settle_subagent_llm_admission,
)

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext

logger = logging.getLogger(__name__)

from vulnclaw.agent.context_budget import prepare_context  # noqa: E402
from vulnclaw.agent.cost_budget import (  # noqa: E402
    SessionCostExceeded,
    check_and_accumulate_cost,
)
from vulnclaw.agent.token_counter import (  # noqa: E402
    estimate_tokens,
    group_tool_exchanges,
    truncate_messages,
)
from vulnclaw.agent.tool_call_manager import (  # noqa: E402
    handle_tool_calls,
    handle_tool_calls_with_results,
)

_CONTEXT_USABLE_RATIO = 0.9
_DEFAULT_AUTO_TOOL_ROUNDS = 6
_TOOL_LOOP_TARGET_RATIO = 26_000 / 32_000
_SYNC_STREAM_END = object()


def _next_sync_stream_item(iterator: Any) -> Any:
    try:
        return next(iterator)
    except StopIteration:
        return _SYNC_STREAM_END


async def _create_streaming_response(
    agent: AgentContext, kwargs: dict[str, Any]
) -> Any:
    """Open a synchronous provider stream without blocking sibling agents."""

    create = agent._get_client().chat.completions.create
    response = await asyncio.to_thread(create, **kwargs, stream=True)
    if inspect.isawaitable(response):
        response = await response
    return response


def _fit_context_window(
    agent: AgentContext,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    *,
    purpose: str = "agent",
) -> list[dict[str, Any]]:
    """Fit messages to the configured context window via the unified budget."""
    result = prepare_context(agent, messages, tools, purpose=purpose)
    if result.compacted or result.reason:
        logger.info(
            "Context budget %d -> %d tokens (%s)",
            result.before_tokens,
            result.after_tokens,
            result.reason or "prepared",
        )
    # Subagent hard-fit: subagent budgets are tighter than the LLM window;
    # clamp again when the prepare step left a subagent working set oversized.
    if _is_subagent(agent):
        llm = getattr(agent, "config", None)
        llm = getattr(llm, "llm", None) if llm is not None else None
        max_context = getattr(llm, "max_context_tokens", None)
        if (
            isinstance(max_context, (int, float))
            and not isinstance(max_context, bool)
            and max_context > 0
        ):
            budget = int(max_context * _CONTEXT_USABLE_RATIO)
            if estimate_tokens(result.messages) > budget:
                return _hard_fit_subagent_messages(result.messages, budget)
    return result.messages


def _tool_loop_hot_budget(agent: AgentContext) -> int:
    """Return the high-water mark for one internal tool-loop working set."""
    context = getattr(agent, "context", None)
    budget = getattr(context, "max_tokens", 32_000)
    if not isinstance(budget, (int, float)) or isinstance(budget, bool):
        return 32_000
    return max(1_024, int(budget))


def _tool_loop_target_budget(agent: AgentContext) -> int:
    """Return the post-compaction target, 26K for the default 32K high-water mark."""
    high_water = _tool_loop_hot_budget(agent)
    return min(high_water, max(1_024, int(high_water * _TOOL_LOOP_TARGET_RATIO)))


def _build_tool_loop_messages(
    agent: AgentContext,
    system_prompt: str,
    round_context: str,
    *,
    include_history: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build a stable prefix followed by the mutable internal tool-loop tail.

    The prefix is created once per ``call_llm_auto`` invocation and never
    reordered while its tool loop runs: system prompt, bounded hot history,
    then the current task instruction.  Assistant/tool exchanges are appended
    after it as the mutable tail.  This lets providers reuse the unchanged
    prefix between tool rounds until a high-water compaction is necessary.
    """
    messages = [{"role": "system", "content": system_prompt}]
    if include_history:
        messages.extend(agent.context.get_messages())
    round_message = {"role": "user", "content": round_context}
    messages.append(round_message)
    return messages, round_message


def _fit_tool_loop_context(
    agent: AgentContext,
    messages: list[dict[str, Any]],
    round_message: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compact an oversized tool-loop tail without breaking tool exchanges.

    ``ContextManager`` bounds persisted history, but a single ``call_llm_auto``
    can append several assistant/tool exchanges before it returns.  Compact that
    local working set only after it crosses the high-water mark.  It then falls
    back to a lower target (26K for the default 32K high-water mark), preserving
    the stable system/task prefix and complete recent tool exchanges.
    """
    high_water = _tool_loop_hot_budget(agent)
    if estimate_tokens(messages) <= high_water:
        return messages
    target = _tool_loop_target_budget(agent)

    try:
        round_index = next(
            index for index, message in enumerate(messages) if message is round_message
        )
    except StopIteration:
        return truncate_messages(messages, target, preserve_system=True)

    system_messages = (
        [messages[0]] if messages and messages[0].get("role") == "system" else []
    )
    history_start = len(system_messages)
    history = messages[history_start:round_index]
    tool_loop = messages[round_index + 1 :]
    required = [*system_messages, round_message]
    if estimate_tokens(required) >= target:
        return truncate_messages(required, target, preserve_system=True, min_recent=1)

    running = estimate_tokens(required)

    def keep_recent(
        groups: list[list[dict[str, Any]]],
    ) -> list[list[dict[str, Any]]]:
        nonlocal running
        kept: list[list[dict[str, Any]]] = []
        for group in reversed(groups):
            cost = estimate_tokens(group)
            if running + cost > target:
                break
            running += cost
            kept.insert(0, group)
        return kept

    # Prefer the evidence acquired in this still-active tool loop, then fill
    # remaining space with older persistent history.
    kept_tool_loop = keep_recent(group_tool_exchanges(tool_loop))
    kept_history = keep_recent(group_tool_exchanges(history))
    return [
        *system_messages,
        *(message for group in kept_history for message in group),
        round_message,
        *(message for group in kept_tool_loop for message in group),
    ]


def _resolve_auto_tool_rounds(agent: AgentContext, max_tool_rounds: int | None = None) -> int:
    """Resolve the internal follow-up cap for one model-led turn."""

    if isinstance(max_tool_rounds, int) and max_tool_rounds > 0:
        return max_tool_rounds
    session = getattr(getattr(agent, "config", None), "session", None)
    configured = getattr(session, "solve_max_tool_rounds", None)
    if isinstance(configured, int) and configured > 0:
        return configured
    return _DEFAULT_AUTO_TOOL_ROUNDS


def _tool_call_to_message_dict(tool_call: Any) -> dict[str, Any]:
    """Convert provider tool-call objects into Chat Completions message dicts."""

    function = getattr(tool_call, "function", None)
    return {
        "id": str(getattr(tool_call, "id", "") or ""),
        "type": str(getattr(tool_call, "type", "") or "function"),
        "function": {
            "name": str(getattr(function, "name", "") or ""),
            "arguments": str(getattr(function, "arguments", "") or ""),
        },
    }


def _assistant_tool_message(content: str, tool_calls: list[Any]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": content or "",
        "tool_calls": [_tool_call_to_message_dict(tool_call) for tool_call in tool_calls],
    }


def _tool_result_messages(tool_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for item in tool_results:
        if not isinstance(item, dict):
            continue
        tool_call_id = str(item.get("tool_call_id") or "")
        if not tool_call_id:
            tool_call = item.get("tool_call")
            tool_call_id = str(getattr(tool_call, "id", "") or "")
        if not tool_call_id:
            continue
        messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": str(item.get("content", "") or ""),
        })
    return messages


def _append_context_message(agent: AgentContext, message: dict[str, Any]) -> None:
    context = getattr(agent, "context", None)
    if context is None:
        return
    add_message = getattr(context, "add_message", None)
    if callable(add_message):
        add_message(message)
        return
    role = message.get("role")
    content = str(message.get("content", "") or "")
    if role == "assistant" and content and callable(getattr(context, "add_assistant_message", None)):
        context.add_assistant_message(content)
    elif role == "user" and content and callable(getattr(context, "add_user_message", None)):
        context.add_user_message(content)


def _message_from_stream(full_text: str, tool_calls: list[Any]) -> Any:
    return SimpleNamespace(content=full_text, tool_calls=tool_calls)


async def _stream_chat_completion_message(
    agent: AgentContext,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    stream_sink: "StreamSink",
) -> Any:
    """Run one streaming Chat Completions request and return a message-like object."""

    kwargs = build_chat_completion_kwargs(agent, messages, tools)
    stream_sink.on_status("Thinking...")
    response = await _create_streaming_response(agent, kwargs)

    full_text = ""
    reasoning_buffer = ""
    tool_calls_chunks: list[dict] = []
    stream = _ensure_async_iter(response)
    if stream is None:
        raise ValueError("LLM response is not a valid stream object")

    async for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        reasoning = getattr(delta, "reasoning_content", None) or ""
        if reasoning:
            reasoning_buffer += reasoning
            stream_sink.on_thinking_token(reasoning)

        content = getattr(delta, "content", None) or ""
        if content:
            if reasoning_buffer:
                full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
                reasoning_buffer = ""
            stream_sink.on_content_token(content)
            full_text += content

        _collect_tool_call_deltas(delta, tool_calls_chunks)

    if reasoning_buffer:
        full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
    stream_sink.on_stream_end()
    return _message_from_stream(full_text, _assemble_tool_calls(tool_calls_chunks))


def extract_response(message: Any) -> str:
    """Extract the actual response text from an LLM message.

    Handles:
    1. Normal content (no thinking)
    2. Content with inline <thinking> tags (open/closed)
    3. Separate reasoning_content field (DeepSeek R1, etc.)
    """
    content = message.content or ""
    reasoning = getattr(message, "reasoning_content", None) or ""
    if reasoning and not content:
        content = f"<thinking>\n{reasoning}\n</thinking>\n"
    elif reasoning and content:
        content = f"<thinking>\n{reasoning}\n</thinking>\n{content}"
    return content


def _is_non_retriable_llm_error(error_text: str) -> bool:
    """Return True for configuration/auth errors that should fail fast."""
    hard_fail_markers = [
        "bad_request_error",
        "incorrect api key",
        "invalid api key",
        "invalid chat setting",
        "invalid function arguments json string",
        "tool_call_id",
        "authentication",
        "unauthorized",
        "permission denied",
        "model not found",
        "no such model",
        "invalid_request_error",
        "unsupported parameter",
    ]
    return any(marker in error_text for marker in hard_fail_markers)


def _is_key_exhausted_error(error_text: str) -> bool:
    """Return True for errors that mean the *current* API key is unusable.

    These are rate-limit / quota / balance exhaustion signals where switching to
    a different key is the right recovery. Covers OpenAI-style 429/quota plus
    deepseek (402 insufficient balance) and zhipu (codes 1302/1113, 余额) errors.
    """
    exhausted_markers = [
        "rate limit",
        "rate_limit",
        "too many requests",
        "429",
        "quota",
        "insufficient balance",
        "余额",  # zhipu/deepseek: account balance insufficient
        "402",
        "1302",  # zhipu: concurrency / rate limit
        "1113",  # zhipu: account balance insufficient
    ]
    return any(marker in error_text for marker in exhausted_markers)


def _is_openai_reasoning_model(provider: str, model: str) -> bool:
    """Return True for OpenAI models that use the newer reasoning parameter set."""
    if provider.lower() != "openai":
        return False
    normalized = model.lower()
    return normalized.startswith(("o1", "o3", "o4", "gpt-5"))


# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: V2 修复 — 核心逻辑已移至 config/llm_utils.py，此处提供向后兼容包装。
from vulnclaw.config.llm_utils import (  # noqa: E402
    build_chat_completion_kwargs as _build_chat_completion_kwargs_llm,
)


def build_chat_completion_kwargs(
    agent: AgentContext,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> dict[str, Any]:
    """Build provider-compatible Chat Completions kwargs.

    Backward-compatible wrapper that accepts AgentContext and delegates to
    config/llm_utils.build_chat_completion_kwargs with agent.config.llm.
    """
    max_tokens = _prepare_subagent_llm_request(agent, messages, max_tokens)

    return _build_chat_completion_kwargs_llm(
        agent.config.llm,
        messages,
        tools,
        max_tokens=max_tokens,
        temperature=temperature,
    )


async def _call_with_persistent_retries_unbudgeted(
    agent: AgentContext, request_fn, stage_label: str, max_retries: int = 20
) -> tuple[Any, int]:
    """Keep retrying retriable LLM calls until success, max retries, or manual interruption.

    Args:
        max_retries: Maximum number of retry attempts before raising RuntimeError.
                     Default is 20 (at 5s intervals = ~100s total wait).

    Returns:
        (response, retry_attempts)

    Raises:
        RuntimeError: If max_retries is exceeded.
    """
    loop = asyncio.get_running_loop()
    retry_attempts = 0
    pool_size = len(getattr(agent, "_key_pool", None) or [])
    can_rotate = pool_size > 1 and callable(getattr(agent, "rotate_api_key", None))
    keys_tried: set[int] = set()

    while retry_attempts < max_retries:
        try:
            maybe_response = loop.run_in_executor(None, request_fn)
            response = await maybe_response if inspect.isawaitable(maybe_response) else maybe_response
            if response is not None and getattr(response, "choices", None):
                return response, retry_attempts

            retry_attempts += 1
            logger.warning(
                "%s LLM API 异常响应，第 %d 次重连尝试中... (5s 后重试)",
                stage_label, retry_attempts,
            )
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            raise
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            error_text = str(exc).lower()
            is_exhausted = _is_key_exhausted_error(error_text)
            is_auth = _is_non_retriable_llm_error(error_text)

            # Multi-key failover: rotate past a rate-limited / quota-drained /
            # invalid key to the next one before falling back to plain retry.
            if can_rotate and (is_exhausted or is_auth):
                keys_tried.add(getattr(agent, "_key_index", 0))
                if len(keys_tried) < pool_size:
                    agent.rotate_api_key()
                    retry_attempts += 1
                    logger.warning(
                        "%s 当前密钥失败 (%s)，切换到下一个 API 密钥并重试...",
                        stage_label, exc,
                    )
                    continue
                # Every key has now failed in this burst.
                if is_auth and not is_exhausted:
                    # All keys are invalid/unauthorized -> nothing to recover.
                    raise
                # All keys rate-limited: keep cycling, but back off first so we
                # never hard-fail on transient quota limits.
                keys_tried.clear()
                agent.rotate_api_key()
                retry_attempts += 1
                logger.warning(
                    "%s 所有 API 密钥均已限流，第 %d 次重连尝试中... (5s 后重试)",
                    stage_label, retry_attempts,
                )
                await asyncio.sleep(5)
                continue

            if is_auth and not is_exhausted:
                raise

            retry_attempts += 1
            logger.warning(
                "%s LLM 连接异常，第 %d 次重连尝试中... (%s)",
                stage_label, retry_attempts, exc,
            )
            await asyncio.sleep(5)

    raise RuntimeError(
        f"{stage_label} LLM 调用失败：已达到最大重试次数 {max_retries}"
    )


async def _call_with_persistent_retries(
    agent: AgentContext, request_fn, stage_label: str, max_retries: int = 20
) -> tuple[Any, int]:
    """Note: the subagent-scoped token budget above (reserve/settle) and the
    session-wide USD cost ceiling below are two independent, complementary
    checks -- the former bounds a sub-agent's own token allotment, the latter
    bounds real dollar spend for the whole session (main agent included,
    which the subagent budget never covers -- see is_subagent() in
    subagent/budget.py). Checked once per call, before issuing it, mirroring
    how solve_max_steps already gates once per round rather than mid-call.
    """
    safety = getattr(getattr(agent, "config", None), "safety", None)
    limit_usd = float(getattr(safety, "max_session_cost_usd", 0.0) or 0.0)
    if limit_usd > 0 and float(getattr(agent, "session_cost_usd", 0.0) or 0.0) > limit_usd:
        raise SessionCostExceeded(float(agent.session_cost_usd), limit_usd)

    admission = _reserve_subagent_llm_request(agent)
    try:
        response, retries = await _call_with_persistent_retries_unbudgeted(
            agent, request_fn, stage_label, max_retries
        )
        actual_tokens = _record_subagent_llm_usage(agent, response)
        _settle_subagent_llm_admission(agent, admission, actual_tokens)
        admission = None
        try:
            check_and_accumulate_cost(agent, response)
        except SessionCostExceeded:
            # This call's tokens are already spent -- returning the response
            # it paid for doesn't cost anything further. The pre-check above
            # stops the *next* call once session_cost_usd (just updated) is
            # past the ceiling.
            pass
        return response, retries
    finally:
        if admission is not None:
            _fail_subagent_llm_admission(agent, admission)


def _prepend_retry_notice(text: str, retry_attempts: int) -> str:
    """Annotate a successful response if retries happened within the same round."""
    if retry_attempts <= 0:
        return text
    return f"[LLM恢复] 本轮在第 {retry_attempts} 次重连后恢复。\n{text}"


def _format_tool_results_fallback(
    tool_results: list[dict[str, Any]],
    skipped_info: list[str],
    *,
    assistant_text: str = "",
) -> str:
    """Build deterministic tool-result text from the model-facing observations."""

    parts = [
        "[tool results processed] 工具调用已执行；未进行额外 LLM 总结；已降级为纯文本结果摘要。"
    ]
    if assistant_text.strip():
        parts.append(f"模型行动理由: {assistant_text.strip()[:600]}")
    for item in tool_results:
        if not isinstance(item, dict):
            parts.append(str(item))
            continue
        content = str(item.get("content", ""))
        duration_ms = item.get("duration_ms")
        correction = str(item.get("correction") or "").strip()
        prefix = ""
        tool_call = item.get("tool_call")
        tool_name = getattr(getattr(tool_call, "function", None), "name", "")
        if tool_name:
            prefix = f"工具 {tool_name}"
            if isinstance(duration_ms, int):
                prefix += f" ({duration_ms}ms)"
            prefix += ": "
        parts.append(prefix + content)
        if correction:
            parts.append(f"纠偏信号: {correction}")
    if skipped_info:
        parts.append("本轮提示: " + "; ".join(skipped_info))
    return "\n".join(parts)


async def call_llm(
    agent: AgentContext,
    system_prompt: str,
    *,
    stream_sink: Optional["StreamSink"] = None,
) -> str:
    """Call the LLM with the current context and system prompt (single turn)."""
    if stream_sink is not None:
        return await call_llm_stream(agent, system_prompt, stream_sink)

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    tools = agent._build_openai_tools()
    messages = _fit_context_window(agent, messages, tools, purpose="single_turn")

    kwargs = build_chat_completion_kwargs(agent, messages, tools)
    response, retry_attempts = await _call_with_persistent_retries(
        agent,
        lambda: agent._get_client().chat.completions.create(**kwargs),
        "single turn",
    )

    choice = response.choices[0]
    if choice.message.tool_calls:
        return _prepend_retry_notice(await handle_tool_calls(agent, choice.message), retry_attempts)
    return _prepend_retry_notice(extract_response(choice.message), retry_attempts)


async def call_llm_auto(
    agent: AgentContext,
    system_prompt: str,
    round_context: str,
    *,
    stream_sink: Optional["StreamSink"] = None,
    include_history: bool = True,
    max_tool_rounds: int | None = None,
) -> str:
    """Call the LLM in auto-pentest mode with round context appended.

    The model-led solve engine records assistant tool calls and role=tool
    observations in the chat transcript. Large raw outputs are stored in
    AgentState evidence and represented here by bounded high-signal previews,
    which keeps the active context useful without discarding raw evidence.
    """
    if stream_sink is not None:
        return await call_llm_auto_stream(
            agent,
            system_prompt,
            round_context,
            stream_sink,
            include_history=include_history,
            max_tool_rounds=max_tool_rounds,
        )

    messages, round_message = _build_tool_loop_messages(
        agent,
        system_prompt,
        round_context,
        include_history=include_history,
    )
    tools = agent._build_openai_tools()
    messages = _fit_context_window(agent, messages, tools, purpose="autonomous_turn")

    retry_attempts_total = 0
    last_tool_results: list[dict[str, Any]] | None = None
    last_skipped_info: list[str] = []
    last_assistant_text = ""
    for _tool_round in range(_resolve_auto_tool_rounds(agent, max_tool_rounds) + 1):
        messages = _fit_context_window(
            agent,
            messages,
            tools,
            purpose="autonomous_tool_follow_up",
        )
        kwargs = build_chat_completion_kwargs(agent, messages, tools)
        try:
            response, retry_attempts = await _call_with_persistent_retries(
                agent,
                lambda: agent._get_client().chat.completions.create(**kwargs),
                "autonomous loop",
            )
        except Exception as exc:
            if last_tool_results is not None:
                fallback = _format_tool_results_fallback(
                    last_tool_results,
                    last_skipped_info,
                    assistant_text=last_assistant_text,
                )
                return _prepend_retry_notice(
                    f"{fallback}\n[llm follow-up failed] {exc}",
                    retry_attempts_total,
                )
            raise
        retry_attempts_total += retry_attempts

        choice = response.choices[0]
        tool_calls = list(getattr(choice.message, "tool_calls", None) or [])
        if not tool_calls:
            return _prepend_retry_notice(extract_response(choice.message), retry_attempts_total)

        tool_results, skipped_info = await handle_tool_calls_with_results(agent, choice.message)
        last_tool_results = tool_results
        last_skipped_info = skipped_info
        last_assistant_text = choice.message.content or ""
        executed_tool_calls = [
            item.get("tool_call")
            for item in tool_results
            if isinstance(item, dict) and item.get("tool_call") is not None
        ]
        if not executed_tool_calls:
            return _prepend_retry_notice(
                _format_tool_results_fallback(
                    tool_results,
                    skipped_info,
                    assistant_text=choice.message.content or "",
                ),
                retry_attempts_total,
            )

        assistant_message = _assistant_tool_message(
            extract_response(choice.message),
            executed_tool_calls,
        )
        tool_messages = _tool_result_messages(tool_results)
        messages.append(assistant_message)
        messages.extend(tool_messages)
        messages = _fit_tool_loop_context(agent, messages, round_message)
        if include_history:
            _append_context_message(agent, assistant_message)
            for tool_message in tool_messages:
                _append_context_message(agent, tool_message)

    return _prepend_retry_notice(
        "[tool loop paused] Internal tool follow-up cap reached; continue from the recorded tool evidence.",
        retry_attempts_total,
    )

# === Stream LLM Call Helpers ===


class _AsyncIterWrapper:
    """Wrap sync iterable as async iterable for unified async for usage.

    OpenAI sync client → sync Stream（需包装后 async for）
    测试 mock / async client → async Stream（直接用 async for）
    """

    def __init__(self, iterable):
        self._iter = iter(iterable)

    def __aiter__(self):
        return self

    async def __anext__(self):
        item = await asyncio.to_thread(_next_sync_stream_item, self._iter)
        if item is _SYNC_STREAM_END:
            raise StopAsyncIteration
        return item


def _ensure_async_iter(response):
    """返回 async 可迭代对象，兼容 sync 和 async Stream。

    检查顺序：async 可迭代 → sync 可迭代 → 不可迭代返回 None（触发降级）。
    """
    if hasattr(response, "__aiter__"):
        return response
    if hasattr(response, "__iter__"):
        return _AsyncIterWrapper(response)
    return None  # 不是可迭代对象，由调用方走降级路径


def _collect_tool_call_deltas(delta: Any, tool_calls_chunks: list[dict]) -> None:
    """从单个流式 delta 中提取 tool_call 分片，追加到累积列表。

    处理各 provider 的差异：
    - 某些 provider 第一个分片只带 id（function 字段为 None）
    - 某些 provider name 与 arguments 分别在不同分片到达
    - index 缺失/为 None（回退到 0）
    - tc_delta 本身为 None
    """
    tc = getattr(delta, "tool_calls", None)
    if not tc:
        return
    for tc_delta in tc:
        if tc_delta is None:
            continue
        # function 字段在仅含 id 的首个分片中可能为 None
        func = getattr(tc_delta, "function", None)
        if func is not None:
            name = getattr(func, "name", None) or ""
            arguments = getattr(func, "arguments", None) or ""
        else:
            name = ""
            arguments = ""
        index = getattr(tc_delta, "index", None)
        if index is None:
            index = 0
        tool_calls_chunks.append({
            "index": index,
            "id": getattr(tc_delta, "id", None) or "",
            "function": {"name": name, "arguments": arguments},
        })


def _validate_tool_call(tool_call: Any) -> bool:
    """验证聚合后的 tool_call 是否完整可用。

    要求：
    - id 非空（某些 provider 仅在首个分片给出，分片丢失会导致空 id）
    - function.name 非空
    - arguments 为合法 JSON 或空字符串（流式中断会产生截断的不完整 JSON）
    """
    tc_id = getattr(tool_call, "id", None)
    if not tc_id:
        return False
    func = getattr(tool_call, "function", None)
    if func is None or not getattr(func, "name", None):
        return False
    arguments = getattr(func, "arguments", None)
    if arguments in (None, ""):
        return True
    try:
        json.loads(arguments)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def _build_tool_call(tc_id: str, name: str, arguments: str) -> Any:
    """构造一个 tool_call 对象。

    优先使用 OpenAI 官方 pydantic 类型（生产路径）；导入失败时回退到等价
    轻量对象（仅暴露下游用到的 .id/.type/.function.name/.function.arguments），
    保证组装逻辑可在不安装 openai 的环境中独立测试。
    """
    try:
        from openai.types.chat.chat_completion_message_tool_call import (
            ChatCompletionMessageToolCall,
            Function,
        )

        return ChatCompletionMessageToolCall(
            id=tc_id,
            type="function",
            function=Function(name=name, arguments=arguments),
        )
    except (TypeError, ValueError, AttributeError, ImportError):
        func = type("Function", (), {"name": name, "arguments": arguments})()
        return type("ToolCall", (), {"id": tc_id, "type": "function", "function": func})()


def _assemble_tool_calls(tool_calls_chunks: list[dict]) -> list[Any]:
    """将累积的流式分片按 index 聚合为完整 tool_call 列表。

    跨多个 chunk 分片到达的 id/name/arguments 按 index 对齐拼接。
    聚合后逐个校验，丢弃缺失 id、缺失 name 或 arguments JSON 不完整的调用并记录警告。
    """
    if not tool_calls_chunks:
        return []

    # 按 index 对齐拼接（dict 保持首次出现顺序）
    tc_by_index: dict[int, dict] = {}
    for tc_chunk in tool_calls_chunks:
        idx = tc_chunk["index"]
        if idx not in tc_by_index:
            tc_by_index[idx] = {"id": "", "function": {"name": "", "arguments": ""}}
        tc_by_index[idx]["id"] += tc_chunk["id"]
        tc_by_index[idx]["function"]["name"] += tc_chunk["function"]["name"]
        tc_by_index[idx]["function"]["arguments"] += tc_chunk["function"]["arguments"]

    tool_calls: list[Any] = []
    for tc_data in tc_by_index.values():
        candidate = _build_tool_call(
            tc_data["id"],
            tc_data["function"]["name"],
            tc_data["function"]["arguments"],
        )
        if not _validate_tool_call(candidate):
            logger.warning(
                "丢弃不完整的流式 tool_call: id=%r name=%r args=%r",
                tc_data["id"],
                tc_data["function"]["name"],
                tc_data["function"]["arguments"][:80],
            )
            continue
        tool_calls.append(candidate)

    return tool_calls


async def call_llm_stream(
    agent: AgentContext,
    system_prompt: str,
    stream_sink: Optional["StreamSink"] = None,
) -> str:
    """Call the LLM with streaming output.

    Args:
        agent: AgentCore instance
        system_prompt: System prompt
        stream_sink: Output sink for streaming (None = silent)

    Returns:
        Full response text (same as non-streaming version)
    """
    if stream_sink is None:
        stream_sink = _NullSink()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    tools = agent._build_openai_tools()
    messages = _fit_context_window(agent, messages, tools, purpose="single_turn_stream")

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    try:
        stream_sink.on_status("Thinking...")
        response = await _create_streaming_response(agent, kwargs)

        full_text = ""
        reasoning_buffer = ""
        tool_calls_chunks: list[dict] = []

        # 自动适配 sync/async Stream（sync Stream 用 _AsyncIterWrapper 包装）
        _stream = _ensure_async_iter(response)
        if _stream is None:
            raise ValueError("LLM response is not a valid stream object")
        async for chunk in _stream:
            if chunk.choices and len(chunk.choices) > 0:
                delta = chunk.choices[0].delta

                # Handle reasoning_content (DeepSeek R1, etc.)
                reasoning = getattr(delta, "reasoning_content", None) or ""
                if reasoning:
                    reasoning_buffer += reasoning
                    stream_sink.on_thinking_token(reasoning)

                # Handle content
                content = getattr(delta, "content", None) or ""
                if content:
                    if reasoning_buffer:
                        full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
                        reasoning_buffer = ""
                    stream_sink.on_content_token(content)
                    full_text += content

                # Handle tool_calls（流式 chat 模式也需要处理）
                _collect_tool_call_deltas(delta, tool_calls_chunks)

        if reasoning_buffer:
            full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"

        stream_sink.on_stream_end()

        # 如果有 tool_calls，路由到 handle_tool_calls（同 call_llm_auto_stream 的逻辑）
        if tool_calls_chunks:
            tool_calls = _assemble_tool_calls(tool_calls_chunks)

            if tool_calls:
                dummy_msg = type("obj", (object,), {
                    "content": full_text,
                    "tool_calls": tool_calls,
                })()
                for tc in tool_calls:
                    stream_sink.on_tool_call(tc.function.name, tc.function.arguments[:200])
                # handle_tool_calls 执行工具并做第二轮 LLM 调用
                result = await handle_tool_calls(agent, dummy_msg)
                if result:
                    stream_sink.on_content_token(result)
                stream_sink.on_stream_end()
                return result

        return full_text

    except Exception as e:
        # Fallback to non-streaming on streaming-related errors or general failures
        error_text = str(e).lower()
        streaming_markers = [
            "not supported", "not implemented", "streaming",
            "requires an object with __aiter__",
            "stream is not iterable", "doesn't support",
            "not a valid stream",
        ]
        if any(marker in error_text for marker in streaming_markers):
            # Provider doesn't support streaming or other streaming error, fall back
            pass
        else:
            # Other error, re-raise
            raise

    # Fallback: non-streaming with simulated streaming
    # Use existing call_llm as fallback
    response_fallback, _ = await _call_with_persistent_retries(
        agent,
        lambda: agent._get_client().chat.completions.create(**kwargs),
        "单轮",
    )

    # 降级到非流式 call_llm（有 retry + tool_calls 处理），行为一致
    return await call_llm(agent, system_prompt)


async def call_llm_auto_stream(
    agent: AgentContext,
    system_prompt: str,
    round_context: str,
    stream_sink: Optional["StreamSink"] = None,
    *,
    include_history: bool = True,
    max_tool_rounds: int | None = None,
) -> str:
    """Call the LLM in auto-pentest mode with streaming output.

    Args:
        agent: AgentCore instance
        system_prompt: System prompt
        round_context: Round context for auto mode
        stream_sink: Output sink for streaming (None = silent)

    Returns:
        Full response text
    """
    if stream_sink is None:
        stream_sink = _NullSink()

    messages, round_message = _build_tool_loop_messages(
        agent,
        system_prompt,
        round_context,
        include_history=include_history,
    )
    tools = agent._build_openai_tools()
    messages = _fit_context_window(agent, messages, tools, purpose="autonomous_stream")

    last_tool_results: list[dict[str, Any]] | None = None
    last_skipped_info: list[str] = []
    last_assistant_text = ""
    try:
        for _tool_round in range(_resolve_auto_tool_rounds(agent, max_tool_rounds) + 1):
            messages = _fit_context_window(
                agent,
                messages,
                tools,
                purpose="autonomous_stream_tool_follow_up",
            )
            message = await _stream_chat_completion_message(agent, messages, tools, stream_sink)
            tool_calls = list(getattr(message, "tool_calls", None) or [])
            if not tool_calls:
                return extract_response(message)

            for tc in tool_calls:
                stream_sink.on_tool_call(tc.function.name, tc.function.arguments[:200])

            tool_results, skipped_info = await handle_tool_calls_with_results(agent, message)
            last_tool_results = tool_results
            last_skipped_info = skipped_info
            last_assistant_text = message.content or ""
            for item in tool_results:
                if isinstance(item, dict) and "content" in item:
                    stream_sink.on_tool_result(item["content"])

            executed_tool_calls = [
                item.get("tool_call")
                for item in tool_results
                if isinstance(item, dict) and item.get("tool_call") is not None
            ]
            if not executed_tool_calls:
                return _format_tool_results_fallback(
                    tool_results,
                    skipped_info,
                    assistant_text=message.content or "",
                )

            assistant_message = _assistant_tool_message(extract_response(message), executed_tool_calls)
            tool_messages = _tool_result_messages(tool_results)
            messages.append(assistant_message)
            messages.extend(tool_messages)
            messages = _fit_tool_loop_context(agent, messages, round_message)
            if include_history:
                _append_context_message(agent, assistant_message)
                for tool_message in tool_messages:
                    _append_context_message(agent, tool_message)

        return "[tool loop paused] Internal tool follow-up cap reached; continue from the recorded tool evidence."
    except (NotImplementedError, ValueError, Exception) as e:
        error_text = str(e).lower()
        if last_tool_results is not None:
            return _format_tool_results_fallback(
                last_tool_results,
                last_skipped_info,
                assistant_text=last_assistant_text,
            ) + f"\n[llm follow-up failed] {e}"
        if not any(
            marker in error_text
            for marker in [
                "not supported", "not implemented", "streaming", "not a valid stream",
            ]
        ):
            raise

    return await call_llm_auto(
        agent,
        system_prompt,
        round_context,
        include_history=include_history,
        max_tool_rounds=max_tool_rounds,
    )

# === Stream Output Protocol ===


@runtime_checkable
class StreamSink(Protocol):
    """输出流接收器抽象。

    LLM 调用层通过此接口将输出定向到不同目标（CLI/Web/静默）。
    放在 llm_client.py 中符合 CONTRIBUTING.md 的模块放置原则。
    """

    def on_status(self, message: str) -> None:
        """显示状态提示（如 "Thinking..."）。"""
        ...

    def on_thinking_token(self, token: str) -> None:
        """接收思考过程的 token（可选择是否显示）。"""
        ...

    def on_content_token(self, token: str) -> None:
        """接收正文 token。"""
        ...

    def on_tool_call(self, tool_name: str, args: str) -> None:
        """显示工具调用提示。"""
        ...

    def on_tool_result(self, result_summary: str) -> None:
        """显示工具结果摘要。"""
        ...

    def on_stream_end(self) -> None:
        """流式结束回调（换行/清理）。"""
        ...


class _NullSink:
    """空实现，确保无 sink 时不产生任何输出。"""

    def on_status(self, message: str) -> None:
        pass

    def on_thinking_token(self, token: str) -> None:
        pass

    def on_content_token(self, token: str) -> None:
        pass

    def on_tool_call(self, tool_name: str, args: str) -> None:
        pass

    def on_tool_result(self, result_summary: str) -> None:
        pass

    def on_stream_end(self) -> None:
        pass
