"""LLM client helpers for AgentCore."""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
from typing import Any, Callable

from vulnclaw.agent.tool_call_manager import (
    handle_tool_calls,
    handle_tool_calls_with_results,
)


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


def _is_openai_reasoning_model(provider: str, model: str) -> bool:
    """Return True for OpenAI models that use the newer reasoning parameter set."""
    if provider.lower() != "openai":
        return False
    normalized = model.lower()
    return normalized.startswith(("o1", "o3", "o4", "gpt-5"))


def build_chat_completion_kwargs(
    agent: Any,
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
    """
    llm = agent.config.llm
    provider = str(getattr(llm, "provider", "") or "").lower()
    model = str(getattr(llm, "model", "") or "")
    token_limit = max_tokens if max_tokens is not None else getattr(llm, "max_tokens", None)
    temp = temperature if temperature is not None else getattr(llm, "temperature", None)
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
        reasoning_effort = getattr(llm, "reasoning_effort", None)
        if reasoning_effort:
            kwargs["reasoning_effort"] = reasoning_effort
    return kwargs


async def _call_with_persistent_retries(
    agent: Any, request_fn, stage_label: str
) -> tuple[Any, int]:
    """Keep retrying retriable LLM calls until success or manual interruption.

    Returns:
        (response, retry_attempts)
    """
    loop = asyncio.get_running_loop()
    retry_attempts = 0

    while True:
        try:
            maybe_response = loop.run_in_executor(None, request_fn)
            response = await maybe_response if inspect.isawaitable(maybe_response) else maybe_response
            if response is not None and getattr(response, "choices", None):
                return response, retry_attempts

            retry_attempts += 1
            print(
                f"[!] {stage_label} LLM API 异常响应，第 {retry_attempts} 次重连尝试中... (5s 后重试)",
                file=sys.stdout,
                flush=True,
            )
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            raise
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            error_text = str(exc).lower()
            if _is_non_retriable_llm_error(error_text):
                raise

            retry_attempts += 1
            print(
                f"[!] {stage_label} LLM 连接异常，第 {retry_attempts} 次重连尝试中... ({exc})",
                file=sys.stdout,
                flush=True,
            )
            await asyncio.sleep(5)


def _prepend_retry_notice(text: str, retry_attempts: int) -> str:
    """Annotate a successful response if retries happened within the same round."""
    if retry_attempts <= 0:
        return text
    return f"[LLM恢复] 本轮在第 {retry_attempts} 次重连后恢复。\n{text}"


def _format_tool_results_fallback(
    tool_results: list[dict[str, Any]], skipped_info: list[str]
) -> str:
    """Build a plain-text fallback summary when provider tool-summary format is incompatible."""
    parts = ["[tool results processed] 当前提供商不兼容标准工具总结回传，已降级为纯文本结果摘要："]
    for item in tool_results:
        content = item.get("content", "") if isinstance(item, dict) else str(item)
        if len(content) > 800:
            content = content[:400] + "\n...[中间省略]...\n" + content[-400:]
        parts.append(content)
    if skipped_info:
        parts.append("⚠️ 本轮跳过: " + "; ".join(skipped_info))
    return "\n".join(parts)


async def call_llm(
    agent: Any,
    system_prompt: str,
    *,
    stream_sink: Optional["StreamSink"] = None,
) -> str:
    """Call the LLM with the current context and system prompt (single turn)."""
    if stream_sink is not None:
        return await call_llm_stream(agent, system_prompt, stream_sink)

    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    response, retry_attempts = await _call_with_persistent_retries(
        agent,
        lambda: client.chat.completions.create(**kwargs),
        "单轮",
    )

    choice = response.choices[0]
    if choice.message.tool_calls:
        return _prepend_retry_notice(await handle_tool_calls(agent, choice.message), retry_attempts)
    return _prepend_retry_notice(extract_response(choice.message), retry_attempts)


async def call_llm_auto_stream(
    agent: Any,
    system_prompt: str,
    round_context: str,
    on_token: Callable[[str], None] | None = None,
    on_tool_call: Callable[[dict], None] | None = None,
    on_tool_result: Callable[[dict], None] | None = None,
) -> str:
    """Call the LLM in auto-pentest mode with streaming token output."""
    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    messages.append({"role": "user", "content": round_context})
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)
    kwargs["stream"] = True
    kwargs["stream_options"] = {"include_usage": False}

    loop = asyncio.get_running_loop()
    retry_attempts = 0

    while True:
        try:
            full_content: list[str] = []
            tool_call_deltas: dict[int, dict] = {}

            def _do_stream() -> None:
                nonlocal retry_attempts
                try:
                    response = client.chat.completions.create(**kwargs)
                    for chunk in response:
                        if len(chunk.choices) == 0:
                            continue
                        delta = chunk.choices[0].delta
                        if delta is None:
                            continue

                        if delta.content:
                            full_content.append(delta.content)
                            if on_token:
                                on_token(delta.content)

                        if delta.tool_calls:
                            for tc_delta in delta.tool_calls:
                                idx = tc_delta.index
                                if idx not in tool_call_deltas:
                                    tool_call_deltas[idx] = {
                                        "id": tc_delta.id or "",
                                        "type": "function",
                                        "function": {"name": "", "arguments": ""},
                                    }
                                if tc_delta.id:
                                    tool_call_deltas[idx]["id"] = tc_delta.id
                                if tc_delta.function:
                                    if tc_delta.function.name:
                                        tool_call_deltas[idx]["function"]["name"] += tc_delta.function.name
                                    if tc_delta.function.arguments:
                                        tool_call_deltas[idx]["function"]["arguments"] += tc_delta.function.arguments
                except Exception as exc:
                    raise exc

            await loop.run_in_executor(None, _do_stream)

            response_text = "".join(full_content)

            if tool_call_deltas and on_tool_call:
                for tc in tool_call_deltas.values():
                    if on_tool_call:
                        on_tool_call(tc)

            if tool_call_deltas:

                reconstructed_calls = []
                for tc in tool_call_deltas.values():
                    reconstructed_calls.append({
                        "id": tc["id"],
                        "type": tc["type"],
                        "function": {
                            "name": tc["function"]["name"],
                            "arguments": tc["function"]["arguments"],
                        },
                    })

                assistant_msg = {
                    "role": "assistant",
                    "content": response_text or "",
                    "tool_calls": reconstructed_calls,
                }
                messages.append(assistant_msg)

                tool_results, skipped_info = await handle_tool_calls_with_results(agent, reconstructed_calls)

                for tr in tool_results:
                    if isinstance(tr, dict) and "tool_call_id" in tr:
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tr["tool_call_id"],
                            "content": tr.get("content", ""),
                        })
                        if on_tool_result:
                            on_tool_result(tr)

                tool_summary = _format_tool_results_fallback(tool_results, skipped_info)
                kwargs["messages"] = messages
                kwargs["stream"] = False
                kwargs.pop("stream_options", None)

                try:
                    response2, _ = await _call_with_persistent_retries(
                        agent,
                        lambda: client.chat.completions.create(**kwargs),
                        "工具总结(流式)",
                    )
                    final_text = extract_response(response2.choices[0].message)
                    agent.context.add_assistant_message(final_text)
                    return _prepend_retry_notice(final_text, retry_attempts)
                except Exception:
                    agent.context.add_assistant_message(tool_summary)
                    return _prepend_retry_notice(tool_summary, retry_attempts)

            agent.context.add_assistant_message(response_text)
            return _prepend_retry_notice(response_text, retry_attempts)

        except asyncio.CancelledError:
            raise
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            error_text = str(exc).lower()
            if _is_non_retriable_llm_error(error_text):
                raise
            retry_attempts += 1
            print(f"[!] 流式 LLM 连接异常，第 {retry_attempts} 次重连尝试中... ({exc})", file=sys.stdout, flush=True)
            await asyncio.sleep(5)


async def call_llm_auto(agent: Any, system_prompt: str, round_context: str) -> str:
    """Call the LLM in auto-pentest mode with round context appended."""
    if stream_sink is not None:
        return await call_llm_auto_stream(agent, system_prompt, round_context, stream_sink)

    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    messages.append({"role": "user", "content": round_context})
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    response, retry_attempts = await _call_with_persistent_retries(
        agent,
        lambda: client.chat.completions.create(**kwargs),
        "自主循环",
    )

    choice = response.choices[0]
    if choice.message.tool_calls:
        tool_results, skipped_info = await handle_tool_calls_with_results(agent, choice.message)

        executed_tcs = []
        for tc in tool_results:
            if not isinstance(tc, dict) or "tool_call" not in tc:
                import sys

                print(f"[!] 跳过异常工具结果: {type(tc).__name__} {str(tc)[:100]}", file=sys.stderr)
                continue
            executed_tcs.append(tc["tool_call"])

        assistant_msg = {
            "role": "assistant",
            "content": choice.message.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in executed_tcs
            ],
        }
        messages.append(assistant_msg)

        for tool_result in tool_results:
            if isinstance(tool_result, dict) and "tool_call_id" in tool_result:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_result["tool_call_id"],
                        "content": tool_result.get("content", ""),
                    }
                )

        tool_summary_parts = []
        for tc in executed_tcs:
            try:
                args_str = str(tc.function.arguments)[:200]
            except Exception:
                args_str = "<无法读取>"
            tool_summary_parts.append(f"调用工具: {tc.function.name}({args_str})")
        for tr in tool_results:
            content = tr.get("content", "") if isinstance(tr, dict) else str(tr)
            if len(content) > 1000:
                content = content[:500] + "\n...[中间省略]...\n" + content[-500:]
            tool_summary_parts.append(f"工具结果: {content}")
            if (
                isinstance(tr, dict)
                and isinstance(tr.get("structured_content"), dict)
                and tr["structured_content"]
            ):
                structured = json.dumps(tr["structured_content"], ensure_ascii=False)
                if len(structured) > 1000:
                    structured = structured[:500] + "\n...[中间省略]...\n" + structured[-500:]
                tool_summary_parts.append(f"结构化结果: {structured}")
        if skipped_info:
            tool_summary_parts.append(f"⚠️ 本轮跳过: {'; '.join(skipped_info)}")

        try:
            kwargs["messages"] = messages
            response2, second_retry_attempts = await _call_with_persistent_retries(
                agent,
                lambda: client.chat.completions.create(**kwargs),
                "工具总结",
            )
            final_text = extract_response(response2.choices[0].message)
            agent.context.add_assistant_message(final_text)
            return _prepend_retry_notice(final_text, retry_attempts + second_retry_attempts)
        except Exception as e2:
            error_text = str(e2).lower()
            if _is_non_retriable_llm_error(error_text):
                fallback = _format_tool_results_fallback(tool_results, skipped_info)
                agent.context.add_assistant_message(fallback)
                return fallback
            return f"[tool results processed] 继续分析错误: {e2}"

    return _prepend_retry_notice(extract_response(choice.message), retry_attempts)


# === Stream LLM Call Helpers ===

async def call_llm_stream(
    agent: Any,
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

    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    try:
        stream_sink.on_status("Thinking...")
        response = client.chat.completions.create(**kwargs, stream=True)

        full_text = ""
        reasoning_buffer = ""

        async for chunk in response:
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
                    # If we were collecting reasoning and now get content,
                    # wrap the reasoning in tags
                    if reasoning_buffer:
                        full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
                        reasoning_buffer = ""

                    stream_sink.on_content_token(content)
                    full_text += content

        # Flush any remaining reasoning
        if reasoning_buffer:
            full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"

        stream_sink.on_stream_end()
        return full_text

    except Exception as e:
        # Fallback to non-streaming on streaming-related errors or general failures
        error_text = str(e).lower()
        streaming_markers = [
            "not supported",
            "not implemented",
            "streaming",
            "async for",
            "requires an object with __aiter__",
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
        lambda: client.chat.completions.create(**kwargs),
        "单轮",
    )

    choice = response_fallback.choices[0]
    if choice.message.tool_calls:
        # Has tool calls, need full handling
        return await handle_tool_calls(agent, choice.message)

    full_text = extract_response(choice.message)

    # Simulate streaming output for fallback
    if full_text:
        stream_sink.on_content_token(full_text)
    stream_sink.on_stream_end()

    return full_text


async def call_llm_auto_stream(
    agent: Any,
    system_prompt: str,
    round_context: str,
    stream_sink: Optional["StreamSink"] = None,
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

    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    messages.append({"role": "user", "content": round_context})
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    try:
        # First LLM call with streaming
        stream_sink.on_status("Thinking...")
        response = client.chat.completions.create(**kwargs, stream=True)

        full_text = ""
        reasoning_buffer = ""
        tool_calls_chunks: list[dict] = []

        for chunk in response:
            if chunk.choices and len(chunk.choices) > 0:
                delta = chunk.choices[0].delta

                # Handle reasoning_content
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

                # Handle tool_calls
                tc = getattr(delta, "tool_calls", None)
                if tc:
                    for tc_delta in tc:
                        tool_calls_chunks.append({
                            "index": getattr(tc_delta, "index", 0),
                            "id": getattr(tc_delta, "id", None) or "",
                            "function": {
                                "name": getattr(tc_delta.function, "name", None) or "",
                                "arguments": getattr(tc_delta.function, "arguments", None) or "",
                            },
                        })

        stream_sink.on_stream_end()

        # Flush reasoning
        if reasoning_buffer:
            full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"

        # Check if we have tool calls
        choice_dummy = type("obj", (object,), {"message": type("obj", (object,), {
            "content": full_text,
            "tool_calls": None,
        })()})()

        # Reconstruct message for tool call handling
        # We need to check if there are tool calls from the accumulated chunks
        if tool_calls_chunks:
            # Build tool_calls from accumulated chunks
            from openai.types.chat.chat_completion_message_tool_call import (
                ChatCompletionMessageToolCall,
                Function,
            )

            # Group chunks by index
            tc_by_index: dict[int, dict] = {}
            for tc_chunk in tool_calls_chunks:
                idx = tc_chunk["index"]
                if idx not in tc_by_index:
                    tc_by_index[idx] = {"id": "", "function": {"name": "", "arguments": ""}}
                tc_by_index[idx]["id"] += tc_chunk["id"]
                tc_by_index[idx]["function"]["name"] += tc_chunk["function"]["name"]
                tc_by_index[idx]["function"]["arguments"] += tc_chunk["function"]["arguments"]

            tool_calls = [
                ChatCompletionMessageToolCall(
                    id=tc_data["id"],
                    type="function",
                    function=Function(
                        name=tc_data["function"]["name"],
                        arguments=tc_data["function"]["arguments"],
                    ),
                )
                for tc_data in tc_by_index.values()
                if tc_data["function"]["name"]
            ]

            if tool_calls:
                # [修改] 流式聚合后 tool_calls 仅存在于 delta 片段中, 需回填到聚合消息对象以便后续处理
                # Patch the dummy message with actual tool calls
                choice_dummy.message.tool_calls = tool_calls
                # Execute tool calls
                for tc in tool_calls:
                    stream_sink.on_tool_call(tc.function.name, tc.function.arguments[:200])

                tool_results, skipped_info = await handle_tool_calls_with_results(agent, choice_dummy.message)

                for tr in tool_results:
                    if isinstance(tr, dict) and "content" in tr:
                        content = tr["content"]
                        if len(content) > 200:
                            content = content[:200] + "..."
                        stream_sink.on_tool_result(content)

                # Continue with the messages including tool results
                assistant_msg = {
                    "role": "assistant",
                    "content": full_text,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in tool_calls
                    ],
                }
                messages.append(assistant_msg)

                for tool_result in tool_results:
                    if isinstance(tool_result, dict) and "tool_call_id" in tool_result:
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_result["tool_call_id"],
                            "content": tool_result.get("content", ""),
                        })

                # Second LLM call (streaming) for summary
                kwargs["messages"] = messages
                stream_sink.on_status("Summarizing...")

                try:
                    response2 = client.chat.completions.create(**kwargs, stream=True)
                    full_text = ""

                    for chunk in response2:
                        if chunk.choices and len(chunk.choices) > 0:
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

                    if reasoning_buffer:
                        full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"

                    agent.context.add_assistant_message(full_text)
                    stream_sink.on_stream_end()
                    return full_text

                except Exception as e2:
                    error_text = str(e2).lower()
                    if _is_non_retriable_llm_error(error_text):
                        fallback = _format_tool_results_fallback(tool_results, skipped_info)
                        agent.context.add_assistant_message(fallback)
                        return fallback
                    return f"[tool results processed] 继续分析错误: {e2}"

        agent.context.add_assistant_message(full_text)
        return full_text

    except (NotImplementedError, ValueError, Exception) as e:
        error_text = str(e).lower()
        if any(
            marker in error_text
            for marker in ["not supported", "not implemented", "streaming"]
        ):
            pass
        else:
            raise

    # Fallback to non-streaming
    return await call_llm_auto(agent, system_prompt, round_context)


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
