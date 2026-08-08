"""Lightweight token estimation and sliding-window truncation for LLM context.

Pure-Python approximation (no tiktoken). Uses a ~4-chars-per-token heuristic
plus small per-message and per-field overheads to stay roughly aligned with
OpenAI-compatible tokenizers without external dependencies.
"""

from __future__ import annotations

import json
from typing import Any

from vulnclaw.i18n import current_lang

# Approximate average characters per token for mixed English/Chinese text.
_CHARS_PER_TOKEN = 4.0
# Per-message structural overhead (role tokens, message framing).
_MESSAGE_OVERHEAD = 4
# Per-tool-call structural overhead (id, type, function wrapper).
_TOOL_CALL_OVERHEAD = 8

def _truncation_notice() -> str:
    """Return the context-truncation notice in the active UI language."""
    if current_lang() == "en":
        return (
            "[Context truncated] To control token usage, some earlier history was removed; "
            "only the system prompt and the most recent messages are kept."
        )
    return (
        "[上下文截断] 为控制 token 用量，部分较早的历史消息已被移除，"
        "仅保留系统提示和最近的对话。"
    )


def _text_tokens(text: str) -> int:
    """Estimate tokens for a raw string."""
    if not text:
        return 0
    return int(len(text) / _CHARS_PER_TOKEN) + 1


def _content_tokens(content: Any) -> int:
    """Estimate tokens for a message content field (str or multimodal list)."""
    if content is None:
        return 0
    if isinstance(content, str):
        return _text_tokens(content)
    if isinstance(content, list):
        total = 0
        for part in content:
            if isinstance(part, dict):
                # Text parts: {"type": "text", "text": "..."}
                if "text" in part and isinstance(part["text"], str):
                    total += _text_tokens(part["text"])
                # Image parts: fixed approximate cost, don't measure base64 length
                elif part.get("type") in ("image_url", "image"):
                    total += 256
                else:
                    total += _text_tokens(json.dumps(part, ensure_ascii=False))
            elif isinstance(part, str):
                total += _text_tokens(part)
        return total
    return _text_tokens(str(content))


def _tool_calls_tokens(tool_calls: Any) -> int:
    """Estimate tokens for an assistant message's tool_calls field."""
    if not tool_calls or not isinstance(tool_calls, list):
        return 0
    total = 0
    for tc in tool_calls:
        total += _TOOL_CALL_OVERHEAD
        if not isinstance(tc, dict):
            total += _text_tokens(str(tc))
            continue
        fn = tc.get("function", {})
        if isinstance(fn, dict):
            total += _text_tokens(str(fn.get("name", "")))
            total += _text_tokens(str(fn.get("arguments", "")))
        if tc.get("id"):
            total += _text_tokens(str(tc["id"]))
    return total


def estimate_message_tokens(message: dict) -> int:
    """Estimate the token count of a single chat message."""
    if not isinstance(message, dict):
        return _text_tokens(str(message)) + _MESSAGE_OVERHEAD
    total = _MESSAGE_OVERHEAD
    total += _text_tokens(str(message.get("role", "")))
    total += _content_tokens(message.get("content"))
    if "tool_calls" in message:
        total += _tool_calls_tokens(message.get("tool_calls"))
    if "tool_call_id" in message:
        total += _text_tokens(str(message["tool_call_id"]))
    if "name" in message:
        total += _text_tokens(str(message["name"]))
    return total


def estimate_tokens(messages: list[dict]) -> int:
    """Estimate the total token count of a list of chat messages."""
    if not messages:
        return 0
    return sum(estimate_message_tokens(m) for m in messages)


def estimate_tool_tokens(tools: list[dict] | None) -> int:
    """Estimate the request budget used by function/tool schemas.

    Tool definitions are part of a Chat Completions request but were previously
    omitted from the context calculation. Serializing them is intentionally an
    approximation, consistent with the lightweight estimator used for message
    content above.
    """
    if not tools:
        return 0
    try:
        rendered = json.dumps(tools, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        rendered = str(tools)
    return _text_tokens(rendered)


def group_tool_exchanges(messages: list[dict]) -> list[list[dict]]:
    """Group assistant tool calls with their consecutive tool responses.

    OpenAI-compatible providers reject a ``tool`` message when the assistant
    message that declared its ``tool_call_id`` is absent.  Context trimming
    therefore has to treat that exchange as one indivisible unit.
    """
    groups: list[list[dict]] = []
    index = 0
    while index < len(messages):
        message = messages[index]
        group = [message]
        tool_calls = message.get("tool_calls") if isinstance(message, dict) else None
        if message.get("role") == "assistant" and isinstance(tool_calls, list) and tool_calls:
            expected_ids = {
                str(call.get("id") or "")
                for call in tool_calls
                if isinstance(call, dict) and call.get("id")
            }
            cursor = index + 1
            while cursor < len(messages):
                candidate = messages[cursor]
                if candidate.get("role") != "tool":
                    break
                if str(candidate.get("tool_call_id") or "") not in expected_ids:
                    break
                group.append(candidate)
                cursor += 1
            index = cursor
        else:
            index += 1
        groups.append(group)
    return groups


# Alias kept for callers of the original name (context_budget.py and its tests).
group_messages = group_tool_exchanges


def group_conversation_turns(messages: list[dict]) -> list[list[dict]]:
    """Group hot/cold history into user-led turns without splitting tools."""
    turns: list[list[dict]] = []
    current: list[dict] = []
    for exchange in group_tool_exchanges(messages):
        if exchange[0].get("role") == "user" and current:
            turns.append(current)
            current = []
        current.extend(exchange)
    if current:
        turns.append(current)
    return turns


def flatten_message_groups(groups: list[list[dict]]) -> list[dict]:
    """Flatten groups produced by :func:`group_messages`."""
    return [message for group in groups for message in group]


def estimate_message_group_tokens(group: list[dict]) -> int:
    """Estimate one protocol-safe message group's token count."""
    return estimate_tokens(group)


def truncate_message_groups(
    messages: list[dict],
    max_tokens: int,
    *,
    preserve_system: bool = True,
    min_recent_groups: int = 1,
    notice: str | None = None,
) -> list[dict]:
    """Sliding-window truncation that never splits assistant/tool exchanges."""
    if not messages or max_tokens <= 0 or estimate_tokens(messages) <= max_tokens:
        return list(messages)

    groups = group_messages(messages)
    system_groups: list[list[dict]] = []
    if preserve_system:
        while groups:
            first = groups[0]
            if len(first) != 1 or first[0].get("role") != "system":
                break
            system_groups.append(groups.pop(0))

    min_recent_groups = max(1, min_recent_groups)
    recent = groups[-min_recent_groups:]
    middle = groups[:-min_recent_groups]
    notice_message = (
        {"role": "system", "content": notice or _truncation_notice()}
        if middle
        else None
    )
    running = estimate_tokens(flatten_message_groups(system_groups))
    running += estimate_tokens(flatten_message_groups(recent))
    if notice_message is not None:
        running += estimate_message_tokens(notice_message)

    kept_middle: list[list[dict]] = []
    for group in reversed(middle):
        cost = estimate_message_group_tokens(group)
        if running + cost > max_tokens:
            break
        kept_middle.insert(0, group)
        running += cost

    result = flatten_message_groups(system_groups)
    if notice_message is not None and len(kept_middle) < len(middle):
        result.append(notice_message)
    result.extend(flatten_message_groups(kept_middle))
    result.extend(flatten_message_groups(recent))
    return result


def truncate_messages(
    messages: list[dict],
    max_tokens: int,
    preserve_system: bool = True,
    min_recent: int = 4,
) -> list[dict]:
    """Sliding-window truncation to fit messages within max_tokens.

    Always keeps the system prompt (first message) when preserve_system is True,
    always keeps the most recent min_recent messages, and drops the oldest
    middle messages first. Inserts a system notice at the truncation point.
    """
    if not messages or max_tokens <= 0:
        return list(messages)
    if estimate_tokens(messages) <= max_tokens:
        return list(messages)

    system_msgs: list[dict] = []
    body = list(messages)
    if preserve_system and body and body[0].get("role") == "system":
        system_msgs = [body[0]]
        body = body[1:]

    min_recent = max(min_recent, 1)
    groups = group_tool_exchanges(body)
    if len(body) <= min_recent:
        return system_msgs + body

    recent_groups: list[list[dict]] = []
    recent_count = 0
    while groups and recent_count < min_recent:
        group = groups.pop()
        recent_groups.insert(0, group)
        recent_count += len(group)
    recent = [message for group in recent_groups for message in group]

    notice = {"role": "system", "content": _truncation_notice()}
    base_tokens = estimate_tokens(system_msgs) + estimate_tokens(recent)
    base_tokens += estimate_message_tokens(notice)

    kept_groups: list[list[dict]] = []
    running = base_tokens
    # Add older atomic exchanges from newest to oldest until the budget is exhausted.
    for group in reversed(groups):
        cost = estimate_tokens(group)
        if running + cost > max_tokens:
            break
        running += cost
        kept_groups.insert(0, group)

    truncated_any = len(kept_groups) < len(groups)
    kept_middle = [message for group in kept_groups for message in group]
    result = list(system_msgs)
    if truncated_any:
        result.append(notice)
    result.extend(kept_middle)
    result.extend(recent)
    return result
