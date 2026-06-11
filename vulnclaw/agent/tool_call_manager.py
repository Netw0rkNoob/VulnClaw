"""Tool-call orchestration helpers for AgentCore."""

from __future__ import annotations

import json
import re
from typing import Any


async def handle_tool_calls(agent: Any, message: Any) -> str:
    """Handle tool calls from the LLM response (legacy single-turn)."""
    results: list[str] = []
    # [修改] 2026-06-10 Nyaecho - 修复 tool_calls 属性访问问题，使用 getattr 防止 AttributeError
    for tool_call in (getattr(message, "tool_calls", None) or []):
        func_name = tool_call.function.name
        func_args = safe_parse_tool_args(tool_call.function.arguments)
        tool_result = await agent._execute_mcp_tool(func_name, func_args)
        results.append(f"[tool:{func_name}] {tool_result}")
    return "\n".join(results)


async def handle_tool_calls_with_results(
    agent: Any, message: Any
) -> tuple[list[dict[str, Any]], list[str]]:
    """Handle tool calls with deduplication and rate limiting."""
    max_calls_per_round = 10

    seen: dict[str, dict[str, Any]] = {}
    # [修改] 2026-06-10 Nyaecho - 修复 tool_calls 属性访问问题，使用 getattr 防止 AttributeError
    for tool_call in (getattr(message, "tool_calls", None) or []):
        func_name = tool_call.function.name
        func_args = safe_parse_tool_args(tool_call.function.arguments)
        args_key = json.dumps(func_args, sort_keys=True, ensure_ascii=False)
        key = f"{func_name}::{args_key}"
        if key not in seen:
            seen[key] = {
                "tool_call": tool_call,
                "func_name": func_name,
                "func_args": func_args,
            }

    deduplicated = list(seen.values())
    # [修改] 2026-06-10 Nyaecho - 修复 tool_calls 属性访问问题，使用 getattr 防止 AttributeError
    total_count = len(getattr(message, "tool_calls", None) or [])
    dedup_count = len(deduplicated)

    to_execute = deduplicated[:max_calls_per_round]
    skipped_calls = deduplicated[max_calls_per_round:]
    skipped_info: list[str] = []

    if total_count > dedup_count:
        skipped_info.append(f"[去重] {total_count - dedup_count} 个重复调用已合并")
    if skipped_calls:
        for sc in skipped_calls:
            skipped_info.append(
                f"[跳过] {sc['func_name']}({str(sc['func_args'])[:100]}) — 本轮已达上限，下轮继续"
            )

    results: list[dict[str, Any]] = []
    for item in to_execute:
        tool_call = item["tool_call"]
        func_name = item["func_name"]
        func_args = item["func_args"]
        try:
            tool_result = await agent._execute_mcp_tool(func_name, func_args)
            structured_content = None
            if getattr(agent, "mcp_manager", None):
                try:
                    raw_result = await agent.mcp_manager.call_tool(func_name, func_args)
                    if isinstance(raw_result, dict):
                        structured_content = raw_result.get("structured_content")
                except Exception:
                    structured_content = None
            results.append(
                {
                    "tool_call": tool_call,
                    "tool_call_id": tool_call.id,
                    "content": f"[tool:{func_name}] {tool_result}",
                    "structured_content": structured_content,
                }
            )
        except Exception as e:
            import sys

            print(f"[!] 工具执行失败 {func_name}: {e}", file=sys.stderr)
            continue

    return results, skipped_info


def safe_parse_tool_args(arguments: str | None) -> dict[str, Any]:
    """Safely parse tool call arguments JSON, with fallback for malformed input."""
    if not arguments:
        return {}
    try:
        return json.loads(arguments)
    except json.JSONDecodeError:
        for suffix in ['"}', '"}]', '"}}', '"}}]', '"]', "}"]:
            try:
                return json.loads(arguments + suffix)
            except json.JSONDecodeError:
                continue
        partial: dict[str, Any] = {}
        kv_pattern = r'"(\w+)"\s*:\s*"([^"]*?)"'
        for match in re.finditer(kv_pattern, arguments):
            partial[match.group(1)] = match.group(2)
        return partial
