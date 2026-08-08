"""Tool-call orchestration helpers for AgentCore."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import TYPE_CHECKING, Any

from vulnclaw.agent.agent_state import parse_status_code
from vulnclaw.agent.correction_layer import (
    after_tool_batch,
    after_tool_call,
    before_tool_call,
)
from vulnclaw.agent.subagent.tooling import (
    partition_calls as _partition_subagent_calls,
)
from vulnclaw.agent.subagent.tooling import (
    raise_if_cancelled as _raise_if_subagent_cancelled,
)
from vulnclaw.agent.subagent.tooling import (
    record_evidence_bytes as _reserve_subagent_evidence_bytes,
)
from vulnclaw.agent.subagent.tooling import (
    reserve_tool_call as _reserve_subagent_tool_call,
)
from vulnclaw.agent.tool_result_overrides import pop_raw_tool_output_override
from vulnclaw.i18n import _

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext

logger = logging.getLogger(__name__)


# Default concurrency cap used when the agent config does not specify one.
DEFAULT_TOOL_MAX_CONCURRENT = 5


async def handle_tool_calls(agent: AgentContext, message: Any) -> str:
    """Handle tool calls from the LLM response (legacy single-turn)."""
    results: list[str] = []
    # [修改] 2026-06-10 Nyaecho - 修复 tool_calls 属性访问问题，使用 getattr 防止 AttributeError
    for tool_call in (getattr(message, "tool_calls", None) or []):
        func_name = tool_call.function.name
        func_args = safe_parse_tool_args(tool_call.function.arguments)
        pre_hint = before_tool_call(agent, func_name, func_args)
        started = time.perf_counter()
        try:
            tool_result = await agent._execute_mcp_tool(func_name, func_args)
            duration_ms = _elapsed_ms(started)
            content, record, raw = _record_tool_result_with_record(
                agent,
                func_name,
                func_args,
                tool_result,
                duration_ms=duration_ms,
                ok=True,
            )
            signal = after_tool_call(
                agent,
                tool=func_name,
                arguments=func_args,
                raw_output=raw,
                duration_ms=duration_ms,
                evidence=record,
            )
            content = _append_correction_note(content, pre_hint, signal.model_hint())
        except asyncio.CancelledError as exc:
            if not _looks_like_tool_local_cancellation(exc):
                raise
            duration_ms = _elapsed_ms(started)
            content, record, raw = _record_tool_failure_with_record(
                agent, func_name, func_args, exc, duration_ms=duration_ms
            )
            signal = after_tool_call(
                agent,
                tool=func_name,
                arguments=func_args,
                raw_output=raw,
                duration_ms=duration_ms,
                evidence=record,
                error=exc,
            )
            content = _append_correction_note(content, pre_hint, signal.model_hint())
        except Exception as exc:
            duration_ms = _elapsed_ms(started)
            content, record, raw = _record_tool_failure_with_record(
                agent, func_name, func_args, exc, duration_ms=duration_ms
            )
            signal = after_tool_call(
                agent,
                tool=func_name,
                arguments=func_args,
                raw_output=raw,
                duration_ms=duration_ms,
                evidence=record,
                error=exc,
            )
            content = _append_correction_note(content, pre_hint, signal.model_hint())
        results.append(f"[tool:{func_name}] {content}")
    return "\n".join(results)


async def handle_tool_calls_with_results(
    agent: AgentContext, message: Any
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
                "index": len(seen),
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
        skipped_info.append(
            f"[{_('agent.tool.dedup')}] {total_count - dedup_count} {_('agent.tool.dedup_merged')}"
        )
    if skipped_calls:
        for sc in skipped_calls:
            skipped_info.append(
                f"[{_('agent.tool.skip')}] {sc['func_name']}({str(sc['func_args'])[:100]}) "
                f"{_('agent.tool.skip_reason')}"
            )

    # Meta calls mutate task ownership. Execute them first so a spawn and a
    # conflicting direct probe from the same model response cannot race.
    meta_calls, normal_calls = _partition_subagent_calls(
        agent, message, to_execute
    )
    executed_meta = [await _execute_single(agent, item) for item in meta_calls]

    parallel, max_concurrent = _resolve_parallel_settings(agent)
    if parallel and max_concurrent > 1 and len(normal_calls) > 1:
        executed_normal = await _execute_parallel(
            agent, normal_calls, max_concurrent
        )
    else:
        executed_normal = [
            await _execute_single(agent, item) for item in normal_calls
        ]
    combined = list(zip(meta_calls, executed_meta)) + list(
        zip(normal_calls, executed_normal)
    )
    combined.sort(key=lambda pair: int(pair[0].get("index", 0)))
    executed = [result for _, result in combined]

    # Drop failed calls (preserves legacy behavior) while keeping original order.
    results = [r for r in executed if r is not None]
    after_tool_batch(
        agent,
        [
            r["correction_signal"]
            for r in results
            if isinstance(r, dict) and r.get("correction_signal")
        ],
    )
    for result in results:
        if isinstance(result, dict):
            result.pop("correction_signal", None)

    return results, skipped_info


def _resolve_parallel_settings(agent: AgentContext) -> tuple[bool, int]:
    """Read tool parallelization settings from the agent config with safe defaults."""
    safety = getattr(getattr(agent, "config", None), "safety", None)
    if safety is None:
        return True, DEFAULT_TOOL_MAX_CONCURRENT
    parallel = bool(getattr(safety, "tool_parallel", True))
    max_concurrent = int(getattr(safety, "tool_max_concurrent", DEFAULT_TOOL_MAX_CONCURRENT) or 1)
    if max_concurrent < 1:
        max_concurrent = 1
    return parallel, max_concurrent


async def _execute_parallel(
    agent: AgentContext, to_execute: list[dict[str, Any]], max_concurrent: int
) -> list[dict[str, Any] | None]:
    """Run independent tool calls concurrently, capped by a semaphore.

    Each call is isolated: an exception in one does not affect the others, and
    the returned list preserves the original ``to_execute`` ordering.
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _guarded(item: dict[str, Any]) -> dict[str, Any] | None:
        async with semaphore:
            return await _execute_single(agent, item)

    return await asyncio.gather(*(_guarded(item) for item in to_execute))


def _extract_structured_content(tool_result: Any) -> dict[str, Any] | None:
    """Recover the structured payload embedded by execute_mcp_tool.

    On a successful MCP call, ``execute_mcp_tool`` appends
    ``[structured] {json}`` to the result string. Parse it back so callers get a
    separate ``structured_content`` field without re-executing the tool.
    """
    if not isinstance(tool_result, str):
        return None
    marker = "[structured] "
    idx = tool_result.rfind(marker)
    if idx == -1:
        return None
    try:
        parsed = json.loads(tool_result[idx + len(marker):].strip())
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def _execute_single(agent: AgentContext, item: dict[str, Any]) -> dict[str, Any] | None:
    """Execute one tool call with isolated error handling.

    Returns one tool response per requested tool call.  Failed tools are returned
    as prompt-visible error results instead of being dropped, because OpenAI-style
    tool calling expects every tool_call id to receive a corresponding tool
    message and the model needs the failure evidence to choose a fallback.
    """
    tool_call = item["tool_call"]
    func_name = item["func_name"]
    func_args = item["func_args"]
    # Fence cancellation before all fast paths. A cancellation-suppressing child
    # must not receive additional observations after its token is revoked.
    _raise_if_subagent_cancelled(agent)
    pre_hint = before_tool_call(agent, func_name, func_args)
    started = time.perf_counter()
    redundant_local_view = _redundant_evidence_view_reason(agent, func_name, func_args)
    if redundant_local_view:
        duration_ms = _elapsed_ms(started)
        raw = f"[guard] Redundant evidence_view suppressed. {redundant_local_view}"
        _record_tool_call_without_new_evidence(
            agent,
            func_name,
            func_args,
            raw,
            duration_ms=duration_ms,
            ok=True,
        )
        signal = after_tool_call(
            agent,
            tool=func_name,
            arguments=func_args,
            raw_output=raw,
            duration_ms=duration_ms,
            evidence=None,
        )
        content = _append_correction_note(raw, pre_hint, signal.model_hint())
        return {
            "tool_call": tool_call,
            "tool_call_id": tool_call.id,
            "content": f"[tool:{func_name}] {content}",
            "structured_content": None,
            "duration_ms": duration_ms,
            "correction": signal.model_hint(),
            "correction_signal": signal,
        }
    try:
        _reserve_subagent_tool_call(agent)
        tool_result = await agent._execute_mcp_tool(func_name, func_args)
        _reserve_subagent_evidence_bytes(agent, tool_result)
        duration_ms = _elapsed_ms(started)
        # NOTE: do not re-invoke agent.mcp_manager.call_tool here. _execute_mcp_tool
        # already dispatches MCP tools through call_tool (running the side effect
        # once) and embeds any structured content into tool_result as
        # "[structured] {...}". A second call_tool would run the side effect twice,
        # so we recover the structured payload from the result string instead.
        structured_content = _extract_structured_content(tool_result)
        content, record, raw = _record_tool_result_with_record(
            agent,
            func_name,
            func_args,
            tool_result,
            duration_ms=duration_ms,
            ok=True,
        )
        signal = after_tool_call(
            agent,
            tool=func_name,
            arguments=func_args,
            raw_output=raw,
            duration_ms=duration_ms,
            evidence=record,
        )
        content = _append_correction_note(content, pre_hint, signal.model_hint())
        return {
            "tool_call": tool_call,
            "tool_call_id": tool_call.id,
            "content": f"[tool:{func_name}] {content}",
            "structured_content": structured_content,
            "duration_ms": duration_ms,
            "correction": signal.model_hint(),
            "correction_signal": signal,
        }
    except asyncio.CancelledError as exc:
        if not _looks_like_tool_local_cancellation(exc):
            raise
        logger.warning("工具执行被本地取消 %s: %s", func_name, exc)
        duration_ms = _elapsed_ms(started)
        content, record, raw = _record_tool_failure_with_record(
            agent, func_name, func_args, exc, duration_ms=duration_ms
        )
        signal = after_tool_call(
            agent,
            tool=func_name,
            arguments=func_args,
            raw_output=raw,
            duration_ms=duration_ms,
            evidence=record,
            error=exc,
        )
        content = _append_correction_note(content, pre_hint, signal.model_hint())
        return {
            "tool_call": tool_call,
            "tool_call_id": tool_call.id,
            "content": f"[tool:{func_name}] {content}",
            "structured_content": None,
            "duration_ms": duration_ms,
            "correction": signal.model_hint(),
            "correction_signal": signal,
        }
    except Exception as exc:
        logger.warning("工具执行失败 %s: %s", func_name, exc)
        duration_ms = _elapsed_ms(started)
        content, record, raw = _record_tool_failure_with_record(
            agent, func_name, func_args, exc, duration_ms=duration_ms
        )
        signal = after_tool_call(
            agent,
            tool=func_name,
            arguments=func_args,
            raw_output=raw,
            duration_ms=duration_ms,
            evidence=record,
            error=exc,
        )
        content = _append_correction_note(content, pre_hint, signal.model_hint())
        return {
            "tool_call": tool_call,
            "tool_call_id": tool_call.id,
            "content": f"[tool:{func_name}] {content}",
            "structured_content": None,
            "duration_ms": duration_ms,
            "correction": signal.model_hint(),
            "correction_signal": signal,
        }
def _looks_like_tool_local_cancellation(exc: asyncio.CancelledError) -> bool:
    """Differentiate MCP/AnyIO local cancel scopes from user task cancellation."""

    text = str(exc).lower()
    return "cancel scope" in text or "cancelled via" in text


def _record_tool_failure(
    agent: AgentContext,
    func_name: str,
    func_args: dict[str, Any],
    exc: BaseException,
    *,
    duration_ms: int = 0,
) -> str:
    """Persist a tool failure as evidence and return a model-facing error."""

    content, _, _ = _record_tool_failure_with_record(
        agent,
        func_name,
        func_args,
        exc,
        duration_ms=duration_ms,
    )
    return content


def _record_tool_failure_with_record(
    agent: AgentContext,
    func_name: str,
    func_args: dict[str, Any],
    exc: BaseException,
    *,
    duration_ms: int = 0,
) -> tuple[str, Any | None, str]:
    """Persist a tool failure and return preview, evidence and raw text."""

    message = str(exc).strip() or exc.__class__.__name__
    raw = f"[!] Tool {func_name} failed locally: {exc.__class__.__name__}: {message}"
    return _record_tool_result_with_record(
        agent,
        func_name,
        func_args,
        raw,
        duration_ms=duration_ms,
        ok=False,
        error_type=exc.__class__.__name__,
    )


def _record_and_preview_tool_result(
    agent: AgentContext,
    func_name: str,
    func_args: dict[str, Any],
    tool_result: Any,
    *,
    duration_ms: int = 0,
    ok: bool = True,
    error_type: str = "",
) -> str:
    """Persist raw tool output and return the prompt-facing preview.

    Evidence inspection tools intentionally do not create new evidence records;
    otherwise viewing an evidence blob would recursively duplicate it.
    """

    content, _, _ = _record_tool_result_with_record(
        agent,
        func_name,
        func_args,
        tool_result,
        duration_ms=duration_ms,
        ok=ok,
        error_type=error_type,
    )
    return content


def _record_tool_result_with_record(
    agent: AgentContext,
    func_name: str,
    func_args: dict[str, Any],
    tool_result: Any,
    *,
    duration_ms: int = 0,
    ok: bool = True,
    error_type: str = "",
) -> tuple[str, Any | None, str]:
    """Persist raw tool output and return prompt preview plus evidence record."""

    if func_name in {"evidence_list", "evidence_view", "evidence_search"}:
        raw = str(tool_result)
        _record_tool_call_without_new_evidence(
            agent,
            func_name,
            func_args,
            raw,
            duration_ms=duration_ms,
            ok=ok,
            error_type=error_type,
        )
        return raw, None, raw

    state = getattr(getattr(agent, "context", None), "state", None)
    agent_state = getattr(state, "agent_state", None)
    if agent_state is None:
        raw = str(tool_result)
        return raw, None, raw

    raw = pop_raw_tool_output_override(
        agent,
        tool=func_name,
        arguments=func_args,
    )
    if raw is None:
        raw = str(tool_result)
    record = agent_state.remember_tool_result(
        tool=func_name,
        arguments=func_args,
        output=raw,
        status=parse_status_code(raw),
    )
    agent_state.record_tool_call(
        tool=func_name,
        arguments=func_args,
        status=record.status,
        evidence_id=record.id,
        summary=record.summary,
        duration_ms=duration_ms,
        ok=ok,
        error_type=error_type,
    )
    if record.truncated:
        return (
            f"[evidence:{record.id}] raw output stored ({record.size} chars). "
            "Preview follows; call evidence_view with this id for raw chunks.\n"
            f"{record.preview}"
        ), record, raw
    return f"[evidence:{record.id}]\n{record.preview}", record, raw


def _agent_state(agent: AgentContext) -> Any | None:
    state = getattr(getattr(agent, "context", None), "state", None)
    return getattr(state, "agent_state", None)


def _redundant_evidence_view_reason(
    agent: AgentContext,
    func_name: str,
    func_args: dict[str, Any],
) -> str:
    if func_name != "evidence_view":
        return ""
    agent_state = _agent_state(agent)
    if agent_state is None:
        return ""
    return agent_state.evidence_view_redundancy_reason(func_args)


def _record_tool_call_without_new_evidence(
    agent: AgentContext,
    func_name: str,
    func_args: dict[str, Any],
    raw: Any,
    *,
    duration_ms: int = 0,
    ok: bool = True,
    error_type: str = "",
) -> None:
    agent_state = _agent_state(agent)
    if agent_state is None:
        return
    evidence_id = ""
    if func_name in {"evidence_view", "evidence_search"}:
        evidence_id = str(func_args.get("evidence_id", "") or "").strip()
    agent_state.record_tool_call(
        tool=func_name,
        arguments=func_args,
        status=parse_status_code(str(raw or "")),
        evidence_id=evidence_id,
        summary=str(raw or ""),
        duration_ms=duration_ms,
        ok=ok,
        error_type=error_type,
    )


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1000))


def _append_correction_note(content: str, pre_hint: str, post_hint: str) -> str:
    notes = [item for item in (pre_hint, post_hint) if item]
    if not notes:
        return content
    return f"{content}\n[diagnostic] {' '.join(notes)}"


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
