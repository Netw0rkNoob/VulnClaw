"""Persist plugin observations for later explicit structured finding submission."""

from __future__ import annotations

from vulnclaw.agent.context import SessionState
from vulnclaw.plugins.base import PluginContext
from vulnclaw.plugins.result import PluginResult


def record_plugin_result(session: SessionState, result: PluginResult, context: PluginContext) -> str:
    """Record the real plugin output without automatically creating vulnerability claims."""
    if session.target and context.target and session.target != context.target:
        raise ValueError("Plugin result belongs to another session target")
    session.target = session.target or context.target
    record = session.agent_state.remember_tool_result(
        tool=f"plugin:{result.plugin_id}", arguments=context.model_dump(mode="json"),
        output=result.model_dump_json(), target=session.target or "",
    )
    session.agent_state.record_tool_call(
        tool=record.tool, arguments=record.arguments, evidence_id=record.id,
        summary=record.summary, duration_ms=int(result.elapsed_seconds * 1000),
        ok=result.ok, error_type=result.error_type or "",
    )
    session._notify_checkpoint("plugin_result_recorded")
    return record.id
