"""Target-state service for the Web UI backend."""

from __future__ import annotations

import json
from pathlib import Path

from vulnclaw.agent.context import SessionState
from vulnclaw.config.settings import TARGETS_DIR, ensure_dirs
from vulnclaw.target_state.store import (
    clear_target_state,
    diff_target_state_snapshots,
    get_target_state_preview,
    list_target_snapshots,
    load_target_state,
    rollback_target_state,
)
from vulnclaw.web.schemas import (
    TargetPreviewView,
    TargetSnapshotView,
    TargetStateDiffView,
    TargetView,
)


def list_targets(limit: int = 20) -> list[TargetView]:
    """List recent targets from persisted target state."""
    ensure_dirs()
    items: list[tuple[float, TargetView]] = []
    for state_path in TARGETS_DIR.glob("*/state.json"):
        raw = json.loads(state_path.read_text(encoding="utf-8"))
        items.append((_mtime(state_path), _build_target_view(raw)))
    items.sort(key=lambda item: item[0], reverse=True)
    return [view for _, view in items[:limit]]


def get_target(target: str) -> TargetView | None:
    """Load a single target view."""
    raw = load_target_state(target)
    if not raw:
        return None
    return _build_target_view(raw)


def get_target_raw(target: str) -> dict | None:
    """Load raw target state."""
    return load_target_state(target)


def get_snapshots(target: str) -> list[TargetSnapshotView]:
    """Return target snapshots."""
    return [TargetSnapshotView(**item) for item in list_target_snapshots(target)]


def get_preview(target: str, snapshot_id: str | None = None) -> TargetPreviewView | None:
    """Return a preview of the resume plan for a target or snapshot."""
    raw = get_target_state_preview(target, snapshot_id=snapshot_id)
    if not raw:
        return None
    return TargetPreviewView(**raw)


def get_diff(
    target: str, from_snapshot_id: str, to_snapshot_id: str | None = None
) -> TargetStateDiffView | None:
    """Return a diff between two snapshots, or a snapshot and current state."""
    raw = diff_target_state_snapshots(target, from_snapshot_id, to_snapshot_id=to_snapshot_id)
    if not raw:
        return None
    return TargetStateDiffView(**raw)


def rollback_target(target: str, snapshot_id: str) -> bool:
    """Rollback target state to a snapshot."""
    return rollback_target_state(target, snapshot_id) is not None


def clear_target(target: str) -> bool:
    """Clear a target state tree."""
    return clear_target_state(target)


def _build_target_view(raw: dict) -> TargetView:
    session = SessionState(
        **{
            k: v
            for k, v in raw.items()
            if k
            not in {"resume_meta", "resume_summary", "finding_meta", "recon_meta", "runtime_meta"}
        }
    )
    resume_meta = raw.get("resume_meta", {})
    return TargetView(
        target=session.target or resume_meta.get("target", "unknown"),
        schema_version=int(raw.get("schema_version", 1)),
        phase=session.phase.value if hasattr(session.phase, "value") else str(session.phase),
        findings_count=len(session.findings),
        verified_count=len(session.get_verified_findings()),
        pending_count=len(session.get_pending_findings()),
        candidate_count=len(session.get_candidate_findings())
        if hasattr(session, "get_candidate_findings")
        else 0,
        pending_verification_count=(
            len(session.get_pending_verification_findings())
            if hasattr(session, "get_pending_verification_findings")
            else 0
        ),
        manual_review_count=len(session.get_manual_review_findings())
        if hasattr(session, "get_manual_review_findings")
        else 0,
        resume_strategy=resume_meta.get("resume_strategy", ""),
        resume_reason=resume_meta.get("resume_strategy_reason", ""),
        constraints=session.task_constraints.model_dump(mode="json")
        if hasattr(session, "task_constraints")
        else {},
        constraint_violations=list(getattr(session, "constraint_violations", [])),
        constraint_violation_events=[
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item
            for item in getattr(session, "constraint_violation_events", [])
        ],
        raw={**raw, "findings": session.model_dump(mode="json")["findings"]},
    )


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0
