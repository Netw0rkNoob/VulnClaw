from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V3 违规 — 叶子类型已移至 config/domain_models.py。
from vulnclaw.agent.context import SessionState
from vulnclaw.config.domain_models import PentestPhase
from vulnclaw.config.secret_redaction import redact_secrets
from vulnclaw.config.settings import TARGETS_DIR, ensure_dirs
from vulnclaw.run_context import RunContext, atomic_write_json, atomic_write_text
from vulnclaw.target_state.planner import (
    build_resume_plan,
    compute_finding_confidence,
    compute_recon_asset_confidence,
)
from vulnclaw.targets import Target, legacy_target_state_key, parse_target

TARGET_STATE_SCHEMA_VERSION = 2
SNAPSHOT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")


@dataclass
class SessionRestoreResult:
    restored: bool = False
    target: str = ""
    phase: str = ""
    snapshot_id: str = ""
    resume_strategy: str = ""
    resume_reason: str = ""
    preview: dict[str, Any] = field(default_factory=dict)


def _target_key(target: str) -> str:
    return _target_model(target).state_key


def _legacy_target_key(target: str) -> str:
    return legacy_target_state_key(target)


def _target_model(target: str | Target) -> Target:
    if isinstance(target, Target):
        return target
    try:
        return parse_target(target)
    except ValueError:
        canonical = str(target)
        return Target(kind="domain", raw=str(target), canonical=canonical)


def _target_path(target: str) -> Path:
    ensure_dirs()
    return TARGETS_DIR / _target_key(target) / "state.json"


def _target_dir(target: str) -> Path:
    ensure_dirs()
    return TARGETS_DIR / _target_key(target)


def _legacy_target_dir(target: str) -> Path:
    ensure_dirs()
    return TARGETS_DIR / _legacy_target_key(target)


def _legacy_target_path(target: str) -> Path:
    return _legacy_target_dir(target) / "state.json"


def _index_path(target: str | Target) -> Path:
    model = _target_model(target)
    ensure_dirs()
    return TARGETS_DIR / model.state_key / "index.json"


def _snapshot_dir(target: str) -> Path:
    return _target_dir(target) / "snapshots"


def _snapshot_path(target: str, snapshot_id: str) -> Path | None:
    """Return a safe snapshot path, or None for invalid snapshot ids."""
    if not SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id):
        return None
    return _snapshot_dir(target) / f"{snapshot_id}.json"


def _candidate_state_paths(
    target: str,
    *,
    snapshot_id: Optional[str] = None,
    run_context: RunContext | None = None,
    target_model: Target | None = None,
) -> list[Path | None]:
    paths: list[Path | None] = []
    if run_context is not None:
        if snapshot_id:
            if SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id):
                paths.append(run_context.snapshot_path(snapshot_id, target_model))
        else:
            paths.append(run_context.state_path(target_model))

    if snapshot_id:
        paths.append(_snapshot_path(target, snapshot_id))
        paths.append(_indexed_state_path(target, snapshot_id=snapshot_id))
        legacy_snapshot = _legacy_snapshot_path(target, snapshot_id)
        if legacy_snapshot != paths[-2]:
            paths.append(legacy_snapshot)
    else:
        paths.append(_target_path(target))
        paths.append(_indexed_state_path(target))
        legacy_path = _legacy_target_path(target)
        if legacy_path != paths[0]:
            paths.append(legacy_path)
    return _unique_paths(paths)


def _legacy_snapshot_path(target: str, snapshot_id: str) -> Path | None:
    if not SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id):
        return None
    return _legacy_target_dir(target) / "snapshots" / f"{snapshot_id}.json"


def _indexed_state_path(target: str | Target, snapshot_id: Optional[str] = None) -> Path | None:
    index_path = _index_path(target)
    if not index_path.exists():
        return None
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(index, dict):
        return None
    run_dir_value = index.get("run_dir")
    target_id = str(index.get("target_id") or "")
    if not run_dir_value or not target_id:
        return None
    state_dir = Path(str(run_dir_value)) / "targets" / target_id / "state"
    if snapshot_id:
        if not SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id):
            return None
        return state_dir / "snapshots" / f"{snapshot_id}.json"
    return state_dir / "current.json"


def _unique_paths(paths: list[Path | None]) -> list[Path | None]:
    seen: set[str] = set()
    unique: list[Path | None] = []
    for path in paths:
        if path is None:
            unique.append(None)
            continue
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def load_target_state(
    target: str,
    snapshot_id: Optional[str] = None,
    *,
    run_context: RunContext | None = None,
    target_model: Target | None = None,
) -> Optional[dict[str, Any]]:
    paths = _candidate_state_paths(
        target,
        snapshot_id=snapshot_id,
        run_context=run_context,
        target_model=target_model,
    )
    for path in paths:
        if path is None or not path.exists():
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            raw.setdefault("schema_version", TARGET_STATE_SCHEMA_VERSION)
            return raw
    return None


def save_target_state(
    target: str,
    session: SessionState,
    *,
    command: str,
    session_file: Optional[str] = None,
    runtime: Any | None = None,
    run_context: RunContext | None = None,
    target_model: Target | None = None,
    checkpoint_reason: str = "checkpoint",
    merge_existing: bool = True,
    update_index: bool = True,
) -> Path:
    model = target_model or _target_model(target)
    path = run_context.state_path(model) if run_context is not None else _target_path(model.raw)
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = (
        load_target_state(
            target,
            run_context=run_context,
            target_model=model if run_context is not None else None,
        )
        if merge_existing
        else None
    )
    raw = session.model_dump(mode="json")
    raw["target"] = raw.get("target") or model.raw
    raw["target_model"] = model.to_manifest()
    raw["schema_version"] = TARGET_STATE_SCHEMA_VERSION
    if existing:
        raw = _merge_target_state(existing, raw)
        raw["schema_version"] = max(
            int(existing.get("schema_version", TARGET_STATE_SCHEMA_VERSION)),
            TARGET_STATE_SCHEMA_VERSION,
        )

    raw["recon_meta"] = _merge_recon_meta(
        existing.get("recon_meta", {}) if existing else {},
        raw.get("recon_data", {}),
    )
    raw["runtime_meta"] = _merge_runtime_meta(
        existing.get("runtime_meta", {}) if existing else {},
        session,
        runtime,
    )
    raw["finding_meta"] = _merge_finding_meta(
        existing.get("finding_meta", {}) if existing else {},
        raw.get("findings", []),
    )

    plan = build_resume_plan(raw)
    raw["resume_meta"] = {
        "target": target,
        "schema_version": raw.get("schema_version", TARGET_STATE_SCHEMA_VERSION),
        "last_saved_at": datetime.now().isoformat(),
        "last_command": command,
        "session_file": session_file,
        "verified_findings": len(session.get_verified_findings()),
        "pending_findings": len(session.get_pending_findings()),
        "executed_steps": len(session.executed_steps),
        "resume_strategy": plan["strategy"],
        "resume_strategy_reason": plan["reason"],
        "recommended_phase": plan["recommended_phase"],
        "priority_findings": plan.get("priority_findings", []),
        "priority_targets": plan.get("priority_targets", []),
        "priority_recon_assets": plan.get("priority_recon_assets", []),
        "next_actions": plan.get("next_actions", []),
        "blocked_targets": plan.get("blocked_targets", []),
        "failed_targets": plan.get("failed_targets", []),
        "recent_failed_steps": plan.get("recent_failed_steps", []),
        "low_value_rounds": plan.get("low_value_rounds", 0),
    }

    snapshot_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f") + f"_{command}"
    raw["resume_meta"]["snapshot_id"] = snapshot_id
    raw["resume_meta"]["checkpoint_reason"] = checkpoint_reason
    if run_context is not None:
        raw["resume_meta"]["run_name"] = run_context.run_name
        raw["resume_meta"]["run_dir"] = str(run_context.run_dir)
        raw["resume_meta"]["target_id"] = model.target_id

    if run_context is not None:
        snapshots = run_context.state_dir(model) / "snapshots"
    else:
        snapshots = _snapshot_dir(model.raw)
    snapshots.mkdir(parents=True, exist_ok=True)
    # 修改者: security-hardening pass (plaintext credential persistence fix)
    # 修改原因: `raw` carries the full session (tool call args/results
    # verbatim) into a *second* on-disk location beyond SessionState.save()'s
    # own file -- same redaction, applied once here via atomic_write_text
    # instead of atomic_write_json so the generic JSON-writing helper (used
    # elsewhere for things like config files that may legitimately need
    # their own keys preserved) doesn't get redaction behavior forced onto
    # every caller.
    redacted_content = redact_secrets(json.dumps(raw, ensure_ascii=False, indent=2))
    atomic_write_text(path, redacted_content)
    atomic_write_text(snapshots / f"{snapshot_id}.json", redacted_content)

    if run_context is not None:
        atomic_write_json(run_context.target_json_path(model), model.to_manifest())
        if update_index:
            _write_index_mirror(model, run_context, snapshot_id)
        run_context.record_checkpoint(
            snapshot_id,
            reason=checkpoint_reason,
            target_id=model.target_id,
        )

    return path


def get_target_state_preview(
    target: str,
    snapshot_id: Optional[str] = None,
    *,
    run_context: RunContext | None = None,
    target_model: Target | None = None,
) -> Optional[dict[str, Any]]:
    raw = load_target_state(
        target,
        snapshot_id=snapshot_id,
        run_context=run_context,
        target_model=target_model,
    )
    if not raw:
        return None

    resume_meta = raw.get("resume_meta", {}) if isinstance(raw.get("resume_meta"), dict) else {}
    plan = build_resume_plan(raw)
    findings = raw.get("findings", [])
    verified = [f for f in findings if f.get("verification_status") == "verified"]
    pending = [f for f in findings if f.get("verification_status", "pending") == "pending"]
    candidate = [f for f in findings if f.get("lifecycle_status") == "candidate"]
    pending_verification = [
        f for f in findings if f.get("lifecycle_status") == "pending_verification"
    ]
    manual_review_count = _manual_review_count(findings)

    return {
        "target": raw.get("target") or resume_meta.get("target") or target,
        "schema_version": int(raw.get("schema_version", TARGET_STATE_SCHEMA_VERSION)),
        "phase": _phase_name(raw.get("phase")),
        "snapshot_id": resume_meta.get("snapshot_id") or snapshot_id or "",
        "last_command": resume_meta.get("last_command", ""),
        "resume_strategy": resume_meta.get("resume_strategy", ""),
        "resume_reason": resume_meta.get("resume_strategy_reason", ""),
        "findings_count": len(findings),
        "verified_count": len(verified),
        "pending_count": len(pending),
        "candidate_count": len(candidate),
        "pending_verification_count": len(pending_verification),
        "manual_review_count": manual_review_count,
        "priority_targets": plan.get("priority_targets", []),
        "priority_recon_assets": plan.get("priority_recon_assets", []),
        "blocked_targets": plan.get("blocked_targets", []),
        "failed_targets": plan.get("failed_targets", []),
        "recent_failed_steps": plan.get("recent_failed_steps", []),
        "next_actions": plan.get("next_actions", []),
        "low_value_rounds": plan.get("low_value_rounds", 0),
        "constraints": raw.get("task_constraints", {})
        if isinstance(raw.get("task_constraints"), dict)
        else {},
        "constraint_violations": raw.get("constraint_violations", [])
        if isinstance(raw.get("constraint_violations"), list)
        else [],
        "constraint_violation_events": raw.get("constraint_violation_events", [])
        if isinstance(raw.get("constraint_violation_events"), list)
        else [],
    }


def diff_target_state_snapshots(
    target: str,
    from_snapshot_id: str,
    to_snapshot_id: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    base = load_target_state(target, snapshot_id=from_snapshot_id)
    compare = (
        load_target_state(target, snapshot_id=to_snapshot_id)
        if to_snapshot_id
        else load_target_state(target)
    )
    if not base or not compare:
        return None

    base_resume = base.get("resume_meta", {}) if isinstance(base.get("resume_meta"), dict) else {}
    compare_resume = (
        compare.get("resume_meta", {}) if isinstance(compare.get("resume_meta"), dict) else {}
    )

    return {
        "target": target,
        "schema_version_from": int(base.get("schema_version", TARGET_STATE_SCHEMA_VERSION)),
        "schema_version_to": int(compare.get("schema_version", TARGET_STATE_SCHEMA_VERSION)),
        "from_snapshot_id": from_snapshot_id,
        "to_snapshot_id": to_snapshot_id or compare_resume.get("snapshot_id", "current"),
        "resume_strategy_from": base_resume.get("resume_strategy", ""),
        "resume_strategy_to": compare_resume.get("resume_strategy", ""),
        "added_findings": _diff_finding_titles(
            base.get("findings", []), compare.get("findings", []), mode="added"
        ),
        "removed_findings": _diff_finding_titles(
            base.get("findings", []), compare.get("findings", []), mode="removed"
        ),
        "updated_findings": _diff_updated_findings(
            base.get("findings", []), compare.get("findings", [])
        ),
        "added_steps": _diff_list(
            base.get("executed_steps", []), compare.get("executed_steps", [])
        ),
        "removed_steps": _diff_list(
            compare.get("executed_steps", []), base.get("executed_steps", [])
        ),
        "added_notes": _diff_list(base.get("notes", []), compare.get("notes", [])),
        "removed_notes": _diff_list(compare.get("notes", []), base.get("notes", [])),
        "added_recon_assets": _diff_recon_assets(
            base.get("recon_meta", {}), compare.get("recon_meta", {}), mode="added"
        ),
        "removed_recon_assets": _diff_recon_assets(
            base.get("recon_meta", {}), compare.get("recon_meta", {}), mode="removed"
        ),
    }


def hydrate_session_from_target_state(
    target: str,
    snapshot_id: Optional[str] = None,
    *,
    run_context: RunContext | None = None,
    target_model: Target | None = None,
) -> Optional[SessionState]:
    raw = load_target_state(
        target,
        snapshot_id=snapshot_id,
        run_context=run_context,
        target_model=target_model,
    )
    if not raw:
        return None

    resume_meta = raw.get("resume_meta", {})
    strategy = resume_meta.get("resume_strategy")
    if strategy == "verify_pending_findings":
        raw["phase"] = PentestPhase.VULN_DISCOVERY
    elif strategy == "exploit_expand":
        raw["phase"] = PentestPhase.EXPLOITATION

    raw["resume_meta"] = resume_meta
    raw["resume_summary"] = _build_resume_summary(raw, resume_meta)
    return SessionState(**raw)


def apply_target_state_to_agent(
    agent: Any,
    target: str,
    snapshot_id: Optional[str] = None,
    *,
    run_context: RunContext | None = None,
    target_model: Target | None = None,
) -> SessionRestoreResult:
    """Restore a target state into an agent and return a structured restore result."""
    restored_state = hydrate_session_from_target_state(
        target,
        snapshot_id=snapshot_id,
        run_context=run_context,
        target_model=target_model,
    )
    if restored_state:
        agent.context.state = restored_state
        preview = (
            get_target_state_preview(
                target,
                snapshot_id=snapshot_id,
                run_context=run_context,
                target_model=target_model,
            )
            or {}
        )
        return SessionRestoreResult(
            restored=True,
            target=restored_state.target or target,
            phase=_phase_name(restored_state.phase),
            snapshot_id=str(preview.get("snapshot_id", snapshot_id or "")),
            resume_strategy=str(preview.get("resume_strategy", "")),
            resume_reason=str(preview.get("resume_reason", "")),
            preview=preview,
        )

    agent.context.state.target = target
    return SessionRestoreResult(
        restored=False,
        target=target,
        phase=_phase_name(agent.context.state.phase),
        snapshot_id=snapshot_id or "",
        preview={"target": target, "schema_version": TARGET_STATE_SCHEMA_VERSION},
    )


def build_task_session_summary(
    session: SessionState,
    *,
    command: str,
    restored: bool = False,
    snapshot_id: str = "",
) -> dict[str, Any]:
    """Build a structured session summary for task completion surfaces."""
    resume_meta = (
        session.resume_meta if isinstance(getattr(session, "resume_meta", {}), dict) else {}
    )
    return {
        "target": session.target or "",
        "command": command,
        "restored": restored,
        "snapshot_id": snapshot_id,
        "schema_version": int(resume_meta.get("schema_version", TARGET_STATE_SCHEMA_VERSION)),
        "phase": _phase_name(session.phase),
        "findings_count": len(session.findings),
        "verified_count": len(session.get_verified_findings()),
        "pending_count": len(session.get_pending_findings()),
        "executed_steps": len(session.executed_steps),
        "resume_strategy": resume_meta.get("resume_strategy", ""),
        "resume_reason": resume_meta.get("resume_strategy_reason", ""),
        "constraints": session.task_constraints.model_dump(mode="json")
        if hasattr(session, "task_constraints")
        else {},
        "constraint_violations": list(getattr(session, "constraint_violations", [])),
        "constraint_violation_events": [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item
            for item in getattr(session, "constraint_violation_events", [])
        ],
    }


def list_target_snapshots(target: str) -> list[dict[str, Any]]:
    indexed_current = _indexed_state_path(target)
    snapshots = (
        indexed_current.parent / "snapshots"
        if indexed_current is not None
        else _snapshot_dir(target)
    )
    if not snapshots.exists():
        return []

    items: list[dict[str, Any]] = []
    for path in sorted(snapshots.glob("*.json"), reverse=True):
        raw = json.loads(path.read_text(encoding="utf-8"))
        meta = raw.get("resume_meta", {})
        items.append(
            {
                "snapshot_id": path.stem,
                "schema_version": int(raw.get("schema_version", TARGET_STATE_SCHEMA_VERSION)),
                "last_saved_at": meta.get("last_saved_at", ""),
                "last_command": meta.get("last_command", ""),
                "verified_findings": meta.get("verified_findings", 0),
                "pending_findings": meta.get("pending_findings", 0),
                "executed_steps": meta.get("executed_steps", 0),
                "resume_strategy": meta.get("resume_strategy", ""),
            }
        )
    return items


def rollback_target_state(target: str, snapshot_id: str) -> Optional[Path]:
    raw = load_target_state(target, snapshot_id=snapshot_id)
    if not raw:
        return None
    indexed_current = _indexed_state_path(target)
    path = indexed_current if indexed_current is not None else _target_path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, raw)
    return path


def clear_target_state(target: str) -> bool:
    target_dir = _target_dir(target)
    if not target_dir.exists():
        return False
    shutil.rmtree(target_dir, ignore_errors=True)
    return True


def legacy_target_state_exists(target: str, target_model: Target | None = None) -> bool:
    model = target_model or _target_model(target)
    legacy_dir = _legacy_target_dir(target)
    return model.state_key != _legacy_target_key(target) and (legacy_dir / "state.json").exists()


def import_legacy_target_state(
    target: str,
    *,
    run_context: RunContext,
    target_model: Target | None = None,
    command: str,
    runtime: Any | None = None,
    no_import: bool = False,
) -> SessionRestoreResult:
    """Import a raw-hash legacy target state into a run-backed checkpoint."""
    model = target_model or _target_model(target)
    legacy_path = _legacy_target_path(target)
    if not legacy_target_state_exists(target, model) or not legacy_path.exists():
        return SessionRestoreResult(restored=False, target=target)

    raw = json.loads(legacy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return SessionRestoreResult(restored=False, target=target)
    state = SessionState(**raw)
    state.target = state.target or target

    if no_import:
        preview = get_target_state_preview(target) or {}
        return SessionRestoreResult(
            restored=True,
            target=state.target or target,
            phase=_phase_name(state.phase),
            snapshot_id=str(preview.get("snapshot_id", "")),
            preview=preview,
        )

    save_target_state(
        model.raw,
        state,
        command=command,
        runtime=runtime,
        run_context=run_context,
        target_model=model,
        checkpoint_reason="legacy_import",
        merge_existing=False,
    )
    _make_tree_read_only(legacy_path.parent)
    run_context.append_event(
        "legacy_import",
        {
            "raw": target,
            "canonical": model.canonical,
            "legacy_dir": str(legacy_path.parent),
            "target_id": model.target_id,
        },
    )
    preview = (
        get_target_state_preview(model.raw, run_context=run_context, target_model=model) or {}
    )
    return SessionRestoreResult(
        restored=True,
        target=state.target or target,
        phase=_phase_name(state.phase),
        snapshot_id=str(preview.get("snapshot_id", "")),
        resume_strategy=str(preview.get("resume_strategy", "")),
        resume_reason=str(preview.get("resume_reason", "")),
        preview=preview,
    )


def _build_resume_summary(raw: dict[str, Any], resume_meta: dict[str, Any]) -> str:
    findings = raw.get("findings", [])
    finding_meta = raw.get("finding_meta", {})
    recon_data = raw.get("recon_data", {})
    recon_meta = raw.get("recon_meta", {})
    runtime_meta = raw.get("runtime_meta", {})
    executed_steps = raw.get("executed_steps", [])
    pending_count = resume_meta.get("pending_findings", 0)
    verified_count = resume_meta.get("verified_findings", 0)

    parts = [
        "## 历史成果摘要",
        f"- 最近命令: {resume_meta.get('last_command', 'unknown')}",
        f"- 已执行步骤: {resume_meta.get('executed_steps', len(executed_steps))}",
        f"- 已验证漏洞: {verified_count}",
        f"- 待验证漏洞: {pending_count}",
    ]

    if resume_meta.get("resume_strategy"):
        parts.append(f"- 恢复优先策略: {resume_meta['resume_strategy']}")
    if resume_meta.get("resume_strategy_reason"):
        parts.append(f"- 策略原因: {resume_meta['resume_strategy_reason']}")
    if resume_meta.get("low_value_rounds"):
        parts.append(f"- 连续低价值轮次: {resume_meta['low_value_rounds']}")
    if resume_meta.get("blocked_targets"):
        parts.append(f"- 已阻塞目标: {', '.join(resume_meta['blocked_targets'][:5])}")
    if runtime_meta.get("current_attack_path"):
        parts.append(f"- 最近攻击路径: {runtime_meta['current_attack_path']}")
    if recon_data:
        parts.append(f"- 已有侦察数据键: {', '.join(sorted(recon_data.keys())[:10])}")
    if resume_meta.get("priority_targets"):
        parts.append(f"- 恢复优先目标: {', '.join(resume_meta['priority_targets'][:5])}")

    if findings:
        parts.append("- 最近漏洞线索")
        prioritized = sorted(
            findings,
            key=lambda item: (
                -float(finding_meta.get(_finding_key(item), {}).get("confidence", 0.5))
            ),
        )
        for finding in prioritized[:5]:
            title = finding.get("title", "unknown")
            vuln_type = finding.get("vuln_type", "")
            status = finding.get("verification_status", "pending")
            confidence = finding_meta.get(_finding_key(finding), {}).get("confidence", 0.5)
            parts.append(f"  - {title} [{vuln_type or '未分类'}] ({status}, conf={confidence})")

    high_value_assets = _top_recon_assets_for_summary(recon_meta)
    if high_value_assets:
        parts.append("- 高置信度侦察资产")
        for item in high_value_assets[:5]:
            parts.append(f"  - {item}")

    failed_targets = resume_meta.get("failed_targets", [])
    if failed_targets:
        parts.append("- 历史失败目标")
        for item in failed_targets[:5]:
            parts.append(f"  - {item}")

    failed_steps = resume_meta.get("recent_failed_steps", [])
    if failed_steps:
        parts.append("- 最近失败路径/步骤")
        for item in failed_steps[:5]:
            parts.append(f"  - {item}")

    next_actions = resume_meta.get("next_actions", [])
    if next_actions:
        parts.append("- 恢复建议动作")
        for item in next_actions[:5]:
            parts.append(f"  - {item}")

    return "\n".join(parts)


def _merge_target_state(existing: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    merged.update(current)

    merged["recon_data"] = _merge_recon_data(
        existing.get("recon_data", {}), current.get("recon_data", {})
    )
    merged["findings"] = _merge_findings(existing.get("findings", []), current.get("findings", []))

    # [P18 修改] 合并 step_records，不再合并 executed_steps
    # executed_steps 在序列化时会自动从 step_records 生成
    existing_records = existing.get("step_records", [])
    current_records = current.get("step_records", [])
    merged["step_records"] = existing_records + [
        record for record in current_records if record not in existing_records
    ]

    existing_notes = existing.get("notes", [])
    current_notes = current.get("notes", [])
    merged["notes"] = existing_notes + [
        note for note in current_notes if note not in existing_notes
    ]

    existing_constraints = existing.get("task_constraints", {})
    current_constraints = current.get("task_constraints", {})
    if isinstance(existing_constraints, dict) and isinstance(current_constraints, dict):
        if any(current_constraints.values()):
            merged["task_constraints"] = current_constraints
        else:
            merged["task_constraints"] = existing_constraints

    existing_violations = existing.get("constraint_violations", [])
    current_violations = current.get("constraint_violations", [])
    if isinstance(existing_violations, list) and isinstance(current_violations, list):
        merged["constraint_violations"] = existing_violations + [
            item for item in current_violations if item not in existing_violations
        ]

    existing_violation_events = existing.get("constraint_violation_events", [])
    current_violation_events = current.get("constraint_violation_events", [])
    if isinstance(existing_violation_events, list) and isinstance(current_violation_events, list):
        seen_event_keys = {
            f"{item.get('timestamp', '')}:{item.get('summary', '')}:{item.get('source', '')}"
            for item in existing_violation_events
            if isinstance(item, dict)
        }
        merged_events = list(existing_violation_events)
        for item in current_violation_events:
            if not isinstance(item, dict):
                continue
            key = f"{item.get('timestamp', '')}:{item.get('summary', '')}:{item.get('source', '')}"
            if key not in seen_event_keys:
                merged_events.append(item)
                seen_event_keys.add(key)
        merged["constraint_violation_events"] = merged_events[-20:]

    return merged


def _merge_finding_meta(
    existing_meta: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    now = datetime.now().isoformat()
    merged = dict(existing_meta)
    for finding in findings:
        key = _finding_key(finding)
        prev = merged.get(key, {})
        observation_count = int(prev.get("observation_count", 0)) + 1
        meta = {
            "title": finding.get("title", ""),
            "vuln_type": finding.get("vuln_type", ""),
            "verification_status": finding.get("verification_status", "pending"),
            "first_seen_at": prev.get("first_seen_at", now),
            "last_seen_at": now,
            "last_verified_at": prev.get("last_verified_at"),
            "observation_count": observation_count,
        }
        if finding.get("verification_status") == "verified":
            meta["last_verified_at"] = finding.get("verified_at") or now
        meta["confidence"] = compute_finding_confidence(meta)
        merged[key] = meta
    return merged


def _merge_recon_data(existing: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in current.items():
        if isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = merged[key] + [item for item in value if item not in merged[key]]
        elif key not in merged or not merged[key]:
            merged[key] = value
        else:
            merged[key] = value
    return merged


def _merge_recon_meta(existing_meta: dict[str, Any], recon_data: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now().isoformat()
    merged: dict[str, dict[str, Any]] = {
        category: dict(items) if isinstance(items, dict) else {}
        for category, items in existing_meta.items()
    }

    for category in ("subdomains", "paths", "params"):
        values = recon_data.get(category, [])
        if not isinstance(values, list):
            continue
        bucket = merged.setdefault(category, {})
        for value in values:
            normalized = str(value).strip()
            if not normalized:
                continue
            prev = bucket.get(normalized, {})
            observation_count = int(prev.get("observation_count", 0)) + 1
            meta = {
                "category": category,
                "value": normalized,
                "first_seen_at": prev.get("first_seen_at", now),
                "last_seen_at": now,
                "observation_count": observation_count,
            }
            meta["confidence"] = compute_recon_asset_confidence(meta)
            bucket[normalized] = meta

    return merged


def _merge_findings(
    existing: list[dict[str, Any]], current: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for finding in existing + current:
        key = (
            finding.get("finding_id")
            or f"{finding.get('title', '')}::{finding.get('vuln_type', '')}"
        )
        prev = by_key.get(key)
        if prev is None:
            by_key[key] = finding
            continue

        prev_status = prev.get("verification_status", "pending")
        new_status = finding.get("verification_status", "pending")
        if prev_status != "verified" and new_status == "verified":
            by_key[key] = finding
        elif prev_status == "pending" and new_status == "rejected":
            by_key[key] = finding
    return list(by_key.values())


def _finding_key(finding: dict[str, Any]) -> str:
    return (
        finding.get("finding_id") or f"{finding.get('title', '')}::{finding.get('vuln_type', '')}"
    )


def _phase_name(value: Any) -> str:
    if hasattr(value, "value"):
        return str(value.value)
    return str(value or "")


def _write_index_mirror(model: Target, run_context: RunContext, snapshot_id: str) -> None:
    atomic_write_json(
        _index_path(model),
        {
            "raw": model.raw,
            "canonical": model.canonical,
            "latest_run": run_context.run_name,
            "run_dir": str(run_context.run_dir),
            "target_id": model.target_id,
            "latest_snapshot_id": snapshot_id,
            "updated_at": datetime.now().isoformat(),
        },
    )


def _make_tree_read_only(path: Path) -> None:
    for current, dirs, files in os.walk(path):
        for dirname in dirs:
            item = Path(current) / dirname
            item.chmod(item.stat().st_mode & ~0o222)
        for filename in files:
            item = Path(current) / filename
            item.chmod(item.stat().st_mode & ~0o222)
    path.chmod(path.stat().st_mode & ~0o222)


def _manual_review_count(findings: list[dict[str, Any]]) -> int:
    count = 0
    for finding in findings:
        severity = str(finding.get("severity", "")).strip()
        lifecycle = str(
            finding.get("lifecycle_status", finding.get("verification_status", ""))
        ).strip()
        verified = bool(finding.get("verified"))
        verification_status = str(finding.get("verification_status", "")).strip()
        if lifecycle == "needs_manual_review":
            count += 1
            continue
        if (
            not verified
            and verification_status != "rejected"
            and severity in {"Critical", "High"}
            and lifecycle in {"candidate", "pending_verification"}
        ):
            count += 1
    return count


def _display_finding_title(finding: dict[str, Any]) -> str:
    title = str(finding.get("title", "")).strip()
    vuln_type = str(finding.get("vuln_type", "")).strip()
    if title:
        return title
    if vuln_type:
        return vuln_type
    return _finding_key(finding)


def _diff_list(base: list[Any], compare: list[Any], limit: int = 10) -> list[str]:
    base_items = [str(item) for item in base]
    compare_items = [str(item) for item in compare]
    return [item for item in compare_items if item not in base_items][:limit]


def _diff_finding_titles(
    base: list[dict[str, Any]], compare: list[dict[str, Any]], *, mode: str
) -> list[str]:
    base_map = {_finding_key(item): item for item in base}
    compare_map = {_finding_key(item): item for item in compare}
    if mode == "added":
        keys = [key for key in compare_map if key not in base_map]
        source = compare_map
    else:
        keys = [key for key in base_map if key not in compare_map]
        source = base_map
    return [_display_finding_title(source[key]) for key in keys[:10]]


def _diff_updated_findings(base: list[dict[str, Any]], compare: list[dict[str, Any]]) -> list[str]:
    base_map = {_finding_key(item): item for item in base}
    compare_map = {_finding_key(item): item for item in compare}
    changed: list[str] = []
    shared_keys = [key for key in compare_map if key in base_map]
    for key in shared_keys:
        before = base_map[key]
        after = compare_map[key]
        if (
            before.get("verification_status") != after.get("verification_status")
            or before.get("severity") != after.get("severity")
            or before.get("verified") != after.get("verified")
        ):
            changed.append(_display_finding_title(after))
    return changed[:10]


def _flatten_recon_assets(recon_meta: dict[str, Any]) -> list[str]:
    assets: list[str] = []
    for category, items in recon_meta.items():
        if not isinstance(items, dict):
            continue
        for value in items:
            assets.append(f"{category}:{value}")
    return sorted(set(assets))


def _diff_recon_assets(base: dict[str, Any], compare: dict[str, Any], *, mode: str) -> list[str]:
    base_assets = _flatten_recon_assets(base)
    compare_assets = _flatten_recon_assets(compare)
    if mode == "added":
        return [item for item in compare_assets if item not in base_assets][:10]
    return [item for item in base_assets if item not in compare_assets][:10]


def _top_recon_assets_for_summary(recon_meta: dict[str, Any]) -> list[str]:
    ranked: list[tuple[float, str]] = []
    for category, items in recon_meta.items():
        if not isinstance(items, dict):
            continue
        for value, meta in items.items():
            confidence = float(meta.get("confidence", compute_recon_asset_confidence(meta)))
            ranked.append((confidence, f"{category}:{value} (conf={confidence:.2f})"))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [label for _, label in ranked[:8]]


def _merge_runtime_meta(
    existing: dict[str, Any], session: SessionState, runtime: Any | None
) -> dict[str, Any]:
    blocked_targets = set(existing.get("blocked_targets", []))
    failed_targets = dict(existing.get("failed_targets", {}))
    failed_steps = list(existing.get("failed_steps", []))

    if runtime is not None:
        blocked_targets.update(getattr(runtime, "blocked_targets", set()) or set())
        for host, count in (getattr(runtime, "failed_targets", {}) or {}).items():
            failed_targets[host] = max(int(count), int(failed_targets.get(host, 0)))

    extracted_failed_steps = _extract_failed_steps(session.executed_steps)
    for step in extracted_failed_steps:
        if step not in failed_steps:
            failed_steps.append(step)

    return {
        "blocked_targets": sorted(blocked_targets),
        "failed_targets": failed_targets,
        "failed_steps": failed_steps[-10:],
        "rounds_without_progress": int(getattr(runtime, "rounds_without_progress", 0) or 0),
        "current_attack_path": getattr(runtime, "current_attack_path", None),
        "same_path_fail_count": int(getattr(runtime, "same_path_fail_count", 0) or 0),
        "updated_at": datetime.now().isoformat(),
    }


def _extract_failed_steps(executed_steps: list[str]) -> list[str]:
    markers = (
        "失败",
        "超时",
        "拒绝",
        "blocked",
        "timeout",
        "denied",
        "404",
        "error",
        "无法",
        "未成功",
        "不可达",
    )
    failed: list[str] = []
    for step in executed_steps[-30:]:
        lower = step.lower()
        if any(marker in lower for marker in markers):
            brief = step[:160]
            if brief not in failed:
                failed.append(brief)
    return failed[-8:]
