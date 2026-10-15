"""Evidence isolation and collision-safe terminal commit."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Optional

from vulnclaw.agent.agent_state import (
    MAX_STORED_EVIDENCE,
    MAX_STORED_PINNED_FACTS,
    MAX_STORED_PROGRESS_SIGNALS,
    MAX_STORED_STEPS,
    MAX_STORED_TOOL_CALLS,
    AgentState,
    extract_flags,
)
from vulnclaw.agent.parallel_agents import merge_session_state
from vulnclaw.agent.subagent.models import get_subagent_context
from vulnclaw.findings.types import replace_snapshot_refs


@dataclass(frozen=True)
class MergeReport:
    id_map: dict[str, str]
    evidence_ids: tuple[str, ...]


def _task_path(parent_agent: Any, task_id: str) -> list[str]:
    context = get_subagent_context(parent_agent)
    parent_task = (
        context.task_context.task_id
        if context is not None and context.task_context is not None
        else ""
    )
    return [item for item in (parent_task, task_id) if item and item != "main"]


def _normalize_contributors(
    provenance: Any,
    *,
    fallback_task_id: str,
    fallback_agent_type: str,
    fallback_evidence_ids: list[str],
    fallback_path: list[str],
) -> list[dict[str, Any]]:
    source = provenance if isinstance(provenance, dict) else {}
    raw = source.get("contributors")
    if not isinstance(raw, list) or not raw:
        raw = [source] if source.get("task_id") else []
    contributors: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        task_id = str(item.get("task_id") or "").strip()
        if not task_id:
            continue
        normalized = {
            "task_id": task_id,
            "agent_type": str(item.get("agent_type") or "").strip(),
            "source_evidence_ids": sorted(
                {
                    str(value)
                    for value in (
                        item.get("source_evidence_ids")
                        or item.get("child_evidence_ids")
                        or []
                    )
                    if str(value)
                }
            ),
            "path": [
                str(value)
                for value in (item.get("path") or [])
                if str(value)
            ],
        }
        if not normalized["path"]:
            normalized["path"] = fallback_path
        contributors.append(normalized)
    if contributors:
        return contributors
    return [
        {
            "task_id": fallback_task_id,
            "agent_type": fallback_agent_type,
            "source_evidence_ids": fallback_evidence_ids,
            "path": fallback_path,
        }
    ]


def _merge_contributors(
    target: list[dict[str, Any]],
    additions: list[dict[str, Any]],
) -> None:
    for addition in additions:
        key = (
            addition["task_id"],
            addition["agent_type"],
            tuple(addition["path"]),
        )
        existing = next(
            (
                item
                for item in target
                if (
                    item["task_id"],
                    item["agent_type"],
                    tuple(item["path"]),
                )
                == key
            ),
            None,
        )
        if existing is None:
            target.append(copy.deepcopy(addition))
            continue
        existing["source_evidence_ids"] = sorted(
            {
                *existing["source_evidence_ids"],
                *addition["source_evidence_ids"],
            }
        )


def _select_evidence(
    candidates: list[Any],
    child: AgentState,
    max_records: int,
) -> list[Any]:
    referenced = {
        evidence_id
        for claim in child.verified_claims
        for evidence_id in claim.evidence_ids
    }
    referenced.update(
        fact.evidence_id for fact in child.pinned_facts if fact.evidence_id
    )

    def priority(item: Any) -> tuple[int, int, int]:
        return (
            0 if extract_flags(item.content or "") else 1,
            0 if item.id in referenced else 1,
            -int(item.id[1:]) if item.id[1:].isdigit() else 0,
        )

    return sorted(candidates, key=priority)[: max(0, max_records)]


def _drop_evidence_indexes(state: AgentState, indexes: list[int]) -> None:
    valid = sorted({index for index in indexes if 0 <= index < len(state.evidence)})
    if not valid:
        return
    removed_ids = {state.evidence[index].id for index in valid}
    for index in reversed(valid):
        del state.evidence[index]
    for claim in state.verified_claims:
        claim.evidence_ids = [
            evidence_id
            for evidence_id in claim.evidence_ids
            if evidence_id not in removed_ids
        ]
    for fact in state.pinned_facts:
        if fact.evidence_id in removed_ids:
            fact.evidence_id = ""
    for signal in state.progress_signals:
        if signal.evidence_id in removed_ids:
            signal.evidence_id = ""
    for call in state.tool_calls:
        if call.evidence_id in removed_ids:
            call.evidence_id = ""
    for record in state.evidence:
        if record.duplicate_of in removed_ids:
            record.duplicate_of = ""


def _reserve_evidence_capacity(
    state: AgentState,
    incoming: int,
    *,
    protected_ids: set[str],
) -> int:
    requested = min(MAX_STORED_EVIDENCE, max(0, int(incoming)))
    protected = {
        evidence_id
        for claim in state.verified_claims
        for evidence_id in claim.evidence_ids
    }
    protected.update(
        fact.evidence_id for fact in state.pinned_facts if fact.evidence_id
    )
    protected.update(protected_ids)

    def evictable() -> list[int]:
        return [
            index
            for index, item in enumerate(state.evidence)
            if item.id not in protected
        ]

    overflow = max(0, len(state.evidence) - MAX_STORED_EVIDENCE)
    if overflow:
        _drop_evidence_indexes(state, evictable()[:overflow])
        overflow = max(0, len(state.evidence) - MAX_STORED_EVIDENCE)
        if overflow:
            _drop_evidence_indexes(state, list(range(overflow)))

    needed = max(0, len(state.evidence) + requested - MAX_STORED_EVIDENCE)
    if needed:
        _drop_evidence_indexes(state, evictable()[:needed])
    return min(requested, max(0, MAX_STORED_EVIDENCE - len(state.evidence)))


def _enforce_auxiliary_capacity(state: AgentState) -> None:
    for records, limit in (
        (state.tool_calls, MAX_STORED_TOOL_CALLS),
        (state.steps, MAX_STORED_STEPS),
        (state.progress_signals, MAX_STORED_PROGRESS_SIGNALS),
        (state.pinned_facts, MAX_STORED_PINNED_FACTS),
    ):
        overflow = len(records) - limit
        if overflow > 0:
            del records[:overflow]


def merge_agent_state(
    parent: AgentState,
    child: AgentState,
    *,
    max_records: int,
    baseline_fingerprints: Optional[set[str]] = None,
) -> dict[str, str]:
    """Merge child additions and rewrite every evidence reference."""

    if parent is child:
        return {}

    id_map: dict[str, str] = {}
    parent_by_fingerprint = {
        item.fingerprint: item for item in parent.evidence if item.fingerprint
    }
    reference_map = {
        item.id: parent_by_fingerprint[item.fingerprint].id
        for item in child.evidence
        if item.fingerprint in parent_by_fingerprint
    }
    candidate_by_fingerprint = {
        item.fingerprint: item
        for item in child.evidence
        if item.fingerprint and item.fingerprint not in parent_by_fingerprint
    }
    kept = _select_evidence(
        list(candidate_by_fingerprint.values()),
        child,
        max_records,
    )
    child_referenced = {
        evidence_id
        for claim in child.verified_claims
        for evidence_id in claim.evidence_ids
    }
    child_referenced.update(
        fact.evidence_id for fact in child.pinned_facts if fact.evidence_id
    )
    protected_parent_ids = {
        reference_map[evidence_id]
        for evidence_id in child_referenced
        if evidence_id in reference_map
    }
    kept = kept[
        : _reserve_evidence_capacity(
            parent,
            len(kept),
            protected_ids=protected_parent_ids,
        )
    ]

    for item in kept:
        parent.evidence_seq += 1
        new_id = f"e{parent.evidence_seq:03d}"
        record = copy.deepcopy(item)
        record.id = new_id
        parent.evidence.append(record)
        parent_by_fingerprint[item.fingerprint] = record
        id_map[item.id] = new_id
        reference_map[item.id] = new_id

    for item in child.evidence:
        if item.fingerprint in parent_by_fingerprint:
            reference_map[item.id] = parent_by_fingerprint[item.fingerprint].id

    child_fingerprints = {
        item.id: item.fingerprint for item in child.evidence if item.fingerprint
    }
    for old_id, parent_id in reference_map.items():
        contributed_same_id = bool(
            baseline_fingerprints is not None
            and child_fingerprints.get(old_id)
            and child_fingerprints[old_id] not in baseline_fingerprints
        )
        if old_id != parent_id or contributed_same_id:
            id_map.setdefault(old_id, parent_id)

    for item in kept:
        parent_record = parent.get_evidence(id_map[item.id])
        if parent_record is None or not parent_record.duplicate_of:
            continue
        parent_record.duplicate_of = reference_map.get(
            parent_record.duplicate_of,
            "",
        )
        if parent_record.duplicate_of == parent_record.id:
            parent_record.duplicate_of = ""

    seen_claims = {claim.claim for claim in parent.verified_claims}
    for claim in child.verified_claims:
        if claim.claim in seen_claims:
            continue
        copied = copy.deepcopy(claim)
        parent.claim_seq += 1
        copied.id = f"c{parent.claim_seq:03d}"
        copied.evidence_ids = [
            reference_map[evidence_id]
            for evidence_id in claim.evidence_ids
            if evidence_id in reference_map
        ]
        parent.verified_claims.append(copied)
        seen_claims.add(claim.claim)

    seen_pins = {fact.text for fact in parent.pinned_facts}
    for fact in child.pinned_facts:
        if fact.text in seen_pins:
            continue
        copied = copy.deepcopy(fact)
        copied.evidence_id = reference_map.get(copied.evidence_id, "")
        parent.pinned_facts.append(copied)
        seen_pins.add(fact.text)

    seen_signals = {
        (signal.kind, signal.detail) for signal in parent.progress_signals
    }
    for signal in child.progress_signals:
        key = (signal.kind, signal.detail)
        if key in seen_signals:
            continue
        copied = copy.deepcopy(signal)
        copied.evidence_id = reference_map.get(copied.evidence_id, "")
        parent.progress_signals.append(copied)
        seen_signals.add(key)

    for tool_call in child.tool_calls:
        copied = copy.deepcopy(tool_call)
        copied.evidence_id = reference_map.get(copied.evidence_id, "")
        if copied not in parent.tool_calls:
            parent.tool_calls.append(copied)
    for step in child.steps:
        if step not in parent.steps:
            parent.steps.append(copy.deepcopy(step))
    parent.pending_questions.extend(
        question
        for question in child.pending_questions
        if question not in parent.pending_questions
    )
    _enforce_auxiliary_capacity(parent)
    return id_map


class EvidenceCommitter:
    """Commit leaf→Leader and terminal Leader→Main through one path."""

    def __init__(self, *, max_records: int = 48):
        self.max_records = max(1, int(max_records))

    def commit(
        self,
        parent_agent: Any,
        child_session: Any,
        *,
        task_id: str,
        agent_type: str,
        baseline_fingerprints: set[str],
        include_session_state: bool,
    ) -> MergeReport:
        parent_session = parent_agent.context.state
        current_path = _task_path(parent_agent, task_id)
        if include_session_state:
            for finding in getattr(child_session, "findings", []) or []:
                provenance = getattr(finding, "subagent_provenance", None)
                if not isinstance(provenance, dict) or not provenance.get(
                    "task_id"
                ):
                    finding.subagent_provenance = {
                        "task_id": task_id,
                        "agent_type": agent_type,
                        "path": current_path,
                    }
                elif not provenance.get("path"):
                    origin_task = str(provenance.get("task_id") or "")
                    finding.subagent_provenance = {
                        **provenance,
                        "path": [
                            item
                            for item in (*current_path, origin_task)
                            if item
                        ],
                    }
            merge_session_state(parent_session, child_session)

        before_ids = set(parent_session.agent_state.evidence_ids())
        id_map = merge_agent_state(
            parent_session.agent_state,
            child_session.agent_state,
            max_records=self.max_records,
            baseline_fingerprints=baseline_fingerprints,
        )
        for finding in parent_session.findings:
            refs = []
            for ref in finding.evidence_snapshots:
                mapped = next((record.id for record in parent_session.agent_state.evidence
                               if record.fingerprint == ref.fingerprint), None)
                refs.append(ref.model_copy(update={"evidence_id": mapped or ref.evidence_id}))
            replace_snapshot_refs(finding, refs)
        new_ids = sorted(set(id_map.values()))
        for parent_id in new_ids:
            child_ids = sorted(
                child_id
                for child_id, mapped_id in id_map.items()
                if mapped_id == parent_id
            )
            existing = parent_session.subagent_evidence_provenance.get(parent_id)
            contributors = _normalize_contributors(
                existing,
                fallback_task_id=task_id,
                fallback_agent_type=agent_type,
                fallback_evidence_ids=child_ids,
                fallback_path=current_path,
            ) if existing else []
            for child_id in child_ids:
                child_provenance = (
                    child_session.subagent_evidence_provenance.get(child_id)
                )
                additions = _normalize_contributors(
                    child_provenance,
                    fallback_task_id=task_id,
                    fallback_agent_type=agent_type,
                    fallback_evidence_ids=[child_id],
                    fallback_path=current_path,
                )
                _merge_contributors(contributors, additions)
            parent_session.subagent_evidence_provenance[parent_id] = {
                "origin_kind": (
                    str(existing.get("origin_kind") or "")
                    if isinstance(existing, dict)
                    else ""
                )
                or ("parent" if parent_id in before_ids else "subagent"),
                "contributors": contributors,
            }
        return MergeReport(id_map=id_map, evidence_ids=tuple(new_ids))
