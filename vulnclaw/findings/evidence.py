"""Immutable snapshots of tool evidence, independent of hot-history eviction."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from vulnclaw.findings.types import (
    EvidenceSnapshotRef,
    Snapshot,
    apply_assessment,
    finding_input_digest,
    merge_snapshot_refs,
    replace_snapshot_refs,
)
from vulnclaw.run_context import atomic_write_json


def scope_identity(target: str) -> tuple[str, int | None]:
    parsed = urlsplit(target if "://" in target else "//" + target)
    return (parsed.hostname or "").lower(), parsed.port


def endpoint_identity(url: str) -> tuple[str, str, int | None, str]:
    """Comparable (scheme, host, effective port, path) for endpoint matching.

    Ports default by scheme (443 for https, 80 for http) so an explicit ``:443``
    matches an implicit one, while a different port or scheme never cross-matches:
    two ports can host entirely different services.
    """
    parsed = urlsplit(url if "://" in url else "//" + url)
    scheme = (parsed.scheme or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, (parsed.hostname or "").lower(), port, parsed.path or "/"


def recorded_requests(record: Any) -> list[tuple[str, str]]:
    """Extract the (url, method) pairs a tool record actually requested.

    Mirrors the HTTP tools' argument shapes: single-request tools keep a
    top-level ``url``/``method``; ``http_probe_batch`` keeps per-request specs
    in ``requests[]``, with relative urls resolved against ``base_url`` exactly
    like the tool itself does.
    """
    arguments = record.arguments or {}
    requests: list[tuple[str, str]] = []
    url = arguments.get("url")
    if isinstance(url, str) and url:
        requests.append((url, str(arguments.get("method") or "GET").upper()))
    if record.tool == "http_probe_batch":
        base = str(arguments.get("base_url") or "").strip()
        specs = arguments.get("requests")
        if isinstance(specs, list):
            for spec in specs:
                if not isinstance(spec, dict):
                    continue
                requested = str(spec.get("raw_url") or spec.get("url") or base or "").strip()
                if not requested:
                    continue
                if not urlsplit(requested).scheme and base:
                    requested = urljoin(base.rstrip("/") + "/", requested)
                requests.append((requested, str(spec.get("method") or "GET").upper()))
    return requests


def snapshot_records(agent: Any, evidence_ids: list[str]) -> list[EvidenceSnapshotRef]:
    session = agent.context.state
    records = []
    for evidence_id in dict.fromkeys(evidence_ids):
        record = session.agent_state.get_evidence(evidence_id)
        if record is None or record.tool == "submit_finding":
            raise ValueError(f"Evidence is not available in this session: {evidence_id}")
        if record.target != session.target:
            raise ValueError(f"Evidence belongs to another target: {evidence_id}")
        records.append(record)
    root = (Path(agent.config.session.output_dir) / "evidence").resolve()
    namespace = hashlib.sha256(
        f"{session.started_at}:{session.target}:{session.task_id}".encode()
    ).hexdigest()[:24]
    result = []
    for record in records:
        snapshot = Snapshot(
            evidence_id=record.id, target=session.target or "", task_id=session.task_id,
            tool=record.tool, arguments=record.arguments, content=record.content,
            fingerprint=record.fingerprint,
        )
        payload = snapshot.model_dump(mode="json")
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        relative = f"findings/{namespace}/{digest}.json"
        atomic_write_json(root / relative, payload)
        result.append(EvidenceSnapshotRef(
            evidence_id=record.id, source_id=record.id, target=snapshot.target,
            root=str(root), path=relative, sha256=digest,
            fingerprint=record.fingerprint, task_id=session.task_id,
        ))
    return result


def load_snapshots(finding: Any) -> dict[str, Snapshot]:
    result = {}
    for ref in merge_snapshot_refs(finding.evidence_snapshots):
        root = Path(ref.root).resolve()
        path = (root / ref.path).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Evidence snapshot path escapes its evidence directory")
        payload = json.loads(path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        if digest != ref.sha256:
            raise ValueError("Evidence snapshot integrity check failed")
        snapshot = Snapshot.model_validate(payload)
        if snapshot.evidence_id != ref.source_id or snapshot.target != ref.target:
            raise ValueError("Evidence snapshot ownership does not match its reference")
        if snapshot.target != finding.target:
            raise ValueError("Evidence snapshot belongs to another target")
        result[ref.evidence_id] = snapshot
    if not result:
        raise ValueError("No structured tool evidence is attached to this finding")
    return result


def merge_finding_evidence(target_finding: Any, source_finding: Any) -> bool:
    """Fold source's evidence into an existing finding with the same identity.

    Returns True when new evidence was added. Only identical snapshot hashes
    deduplicate; distinct snapshots retain their source IDs and get unique
    reference IDs when necessary. Refs dedupe by their pointer. The
    free-text evidence listing and the verification history grow by union. The
    caller restores the latest assessment after the merge; changed inputs
    invalidate conclusions that no longer match the evidence.
    """
    snapshots = merge_snapshot_refs([
        *target_finding.evidence_snapshots, *source_finding.evidence_snapshots,
    ])
    changed = snapshots != target_finding.evidence_snapshots
    source_finding = source_finding.model_copy(deep=True)
    replace_snapshot_refs(source_finding, snapshots)
    replace_snapshot_refs(target_finding, snapshots)

    known_refs = {(ref.kind, ref.path, ref.request_id) for ref in target_finding.evidence_refs}
    ref_additions = [
        ref for ref in source_finding.evidence_refs
        if (ref.kind, ref.path, ref.request_id) not in known_refs
    ]
    if ref_additions:
        target_finding.evidence_refs = list(target_finding.evidence_refs) + ref_additions
        changed = True

    lines = target_finding.evidence.splitlines() if target_finding.evidence else []
    additions = [
        line for line in (source_finding.evidence or "").splitlines()
        if line and line not in lines
    ]
    if additions:
        target_finding.evidence = "\n".join(lines + additions)
        changed = True

    for entry in source_finding.verification_history:
        if entry not in target_finding.verification_history:
            target_finding.verification_history.append(entry)
    if not target_finding.submission_id and source_finding.submission_id:
        target_finding.submission_id = source_finding.submission_id
    return changed


def restore_latest_verdict(finding: Any) -> None:
    """Restore the newest audit of these inputs; retain other verdicts as history."""
    digest = finding_input_digest(finding)
    records = list(finding.verification_history)
    if finding.assessment is not None and finding.assessment not in records:
        records.append(finding.assessment)
    current = [a for a in records if a.input_digest == digest]
    if current:
        def assessed_time(assessment):
            try:
                value = datetime.fromisoformat(assessment.assessed_at.replace("Z", "+00:00"))
                return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
            except ValueError:
                return datetime.min.replace(tzinfo=timezone.utc)
        apply_assessment(finding, max(current, key=assessed_time))
    elif any(a.input_digest for a in records):
        finding.assessment = None
        finding.mark_manual_review("Finding inputs changed; a new audit is required")
        finding.verified_at = None
        finding.poc_script = None


def merge_structured_findings(findings: list[Any]) -> list[Any]:
    """Consolidate canonical structured identities when loading existing data."""
    kept = []
    positions = {}
    for finding in findings:
        if not finding.submission_id:
            kept.append(finding)
            continue
        position = positions.get(finding.finding_id)
        if position is None:
            positions[finding.finding_id] = len(kept)
            kept.append(finding)
            continue
        base, other = kept[position], finding
        if ((base.verification_status != "verified" and other.verification_status == "verified")
                or (base.verification_status == "pending" and other.verification_status == "rejected")):
            base, other = other, base
        merge_finding_evidence(base, other)
        restore_latest_verdict(base)
        kept[position] = base
    for finding in kept:
        restore_latest_verdict(finding)
    return kept
