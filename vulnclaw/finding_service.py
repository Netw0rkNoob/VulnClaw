"""Application flows for auditing active, saved, and historical finding data."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

from vulnclaw.agent.context import SessionState
from vulnclaw.config.settings import load_config
from vulnclaw.findings.evidence import restore_latest_verdict
from vulnclaw.findings.types import finding_input_digest
from vulnclaw.findings.verification import verify_findings
from vulnclaw.run_context import atomic_write_json, load_run_context
from vulnclaw.target_state.store import load_target_state, save_target_state, target_state_path


class FindingStateChangedError(ValueError):
    """The target changed while an independent audit was in progress."""


def assessment_summary(session: SessionState) -> dict[str, int]:
    return {
        "total": len(session.findings),
        **{outcome: sum(f.assessment is not None and f.assessment.outcome == outcome
                        for f in session.findings)
           for outcome in ("verified", "rejected", "suspected_high", "suspected_low")},
        "incomplete": sum(f.assessment is not None and not f.assessment.complete
                          for f in session.findings),
    }


async def verify_session_file(session_path: str, *, config=None, poc_verify=None, reuse=False):
    """Persist a separate audited copy; never rewrite a file supplied for export."""
    config = config or load_config()
    source_path = Path(session_path).expanduser().resolve()
    session = SessionState.load(source_path)
    key = hashlib.sha256(str(source_path).encode()).hexdigest()
    path = Path(config.session.output_dir) / "evidence" / "verification" / "sessions" / key / "session.json"
    if path.exists():
        cached = SessionState.load(path)
        for finding in session.findings:
            prior = next((f for f in cached.findings if f.finding_id == finding.finding_id), None)
            if prior is None:
                continue
            for assessment in prior.verification_history:
                if assessment not in finding.verification_history:
                    finding.verification_history.append(copy.deepcopy(assessment))
            if finding_input_digest(finding) == finding_input_digest(prior):
                if finding.assessment and finding.assessment not in finding.verification_history:
                    finding.verification_history.append(finding.assessment)
                finding.assessment = copy.deepcopy(prior.assessment)
                finding.previous_verification = copy.deepcopy(prior.previous_verification)
                restore_latest_verdict(finding)
    session.set_save_path(path)
    session.set_checkpoint_callback(lambda state, _reason: atomic_write_json(path, state.model_dump(mode="json")))
    view = await verify_findings(session, config=config, poc_verify=poc_verify, reuse=reuse)
    atomic_write_json(path, session.model_dump(mode="json"))
    return view, path


async def verify_target(target: str, *, config=None, poc_verify=None, reuse=False):
    """Audit a target and append checkpoints through its existing persistence flow."""
    config = config or load_config()
    raw = load_target_state(target)
    if not raw:
        raise FileNotFoundError(f"Target state not found: {target}")
    session = SessionState(**raw)
    meta = raw.get("resume_meta") or {}
    run_context = (
        load_run_context(meta["run_name"], runs_dir=str(Path(meta["run_dir"]).parent), config=config)
        if meta.get("run_name") and meta.get("run_dir") else None
    )
    paths = []
    expected_raw = raw

    def checkpoint(state, reason):
        nonlocal expected_raw
        if load_target_state(target) != expected_raw:
            raise FindingStateChangedError("Target state changed during audit; retry with current data")
        paths.append(save_target_state(
            target, state, command="verify", run_context=run_context,
            checkpoint_reason=reason, merge_existing=False,
        ))
        expected_raw = load_target_state(target)

    session.set_checkpoint_callback(checkpoint)
    view = await verify_findings(session, config=config, poc_verify=poc_verify, reuse=reuse)
    if not paths:
        if reuse:
            return view, target_state_path(target), raw
        checkpoint(session, "findings_assessed")
    return view, paths[-1], expected_raw
