"""Shared application orchestration before entering the report renderer."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from vulnclaw.agent.context import SessionState
from vulnclaw.finding_service import verify_session_file, verify_target
from vulnclaw.findings.verification import verify_findings
from vulnclaw.report.generator import generate_report
from vulnclaw.target_state.store import load_target_state

if TYPE_CHECKING:
    from vulnclaw.config.schema import VulnClawConfig
    from vulnclaw.orchestrator import OrchestratorRunResult

CONTEXT_FIELDS = ("resume_meta", "resume_summary", "recon_meta", "runtime_meta", "finding_meta")


async def generate_report_for_run(
    run: OrchestratorRunResult, *, config: VulnClawConfig,
) -> dict[str, str]:
    """Export a completed run's audited snapshot without loading or auditing data."""
    if run.audited_session is None:
        raise ValueError("Report export requires the run's audited session snapshot")
    output_path = None
    if run.run_context is not None:
        output_path = str(
            run.run_context.run_dir / "reports"
            / f"report_{datetime.now():%Y%m%d_%H%M%S}_{uuid4().hex[:8]}.md"
        )
    path = Path(await generate_report(
        run.audited_session, output_path, report_format=config.session.report_format,
    )).resolve()
    artifacts = path.parent / (path.stem + ".artifacts") / "findings"
    return {
        "path": str(path),
        "findings_json": str(artifacts / "findings.json"),
        "findings_sarif": str(artifacts / "findings.sarif"),
    }


async def generate_report_from_file(session_path: str, *, config=None):
    session, _path = await verify_session_file(session_path, config=config, reuse=True)
    return await generate_report(session)


async def generate_report_for_target(
    target: str, *, current_session=None, report_format="markdown", output_path=None, config=None,
):
    """Use a task's audited snapshot, or audit persisted data before exporting."""
    if current_session is not None:
        from vulnclaw.findings.types import require_assessed

        try:
            require_assessed(current_session)
        except ValueError:
            current_session = await verify_findings(current_session, config=config)
        return await generate_report(current_session, output_path, report_format=report_format)
    if load_target_state(target):
        session, _path, raw = await verify_target(target, config=config, reuse=True)
        return await generate_report(
            session, output_path, report_format=report_format,
            target_state_context={key: raw.get(key) for key in CONTEXT_FIELDS},
        )
    return await generate_report(SessionState(target=target), output_path, report_format=report_format)
