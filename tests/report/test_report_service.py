import json
from pathlib import Path

import pytest

from tests.reporting_fixtures import assessed_snapshot
from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.findings.types import FindingAssessment
from vulnclaw.orchestrator import OrchestratorRunResult
from vulnclaw.report_service import generate_report_for_run
from vulnclaw.run_context import RunContext
from vulnclaw.target_state.store import SessionRestoreResult


@pytest.mark.parametrize("report_format,outcome,with_run", [
    ("markdown", None, True),
    ("html", None, False),
    ("markdown", "verified", True),
    ("html", "verified", True),
    ("markdown", "suspected_low", False),
    ("html", "suspected_low", True),
])
async def test_run_report_exports_audited_snapshot_and_all_artifacts(
    tmp_path, monkeypatch, report_format, outcome, with_run,
):
    import vulnclaw.report.generator as generator
    import vulnclaw.report_service as service

    config = VulnClawConfig()
    config.session.report_format = report_format
    session = SessionState(target="https://lab.test")
    if outcome:
        session.add_finding(VulnerabilityFinding(
            title="Controlled candidate", vuln_type="SQLi", evidence="Saved observation",
            assessment=FindingAssessment(
                outcome=outcome, method="poc" if outcome == "verified" else "evidence_review",
                complete=outcome == "verified", reason="Controlled audit",
            ),
        ))
    assessed_snapshot(session)
    context = RunContext(tmp_path / "run", {}, tmp_path) if with_run else None
    run = OrchestratorRunResult(
        SessionRestoreResult(target=session.target), {}, run_context=context,
        audited_session=session,
    )
    prior = session.model_dump(mode="json")
    monkeypatch.setattr(generator, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(generator, "_generate_attack_summary_from_session", lambda _: "Saved audit")

    def unexpected(*_args, **_kwargs):
        pytest.fail("Audited run export must not load target state or verify findings")

    monkeypatch.setattr(service, "load_target_state", unexpected)
    monkeypatch.setattr(service, "verify_findings", unexpected)
    monkeypatch.setattr("vulnclaw.findings.verification.verify_findings", unexpected)
    first = await generate_report_for_run(run, config=config)
    second = await generate_report_for_run(run, config=config)
    assert first["path"] != second["path"]
    for report in (first, second):
        assert all(Path(path).is_absolute() and Path(path).is_file() for path in report.values())
        path = Path(report["path"])
        assert path.suffix == (".html" if report_format == "html" else ".md")
        assert path.parent == ((context.run_dir / "reports") if with_run else generator.SESSIONS_DIR)
        artifacts = path.parent / (path.stem + ".artifacts") / "findings"
        assert Path(report["findings_json"]).parent == artifacts
        assert Path(report["findings_sarif"]).parent == artifacts
        document = json.loads(Path(report["findings_json"]).read_text())
        sarif = json.loads(Path(report["findings_sarif"]).read_text())
        assert document["summary"]["total"] == (1 if outcome else 0)
        assert len(document["verified"]) == len(sarif["runs"][0]["results"]) == (outcome == "verified")
        if outcome:
            assert document["findings"][0]["assessment"]["outcome"] == outcome
            assert document["findings"][0]["assessment"]["complete"] == (outcome == "verified")
    assert session.model_dump(mode="json") == prior


async def test_run_report_requires_audited_snapshot():
    run = OrchestratorRunResult(SessionRestoreResult(target="lab.test"), {})
    with pytest.raises(ValueError, match="audited session snapshot"):
        await generate_report_for_run(run, config=VulnClawConfig())
