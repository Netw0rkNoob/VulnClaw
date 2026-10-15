import asyncio
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from tests.cli.test_tui_backend import (
    FakeRuntime,
    events,
    protocol_validator,
    request,
    task_payload,
)
from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.orchestrator import OrchestratorRunResult
from vulnclaw.target_state.store import SessionRestoreResult
from vulnclaw.task_service import TaskExecution
from vulnclaw.tui_backend import BackendSession
from vulnclaw.tui_protocol import JsonlWriter


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    import vulnclaw.target_state.store as store

    config = VulnClawConfig()
    config.session.output_dir = tmp_path / "output"
    config.session.runs_dir = tmp_path / "runs"
    monkeypatch.setattr(store, "TARGETS_DIR", tmp_path / "targets")
    monkeypatch.setattr("vulnclaw.report.generator._generate_attack_summary_from_session",
                        lambda _: "Saved conclusions")
    state = SessionState(target="https://lab.test")
    runtime = FakeRuntime()
    runtime.config = config
    runtime.agent = SimpleNamespace(
        config=config, context=SimpleNamespace(state=state), session_state=state, runtime=None,
        apply_task_constraints=lambda constraints: setattr(state, "task_constraints", constraints),
    )
    return runtime


@pytest.mark.parametrize("engine", ["solve", "team", "rounds"])
async def test_tui_run_audits_and_exports_before_completion(runtime, monkeypatch, engine):
    import vulnclaw.findings.verification as verification
    import vulnclaw.report_service as reports
    import vulnclaw.target_state.store as store

    order = []
    state = runtime.agent.session_state
    target = state.target

    async def action(*_args, **_kwargs):
        order.append("action")
        state.add_finding(VulnerabilityFinding(
            title="Needs reproduction", vuln_type="SQLi", evidence="Observation without snapshots",
        ))

    runtime.agent.solve = action
    runtime.agent.auto_pentest = action
    monkeypatch.setattr("vulnclaw.agent.team.run_team_pentest", action)
    original_audit = verification.verify_findings

    async def audit(*args, **kwargs):
        view = await original_audit(*args, **kwargs)
        order.append("audit")
        return view

    monkeypatch.setattr(verification, "verify_findings", audit)

    async def report(run, *, config):
        assert run.audited_session is not None
        assert run.audited_session.findings[0].assessment.complete is False
        persisted = store.load_target_state(state.target)
        assert persisted["findings"][0]["assessment"]["outcome"] == "suspected_low"
        assert persisted["resume_meta"]["checkpoint_reason"] == "run_complete"
        order.append("report")
        return await reports.generate_report_for_run(run, config=config)

    monkeypatch.setattr("vulnclaw.tui_backend.generate_report_for_run", report)
    stream = io.StringIO()
    session = BackendSession(JsonlWriter(stream), runtime_factory=lambda: runtime)
    await session.handle(request("initialize", "init"))
    await session.handle(request("start_task", "run", task_id="t1", payload=task_payload(
        "run", target, options={"engine": engine}, resume=False,
    )))
    await session.wait_for_idle()
    emitted = events(stream)
    for event in emitted:
        protocol_validator().validate(event)
    assert order == ["action", "audit", "report"]
    statuses = [event["status"] for event in emitted if event["type"] == "status"]
    assert "Generating report..." in statuses
    completed = next(event for event in emitted if event["type"] == "task_completed")
    result = completed["result"]
    assert result["status"] == "completed" and result["exit_code"] == 0
    assert result["report_error"] is None
    assert all(Path(path).is_file() for path in result["report"].values())
    document = json.loads(Path(result["report"]["findings_json"]).read_text())
    assert document["summary"]["suspected_low"] == 1
    assert completed["state"]["last_run"]["report"] == result["report"]
    await session.handle(request("get_state", "state"))
    assert events(stream)[-1]["state"]["last_run"]["report"] == result["report"]


@pytest.mark.parametrize("missing_snapshot", [False, True])
async def test_report_failure_preserves_successful_tui_task(runtime, monkeypatch, missing_snapshot):
    run = OrchestratorRunResult(
        SessionRestoreResult(target="lab.test"), {"findings_count": 0},
        audited_session=None if missing_snapshot else SessionState(target="lab.test"),
    )
    monkeypatch.setattr("vulnclaw.tui_backend.execute_task",
                        AsyncMock(return_value=TaskExecution(run, None)))
    if not missing_snapshot:
        monkeypatch.setattr("vulnclaw.report_service.generate_report",
                            AsyncMock(side_effect=OSError("Disk full")))
    stream = io.StringIO()
    session = BackendSession(JsonlWriter(stream), runtime_factory=lambda: runtime)
    await session.handle(request("initialize", "init"))
    await session.handle(request("start_task", "run", task_id="t1",
                                 payload=task_payload("run", "lab.test")))
    await session.wait_for_idle()
    emitted = events(stream)
    assert not any(event["type"] == "task_failed" for event in emitted)
    completed = next(event for event in emitted if event["type"] == "task_completed")
    result = completed["result"]
    assert result["status"] == "completed" and result["exit_code"] == 0
    assert result["summary"] == run.summary
    assert result["report"] is None
    assert ("snapshot" if missing_snapshot else "Disk full") in result["report_error"]
    assert completed["state"]["last_run"]["report_error"] == result["report_error"]
    protocol_validator().validate(completed)


@pytest.mark.parametrize("command,status", [
    ("persistent", "completed"), ("scan", "completed"), ("run", "interrupted"),
])
async def test_report_export_only_runs_for_completed_run(runtime, monkeypatch, command, status):
    run = OrchestratorRunResult(SessionRestoreResult(target="lab.test"), {}, status=status)
    monkeypatch.setattr("vulnclaw.tui_backend.execute_task",
                        AsyncMock(return_value=TaskExecution(run, None)))
    report = AsyncMock(side_effect=AssertionError("Unexpected extra report"))
    monkeypatch.setattr("vulnclaw.tui_backend.generate_report_for_run", report)
    from vulnclaw.task_service import TaskCreateRequest, prepare_task
    from vulnclaw.tui_backend import BackendStreamSink, _run_task

    sink = BackendStreamSink(JsonlWriter(io.StringIO()), "t1", show_thinking=False)
    result = await _run_task(runtime, prepare_task(TaskCreateRequest(command=command, target="lab.test")), sink)
    assert result["report"] is None and result["report_error"] is None
    report.assert_not_awaited()


async def test_cancelling_report_export_preserves_saved_audit(runtime, monkeypatch):
    import vulnclaw.target_state.store as store

    started = asyncio.Event()

    async def action(*_args, **_kwargs):
        runtime.agent.session_state.add_finding(VulnerabilityFinding(
            title="Candidate", vuln_type="SQLi", evidence="Saved observation",
        ))

    runtime.agent.solve = action

    async def report(*_args, **_kwargs):
        started.set()
        await asyncio.Future()

    monkeypatch.setattr("vulnclaw.report_service.generate_report", report)
    stream = io.StringIO()
    session = BackendSession(JsonlWriter(stream), runtime_factory=lambda: runtime)
    await session.handle(request("initialize", "init"))
    await session.handle(request("start_task", "run", task_id="t1",
                                 payload=task_payload("run", "https://lab.test", resume=False)))
    await asyncio.wait_for(started.wait(), 5)
    before = store.load_target_state("https://lab.test")
    assert before["findings"][0]["assessment"] is not None
    await session.handle(request("cancel_task", "cancel", task_id="t1"))
    await session.wait_for_idle()
    emitted = events(stream)
    assert any(event["type"] == "task_cancelled" for event in emitted)
    assert not any(event["type"] in {"task_failed", "task_completed"} for event in emitted)
    assert store.load_target_state("https://lab.test") == before
