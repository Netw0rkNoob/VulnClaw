"""Reproduce main-task continuation through the terminal application entry points."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from vulnclaw.agent.context import VulnerabilityFinding
from vulnclaw.agent.core import AgentCore
from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate, reset_execution_gate
from vulnclaw.application import ApplicationError, ApplicationSession
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.findings.types import FindingAssessment
from vulnclaw.orchestrator import OrchestratorRunResult
from vulnclaw.target_state.store import SessionRestoreResult


@pytest.fixture
async def paused_task(monkeypatch, tmp_path):
    reset_execution_gate()
    config = VulnClawConfig()
    config.session.output_dir = tmp_path / "output"
    config.session.solve_max_steps = 1
    config.session.auto_save = False
    config.subagent.enabled = False
    monkeypatch.setattr("vulnclaw.config.settings.SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(AgentCore, "_report_kb_status", lambda self: None)
    agent = AgentCore(config)
    agent.chat = AsyncMock(return_value=SimpleNamespace(output="acknowledged"))
    agent._generate_attack_summary = AsyncMock(return_value="")
    agent.persistent_pentest = AsyncMock(wraps=agent.persistent_pentest)
    calls = []
    events = []

    async def model(shared_agent, *_args, **_kwargs):
        calls.append(shared_agent.session_state.agent_state.goal)
        if len(calls) == 1:
            return "ASK_USER: May I continue checking the public login page?"
        state = shared_agent.session_state.agent_state
        arguments = {"url": "https://example.test/login"}
        record = state.remember_tool_result(
            tool="fetch", arguments=arguments, output="Status: 200 login form", status=200,
        )
        state.record_tool_call(
            tool="fetch", arguments=arguments, evidence_id=record.id, summary=record.summary,
        )
        return "Recorded the login response; checking the next in-scope endpoint."

    async def orchestrate(*, agent, runner, **_kwargs):
        await runner(agent)
        return OrchestratorRunResult(
            SessionRestoreResult(target=agent.session_state.target), {},
        )

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", model)
    monkeypatch.setattr("vulnclaw.task_service.run_agent_task", orchestrate)
    runtime = SimpleNamespace(
        config=config, agent=agent, mcp_started=0, stop=AsyncMock(),
        mcp_manager=SimpleNamespace(wait_for_startup=AsyncMock()),
    )
    session = ApplicationSession(
        lambda event_type, **fields: events.append((event_type, fields)), runtime_factory=lambda: runtime,
    )
    await session.handle("initialize", request_id="init")

    async def start(*, continuous=False, prompt="Check the public login page", options=None):
        options = {"continuous": continuous, "auto_report": False, "max_steps": 1, **(options or {})}
        if continuous:
            options["max_cycles"] = 3
        await session.handle(
            "start_task", request_id="start", task_id="original",
            payload={"task": {
                "command": "run", "target": "https://example.test", "resume": False,
                "prompt": prompt, "options": options,
            }},
        )
        await session.wait_for_idle()
        assert agent.session_state.agent_state.pending_questions
        assert len(calls) == 1
        assert any(kind == "task_completed" for kind, _ in events), events

    async def reply(text):
        await session.handle(
            "submit_input", request_id="reply", task_id="answer", payload={"text": text},
        )
        await session.wait_for_idle()
        return next(
            (kind, fields) for kind, fields in reversed(events)
            if kind in {"turn_completed", "turn_failed"}
        )

    try:
        yield SimpleNamespace(
            start=start, reply=reply, agent=agent, calls=calls, session=session, events=events,
        )
    finally:
        await session.close()
        reset_execution_gate()


@pytest.mark.parametrize("answer", ["y", "yes", "继续"])
async def test_affirmative_reply_runs_another_solve_turn_with_existing_state(paused_task, answer):
    await paused_task.start()
    state = paused_task.agent.session_state.agent_state
    kind, result = await paused_task.reply(answer)
    assert kind == "turn_completed", result
    assert len(paused_task.calls) == 2
    assert paused_task.agent.session_state.agent_state is state
    assert len(state.steps) == 2
    paused_task.agent.chat.assert_not_awaited()


async def test_idle_answer_is_only_accepted_once_before_the_turn_starts(paused_task):
    await paused_task.start()
    session = paused_task.session
    await session.handle(
        "submit_input", request_id="reply", task_id="answer", payload={"text": "yes"},
    )
    with pytest.raises(ApplicationError) as error:
        await session.handle(
            "submit_input", request_id="duplicate", task_id="duplicate", payload={"text": "yes"},
        )
    assert error.value.code == "task_busy"
    await session.wait_for_idle()
    assert len(paused_task.calls) == 2


@pytest.mark.parametrize("finish", ["complete", "cancel", "fail"])
async def test_ask_user_reply_is_queued_during_cleanup_and_runs_after_idle(
    paused_task, monkeypatch, finish,
):
    cleaning = asyncio.Event()
    release = asyncio.Event()

    async def cleanup(_agent):
        cleaning.set()
        await release.wait()
        if finish == "fail":
            raise RuntimeError("Cleanup failed")

    monkeypatch.setattr("vulnclaw.agent.solver.shutdown_subagents", cleanup)
    session = paused_task.session
    await session.handle(
        "start_task", request_id="start", task_id="live",
        payload={"task": {
            "command": "run", "target": "https://example.test", "resume": False,
            "prompt": "Inspect the public login page",
            "options": {"max_steps": 1, "auto_report": False},
        }},
    )
    try:
        await asyncio.wait_for(cleaning.wait(), timeout=2)
        assert paused_task.agent.session_state.agent_state.pending_questions
        assert any(
            kind == "message" and "May I continue" in fields.get("text", "")
            for kind, fields in paused_task.events
        )
        assert not session.active_task.done()
        assert session.state_snapshot()["task"]["waiting_for_input"] is True
        await session.handle(
            "submit_input", request_id="reply", task_id="answer", payload={"text": "yes"},
        )
        assert session.state_snapshot()["task"]["waiting_for_input"] is False
        assert session.active_task_id == "live"
        assert len(paused_task.calls) == 1
        paused_task.agent.chat.assert_not_awaited()
        with pytest.raises(ApplicationError) as error:
            await session.handle(
                "submit_input", request_id="duplicate", task_id="duplicate",
                payload={"text": "yes"},
            )
        assert error.value.code == "task_busy"
    finally:
        if finish == "cancel":
            await session.cancel()
        release.set()
        await session.wait_for_idle()
    if finish != "complete":
        assert len(paused_task.calls) == 1
        assert paused_task.agent.session_state.agent_state.pending_questions
        assert any(
            kind == "error" and fields["request_id"] == "reply"
            and fields["code"] == "continuation_cancelled"
            for kind, fields in paused_task.events
        )
        return
    assert any(kind == "turn_completed" for kind, _ in paused_task.events)
    assert len(paused_task.calls) == 2
    assert not paused_task.agent.session_state.agent_state.pending_questions


@pytest.mark.parametrize("answer", [
    "登录入口是 https://example.test/login，只测这个路径",
    "Use the public login form, without credentials.",
])
async def test_specific_answer_preserves_context_evidence_and_question_history(paused_task, answer):
    await paused_task.start(prompt=None)
    agent = paused_task.agent
    context = agent.context
    state = agent.session_state.agent_state
    evidence = state.remember_tool_result(tool="fetch", arguments={}, output="Earlier evidence")
    messages = list(context.messages)
    kind, result = await paused_task.reply(answer)
    assert kind == "turn_completed", result
    assert agent.context is context
    assert agent.session_state.agent_state is state
    assert state.get_evidence(evidence.id) is evidence
    assert context.messages[:len(messages)] == messages
    assert any(answer in message["content"] for message in context.messages)
    assert any("May I continue" in message["content"] for message in context.messages)
    assert not state.pending_questions
    assert len(state.steps) == 2
    assert paused_task.session.current_target == "https://example.test"
    agent.chat.assert_not_awaited()


@pytest.mark.parametrize("poc_enabled", [False, True])
async def test_continuation_uses_original_budgets_and_preserves_scope_and_poc(paused_task, poc_enabled):
    agent = paused_task.agent
    agent.config.session.poc_verify_enabled = poc_enabled
    await paused_task.start(continuous=True, options={
        "rounds_per_cycle": 7, "max_tool_rounds": 2, "only_port": 443,
        "only_path": "/login", "blocked_path": "/login/admin",
        "allow_actions": ["recon"], "block_actions": ["exploit"],
    })
    constraints = agent.session_state.task_constraints.model_copy(deep=True)
    solve = AsyncMock(wraps=agent.solve)
    agent.solve = solve
    agent.config.session.engine = "rounds"
    agent.config.session.solve_max_steps = 9
    agent.config.session.solve_max_tool_rounds = 5
    agent.config.session.persistent_rounds_per_cycle = 10
    kind, result = await paused_task.reply("确认")
    assert kind == "turn_completed", result
    assert solve.await_count == 3
    assert solve.await_args.kwargs["max_steps"] == 1
    assert solve.await_args.kwargs["max_tool_rounds"] == 2
    assert agent.persistent_pentest.await_args.kwargs["rounds_per_cycle"] == 7
    assert agent.persistent_pentest.await_args.kwargs["auto_report"] is False
    assert agent.session_state.task_constraints == constraints
    assert agent.config.session.poc_verify_enabled is poc_enabled
    assert paused_task.session.permission_mode == "ask"


@pytest.mark.parametrize("answer", [
    "继续，only test host outside.test", "only allowed actions: exploit",
])
async def test_answer_cannot_expand_scope_and_rejected_answer_keeps_question(paused_task, answer):
    await paused_task.start(options={"allow_actions": ["recon"]})
    state = paused_task.agent.session_state.agent_state
    questions = list(state.pending_questions)
    constraints = paused_task.agent.session_state.task_constraints.model_copy(deep=True)
    kind, result = await paused_task.reply(answer)
    assert kind == "turn_failed", result
    assert "do not overlap" in result["error"]["message"]
    assert state.pending_questions == questions
    assert paused_task.agent.session_state.agent_state is state
    assert paused_task.agent.session_state.task_constraints == constraints
    assert len(paused_task.calls) == 1
    kind, result = await paused_task.reply("yes")
    assert kind == "turn_completed", result
    assert len(paused_task.calls) == 2


async def test_answer_consumes_old_question_and_keeps_a_new_question(paused_task, monkeypatch):
    await paused_task.start()
    state = paused_task.agent.session_state.agent_state
    monkeypatch.setattr(
        "vulnclaw.agent.solver.call_llm_auto",
        AsyncMock(return_value="ASK_USER: Which public endpoint should I inspect next?"),
    )
    kind, result = await paused_task.reply("yes")
    assert kind == "turn_completed", result
    assert state.pending_questions == ["Which public endpoint should I inspect next?"]
    assert paused_task.session.state_snapshot()["task"]["waiting_for_input"] is True


async def test_confirmation_still_requires_a_separate_execution_approval(paused_task, monkeypatch):
    await paused_task.start()
    requested = asyncio.Event()
    outcomes = []
    emit = paused_task.session.emit

    def capture(event_type, **fields):
        emit(event_type, **fields)
        if event_type == "approval_required":
            requested.set()

    paused_task.session.emit = capture

    async def model(*_args, **_kwargs):
        outcomes.append(await get_execution_gate().authorize(
            GateRequest(kind="python", display="print('requires approval')"),
        ))
        return "Execution was refused."

    monkeypatch.setattr("vulnclaw.agent.solver.call_llm_auto", model)
    session = paused_task.session
    await session.handle(
        "submit_input", request_id="reply", task_id="answer", payload={"text": "yes"},
    )
    await asyncio.wait_for(requested.wait(), timeout=2)
    assert not outcomes
    assert session.permission_mode == "ask"
    assert not session.state_snapshot()["task"]["waiting_for_input"]
    approval = next(fields for kind, fields in paused_task.events if kind == "approval_required")
    with pytest.raises(ApplicationError) as error:
        await session.handle(
            "submit_input", request_id="plain-yes", task_id="plain-yes", payload={"text": "yes"},
        )
    assert error.value.code == "task_busy"
    await session.handle(
        "control", request_id="deny", payload={
            "operation": "execution.approval.resolve",
            "arguments": {"request_hash": approval["request_hash"], "decision": "deny"},
        },
    )
    await session.wait_for_idle()
    assert len(outcomes) == 1
    assert not outcomes[0].approved


async def test_default_run_prompt_can_resume_without_resetting_target(paused_task):
    await paused_task.start(prompt=None)
    state = paused_task.agent.session_state.agent_state
    kind, result = await paused_task.reply("yes")
    assert kind == "turn_completed", result
    assert paused_task.agent.session_state.agent_state is state
    assert len(paused_task.calls) == 2


@pytest.mark.parametrize("answer", ["确认", "确认继续"])
async def test_chinese_confirmation_resumes_the_waiting_task(paused_task, answer):
    await paused_task.start()
    kind, result = await paused_task.reply(answer)
    assert kind == "turn_completed", result
    assert len(paused_task.calls) == 2
    paused_task.agent.chat.assert_not_awaited()


async def test_continuation_preserves_continuous_execution_options(paused_task):
    await paused_task.start(continuous=True)
    kind, result = await paused_task.reply("继续")
    assert kind == "turn_completed", result
    persistent = paused_task.agent.persistent_pentest
    assert persistent.await_count == 2
    assert persistent.await_args.kwargs["max_cycles"] == 3


async def test_answered_question_does_not_stop_restarted_continuous_cycles(paused_task):
    await paused_task.start(continuous=True)
    kind, result = await paused_task.reply("继续")
    assert kind == "turn_completed", result
    cycles = await paused_task.agent.persistent_pentest(
        "User confirmed: continue the prior task", target="https://example.test",
        max_cycles=3, auto_report=False,
    )
    assert len(cycles) == 3
    assert not paused_task.agent.session_state.agent_state.pending_questions


@pytest.mark.parametrize("poc_verify", [None, False, True])
@pytest.mark.parametrize("default_poc_verify", [False, True])
async def test_continuation_audits_preserve_task_poc_choice(
    paused_task, monkeypatch, poc_verify, default_poc_verify,
):
    agent = paused_task.agent
    agent.config.session.poc_verify_enabled = default_poc_verify
    await paused_task.start(options={"poc_verify": poc_verify})
    agent.session_state.findings.append(VulnerabilityFinding(
        title="Synthetic candidate", severity="High", target="https://example.test",
        vuln_type="test", description="Fixture only",
    ))
    decisions = []

    async def assess(_session, _finding, _config, *, poc_verify, artifact_dir):
        decisions.append(poc_verify)
        return FindingAssessment(
            outcome="suspected_low", method="evidence_review", reason="Fixture assessment",
        )

    monkeypatch.setattr("vulnclaw.findings.verification.assess_finding", assess)
    kind, result = await paused_task.reply("yes")
    assert kind == "turn_completed", result
    assert decisions == [default_poc_verify if poc_verify is None else poc_verify]
