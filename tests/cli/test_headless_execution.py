import asyncio
import io
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from tests.cli.test_session_backend import FakeRuntime
from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate, reset_execution_gate
from vulnclaw.cli.execution import HeadlessExecutor
from vulnclaw.cli.output import CommandOutput
from vulnclaw.findings.types import FindingAssessment, apply_assessment, finding_input_digest
from vulnclaw.input_service import InputRequest
from vulnclaw.task_service import TaskCreateRequest


@pytest.fixture(autouse=True)
def gate():
    reset_execution_gate()
    yield
    reset_execution_gate()


@pytest.mark.parametrize("format", ["json", "jsonl"])
async def test_headless_task_closes_runtime_before_final_result(tmp_path, monkeypatch, format):
    monkeypatch.setattr("vulnclaw.config.settings.RUNS_DIR", tmp_path)
    runtime = FakeRuntime()
    stream = io.StringIO()
    output = CommandOutput(format, stream)

    async def runner(_runtime, _task, sink):
        sink.on_content_token("# 中文 answer")
        return {"status": "completed", "findings": []}

    executor = HeadlessExecutor(output, runtime_factory=lambda: runtime, task_runner=runner)
    result = await executor.execute(InputRequest(task=TaskCreateRequest(command="run", target="example.test")))
    assert runtime.stop_calls == 1
    assert result["status"] == "completed"
    assert result["exit_code"] == 0
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert lines[-1]["type"] == "command_result"
    assert sum(line["type"] == "command_result" for line in lines) == 1
    assert (len(lines) > 1) is (format == "jsonl")
    assert result["artifacts"][0]["kind"] == "summary"


@pytest.mark.parametrize("interaction", ["approval", "question"])
async def test_required_interaction_terminates_execution_and_preserves_policy(monkeypatch, interaction):
    runtime = FakeRuntime()
    runtime.config.safety.permission_mode = "ask"
    runtime.agent = SimpleNamespace(session_state=SessionState())
    continued = []

    async def execute(_agent, _task, *, stream_sink, on_event, **_kwargs):
        if interaction == "approval":
            await get_execution_gate().authorize(GateRequest("shell", "echo synthetic-command"))
        else:
            on_event("ask_user", {"question": "Which authorized target?"})
        continued.append(True)
        raise AssertionError("execution continued after a required interaction")

    monkeypatch.setattr("vulnclaw.application.execute_task", execute)
    stream = io.StringIO()
    executor = HeadlessExecutor(CommandOutput("jsonl", stream), runtime_factory=lambda: runtime)
    result = await asyncio.wait_for(executor.execute(InputRequest(task=TaskCreateRequest(
        command="run", target="example.test",
    ))), timeout=2)
    assert result["status"] == ("requires_approval" if interaction == "approval" else "requires_input")
    assert result["exit_code"] == 1
    assert continued == []
    assert runtime.stop_calls == 1
    assert get_execution_gate().mode == "ask"
    assert get_execution_gate().channel is None
    assert not get_execution_gate()._pending_by_hash
    assert result["result"]["interaction"]
    action = result["result"]["feedback"]["next_actions"][0]
    assert action["describe_argv"][-1] == ("approval_required" if interaction == "approval" else "waiting_for_input")


async def test_cancellation_cleans_up_before_returning_a_machine_result():
    runtime = FakeRuntime()
    started = asyncio.Event()
    cleaned = asyncio.Event()

    async def runner(_runtime, _task, sink):
        sink.on_content_token("```python\npartial")
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    stream = io.StringIO()
    executor = HeadlessExecutor(CommandOutput("jsonl", stream), runtime_factory=lambda: runtime, task_runner=runner)
    pending = asyncio.create_task(executor.execute(InputRequest(task=TaskCreateRequest(command="run", target="example.test"))))
    await started.wait()
    pending.cancel()
    result = await pending
    assert cleaned.is_set()
    assert runtime.stop_calls == 1
    assert result["status"] == "cancelled"
    messages = [json.loads(line) for line in stream.getvalue().splitlines()]
    partial = [message for message in messages if message.get("role") == "assistant"]
    assert partial[0]["text"] == "```python\npartial"
    assert partial[-1]["status"] == "cancelled"
    assert messages[-1]["type"] == "command_result"


@pytest.mark.parametrize(
    "text,operation,result_key",
    [
        ("/help scope", "session.help", "commands"),
        ("/permission", "session.permission.set", "mode"),
        ("/scope --allowed-ports 443", "session.scope.update", "scope"),
        ("/config", "config.document", "config"),
    ],
)
@pytest.mark.parametrize("format", ["jsonl", "json"])
async def test_headless_control_input_returns_business_result(text, operation, result_key, format):
    """JSON must retain the result that the interactive backend sends to its client."""
    runtime = FakeRuntime()
    stream = io.StringIO()
    executor = HeadlessExecutor(CommandOutput(format, stream), runtime_factory=lambda: runtime)
    result = await executor.execute(InputRequest(text=text))
    assert runtime.stop_calls == 1
    assert result["status"] == "completed"
    messages = [json.loads(line) for line in stream.getvalue().splitlines()]
    if format == "jsonl":
        control = next(message for message in messages if message["type"] == "control_result")
        assert control["operation"] == operation
        assert result_key in control["result"]
        assert result["result"] == control["result"]
    else:
        assert result_key in result["result"]


@pytest.mark.parametrize("format", ["json", "jsonl"])
@pytest.mark.parametrize("completed", [False, True])
async def test_natural_task_keeps_verified_findings_exit_code(
    headless_runtime, monkeypatch, format, completed,
):
    headless_runtime.config.session.conversation_auto_report = False
    agent = headless_runtime.agent
    finding = VulnerabilityFinding(
        title="Synthetic verified finding", severity="High", target="https://example.test",
        vuln_type="test", description="Fixture only",
    )
    apply_assessment(finding, FindingAssessment(
        outcome="verified", method="poc", reason="Synthetic validated evidence",
        input_digest=finding_input_digest(finding),
    ))

    async def solve(*_args, **_kwargs):
        agent.session_state.findings.append(finding)
        agent.session_state.agent_state.completed = completed
        return SimpleNamespace(completed=completed, output="fixture output")

    agent.solve = solve
    monkeypatch.setattr(
        "vulnclaw.findings.verification.verify_findings",
        AsyncMock(side_effect=lambda session, **_kwargs: session.model_copy(deep=True)),
    )
    executor = HeadlessExecutor(CommandOutput(format, io.StringIO()))
    result = await executor.execute(InputRequest(text="pentest https://example.test"))
    assert result["status"] == "completed", result
    assert agent.session_state.findings[0].verified
    assert result["exit_code"] == 2, result
    assert result["findings"] == {"verified": 1, "candidates": 0}
    assert any(item["kind"] == "summary" for item in result["artifacts"])


@pytest.mark.parametrize("mode,text", [
    ("full_access", "hello"),
    ("read_only", "hello"),
    ("read_only", "pentest https://example.test"),
])
async def test_chat_does_not_emit_task_summary_or_classification(headless_runtime, mode, text):
    headless_runtime.config.safety.permission_mode = mode
    executor = HeadlessExecutor(CommandOutput("json", io.StringIO()))
    result = await executor.execute(InputRequest(text=text))
    assert result["status"] == "completed", result
    assert result["exit_code"] == 0
    assert result["artifacts"] == []
    assert "findings" not in result
    headless_runtime.agent.chat.assert_awaited_once()
    headless_runtime.agent.solve.assert_not_awaited()
