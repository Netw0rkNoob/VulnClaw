"""End-to-end wiring: dangerous tools refuse without the gate, run with it."""

from __future__ import annotations

import pytest

from tests.agent.test_builtin_tools import DummyAgent
from vulnclaw.agent.exec_gate import (  # noqa: E402
    get_execution_gate,
    reset_execution_gate,
)


class AutoApprove:
    def __init__(self):
        self.views = []

    async def request_approval(self, view):
        self.views.append(view)
        return "approve"


class AlwaysDeny:
    async def request_approval(self, view):
        return "deny"


@pytest.fixture()
def fresh_gate():
    reset_execution_gate()
    yield get_execution_gate()
    reset_execution_gate()


def _agent():
    return DummyAgent()


class TestShellCommandGateWiring:
    async def test_denied_shell_command_returns_refusal_and_never_spawns(
        self, fresh_gate, monkeypatch
    ):
        import vulnclaw.agent.builtin_tools as bt

        fresh_gate.install_channel(AlwaysDeny())
        spawned = False

        def boom(*a, **k):
            nonlocal spawned
            spawned = True
            raise AssertionError("spawn must not happen")

        monkeypatch.setattr(bt.subprocess, "run", boom)
        monkeypatch.setattr(bt.asyncio.get_running_loop(), "run_in_executor", boom)
        result = await bt.execute_shell_command(_agent(), {"command": "id"})
        assert "refused" in result and "denied" in result
        assert spawned is False

    async def test_approved_shell_command_executes(self, fresh_gate):
        from vulnclaw.agent.builtin_tools import execute_shell_command

        fresh_gate.install_channel(AutoApprove())
        agent = _agent()
        result = await execute_shell_command(agent, {"command": "echo GATE_OK"})
        assert "GATE_OK" in result
        assert fresh_gate.stats["approved"] == 1


class TestPythonExecuteGateWiring:
    async def test_python_without_channel_refused_before_spawn(self, fresh_gate):
        import vulnclaw.agent.builtin_tools as bt

        result = await bt.execute_python(_agent(), {"code": "print('x')"})
        assert "no trusted approval channel" in result

    async def test_python_approved_runs_code(self, fresh_gate):
        from vulnclaw.agent.builtin_tools import execute_python

        fresh_gate.install_channel(AutoApprove())
        result = await execute_python(_agent(), {"code": "print('gate-py-ok')"})
        assert "gate-py-ok" in result

    async def test_python_first_call_uses_complete_agent_config(self):
        from vulnclaw.agent.builtin_tools import execute_python

        reset_execution_gate()
        agent = _agent()
        agent.config.safety.permission_mode = "full_access"
        agent.config.safety.approval_timeout_seconds = 17
        agent.config.safety.trusted_commands = ["nmap -sV"]

        result = await execute_python(agent, {"code": "print('configured-gate')"})
        gate = get_execution_gate()
        assert "configured-gate" in result
        assert gate.mode == "full_access"
        assert gate.timeout_seconds == 17
        assert gate.trusted_commands == (("nmap", "-sV"),)
        reset_execution_gate()


class TestVerifierBridge:
    def test_execute_poc_refuses_without_sync_hook(self, fresh_gate):
        from vulnclaw.report.verifier import VerifierExecutor

        rc, output = VerifierExecutor.execute_poc("print('poc')")
        assert rc == -4
        assert "[REFUSED]" in output


class TestModelRiskWiring:
    """args.risk_self_assessment flows from tool call to gate decision."""

    async def test_flagged_ls_headless_refused(self, fresh_gate):
        from vulnclaw.agent.builtin_tools import execute_shell_command

        result = await execute_shell_command(
            _agent(),
            {"command": "ls", "risk_self_assessment": "review",
             "assessment_reason": "dir may contain operator notes"},
        )
        assert "refused" in result and "no trusted approval channel" in result

    async def test_unflagged_ls_headless_still_runs(self, fresh_gate):
        from vulnclaw.agent.builtin_tools import execute_shell_command

        fresh_gate.mode = "auto_review"

        result = await execute_shell_command(_agent(), {"command": "echo WIRE_OK"})
        assert "WIRE_OK" in result

    async def test_python_flagged_reason_reaches_view(self, fresh_gate):
        from vulnclaw.agent.builtin_tools import execute_python

        class Capture:
            def __init__(self):
                self.views = []

            async def request_approval(self, view):
                self.views.append(view)
                return "deny"

        cap = Capture()
        fresh_gate.install_channel(cap)
        result = await execute_python(
            _agent(),
            {"code": "print(1)", "risk_self_assessment": "review",
             "assessment_reason": "touches env"},
        )
        assert "denied" in result
        assert any("needs review" in v.detail and "touches env" in v.detail
                   for v in cap.views)
