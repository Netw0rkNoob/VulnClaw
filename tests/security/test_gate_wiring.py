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


class TestVerifierBridge:
    def test_execute_poc_refuses_without_sync_hook(self, fresh_gate):
        from vulnclaw.report.verifier import VerifierExecutor

        rc, output = VerifierExecutor.execute_poc("print('poc')")
        assert rc == -4
        assert "[REFUSED]" in output
