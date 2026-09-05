"""L4: REPL /mode command."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnclaw.agent.exec_gate import (
    ExecutionGate,
    reset_execution_gate,
)


@pytest.fixture(autouse=True)
def fresh_gate():
    reset_execution_gate()
    yield
    reset_execution_gate()


class TestReplModeCommand:
    def _run(self, args: str, monkeypatch, tmp_path: Path):
        """Invoke the REPL slash-command handler with a stubbed console."""
        import vulnclaw.cli.main as cli_main

        gate = ExecutionGate(timeout_seconds=5)

        class FakeAgent:
            def apply_config(self, cfg):
                pass

        config = object()
        monkeypatch.setattr(
            "vulnclaw.agent.exec_gate.get_execution_gate", lambda cfg=None: gate
        )
        printed: list[str] = []
        monkeypatch.setattr(
            cli_main.console,
            "print",
            lambda *a, **k: printed.append(" ".join(str(x) for x in a)),
        )
        result = cli_main._run_repl_command("mode", args, FakeAgent(), config)
        return gate, result, printed

    def test_show_current_mode_when_no_args(self, monkeypatch, tmp_path):
        gate, _result, printed = self._run("", monkeypatch, tmp_path)
        assert any(gate.mode in line for line in printed)

    def test_switch_to_auto_review(self, monkeypatch, tmp_path):
        gate, _result, printed = self._run("auto_review", monkeypatch, tmp_path)
        assert gate.mode == "auto_review"
        assert any("auto_review" in line for line in printed)
        assert any("trusted read-only" in line for line in printed)

    def test_invalid_mode_reports_error_not_raise(self, monkeypatch, tmp_path):
        gate, _result, printed = self._run("yolo", monkeypatch, tmp_path)
        assert gate.mode == "ask"
        assert any("invalid permission mode" in line for line in printed)
