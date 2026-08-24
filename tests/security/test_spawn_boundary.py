"""C-1/C-2 execution-boundary contract tests.

These freeze the process-spawn attack surface: every spawn call site must
live inside the reviewed allowlist of ``scripts/verify_execution_boundary.py``,
and the model-reachable dangerous tools must refuse leaf agents.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "verify_execution_boundary.py"


class TestMechanicalBoundary:
    def test_verify_script_passes_on_current_tree(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def test_model_reachable_files_are_explicitly_allowlisted(self):
        """Removing a gated file from the allowlist must break this test loudly."""
        from scripts.verify_execution_boundary import ALLOWED_SPAWN_SITES

        for required in (
            "vulnclaw/agent/builtin_tools.py",
            "vulnclaw/report/verifier.py",
        ):
            assert required in ALLOWED_SPAWN_SITES, (
                f"{required} contains model-reachable spawn sites and must stay "
                "on the reviewed allowlist with an ExecutionGate note"
            )

    def test_json_report_lists_reviewed_sites(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        report = __import__("json").loads(result.stdout)
        assert report["ok"] is True
        reviewed = {s["file"] for s in report["reviewed_sites"]}
        assert "vulnclaw/agent/builtin_tools.py" in reviewed


class TestSubagentDangerousToolRefusal:
    """Leaf agents can never reach host execution, whatever their role globs."""

    def _make_agent(self, depth: int = 0):
        import sys

        from vulnclaw.agent.subagent.models import SubagentContext

        sys.path.insert(0, str(REPO_ROOT / "tests" / "agent"))
        try:
            from test_builtin_tools import DummyAgent
        finally:
            sys.path.pop(0)

        agent = DummyAgent()
        agent._subagent_ctx = SubagentContext(depth=depth)
        return agent

    async def test_main_agent_passes_guard_into_execution_path(self, monkeypatch):
        from vulnclaw.agent import builtin_tools

        agent = self._make_agent(depth=0)
        seen = {}

        def fake_run(*args, **kwargs):
            seen["called"] = True
            raise RuntimeError("stop-before-spawn")

        monkeypatch.setattr(builtin_tools.subprocess, "run", fake_run)
        result = await builtin_tools.execute_shell_command(agent, {"command": "id"})
        # Guard passed the main agent through to the (interrupted) spawn path;
        # the failure is the runtime stub, not a refusal.
        assert "not available to subagents" not in result
        assert "[!]" in result  # reached execution and failed on the stub

    async def test_subagent_shell_command_refused(self):
        from vulnclaw.agent.builtin_tools import execute_mcp_tool, execute_shell_command

        agent = self._make_agent(depth=1)
        expected = "not available to subagents"
        assert expected in await execute_shell_command(agent, {"command": "id"})
        assert expected in await execute_mcp_tool(agent, "shell_command", {"command": "id"})

    async def test_subagent_python_execute_refused_even_with_valid_code(self):
        from vulnclaw.agent.builtin_tools import execute_mcp_tool, execute_python

        agent = self._make_agent(depth=1)
        expected = "not available to subagents"
        code = 'print("hello")'
        assert expected in await execute_python(agent, {"code": code})
        assert expected in await execute_mcp_tool(agent, "python_execute", {"code": code})

    async def test_refusal_precedes_all_other_validation(self):
        """A leaf agent gets the refusal even for input that would fail earlier checks."""
        from vulnclaw.agent.builtin_tools import execute_python

        agent = self._make_agent(depth=1)
        result = await execute_python(agent, {"code": ""})  # empty code fails first otherwise
        assert "not available to subagents" in result

    async def test_non_dangerous_tools_unaffected_by_guard(self):
        from vulnclaw.agent.builtin_tools import dangerous_tool_refusal

        assert dangerous_tool_refusal("memory_search") is None
        assert dangerous_tool_refusal("http_probe_batch") is None

    def test_depth_zero_is_main_agent(self):
        from vulnclaw.agent.builtin_tools import is_subagent

        assert is_subagent(self._make_agent(depth=0)) is False
        assert is_subagent(self._make_agent(depth=2)) is True
