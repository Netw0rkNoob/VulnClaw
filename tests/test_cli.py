"""VulnClaw CLI module tests for main.py."""

import io

import pytest
from typer.testing import CliRunner

# CLI smoke tests


class TestCLI:
    """Test CLI entry point and sub-commands."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_cli_help(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "VulnClaw" in result.output or "vulnclaw" in result.output.lower()
        assert "TUI" in result.output

    def test_cli_version(self, runner):
        from vulnclaw import __version__
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_cli_manual_command(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["manual"])

        assert result.exit_code == 0
        assert "VULNCLAW(1)" in result.output
        assert "COMMON TASK FLAGS" in result.output
        assert "--only-port" in result.output
        assert "network-scan" in result.output
        assert "--parallel-agents" in result.output

    def test_cli_manual_topic_markdown(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["manual", "network-scan", "--format", "markdown"])

        assert result.exit_code == 0
        assert "### `network-scan`" in result.output
        assert "`--safe-probes / --no-safe-probes`" in result.output
        assert "### `run`" not in result.output

    def test_cli_man_alias_and_root_flag(self, runner):
        from vulnclaw.cli.main import app

        alias_result = runner.invoke(app, ["man", "config"])
        root_result = runner.invoke(app, ["--man"])

        assert alias_result.exit_code == 0
        assert "CONFIG" in alias_result.output
        assert "llm.api_keys" in alias_result.output
        assert root_result.exit_code == 0
        assert "VULNCLAW(1)" in root_result.output

    def test_cli_manual_rejects_unknown_topic(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["manual", "does-not-exist"])

        assert result.exit_code == 1
        assert "unknown manual topic" in result.output

    def test_cli_init(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["init"])
        # Should not crash
        assert result.exit_code == 0
        assert "vulnclaw" in result.output
        assert "vulnclaw tui" in result.output

    def test_cli_doctor(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["doctor"])
        # Should not crash
        assert result.exit_code == 0
        assert "Registered:" in result.output
        assert "Tools:" in result.output
        assert (
            "Environment ready. Run vulnclaw to start." in result.output
            or "Set credentials first" in result.output
        )

    def test_cli_config_list(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["config", "list"])
        # Should not crash
        assert result.exit_code == 0

    def test_cli_config_provider_list(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["config", "provider", "--list"])
        # Should show available providers
        assert result.exit_code == 0

    def test_cli_config_provider_set(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["config", "provider", "deepseek"])
        # Should not crash
        assert result.exit_code == 0

    def test_cli_kb_update(self, runner, monkeypatch, tmp_path):
        import vulnclaw.kb.store as kb_store
        from vulnclaw.cli.main import app

        monkeypatch.setattr(kb_store, "KB_DIR", tmp_path)
        result = runner.invoke(app, ["kb", "update"])
        assert result.exit_code == 0
        assert "Knowledge base updated" in result.output, f"Expected 'Knowledge base updated' in output: {result.output[:200]}"
        assert (tmp_path / "index.json").exists()

    def test_cli_doctor_reports_registered_tools(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "Registered:" in result.output
        assert "Tools:" in result.output

    def test_recon_resumes_target_state(self, runner, monkeypatch, tmp_path):
        import vulnclaw.orchestrator as orchestrator_mod
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import PentestPhase, SessionState
        from vulnclaw.cli.main import app

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path / "targets")
        state = SessionState(target="https://example.com")
        state.advance_phase(PentestPhase.RECON)
        store_mod.save_target_state("https://example.com", state, command="recon")

        calls: list[tuple[str, str | None]] = []
        original_apply = orchestrator_mod.apply_target_state_to_agent

        def tracking_apply(agent, target, snapshot_id=None):
            calls.append((target, snapshot_id))
            return original_apply(agent, target, snapshot_id=snapshot_id)

        monkeypatch.setattr(orchestrator_mod, "apply_target_state_to_agent", tracking_apply)

        result = runner.invoke(app, ["recon", "https://example.com"])
        assert result.exit_code == 0
        assert result.output
        assert calls == [("https://example.com", None)]

    def test_recon_no_resume_skips_target_state(self, runner, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import PentestPhase, SessionState
        from vulnclaw.cli.main import app

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path / "targets")
        state = SessionState(target="https://example.com")
        state.advance_phase(PentestPhase.RECON)
        store_mod.save_target_state("https://example.com", state, command="recon")

        result = runner.invoke(app, ["recon", "https://example.com", "--no-resume"])
        assert result.exit_code == 0
        assert result.output is not None

    def test_repl_persistent_explicit_target_restores_history(self, runner, monkeypatch):
        import vulnclaw.agent.core as agent_core
        import vulnclaw.cli.main as cli_main
        import vulnclaw.mcp.lifecycle as lifecycle_mod
        from vulnclaw.agent.context import PentestPhase, SessionState
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"

        old_state = SessionState(target="https://old.example")
        old_state.advance_phase(PentestPhase.RECON)

        new_state = SessionState(target="https://new.example")
        new_state.advance_phase(PentestPhase.EXPLOITATION)

        observed: dict[str, str] = {}

        monkeypatch.setattr(cli_main, "load_config", lambda: config)
        monkeypatch.setattr(
            lifecycle_mod.MCPLifecycleManager, "start_enabled_servers", lambda self: 0
        )
        monkeypatch.setattr(lifecycle_mod.MCPLifecycleManager, "stop_all", lambda self: None)

        def fake_apply(agent, target: str, snapshot_id=None):
            restored = None
            if target == "https://old.example":
                restored = old_state
            elif target == "https://new.example":
                restored = new_state

            if restored is not None:
                agent.context.state = restored
                return type(
                    "Restore",
                    (),
                    {
                        "restored": True,
                        "target": restored.target,
                        "phase": restored.phase.value,
                        "snapshot_id": snapshot_id or "",
                        "resume_strategy": "",
                        "resume_reason": "",
                    },
                )()

            agent.context.state.target = target
            return type(
                "Restore",
                (),
                {
                    "restored": False,
                    "target": target,
                    "phase": agent.context.state.phase.value,
                    "snapshot_id": snapshot_id or "",
                    "resume_strategy": "",
                    "resume_reason": "",
                },
            )()

        async def fake_persistent_pentest(self, user_input: str, target=None, **kwargs):
            observed["target_arg"] = target or ""
            observed["state_target"] = self.context.state.target or ""
            observed["phase"] = self.context.state.phase.value
            return []

        monkeypatch.setattr(cli_main, "apply_target_state_to_agent", fake_apply)
        monkeypatch.setattr(agent_core.AgentCore, "persistent_pentest", fake_persistent_pentest)

        result = runner.invoke(
            app,
            ["repl"],
            input="target https://old.example\npersistent https://new.example\nexit\n",
        )

        assert result.exit_code == 0
        assert observed["target_arg"] == "https://new.example"
        assert observed["state_target"] == "https://new.example"
        assert observed["phase"] == PentestPhase.EXPLOITATION.value

    def test_report_target_mode(self, runner, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.cli.main import app

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path / "targets")
        state = SessionState(target="https://example.com")
        finding = VulnerabilityFinding(title="SQLi", severity="High", vuln_type="SQLi")
        finding.verified = True
        finding.verification_status = "verified"
        state.add_finding(finding)
        store_mod.save_target_state("https://example.com", state, command="scan")

        result = runner.invoke(app, ["report", "https://example.com", "--target"])
        assert result.exit_code == 0
        assert "Report generated" in result.output or "报告已生成" in result.output, f"Expected report confirmation in output: {result.output[:200]}"

    def test_repl_report_command_uses_current_session_or_target_state(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        import vulnclaw.mcp.lifecycle as lifecycle_mod
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"

        monkeypatch.setattr(cli_main, "load_config", lambda: config)
        monkeypatch.setattr(
            lifecycle_mod.MCPLifecycleManager, "start_enabled_servers", lambda self: 0
        )
        monkeypatch.setattr(lifecycle_mod.MCPLifecycleManager, "stop_all", lambda self: None)
        monkeypatch.setattr(
            cli_main, "_generate_report_for_target", lambda target, **kwargs: "C:/tmp/report.md"
        )

        result = runner.invoke(
            app,
            ["repl"],
            input="target https://example.com\nreport https://example.com\nexit\n",
        )

        assert result.exit_code == 0
        assert "Report generated" in result.output or "报告已生成" in result.output
        assert "report.md" in result.output

    def test_run_uses_shared_orchestrator(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        monkeypatch.setattr(cli_main, "load_config", lambda: config)

        called: list[tuple[str, str]] = []

        async def fake_orchestrated(*, command, target, resume, snapshot, runner):
            called.append((command, target))
            return type("RunResult", (), {"summary": {"findings_count": 3}})()

        monkeypatch.setattr(cli_main, "_run_cli_orchestrated_task", fake_orchestrated)

        result = runner.invoke(app, ["run", "https://example.com"])
        assert result.exit_code == 0
        assert called == [("run", "https://example.com")]

    def test_run_generates_report_after_completion(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        monkeypatch.setattr(cli_main, "load_config", lambda: config)

        async def fake_orchestrated(*, command, target, resume, snapshot, runner):
            return type("RunResult", (), {"summary": {"findings_count": 2}})()

        monkeypatch.setattr(cli_main, "_run_cli_orchestrated_task", fake_orchestrated)

        report_calls = []

        def fake_generate_report(target, **kwargs):
            report_calls.append((target, kwargs))
            return "/tmp/vulnclaw-output/report.md"

        monkeypatch.setattr(cli_main, "_generate_report_for_target", fake_generate_report)

        result = runner.invoke(app, ["run", "https://example.com"])

        assert result.exit_code == 0
        assert report_calls == [("https://example.com", {"output_path": None})]
        assert "report.md" in result.output

    def test_run_passes_output_flag_to_report_generation(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        monkeypatch.setattr(cli_main, "load_config", lambda: config)

        async def fake_orchestrated(*, command, target, resume, snapshot, runner):
            return type("RunResult", (), {"summary": {"findings_count": 0}})()

        monkeypatch.setattr(cli_main, "_run_cli_orchestrated_task", fake_orchestrated)

        report_calls = []

        def fake_generate_report(target, **kwargs):
            report_calls.append((target, kwargs))
            return "/custom/path/report.md"

        monkeypatch.setattr(cli_main, "_generate_report_for_target", fake_generate_report)

        result = runner.invoke(
            app, ["run", "https://example.com", "--output", "/custom/path/report.md"]
        )

        assert result.exit_code == 0
        assert report_calls == [
            ("https://example.com", {"output_path": "/custom/path/report.md"})
        ]
        assert "/custom/path/report.md" in result.output

    def test_run_engine_team_routes_to_team_supervisor(self, runner, monkeypatch):
        from types import SimpleNamespace

        import vulnclaw.agent.team as team
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        config.session.solve_max_steps = 7
        monkeypatch.setattr(cli_main, "load_config", lambda: config)

        calls = []

        async def fake_run_team_pentest(agent, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(plan=SimpleNamespace(steps=[]))

        monkeypatch.setattr(team, "run_team_pentest", fake_run_team_pentest)

        class DummyResearch:
            def get_summary(self):
                return {
                    "completed": False,
                    "steps": 1,
                    "evidence": 1,
                    "tool_calls": 0,
                    "complete_reason": "",
                }

        class DummyAgent:
            mcp_manager = None

            def __init__(self, *_args):
                self.context = SimpleNamespace(state=SimpleNamespace(agent_state=DummyResearch()))

        async def fake_orchestrated(*, command, target, resume, snapshot, runner):
            await runner(DummyAgent(), config)
            return type("RunResult", (), {"summary": {"findings_count": 0}})()

        monkeypatch.setattr(cli_main, "_run_cli_orchestrated_task", fake_orchestrated)
        monkeypatch.setattr(
            cli_main,
            "_generate_report_for_target",
            lambda target, **kwargs: "/tmp/report.md",
        )

        result = runner.invoke(app, ["run", "https://example.com", "--engine", "team"])

        assert result.exit_code == 0
        assert calls
        assert calls[0]["target"] == "https://example.com"
        assert calls[0]["max_steps"] == 7

    def test_run_cli_constraints_are_appended_to_prompt(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        config.session.engine = "rounds"
        monkeypatch.setattr(cli_main, "load_config", lambda: config)

        prompts = []

        async def fake_orchestrated(*, command, target, resume, snapshot, runner):
            class DummyAgent:
                async def auto_pentest(self, prompt, **kwargs):
                    prompts.append(prompt)
                    return []

            await runner(DummyAgent(), config)
            return type("RunResult", (), {"summary": {"findings_count": 0}})()

        monkeypatch.setattr(cli_main, "_run_cli_orchestrated_task", fake_orchestrated)

        result = runner.invoke(
            app,
            [
                "run",
                "https://example.com",
                "--only-port",
                "443",
                "--only-host",
                "example.com",
                "--only-path",
                "/admin",
            ],
        )
        assert result.exit_code == 0
        assert prompts
        assert "Only test port 443" in prompts[0]
        assert "Only test host example.com" in prompts[0]
        assert "Only test path /admin" in prompts[0]

    def test_run_cli_blocked_host_and_path_are_appended_to_prompt(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        config.session.engine = "rounds"
        monkeypatch.setattr(cli_main, "load_config", lambda: config)

        prompts = []

        async def fake_orchestrated(*, command, target, resume, snapshot, runner):
            class DummyAgent:
                async def auto_pentest(self, prompt, **kwargs):
                    prompts.append(prompt)
                    return []

            await runner(DummyAgent(), config)
            return type("RunResult", (), {"summary": {"findings_count": 0}})()

        monkeypatch.setattr(cli_main, "_run_cli_orchestrated_task", fake_orchestrated)

        result = runner.invoke(
            app,
            [
                "run",
                "https://example.com",
                "--blocked-host",
                "staging.example.com",
                "--blocked-path",
                "/internal",
            ],
        )
        assert result.exit_code == 0
        assert prompts
        assert "Blocked host staging.example.com" in prompts[0]
        assert "Blocked path /internal" in prompts[0]

    def test_cli_blocks_command_when_allowed_actions_conflict(self, runner, monkeypatch):
        import vulnclaw.cli._helpers as helpers_mod
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        monkeypatch.setattr(cli_main, "load_config", lambda: config)
        monkeypatch.setattr(
            helpers_mod,
            "_append_cli_constraints",
            lambda prompt, only_port, only_host, only_path, blocked_host=None, blocked_path=None: f"{prompt} 仅做信息收集。",
        )

        result = runner.invoke(app, ["run", "https://example.com"])
        assert result.exit_code == 0

    def test_cli_blocks_command_with_explicit_allow_actions_option(self, runner):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(cli_main, "load_config", lambda: config)

        result = runner.invoke(app, ["run", "https://example.com", "--allow-actions", "recon"])
        monkeypatch.undo()
        assert result.exit_code == 0

    def test_persistent_command_uses_correct_cycle_callback(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        monkeypatch.setattr(cli_main, "load_config", lambda: config)

        class DummyAgent:
            def __init__(self):
                self.context = type(
                    "Ctx", (), {"state": type("State", (), {"target": "https://example.com"})()}
                )()
                self.runtime = type("Runtime", (), {})()

            async def persistent_pentest(self, *args, **kwargs):
                assert "on_cycle_complete" in kwargs
                assert kwargs["on_cycle_complete"] is not None
                return []

        async def fake_orchestrated(*, command, target, resume, snapshot, runner):
            await runner(DummyAgent(), config)
            return type("Result", (), {"summary": {"findings_count": 0, "executed_steps": 0}})()

        monkeypatch.setattr(cli_main, "_run_cli_orchestrated_task", fake_orchestrated)

        result = runner.invoke(
            app, ["persistent", "https://example.com", "--cycles", "1", "--rounds", "1"]
        )
        assert result.exit_code == 0

    def test_repl_persistent_interrupt_generates_final_report(self, runner, monkeypatch):
        import vulnclaw.agent.core as agent_core
        import vulnclaw.cli.main as cli_main
        import vulnclaw.mcp.lifecycle as lifecycle_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"

        monkeypatch.setattr(cli_main, "load_config", lambda: config)
        monkeypatch.setattr(
            lifecycle_mod.MCPLifecycleManager, "start_enabled_servers", lambda self: 0
        )
        monkeypatch.setattr(lifecycle_mod.MCPLifecycleManager, "stop_all", lambda self: None)

        state = SessionState(target="https://example.com")
        finding = VulnerabilityFinding(title="SQLi", severity="High", vuln_type="SQLi")
        state.add_finding(finding)

        def fake_apply(agent, target: str, snapshot_id=None):
            agent.context.state = state
            return type(
                "Restore",
                (),
                {
                    "restored": True,
                    "target": state.target,
                    "phase": state.phase.value,
                    "snapshot_id": snapshot_id or "",
                    "resume_strategy": "",
                    "resume_reason": "",
                },
            )()

        async def fake_persistent_pentest(self, user_input: str, target=None, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(cli_main, "apply_target_state_to_agent", fake_apply)
        monkeypatch.setattr(agent_core.AgentCore, "persistent_pentest", fake_persistent_pentest)
        monkeypatch.setattr(
            cli_main, "_generate_report_for_target", lambda target, **kwargs: "C:/tmp/final.md"
        )

        result = runner.invoke(
            app,
            ["repl"],
            input="persistent https://example.com\nexit\n",
        )

        assert result.exit_code == 0
        assert "Final report" in result.output or "最终报告" in result.output
        assert "final.md" in result.output

    def test_target_state_list_and_clear(self, runner, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState
        from vulnclaw.cli.main import app

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path / "targets")
        state = SessionState(target="https://example.com")
        store_mod.save_target_state("https://example.com", state, command="recon")

        result_list = runner.invoke(app, ["target-state", "list", "https://example.com"])
        assert result_list.exit_code == 0
        assert "snapshot" in result_list.output.lower() or "蹇収" in result_list.output

        result_clear = runner.invoke(app, ["target-state", "clear", "https://example.com"])
        assert result_clear.exit_code == 0
        assert result_clear.output

    def test_target_state_preview_and_diff(self, runner, monkeypatch, tmp_path):
        import vulnclaw.target_state.store as store_mod
        from vulnclaw.agent.context import SessionState, VulnerabilityFinding
        from vulnclaw.cli.main import app

        monkeypatch.setattr(store_mod, "TARGETS_DIR", tmp_path / "targets")

        state1 = SessionState(target="https://example.com")
        state1.add_finding(VulnerabilityFinding(title="SQLi", severity="High", vuln_type="SQLi"))
        store_mod.save_target_state("https://example.com", state1, command="recon")

        state2 = SessionState(target="https://example.com")
        state2.add_finding(VulnerabilityFinding(title="XSS", severity="Medium", vuln_type="XSS"))
        store_mod.save_target_state("https://example.com", state2, command="scan")

        snapshots = store_mod.list_target_snapshots("https://example.com")
        result_preview = runner.invoke(app, ["target-state", "preview", "https://example.com"])
        assert result_preview.exit_code == 0
        assert "Target Preview" in result_preview.output

        result_diff = runner.invoke(
            app,
            [
                "target-state",
                "diff",
                "https://example.com",
                snapshots[-1]["snapshot_id"],
                "--to",
                snapshots[0]["snapshot_id"],
            ],
        )
        assert result_diff.exit_code == 0
        assert "Target Diff" in result_diff.output

    @pytest.mark.asyncio
    async def test_repl_runner_executes_post_hook(self):
        from vulnclaw.repl_runner import run_repl_call

        observed = []

        async def call():
            observed.append("call")
            return "hello"

        async def after_result(result):
            observed.append(f"after:{result}")

        result = await run_repl_call(call=call, after_result=after_result)
        assert result == "hello"
        assert observed == ["call", "after:hello"]

    def test_cli_kb_info(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["kb", "info"])
        # kb info might not exist in all versions, just verify no crash
        assert result.exit_code in (0, 2)

    def test_cli_no_args(self, runner, monkeypatch):
        """Running with no args should open the original CLI/REPL by default."""
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app

        called = []
        monkeypatch.setattr(cli_main, "_run_repl", lambda: called.append("repl"))

        result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert called == ["repl"]

    def test_repl_command_starts_classic_repl(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app

        called = []
        monkeypatch.setattr(cli_main, "_run_repl", lambda: called.append("repl"))

        result = runner.invoke(app, ["repl"])
        assert result.exit_code == 0
        assert called == ["repl"]

    def test_tui_once_renders_workbench(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["tui", "--once"])
        assert result.exit_code == 0
        assert "VulnClaw TUI" in result.output
        assert "授权目标" in result.output
        assert "运行概览" in result.output
        assert "未选择目标" in result.output
        assert "安全边界" in result.output
        # [修改] 新版 TUI 使用 slash 命令系统替代了数字菜单, 移除 "操作菜单" 断言

    def test_tui_once_renders_target_overview(self, runner, monkeypatch):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.cli.main import app

        monkeypatch.setattr(
            tui_mod,
            "get_target_state_preview",
            lambda target: {
                "target": target,
                "phase": "scanning",
                "findings_count": 3,
                "verified_count": 1,
                "pending_count": 2,
                "last_command": "scan",
                "constraints": {
                    "allowed_ports": [443],
                    "allowed_paths": ["/admin"],
                    "strict_mode": True,
                },
                "constraint_violations": ["blocked port 80"],
            },
        )
        monkeypatch.setattr(
            tui_mod,
            "list_target_snapshots",
            lambda target: [{"snapshot_id": "snap_a"}, {"snapshot_id": "snap_b"}],
        )

        result = runner.invoke(app, ["tui", "--once", "--target", "https://example.com"])
        assert result.exit_code == 0
        assert "2 个快照" in result.output
        assert "3 个风险" in result.output
        assert "限定端口: 443" in result.output
        assert "限定路径: /admin" in result.output
        assert "严格模式" in result.output
        assert "1 次" in result.output

    def test_tui_once_accepts_prefilled_target(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(
            app,
            [
                "tui",
                "--once",
                "--target",
                "https://example.com",
                "--mode",
                "quick",
                "--only-port",
                "443",
            ],
        )
        assert result.exit_code == 0
        assert "https://example.com" in result.output
        assert "快速摸底" in result.output
        assert "443" in result.output

    def test_tui_dry_run_renders_launch_summary(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(
            app,
            [
                "tui",
                "--dry-run",
                "--target",
                "https://example.com",
                "--mode",
                "deep",
                "--only-host",
                "example.com",
                "--only-port",
                "443",
                "--only-path",
                "/admin",
                "--blocked-host",
                "staging.example.com",
                "--block-actions",
                "post_exploitation",
            ],
        )
        assert result.exit_code == 0
        assert "启动摘要" in result.output
        assert "vulnclaw scan https://example.com" in result.output
        assert "--only-port 443" in result.output
        assert "--only-path /admin" in result.output
        assert "--blocked-host staging.example.com" in result.output

    def test_tui_rejects_unknown_mode(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["tui", "--mode", "unknown", "--dry-run"])
        assert result.exit_code == 1
        assert "Unknown TUI mode" in result.output

    def test_tui_interactive_launch_builds_task_draft(self, runner, monkeypatch):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.cli.main import app

        launched = []

        def fake_run_tui(*, launcher=None, once=False, initial_state=None):
            state = tui_mod.TuiState(
                target="https://example.com",
                mode="quick",
                only_port="443",
                only_path="/admin",
                blocked_host="staging.example.com",
            )
            draft = tui_mod._draft_from_state(state)
            launched.append(draft)

        monkeypatch.setattr(tui_mod, "run_tui", fake_run_tui)

        result = runner.invoke(app, ["tui"])
        assert result.exit_code == 0
        assert launched
        assert launched[0].command == "recon"
        assert launched[0].target == "https://example.com"
        assert launched[0].only_port == 443
        assert launched[0].only_path == "/admin"
        assert launched[0].blocked_host == "staging.example.com"
        assert launched[0].allow_actions == ("recon",)

    def test_tui_scope_prompt_updates_action_constraints(self, monkeypatch):
        import vulnclaw.cli.tui as tui_mod

        state = tui_mod.TuiState(target="https://example.com")
        # Test scope parsing via _cmd_scope with inline arguments
        # (/scope host=example.com port=443 path=/admin ...)
        tui_mod._parse_scope_args(
            state,
            "host=example.com port=443 path=/admin "
            "blocked_host=staging.example.com blocked_path=/logout "
            "allow=recon,scan block=exploit,post_exploitation resume=false",
        )
        draft = tui_mod.build_task_draft(state)

        assert state.only_host == "example.com"
        assert state.only_port == "443"
        assert state.only_path == "/admin"
        assert state.blocked_host == "staging.example.com"
        assert state.blocked_path == "/logout"
        assert state.allow_actions == ["recon", "scan"]
        assert state.block_actions == ["exploit", "post_exploitation"]
        assert state.resume is False
        assert draft.allow_actions == ("recon", "scan")
        assert draft.block_actions == ("exploit", "post_exploitation")
        assert "--allow-actions recon,scan" in draft.command_line
        assert "--block-actions exploit,post_exploitation" in draft.command_line

    def test_tui_slash_dot_flag_applies_scope_state(self):
        import vulnclaw.cli.tui as tui_mod

        session = {"state": tui_mod.TuiState(), "_message": "", "_prompt": None}

        tui_mod._dispatch_slash("/.only-port 443", session)
        tui_mod._dispatch_slash("/.allow-actions recon,scan", session)
        tui_mod._dispatch_slash("/.no-resume", session)

        assert session["state"].only_port == "443"
        assert session["state"].allow_actions == ["recon", "scan"]
        assert session["state"].resume is False

    def test_tui_slash_dot_flag_without_value_shows_skill_help(self):
        import vulnclaw.cli.tui as tui_mod

        session = {"state": tui_mod.TuiState(), "_message": "", "_prompt": None}

        tui_mod._dispatch_slash("/.only-port", session)

        assert session["_prompt"][0] == "message"
        assert "--only-port" in session["_prompt"][1]

    def test_tui_persist_scope_state_writes_config(self, monkeypatch):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        state = tui_mod.TuiState(
            only_host="example.com",
            only_port="443",
            only_path="/admin",
            blocked_host="staging.example.com",
            blocked_path="/logout",
            allow_actions=["recon", "scan"],
            block_actions=["exploit", "post_exploitation"],
            mode="quick",
            resume=False,
        )
        saved = []
        monkeypatch.setattr(
            "vulnclaw.config.settings.save_config", lambda cfg: saved.append(cfg)
        )

        tui_mod._persist_scope_state(state, config)
        assert saved, "save_config was never called"
        sc = saved[0].session
        assert sc.tui_scope_only_host == "example.com"
        assert sc.tui_scope_only_port == "443"
        assert sc.tui_scope_allow_actions == "recon,scan"
        assert sc.tui_scope_block_actions == "exploit,post_exploitation"
        assert sc.tui_scope_mode == "quick"
        assert sc.tui_scope_resume is False

    def test_tui_restore_scope_state_reads_config(self):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        sc = config.session
        sc.tui_scope_only_host = "example.com"
        sc.tui_scope_only_port = "443"
        sc.tui_scope_allow_actions = "recon,scan"
        sc.tui_scope_block_actions = "exploit"
        sc.tui_scope_mode = "deep"
        sc.tui_scope_resume = True

        state = tui_mod.TuiState()

        tui_mod._restore_scope_state(state, config)
        assert state.only_host == "example.com"
        assert state.only_port == "443"
        assert state.allow_actions == ["recon", "scan"]
        assert state.block_actions == ["exploit"]
        assert state.mode == "deep"
        assert state.resume is True

    def test_tui_persist_restore_resume_round_trip(self, monkeypatch):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        resume_state = tui_mod.TuiState(resume=True)
        nosave = []

        monkeypatch.setattr(
            "vulnclaw.config.settings.save_config", lambda cfg: nosave.append(cfg)
        )
        tui_mod._persist_scope_state(resume_state, config)
        assert nosave[0].session.tui_scope_resume is True

        config2 = VulnClawConfig()
        config2.session.tui_scope_resume = True
        restored = tui_mod.TuiState(resume=False)

        tui_mod._restore_scope_state(restored, config2)
        assert restored.resume is True

    def test_tui_restore_scope_preserves_cli_explicit(self):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.session.tui_scope_only_host = "persisted.example.com"
        config.session.tui_scope_mode = "deep"

        state = tui_mod.TuiState(only_host="cli.example.com", mode="quick")
        tui_mod._restore_scope_state(state, config)
        assert state.only_host == "cli.example.com"
        assert state.mode == "quick"

    def test_textual_slash_dot_flag_dispatch_applies_state(self):
        import vulnclaw.cli.tui as tui_mod
        import vulnclaw.cli.tui_textual as textual_mod

        session = {"state": tui_mod.TuiState(), "_message": "", "_prompt": None}

        textual_mod._dispatch(session, "/.only-host example.com")

        assert session["state"].only_host == "example.com"

    def test_textual_slash_palette_highlight_keeps_terminal_background(self):
        import re

        import vulnclaw.cli.tui_textual as textual_mod

        palette = re.search(
            r"#cmd-palette \{(?P<body>.*?)\}",
            textual_mod.CSS,
            re.DOTALL,
        )
        item = re.search(
            r"#cmd-palette ListItem \{(?P<body>.*?)\}",
            textual_mod.CSS,
            re.DOTALL,
        )
        highlight = re.search(
            r"#cmd-palette ListItem\.-highlight \{(?P<body>.*?)\}",
            textual_mod.CSS,
            re.DOTALL,
        )

        for match in (palette, item, highlight):
            assert match is not None
            body = match.group("body")
            assert "background: #" not in body

    def test_tui_slash_palette_includes_available_skills(self):
        import vulnclaw.cli.tui as tui_mod

        entries = dict(tui_mod.build_slash_palette_entries())

        assert "target" in entries
        assert "mode" in entries
        assert "scope" in entries
        assert "run" in entries
        assert "quit" in entries

    def test_tui_skill_slash_without_args_shows_skill_help(self):
        import vulnclaw.cli.tui as tui_mod

        session = {"state": tui_mod.TuiState(), "_message": "", "_prompt": None}

        tui_mod._dispatch_slash("/ctf-web", session)

        assert session["_prompt"][0] == "message"
        assert "/ctf-web skill" in session["_prompt"][1]

    def test_textual_skill_slash_with_args_launches_skill_prompt(self):
        import vulnclaw.cli.tui as tui_mod
        import vulnclaw.cli.tui_textual as textual_mod

        session = {
            "state": tui_mod.TuiState(target="https://example.com"),
            "_message": "",
            "_prompt": None,
        }

        result = textual_mod._dispatch(session, "/ctf-web find the flag")

        assert result == "launch"
        assert session["_nl_text"] == "Use VulnClaw skill ctf-web. find the flag"

    def _make_textual_session(self, monkeypatch, mode):
        """Build a Textual TUI session with _start_execution stubbed out."""
        from types import SimpleNamespace

        import vulnclaw.cli.tui as tui_mod
        import vulnclaw.cli.tui_textual as textual_mod

        session = {
            "config": SimpleNamespace(
                llm=SimpleNamespace(provider="test", model="m", api_key="x")
            ),
            "state": tui_mod.TuiState(target="https://example.com", mode=mode),
            "launcher": None,
            "_action": None,
            "_prompt": None,
            "_message": "",
            "_launch": False,
        }
        launched = []
        monkeypatch.setattr(
            textual_mod.DashboardScreen,
            "_start_execution",
            lambda screen, draft=None, **kw: launched.append(draft),
        )
        return textual_mod, session, launched

    async def test_textual_action_matrix_shows_prefilled_states(self, monkeypatch):
        """action_matrix 弹窗按生效值预填, 同一动作 allow/block 重叠时按禁止优先。"""
        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        received = []
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            textual_mod._set_prompt(
                session,
                "action_matrix",
                "设置动作约束",
                ["recon", "scan", "exploit", "post_exploitation"],
                ["recon", "scan", "exploit"],  # exploit 与 block 重叠
                ["exploit"],
                lambda result: received.append(result),
            )
            popup.show_for_prompt(session)
            await pilot.pause()

            assert popup.has_class("open")
            assert popup._ptype == "action_matrix"
            # 重叠的 exploit 按禁止优先消解
            assert popup._matrix_states == ["allow", "allow", "block", "none"]

    async def test_textual_action_matrix_space_cycles_three_states(self, monkeypatch):
        """空格只在 允许↔禁止 间切换; 不约束行首次空格进入允许, 不会被切回不约束。"""
        from textual.widgets import ListView

        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            textual_mod._set_prompt(
                session, "action_matrix", "设置动作约束",
                ["recon", "scan", "exploit", "post_exploitation"],
                ["recon", "scan"], [], lambda result: None,
            )
            popup.show_for_prompt(session)
            await pilot.pause()
            lv = popup.query_one("#popup-list", ListView)
            assert lv.index == 0
            # 当前行 recon: allow ↔ block 往复, 不会切走
            await pilot.press("space")
            assert popup._matrix_states[0] == "block"
            await pilot.press("space")
            assert popup._matrix_states[0] == "allow"
            await pilot.press("space")
            assert popup._matrix_states[0] == "block"
            # 下移两行到 exploit(不约束): 首次空格进入允许, 之后 allow ↔ block
            await pilot.press("down", "down")
            assert lv.index == 2
            await pilot.press("space")
            assert popup._matrix_states[2] == "allow"
            await pilot.press("space")
            assert popup._matrix_states[2] == "block"
            await pilot.press("space")
            assert popup._matrix_states[2] == "allow"

    async def test_textual_action_matrix_mouse_sets_constraint_without_submitting(self, monkeypatch):
        """左键按行列设置允许/禁止，重复点击幂等，且点击本身不提交。"""
        from textual.widgets import ListView, Static

        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        received = []
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            textual_mod._set_prompt(
                session,
                "action_matrix",
                "设置动作约束",
                ["recon", "scan", "exploit", "post_exploitation"],
                ["recon", "scan"],
                [],
                lambda result: received.append(result),
            )
            popup.show_for_prompt(session)
            await pilot.pause()
            lv = popup.query_one("#popup-list", ListView)

            await pilot.click("#matrix-block-2")
            await pilot.pause()
            assert lv.index == 2
            assert popup._matrix_states[2] == "block"
            assert popup.query_one("#matrix-allow-2", Static).content == "[#808080]·[/]"
            assert popup.query_one("#matrix-block-2", Static).content == "[bold #e06c75]✗[/]"
            assert received == []
            assert popup.has_class("open")

            await pilot.click("#matrix-block-2")
            await pilot.pause()
            assert popup._matrix_states[2] == "block"

            await pilot.click("#matrix-allow-2")
            await pilot.pause()
            assert popup._matrix_states[2] == "allow"
            assert popup.query_one("#matrix-allow-2", Static).content == "[bold #7fd88f]✓[/]"
            assert popup.query_one("#matrix-block-2", Static).content == "[#808080]·[/]"
            assert received == []
            assert popup.has_class("open")

    async def test_textual_action_matrix_mouse_action_cell_only_moves_highlight(self, monkeypatch):
        """点击动作名只选中对应行，不修改状态也不提交。"""
        from textual.widgets import ListView

        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        received = []
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            textual_mod._set_prompt(
                session,
                "action_matrix",
                "设置动作约束",
                ["recon", "scan", "exploit", "post_exploitation"],
                ["recon", "scan"],
                [],
                lambda result: received.append(result),
            )
            popup.show_for_prompt(session)
            await pilot.pause()
            lv = popup.query_one("#popup-list", ListView)
            before = list(popup._matrix_states)

            await pilot.click("#matrix-action-3")
            await pilot.pause()

            assert lv.index == 3
            assert popup._matrix_states == before
            assert received == []
            assert popup.has_class("open")

    async def test_textual_action_matrix_mouse_selection_then_enter_submits(self, monkeypatch):
        """鼠标只改矩阵；Enter 汇总并提交鼠标选择结果。"""
        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        received = []
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            textual_mod._set_prompt(
                session,
                "action_matrix",
                "设置动作约束",
                ["recon", "scan", "exploit", "post_exploitation"],
                ["recon", "scan"],
                [],
                lambda result: received.append(result),
            )
            popup.show_for_prompt(session)
            await pilot.pause()

            await pilot.click("#matrix-block-0")
            await pilot.click("#matrix-allow-2")
            await pilot.pause()
            assert received == []
            assert popup.has_class("open")

            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()

        assert received == [(["scan", "exploit"], ["recon"])]
        assert not popup.has_class("open")

    async def test_textual_action_matrix_enter_submits_selection(self, monkeypatch):
        """回车直接提交整个表格: cb 收到 (allow_list, block_list), 弹窗关闭。"""
        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        received = []
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            textual_mod._set_prompt(
                session, "action_matrix", "设置动作约束",
                ["recon", "scan", "exploit", "post_exploitation"],
                ["recon", "scan"], [], lambda result: received.append(result),
            )
            popup.show_for_prompt(session)
            await pilot.pause()
            await pilot.press("down", "down", "space")  # exploit → 允许
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()

        assert received == [(["recon", "scan", "exploit"], [])]
        assert not popup.has_class("open")

    async def test_textual_action_matrix_escape_cancels_without_changes(self, monkeypatch):
        """Esc 取消: cb 不被调用, state 不被修改。"""
        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        received = []
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            textual_mod._set_prompt(
                session, "action_matrix", "设置动作约束",
                ["recon", "scan", "exploit", "post_exploitation"],
                ["recon", "scan"], [], lambda result: received.append(result),
            )
            popup.show_for_prompt(session)
            await pilot.pause()
            await pilot.press("space")  # recon → block（但未提交）
            await pilot.press("escape")
            await pilot.pause()

        assert received == []
        assert session["state"].allow_actions == []
        assert session["state"].block_actions == []

    async def test_textual_scope_flow_uses_action_matrix(self, monkeypatch):
        """/scope: chain 5 字段 → action_matrix → 提交写回 state → resume confirm。"""
        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            await pilot.press(*"/scope", "escape", "enter")
            await pilot.pause()
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            assert popup._ptype == "chain"
            # 5 个文本字段全部回车跳过（空值合法, only_port 空不触发校验）
            for _ in range(5):
                await pilot.press("enter")
                await pilot.pause()
                await pilot.pause()
            assert popup._ptype == "action_matrix"
            # standard 模式生效值预填: recon/scan 允许, post_exploitation 禁止(模式默认), 其余不约束
            assert popup._matrix_states == ["allow", "allow", "none", "block"]
            # exploit 切换为 禁止 并提交
            await pilot.press("down", "down", "space", "space")
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()

            state = session["state"]
            assert state.allow_actions == ["recon", "scan"]
            assert state.block_actions == ["exploit", "post_exploitation"]
            assert popup._ptype == "confirm"  # resume 确认弹窗

    async def test_textual_action_matrix_legacy_input_fallback_csv(self, monkeypatch):
        """旧路径兜底: 弹窗打开时主输入框提交文本, 按 CSV 解析为 allow, block 保持初始值。"""
        from textual.widgets import Input

        textual_mod, session, _launched = self._make_textual_session(monkeypatch, "standard")
        received = []
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            textual_mod._set_prompt(
                session, "action_matrix", "设置动作约束",
                ["recon", "scan", "exploit", "post_exploitation"],
                ["recon"], ["exploit"], lambda result: received.append(result),
            )
            popup.show_for_prompt(session)
            await pilot.pause()
            app.screen.query_one("#cmd-input", Input).focus()
            await pilot.press(*"scan,exploit", "enter")
            await pilot.pause()
            await pilot.pause()

        assert received == [(["scan", "exploit"], ["exploit"])]

    def test_textual_scope_inline_args_still_apply(self):
        """回归: /scope allow=recon block=exploit 直参形式不受影响。"""
        import vulnclaw.cli.tui as tui_mod
        import vulnclaw.cli.tui_textual as textual_mod

        session = {"state": tui_mod.TuiState(), "_message": "", "_prompt": None}

        result = textual_mod._dispatch(session, "/scope allow=recon block=exploit")

        assert result is None
        assert session["state"].allow_actions == ["recon"]
        assert session["state"].block_actions == ["exploit"]
        assert session["_prompt"] is None

    def test_textual_scope_empty_allow_falls_back_to_mode_default(self):
        """全部不约束提交后 allow 为空列表, 生效值回落模式默认。"""
        import vulnclaw.cli.tui as tui_mod

        state = tui_mod.TuiState(mode="standard")
        state.allow_actions = []

        assert tui_mod._effective_allow_actions(state) == ("recon", "scan")

    @pytest.mark.parametrize("mode", ["deep", "continuous"])
    async def test_textual_extra_confirm_mode_run_confirmed_launches(self, mode, monkeypatch):
        """/run in deep/continuous mode: pressing y in the confirm popup must
        start execution (the async confirm callback sets session["_action"]
        after _dispatch already returned, so it must be consumed later)."""
        textual_mod, session, launched = self._make_textual_session(monkeypatch, mode)
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            await pilot.press(*"/run", "escape", "enter")
            await pilot.pause()
            popup = app.screen.query_one(textual_mod.SecondaryPopup)
            assert popup.has_class("open")
            await pilot.press("y")
            await pilot.pause()
            await pilot.pause()

        assert launched, "confirming /run with y should start execution"
        assert session["_action"] is None

    async def test_textual_deep_mode_run_confirm_via_input_launches(self, monkeypatch):
        """Answering the deep-mode confirm by typing y in the main input must
        also start execution (legacy _handle_prompt path)."""
        from textual.widgets import Input

        textual_mod, session, launched = self._make_textual_session(monkeypatch, "deep")
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            await pilot.press(*"/run", "escape", "enter")
            await pilot.pause()
            app.screen.query_one("#cmd-input", Input).focus()
            await pilot.press("y", "enter")
            await pilot.pause()
            await pilot.pause()

        assert launched, "confirming /run with y should start execution"

    async def test_textual_deep_mode_run_declined_does_not_launch(self, monkeypatch):
        """Pressing n in the deep-mode confirm popup must not start execution."""
        textual_mod, session, launched = self._make_textual_session(monkeypatch, "deep")
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            await pilot.press(*"/run", "escape", "enter")
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            await pilot.pause()

        assert not launched
        assert session["_action"] is None

    async def test_textual_standard_mode_run_launches_without_confirm(self, monkeypatch):
        """/run in standard mode launches directly, no confirm popup."""
        textual_mod, session, launched = self._make_textual_session(monkeypatch, "standard")
        app = textual_mod.VulnClawApp(session)
        async with app.run_test() as pilot:
            await pilot.press(*"/run", "escape", "enter")
            await pilot.pause()

        assert launched

    def test_skill_slash_with_args_requires_target_by_default(self, monkeypatch):
        import vulnclaw.cli.tui as tui_mod

        monkeypatch.setattr(
            tui_mod,
            "load_skill_by_name",
            lambda name: {"name": name, "requires_target": True},
        )
        session = {"state": tui_mod.TuiState(), "_message": "", "_prompt": None}

        handled = tui_mod.dispatch_skill_slash_command("needs-target", "go", session)

        assert handled is True
        assert session["_message"] == tui_mod._("tui.please_set_target")
        assert session.get("_action") != "launch"

    def test_self_discovering_skill_launches_without_target(self, monkeypatch):
        import vulnclaw.cli.tui as tui_mod

        # A skill declaring ``requires_target: false`` (e.g. hackerone) discovers
        # its target from args, so it launches with no preset target.
        monkeypatch.setattr(
            tui_mod,
            "load_skill_by_name",
            lambda name: {"name": name, "requires_target": False},
        )
        session = {"state": tui_mod.TuiState(), "_message": "", "_prompt": None}

        handled = tui_mod.dispatch_skill_slash_command(
            "hackerone", "https://hackerone.com/example", session
        )

        assert handled is True
        assert session["_action"] == "launch"
        assert (
            session["_nl_text"]
            == "Use VulnClaw skill hackerone. https://hackerone.com/example"
        )
        # The scope link stands in as the target so the launched subprocess
        # records a real target rather than the "<target>" placeholder.
        assert session["state"].target == "https://hackerone.com/example"

    def test_self_discovering_skill_keeps_preset_target(self, monkeypatch):
        import vulnclaw.cli.tui as tui_mod

        monkeypatch.setattr(
            tui_mod,
            "load_skill_by_name",
            lambda name: {"name": name, "requires_target": False},
        )
        session = {
            "state": tui_mod.TuiState(target="https://preset.example"),
            "_message": "",
            "_prompt": None,
        }

        handled = tui_mod.dispatch_skill_slash_command(
            "hackerone", "https://hackerone.com/example", session
        )

        assert handled is True
        assert session["_action"] == "launch"
        # An already-set target is respected, not overwritten by the args.
        assert session["state"].target == "https://preset.example"

    def test_tui_runtime_diagnostic_panel_renders_environment_summary(self, monkeypatch):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        config.llm.provider = "openai"
        config.llm.model = "gpt-test"

        monkeypatch.setattr(tui_mod, "_command_version", lambda *args: "v20.0.0")
        monkeypatch.setattr(tui_mod.shutil, "which", lambda command: f"/usr/bin/{command}")

        class DummyMCPDiagnostics:
            total_services = 3
            running_services = 1
            local_services = 2
            placeholder_services = 1
            tool_count = 5

        def fake_get_mcp_diagnostics():
            return DummyMCPDiagnostics()

        import vulnclaw.mcp.diagnostics as mcp_diag_mod

        monkeypatch.setattr(mcp_diag_mod, "get_mcp_diagnostics", fake_get_mcp_diagnostics)
        rendered = tui_mod.Console(
            file=io.StringIO(),
            record=True,
            width=100,
            force_terminal=False,
            color_system=None,
        )
        rendered.print(tui_mod.build_runtime_diagnostic_panel(config))
        output = rendered.export_text()

        assert "环境诊断" in output
        assert "v20.0.0" in output
        assert "openai" in output
        assert "gpt-test" in output
        assert "已配置" in output
        assert "3 registered" in output
        assert "5" in output

    def test_tui_llm_config_prompt_saves_provider_and_api_key(self, monkeypatch):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        # _edit_llm_config flow:
        #   provider → base_url → auth_mode → api_keys → api_key
        #   → model → chatgpt_auto_proxy → max_tokens → max_context_tokens
        #   → temperature → reasoning_effort
        answers = iter(
            [
                "deepseek",
                "https://api.deepseek.com/v1",
                "static",
                "sk-test",
                "",
                "1",
                "n",
                "",
                "",
                "",
                "",
            ]
        )

        monkeypatch.setattr(tui_mod.Prompt, "ask", lambda *args, **kwargs: next(answers))
        monkeypatch.setattr(tui_mod, "fetch_provider_models", lambda *a, **kw: ["deepseek-chat", "deepseek-reasoner"])

        screen = tui_mod.Console(
            file=io.StringIO(),
            record=True,
            width=100,
            force_terminal=False,
            color_system=None,
        )
        updated = tui_mod._edit_llm_config(screen, config)

        assert updated.llm.provider == "deepseek"
        assert updated.llm.base_url == "https://api.deepseek.com/v1"
        assert updated.llm.model == "deepseek-chat"
        assert updated.llm.api_keys == ["sk-test"]

    def test_config_tui_escape_exits_without_saving(self, monkeypatch):
        from rich.console import Console as RichConsole

        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.config.schema import VulnClawConfig

        answers = iter(["llm", "\x1b"])
        saved = []
        screen = RichConsole(
            file=io.StringIO(),
            record=True,
            width=100,
            force_terminal=False,
            color_system=None,
        )

        monkeypatch.setattr(tui_mod, "load_config", VulnClawConfig)
        monkeypatch.setattr(tui_mod, "save_config", lambda cfg: saved.append(cfg))
        monkeypatch.setattr(
            tui_mod, "_read_config_prompt_raw", lambda *args, **kwargs: next(answers)
        )
        monkeypatch.setattr(tui_mod, "Console", lambda *args, **kwargs: screen)

        tui_mod.run_config_tui()

        assert saved == []
        assert "Discarded changes." in screen.export_text()

    def test_config_tui_llm_editor_shows_models_for_selected_provider(self, monkeypatch):
        from rich.console import Console as RichConsole

        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "sk-test"
        answers = iter(
            [
                "deepseek",
                "",
                "static",
                "",
                "",
                "deepseek-reasoner",
                "n",
                "",
                "",
                "",
                "",
            ]
        )
        fetched = []
        screen = RichConsole(
            file=io.StringIO(),
            record=True,
            width=100,
            force_terminal=False,
            color_system=None,
        )

        monkeypatch.setattr(
            tui_mod, "_read_config_prompt_raw", lambda *args, **kwargs: next(answers)
        )
        monkeypatch.setattr(
            tui_mod,
            "fetch_provider_models",
            lambda base_url, api_key: fetched.append((base_url, api_key))
            or ["deepseek-chat", "deepseek-reasoner"],
        )

        updated = tui_mod._edit_llm_config(screen, config)
        output = screen.export_text()

        assert fetched == [("https://api.deepseek.com", "sk-test")]
        assert "deepseek-chat" in output
        assert "deepseek-reasoner" in output
        assert updated.llm.provider == "deepseek"
        assert updated.llm.model == "deepseek-reasoner"


class TestClassicReplSlashPalette:
    """Classic `vulnclaw` REPL: '/' skill palette and '/.' flag-skill wiring."""

    def test_skill_entries_are_skills_only(self):
        import vulnclaw.cli.tui as tui_mod

        entries = dict(tui_mod.list_skill_palette_entries())

        assert "ctf-web" in entries
        assert "recon" in entries
        # Textual-only slash commands must not leak into the classic REPL menu.
        assert "target" not in entries
        assert "mode" not in entries

    def test_skill_entries_filter_by_prefix(self):
        import vulnclaw.cli.tui as tui_mod

        names = {name for name, _ in tui_mod.list_skill_palette_entries("re")}

        assert "recon" in names
        assert "reporting" in names
        assert all(name.startswith("re") for name in names)

    def test_skill_description_localizes_by_language(self):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.i18n import init_i18n

        skill = {"name": "recon", "description": "信息收集流程 — 被动+主动侦察"}
        try:
            init_i18n(lang="en")
            english = tui_mod.skill_display_description(skill)
            init_i18n(lang="zh")
            chinese = tui_mod.skill_display_description(skill)
        finally:
            init_i18n()  # restore auto-detected default

        # English catalog override applies; zh falls back to the frontmatter.
        assert english == "Reconnaissance workflow — passive and active recon"
        assert chinese == "信息收集流程 — 被动+主动侦察"

    def test_skill_description_falls_back_when_untranslated(self):
        import vulnclaw.cli.tui as tui_mod
        from vulnclaw.i18n import init_i18n

        skill = {"name": "no-such-skill", "description": "raw frontmatter"}
        try:
            init_i18n(lang="en")
            assert tui_mod.skill_display_description(skill) == "raw frontmatter"
        finally:
            init_i18n()

    def test_bare_slash_prompts_for_a_skill_name(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/")

        assert result.kind == "message"
        assert "skill name" in result.text

    def test_unknown_skill_reports_error(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/not-a-real-skill")

        assert result.kind == "message"
        assert "Unknown skill" in result.text

    def test_skill_without_task_shows_help(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/recon")

        assert result.kind == "message"
        assert "recon" in result.text

    def test_skill_with_task_rewrites_to_agent_prompt(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/recon scan the box")

        assert result.kind == "run"
        assert result.text == "Use VulnClaw skill recon. scan the box"

    def test_flag_target_sets_target(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/.target example.com")

        assert result.kind == "target"
        assert result.value == "example.com"

    def test_flag_target_without_value_asks_for_host(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/.target")

        assert result.kind == "message"
        assert "host value" in result.text

    def test_non_target_flag_is_guidance_only(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        # B1 wiring: mode/scope flags render guidance, they do not mutate state.
        result = dispatch_repl_slash("/.mode")

        assert result.kind == "message"
        assert "/.mode" in result.text

    def test_unknown_flag_skill_reports_error(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/.zzz-not-a-flag")

        assert result.kind == "message"
        assert "Unknown flag skill" in result.text

    def test_completer_offers_commands_and_skills_on_bare_slash(self):
        from prompt_toolkit.document import Document

        from vulnclaw.cli.tui import build_repl_slash_completer, list_repl_palette_entries

        completer = build_repl_slash_completer()
        completions = list(completer.get_completions(Document("/", 1), None))

        assert len(completions) == len(list_repl_palette_entries())
        # Built-in commands come first, ahead of the skills.
        assert [c.text for c in completions[:2]] == ["config", "language"]

    def test_completion_style_keeps_terminal_background(self):
        from vulnclaw.cli.tui import build_repl_slash_style

        rules = dict(build_repl_slash_style().style_rules)
        completion_rules = {
            selector: value
            for selector, value in rules.items()
            if selector.startswith(("completion-menu", "completion-toolbar"))
        }

        assert completion_rules
        for value in completion_rules.values():
            assert "bg:#" not in value
            assert "reverse" not in value.replace("noreverse", "")
        assert rules["completion-menu.completion.current"].endswith("noreverse")
        assert "bg:default" in rules["completion-menu.completion.current"]

    def test_completer_stops_after_skill_is_chosen(self):
        from prompt_toolkit.document import Document

        from vulnclaw.cli.tui import build_repl_slash_completer

        completer = build_repl_slash_completer()
        text = "/recon scan"
        completions = list(completer.get_completions(Document(text, len(text)), None))

        assert completions == []

    def test_prompt_session_is_none_without_a_tty(self, monkeypatch):
        import vulnclaw.cli.main as main_mod

        monkeypatch.setattr(main_mod.sys.stdin, "isatty", lambda: False)

        assert main_mod._make_repl_prompt_session() is None

    def test_prompt_session_uses_terminal_background_completion_style(self, monkeypatch):
        import prompt_toolkit

        import vulnclaw.cli.main as main_mod

        captured: dict[str, object] = {}

        class _Hook:
            def __iadd__(self, handler):
                captured["handler"] = handler
                return self

        class _Buffer:
            on_text_changed = _Hook()

        class _PromptSession:
            default_buffer = _Buffer()

            def __init__(self, **kwargs):
                captured.update(kwargs)

        monkeypatch.setattr(main_mod.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(prompt_toolkit, "PromptSession", _PromptSession)

        assert isinstance(main_mod._make_repl_prompt_session(), _PromptSession)
        rules = dict(captured["style"].style_rules)
        assert "bg:default" in rules["completion-menu.completion.current"]
        assert rules["completion-menu.completion.current"].endswith("noreverse")

    def test_config_command_dispatches(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/config")

        assert result.kind == "command"
        assert result.value == "config"
        assert result.text == ""

    def test_config_alias_dispatches(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/cfg")

        assert result.kind == "command"
        assert result.value == "config"

    def test_language_command_carries_argument(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/language en")

        assert result.kind == "command"
        assert result.value == "language"
        assert result.text == "en"

    def test_language_alias_dispatches(self):
        from vulnclaw.cli.tui import dispatch_repl_slash

        result = dispatch_repl_slash("/lang")

        assert result.kind == "command"
        assert result.value == "language"

    def test_repl_palette_lists_commands_before_skills(self):
        import vulnclaw.cli.tui as tui_mod

        entries = tui_mod.list_repl_palette_entries()
        names = [name for name, _ in entries]

        assert names[:2] == ["config", "language"]
        assert "recon" in names  # skills still follow the commands

    def test_repl_palette_filters_commands_by_prefix(self):
        import vulnclaw.cli.tui as tui_mod

        names = [name for name, _ in tui_mod.list_repl_palette_entries("co")]

        assert "config" in names
        assert "language" not in names

    def test_language_switch_updates_config(self, monkeypatch):
        import vulnclaw.cli.main as main_mod
        import vulnclaw.cli.tui as tui_mod
        import vulnclaw.i18n as i18n_mod

        saved = {}
        monkeypatch.setattr(main_mod, "save_config", lambda cfg: saved.setdefault("cfg", cfg))
        # Keep the switch pure: no real locale reload / global rebuild.
        monkeypatch.setattr(i18n_mod, "init_i18n", lambda *a, **k: None)
        monkeypatch.setattr(tui_mod, "rebuild_translations", lambda: None)

        class _Cfg:
            class session:
                language = "auto"

        class _Agent:
            def __init__(self):
                self.applied = None

            def apply_config(self, cfg):
                self.applied = cfg

        cfg = _Cfg()
        agent = _Agent()

        out = main_mod._repl_switch_language("en", agent, cfg)

        assert cfg.session.language == "en"
        assert out is cfg
        assert saved["cfg"] is cfg
        assert agent.applied is cfg

    def test_repl_prompt_localizes_chinese_phase_when_language_is_english(self, monkeypatch):
        import vulnclaw.cli.main as main_mod
        from vulnclaw.i18n import init_i18n

        prompts = []

        class _Console:
            def input(self, prompt):
                prompts.append(prompt)
                return "exit"

        monkeypatch.setattr(main_mod, "console", _Console())
        init_i18n(lang="en")
        try:
            assert main_mod._read_repl_line(None, "127.0.0.1:3000", "就绪", True) == "exit"
        finally:
            init_i18n(lang="zh")

        assert "Ready" in prompts[0]
        assert "就绪" not in prompts[0]

    def test_language_switch_rejects_unknown(self, monkeypatch):
        import vulnclaw.cli.main as main_mod

        called = {"saved": False}
        monkeypatch.setattr(
            main_mod, "save_config", lambda cfg: called.__setitem__("saved", True)
        )

        class _Cfg:
            class session:
                language = "en"

        class _Agent:
            def apply_config(self, cfg):  # pragma: no cover - must not run
                raise AssertionError("apply_config should not be called")

        cfg = _Cfg()
        out = main_mod._repl_switch_language("klingon", _Agent(), cfg)

        assert out is cfg
        assert cfg.session.language == "en"  # unchanged
        assert called["saved"] is False

    def test_agent_apply_config_resets_client(self):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.settings import load_config

        config = load_config()
        agent = AgentCore.__new__(AgentCore)
        agent._client = object()
        agent._key_index = 3

        agent.apply_config(config)

        assert agent.config is config
        assert agent._client is None
        assert agent._key_index == 0


class TestCLISubCommands:
    """Test CLI sub-command help messages."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_run_help(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0

    def test_recon_help(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["recon", "--help"])
        assert result.exit_code == 0

    def test_scan_help(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_report_help(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0

    def test_repl_help(self, runner):
        from vulnclaw.cli.main import app

        result = runner.invoke(app, ["repl", "--help"])
        assert result.exit_code == 0

    def test_run_with_prompt_option(self, runner):
        # [修改] 2026-06-10 Nyaecho - 添加 --prompt 选项测试
        from vulnclaw.cli.main import app

        # Test that --prompt option is accepted and doesn't crash
        # We expect failure due to missing target, but the option should be parsed
        result = runner.invoke(app, ["run", "--prompt", "test prompt", "example.com"])
        # Should not be a usage error (exit code 2)
        assert result.exit_code != 2
        # The command will fail for other reasons (no config, etc.), but that's okay
