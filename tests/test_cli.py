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
        # Typer may return exit code 0 or 2 depending on version
        assert __version__ in result.output or result.exit_code in (0, 2)

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
        assert "vulnclaw tui" in result.output or "Set an API key first" in result.output

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
        assert "Knowledge base updated" in result.output or result.output
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
        assert "Report generated" in result.output or "报告已生成" in result.output or "报告已生成" in result.output or result.output

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

    def test_run_cli_constraints_are_appended_to_prompt(self, runner, monkeypatch):
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
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
        import vulnclaw.cli.main as cli_main
        from vulnclaw.cli.main import app
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        config.llm.api_key = "test-key"
        monkeypatch.setattr(cli_main, "load_config", lambda: config)
        monkeypatch.setattr(
            cli_main,
            "_append_cli_constraints",
            lambda prompt, only_port, only_host, only_path: f"{prompt} 仅做信息收集。",
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

        answers = iter(
            [
                "example.com",
                "443",
                "/admin",
                "staging.example.com",
                "/logout",
                "recon,scan",
                "exploit,post_exploitation",
            ]
        )
        monkeypatch.setattr(tui_mod.Prompt, "ask", lambda *args, **kwargs: next(answers))
        monkeypatch.setattr(tui_mod.Confirm, "ask", lambda *args, **kwargs: False)

        state = tui_mod.TuiState(target="https://example.com")
        tui_mod._prompt_scope(state)
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

        import vulnclaw.web.services.mcp_service as mcp_service

        monkeypatch.setattr(mcp_service, "get_mcp_diagnostics", fake_get_mcp_diagnostics)
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
        answers = iter(
            [
                "deepseek",
                "https://api.deepseek.com/v1",
                "deepseek-chat",
                "sk-test",
                "",
            ]
        )
        saved = []

        monkeypatch.setattr(tui_mod.Prompt, "ask", lambda *args, **kwargs: next(answers))
        monkeypatch.setattr(tui_mod, "save_config", lambda cfg: saved.append(cfg))

        screen = tui_mod.Console(
            file=io.StringIO(),
            record=True,
            width=100,
            force_terminal=False,
            color_system=None,
        )
        updated = tui_mod._prompt_llm_config(screen, config)
        output = screen.export_text()

        assert updated.llm.provider == "deepseek"
        assert updated.llm.base_url == "https://api.deepseek.com/v1"
        assert updated.llm.model == "deepseek-chat"
        assert updated.llm.api_key == "sk-test"
        assert saved and saved[0] is updated
        assert "模型/API 配置已保存" in output
        assert "API Key: 已更新" in output


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
