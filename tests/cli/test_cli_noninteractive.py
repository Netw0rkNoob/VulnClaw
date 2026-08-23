"""Tests for `run --non-interactive`: scan-mode presets, exit codes, artifacts."""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import vulnclaw.cli.main as cli_main
from vulnclaw.cli.main import app
from vulnclaw.config.schema import VulnClawConfig


class _Finding:
    def __init__(self, verified: bool = False, verification_status: str = "pending"):
        self.verified = verified
        self.verification_status = verification_status


class _FakeAgent:
    """Records the engine kwargs and exposes a session_state with findings."""

    def __init__(self, findings, config):
        self.config = config
        self.context = None  # board lookup resolves to None
        self.session_state = types.SimpleNamespace(findings=findings)
        self.solve_kwargs: dict = {}

    async def solve(self, prompt, **kwargs):
        self.solve_kwargs = kwargs
        return None

    def apply_task_constraints(self, _constraints):
        return None


@pytest.fixture
def runner():
    return CliRunner()


def _config_with_creds():
    config = VulnClawConfig()
    config.llm.api_key = "test-key"
    return config


def _install_fake_run(
    monkeypatch,
    *,
    findings=None,
    raise_exc: Exception | None = None,
    captured: dict | None = None,
):
    """Patch load_config + orchestrator so `run` drives a fake agent.

    The fake ``_run_cli_orchestrated_task`` builds a config + agent and invokes
    the real runner closure so scan-mode/engine wiring is exercised end to end.
    """
    findings = findings if findings is not None else []
    monkeypatch.setattr(cli_main, "load_config", _config_with_creds)

    async def fake_orchestrated(*, command, target, resume, snapshot, runner):
        shared_config = VulnClawConfig()
        agent = _FakeAgent(findings, shared_config)
        if captured is not None:
            captured["agent"] = agent
            captured["shared_config"] = shared_config
        if raise_exc is not None:
            raise raise_exc
        await runner(agent, shared_config)
        return type("RunResult", (), {"summary": {"findings_count": len(findings)}})()

    monkeypatch.setattr(cli_main, "_run_cli_orchestrated_task", fake_orchestrated)
    monkeypatch.setattr(
        cli_main, "_generate_report_for_target", lambda target, **kw: "/tmp/report.md"
    )


# ── Non-interactive: no prompts, structured output ──────────────────


class TestNonInteractiveOutput:
    def test_no_prompt_is_issued_and_run_completes(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)

        # A prompt that would hang/raise must never be reached.
        def _boom(*a, **k):  # pragma: no cover - only fails if a prompt is issued
            raise RuntimeError("interactive prompt issued in non-interactive mode")

        monkeypatch.setattr(cli_main.console, "input", _boom)

        result = runner.invoke(app, ["run", "https://example.com", "--non-interactive"])
        assert result.exit_code == cli_main.headless.EXIT_CLEAN

    def test_structured_summary_lands_in_run_directory(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch, findings=[_Finding(verified=True)])
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)

        result = runner.invoke(
            app, ["run", "https://example.com", "--non-interactive", "--scan-mode", "quick"]
        )
        assert result.exit_code == cli_main.headless.EXIT_VERIFIED

        summaries = list(tmp_path.glob("*/summary.json"))
        assert len(summaries) == 1
        data = json.loads(summaries[0].read_text())
        assert data["target"] == "https://example.com"
        assert data["scan_mode"] == "quick"
        assert data["findings"]["verified"] == 1
        assert data["exit_code"] == cli_main.headless.EXIT_VERIFIED
        assert data["profile"]["max_parallel"] == 1  # quick → fan-out off

    def test_report_is_co_located_in_run_directory_by_default(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)

        report_calls: list = []

        def capture_report(target, **kwargs):
            report_calls.append(kwargs.get("output_path"))
            return kwargs.get("output_path") or "/tmp/report.md"

        monkeypatch.setattr(cli_main, "_generate_report_for_target", capture_report)

        runner.invoke(app, ["run", "https://example.com", "--non-interactive"])
        assert report_calls
        # default (no --output) → report path lives inside the run directory
        assert report_calls[0] is not None
        assert str(tmp_path) in report_calls[0]
        assert report_calls[0].endswith("report.md")

    def test_explicit_output_flag_still_wins(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)

        report_calls: list = []

        def capture_report(target, **kwargs):
            report_calls.append(kwargs.get("output_path"))
            return kwargs.get("output_path")

        monkeypatch.setattr(cli_main, "_generate_report_for_target", capture_report)

        runner.invoke(
            app,
            ["run", "t", "--non-interactive", "--output", "/custom/report.md"],
        )
        assert report_calls == ["/custom/report.md"]


# ── Scan-mode presets applied to the engine ─────────────────────────


class TestScanModeWiring:
    def test_standard_mode_uses_config_knobs(self, runner, monkeypatch, tmp_path):
        captured: dict = {}
        _install_fake_run(monkeypatch, captured=captured)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)

        runner.invoke(app, ["run", "t", "--non-interactive", "--scan-mode", "standard"])
        agent = captured["agent"]
        defaults = VulnClawConfig().session
        assert agent.solve_kwargs["max_steps"] == defaults.solve_max_steps
        assert agent.solve_kwargs["max_tool_rounds"] == defaults.solve_max_tool_rounds

    def test_deep_mode_opens_fan_out(self, runner, monkeypatch, tmp_path):
        captured: dict = {}
        _install_fake_run(monkeypatch, captured=captured)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)

        runner.invoke(app, ["run", "t", "--non-interactive", "--scan-mode", "deep"])
        assert captured["agent"].solve_kwargs["max_steps"] > VulnClawConfig().session.solve_max_steps

    def test_explicit_max_steps_overrides_preset(self, runner, monkeypatch, tmp_path):
        captured: dict = {}
        _install_fake_run(monkeypatch, captured=captured)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)

        runner.invoke(
            app,
            ["run", "t", "--non-interactive", "--scan-mode", "quick", "--max-steps", "999"],
        )
        assert captured["agent"].solve_kwargs["max_steps"] == 999

    def test_team_engine_receives_scan_mode_fan_out_cap(self, runner, monkeypatch, tmp_path):
        # team fan-out reads its own cap (not config), so the CLI must pass it or
        # quick/--max-parallel is silently ignored.
        import vulnclaw.agent.team as team_mod

        _install_fake_run(monkeypatch)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)

        team_calls: list = []

        async def fake_team(agent, **kwargs):
            team_calls.append(kwargs)
            return None

        monkeypatch.setattr(team_mod, "run_team_pentest", fake_team)

        runner.invoke(
            app,
            ["run", "t", "--non-interactive", "--engine", "team", "--scan-mode", "quick"],
        )
        assert team_calls
        assert team_calls[0]["max_parallel"] == 1  # quick → single agent


# ── Exit-code contract ──────────────────────────────────────────────


class TestExitCodes:
    def test_clean_run_exits_zero(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch, findings=[])
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive"])
        assert result.exit_code == 0

    def test_verified_finding_exits_two(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch, findings=[_Finding(verified=True)])
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive"])
        assert result.exit_code == 2

    def test_only_candidates_exits_three_with_fail_on_any(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch, findings=[_Finding(verified=False)])
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive", "--fail-on", "any"])
        assert result.exit_code == 3

    def test_candidates_do_not_block_under_default_fail_on(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch, findings=[_Finding(verified=False)])
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive"])  # default: verified
        assert result.exit_code == 0

    def test_fail_on_never_exits_zero_despite_verified(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch, findings=[_Finding(verified=True)])
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive", "--fail-on", "never"])
        assert result.exit_code == 0

    def test_crash_during_scan_exits_one(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch, raise_exc=RuntimeError("boom"))
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive"])
        assert result.exit_code == 1

    def test_missing_credentials_exits_one(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(cli_main, "load_config", lambda: VulnClawConfig())  # no api_key
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive"])
        assert result.exit_code == 1

    def test_bad_scan_mode_exits_one(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive", "--scan-mode", "bogus"])
        assert result.exit_code == 1

    def test_bad_fail_on_exits_one(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "t", "--non-interactive", "--fail-on", "sometimes"])
        assert result.exit_code == 1

    def test_blank_target_exits_one(self, runner, monkeypatch, tmp_path):
        _install_fake_run(monkeypatch)
        monkeypatch.setattr(cli_main, "RUNS_DIR", tmp_path)
        result = runner.invoke(app, ["run", "   ", "--non-interactive"])
        assert result.exit_code == 1


# ── Prescribed workflow docs parse-check ────────────────────────────


class TestWorkflowDocs:
    DOCS_DIR = Path(__file__).resolve().parents[2] / "docs" / "ci"

    def _run_flags(self, yaml_path: Path) -> list[str]:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        steps = data["jobs"]["vulnclaw"]["steps"]
        run_lines = [s["run"] for s in steps if "run" in s and "vulnclaw run" in s.get("run", "")]
        assert run_lines, f"no `vulnclaw run` step in {yaml_path.name}"
        tokens = run_lines[0].split()
        return [t for t in tokens if t.startswith("--")]

    def _run_option_names(self) -> set[str]:
        """Option strings the `run` command actually registers.

        Introspects the Typer/Click command rather than scraping ``--help``
        text, which Rich wraps/truncates at narrow terminal widths (e.g. CI).
        """
        from typer.main import get_command

        run_cmd = get_command(app).commands["run"]
        names: set[str] = set()
        for param in run_cmd.params:
            names.update(getattr(param, "opts", []) or [])
            names.update(getattr(param, "secondary_opts", []) or [])
        return names

    def test_both_workflow_files_present(self):
        assert (self.DOCS_DIR / "github-actions-pr-scan.yml").exists()
        assert (self.DOCS_DIR / "github-actions-scheduled-scan.yml").exists()

    @pytest.mark.parametrize(
        "filename",
        ["github-actions-pr-scan.yml", "github-actions-scheduled-scan.yml"],
    )
    def test_workflow_uses_flags_the_cli_accepts(self, filename):
        flags = self._run_flags(self.DOCS_DIR / filename)
        assert "--non-interactive" in flags
        accepted = self._run_option_names()
        for flag in flags:
            assert flag in accepted, f"{flag} from {filename} is not a `run` option"

    def test_pr_scan_gates_on_verified(self):
        flags = self._run_flags(self.DOCS_DIR / "github-actions-pr-scan.yml")
        assert "--scan-mode" in flags and "--scope-mode" in flags and "--fail-on" in flags

    def test_scheduled_scan_never_breaks_pipeline(self):
        text = (self.DOCS_DIR / "github-actions-scheduled-scan.yml").read_text(
            encoding="utf-8"
        )
        assert "--fail-on never" in text
        assert "--scan-mode deep" in text
