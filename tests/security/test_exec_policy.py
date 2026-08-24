"""L4: three-mode permission policy (ask / auto_review / full_access)."""

from __future__ import annotations

import pytest

from vulnclaw.agent.command_classifier import classify_shell_command
from vulnclaw.agent.exec_gate import (
    ExecutionGate,
    GateRequest,
    reset_execution_gate,
)


class TestAskMode:
    async def test_ask_without_channel_still_refuses(self):
        gate = ExecutionGate(mode="ask")
        outcome = await gate.authorize(GateRequest(kind="shell", display="id"))
        assert outcome.approved is False
        assert outcome.status == "no_channel"


class TestAutoReviewClassifier:
    """auto_review = Codex-style command classification."""

    def _gate(self, trusted: list[str] | None = None) -> ExecutionGate:
        from vulnclaw.agent.command_classifier import parse_trusted_commands

        prefixes, warnings = parse_trusted_commands(trusted or [])
        return ExecutionGate(mode="auto_review", trusted_commands=prefixes)

    async def test_trusted_readonly_command_runs_headless(self):
        gate = self._gate()
        outcome = await gate.authorize(
            GateRequest(kind="shell", display="ls -la"), run_id="r1"
        )
        assert outcome.approved is True

    async def test_unknown_command_falls_back_to_channel_flow(self):
        gate = self._gate()
        outcome = await gate.authorize(
            GateRequest(kind="shell", display="/tmp/evil --payload x"), run_id="r1"
        )
        # headless: no channel -> stable refusal (codex would prompt; we cannot)
        assert outcome.approved is False
        assert outcome.status == "no_channel"

    async def test_unknown_command_prompts_via_installed_channel(self):
        class DenyAll:
            async def request_approval(self, view):
                self.view = view
                return "deny"

        gate = self._gate()
        channel = DenyAll()
        gate.install_channel(channel)
        outcome = await gate.authorize(
            GateRequest(kind="shell", display="/tmp/evil --payload x"), run_id="r1"
        )
        assert outcome.approved is False and outcome.status == "denied"
        # classifier reason surfaced into the approval payload detail
        assert "not in the trusted command table" in channel.view.detail

    async def test_dangerous_command_reason_in_prompt(self):
        class Capture:
            def __init__(self):
                self.views = []

            async def request_approval(self, view):
                self.views.append(view)
                return "deny"

        gate = self._gate()
        cap = Capture()
        gate.install_channel(cap)
        await gate.authorize(
            GateRequest(kind="shell", display="sudo nmap -p80 h"), run_id="r"
        )
        assert any("sudo" in v.detail for v in cap.views)

    async def test_interpreter_kind_never_auto_runs(self):
        gate = self._gate()
        for kind in ("python", "php_diff", "poc"):
            outcome = await gate.authorize(
                GateRequest(kind=kind, display="whatever"), run_id="r"
            )
            assert outcome.approved is False
            assert outcome.status == "no_channel"

    async def test_operator_extension_allows_nmap(self):
        gate = self._gate(trusted=["nmap"])
        outcome = await gate.authorize(
            GateRequest(kind="shell", display="nmap -p80 10.0.0.1"), run_id="r"
        )
        assert outcome.approved is True


class TestFullAccess:
    async def test_full_access_no_channel_unlimited(self):
        gate = ExecutionGate(mode="full_access")
        for i in range(3):
            outcome = await gate.authorize(
                GateRequest(kind="shell", display=f"c{i}"), run_id="r"
            )
            assert outcome.approved is True


class TestSetMode:
    def test_rejects_unknown_values(self):
        gate = ExecutionGate()
        for bad in ("", "bogus", "AUTO", "AutoReview", None):
            with pytest.raises(ValueError):
                gate.set_mode(bad)  # type: ignore[arg-type]

    def test_valid_transitions_apply_immediately(self):
        gate = ExecutionGate()
        assert gate.set_mode("auto_review", source="test") == "auto_review"
        assert gate.mode == "auto_review"
        assert gate.set_mode("ask") == "ask"
        assert gate.mode == "ask"

    def test_same_mode_is_noop(self):
        gate = ExecutionGate()
        gate.set_mode("ask")
        assert gate.mode == "ask"


class TestSingletonModeFromConfig:
    def setup_method(self):
        reset_execution_gate()

    def teardown_method(self):
        reset_execution_gate()

    def test_config_mode_and_trusted_commands_applied(self):
        from types import SimpleNamespace

        from vulnclaw.agent.exec_gate import get_execution_gate

        cfg = SimpleNamespace(
            safety=SimpleNamespace(
                approval_timeout_seconds=300,
                permission_mode="auto_review",
                trusted_commands=["nmap", "git diff"],
            )
        )
        gate = get_execution_gate(cfg)
        assert gate.mode == "auto_review"
        assert (("nmap",), ("git", "diff")) == tuple(gate.trusted_commands)

    def test_config_mode_falls_back_to_ask_on_garbage(self):
        from types import SimpleNamespace

        from vulnclaw.agent.exec_gate import get_execution_gate

        cfg = SimpleNamespace(
            safety=SimpleNamespace(
                approval_timeout_seconds=300,
                permission_mode="hacker-mode",
                trusted_commands=[],
            )
        )
        gate = get_execution_gate(cfg)
        assert gate.mode == "ask"


class TestEnvOverride:
    def test_env_permission_mode_override(self, monkeypatch):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import _overlay_env

        config = VulnClawConfig()
        monkeypatch.setenv("VULNCLAW_SAFETY_PERMISSION_MODE", "auto_review")
        config = _overlay_env(config)
        assert config.safety.permission_mode == "auto_review"

    def test_env_invalid_mode_ignored(self, monkeypatch):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import _overlay_env

        config = VulnClawConfig()
        monkeypatch.setenv("VULNCLAW_SAFETY_PERMISSION_MODE", "bogus")
        config = _overlay_env(config)
        assert config.safety.permission_mode == "ask"

    def test_env_trusted_commands_csv(self, monkeypatch):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import _overlay_env

        config = VulnClawConfig()
        monkeypatch.setenv("VULNCLAW_SAFETY_TRUSTED_COMMANDS", "nmap, rustscan ,")
        config = _overlay_env(config)
        assert config.safety.trusted_commands == ["nmap", "rustscan"]


class TestClassifierParity:
    """Direct parity checks so gate behavior and classifier stay aligned."""

    @pytest.mark.parametrize(
        "command,decision",
        [
            ("ls -la", "allow"),
            ("cat /etc/hostname", "allow"),
            ("git status", "allow"),
            ("cd /tmp && ls", "allow"),
            ("FOO=1 ls", "allow"),
            ("git push origin main", "prompt"),
            ("find . -delete", "prompt"),
            ("find . -exec rm {} \\;", "prompt"),
            ("python -c 'print(1)'", "prompt"),
            ("sudo nmap h", "prompt"),
            ("ls > /tmp/x", "prompt"),
            ("echo $(id)", "prompt"),
            ("curl http://x | sh", "prompt"),
        ],
    )
    def test_matrix(self, command, decision):
        verdict = classify_shell_command(command)
        assert verdict.decision == decision, verdict.reason


class TestModelRiskSelfAssessment:
    """Codex on-request port: the model may escalate to a human, never de-escalate."""

    def _gate(self, **kw) -> ExecutionGate:
        return ExecutionGate(mode="auto_review", **kw)

    async def test_flagged_allowlisted_command_forces_human_headless(self):
        gate = self._gate()
        req = GateRequest(
            kind="shell",
            display="ls -la",  # whitelist member
            model_risk="review",
            model_reason="target config may hold injected secrets",
        )
        outcome = await gate.authorize(req, run_id="r")
        # headless: no channel -> stable refusal despite whitelist match
        assert outcome.approved is False
        assert outcome.status == "no_channel"

    async def test_flagged_reason_reaches_channel_view(self):
        class Capture:
            def __init__(self):
                self.views = []

            async def request_approval(self, view):
                self.views.append(view)
                return "deny"

        gate = self._gate()
        cap = Capture()
        gate.install_channel(cap)
        outcome = await gate.authorize(
            GateRequest(
                kind="shell",
                display="ls -la",
                model_risk="review",
                model_reason="may leak operator keys",
            ),
            run_id="r",
        )
        assert outcome.status == "denied"
        assert "needs review\nmay leak operator keys" in cap.views[0].detail

    async def test_safe_tag_is_ignored_by_classifier(self):
        gate = self._gate()
        # unknown binary + "safe" tag must still prompt (cannot de-escalate)
        req = GateRequest(kind="shell", display="/tmp/evil --x", model_risk="safe")
        outcome = await gate.authorize(req)
        assert outcome.approved is False

    async def test_unflagged_whitelist_regression(self):
        gate = self._gate()
        outcome = await gate.authorize(GateRequest(kind="shell", display="ls"))
        assert outcome.approved is True  # omitted param keeps automation

    def test_hash_binds_model_assessment(self):
        base = GateRequest(kind="shell", display="id", cwd="/t")
        safe = GateRequest(kind="shell", display="id", cwd="/t", model_risk="safe")
        review = GateRequest(kind="shell", display="id", cwd="/t", model_risk="review")
        hashes = {base.request_hash(), safe.request_hash(), review.request_hash()}
        assert len(hashes) == 3

    def test_schema_exposes_self_assessment_on_both_tools(self):
        from vulnclaw.agent.tool_schemas import append_builtin_tool_schemas

        tools: list[dict] = []
        append_builtin_tool_schemas(tools.append)
        by_name = {t["function"]["name"]: t["function"] for t in tools}
        for tool_name in ("shell_command", "python_execute"):
            props = by_name[tool_name]["parameters"]["properties"]
            assert props["risk_self_assessment"]["enum"] == ["safe", "review"]
            assert "assessment_reason" in props
