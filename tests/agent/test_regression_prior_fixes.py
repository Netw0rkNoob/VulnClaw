"""Regression lock-ins for behaviors fixed earlier that had no test guarding them.

Each class pins a specific fix so a future refactor can't silently undo it:

- ``TestAddFindingCheckpoint``  — commit fd95ea8 (Issue 1): the live
  ``SessionState.add_finding`` must fire the persistence checkpoint; that
  behavior had regressed into a dead ``VulnerabilityStore`` copy.
- ``TestPersistentReconReset`` — commit 739e2ae (Issue 3): a persistent-cycle
  reset must *preserve* accumulated recon progress, while a fresh task resets it.
- ``TestBuiltinToolSchemaSet`` — commit fddb39b (Issue 4): the built-in tool
  schema set must stay stable after being extracted to ``tool_schemas``.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.context import PentestPhase, SessionState, VulnerabilityFinding
from vulnclaw.agent.core import AgentCore
from vulnclaw.config.schema import VulnClawConfig


class TestAddFindingCheckpoint:
    def _state(self) -> SessionState:
        state = SessionState(target="https://t.com")
        # Lower the semantic-dedup threshold so the near-duplicate below collides.
        state.semantic_dedup_threshold = 0.6
        return state

    def test_new_finding_fires_finding_added(self):
        state = self._state()
        reasons: list[str] = []
        state.set_checkpoint_callback(lambda _s, reason: reasons.append(reason))
        added = state.add_finding(
            VulnerabilityFinding(
                title="login SQLi",
                severity="High",
                vuln_type="SQLi",
                description="https://t.com/api/login?u=1 vulnerable",
            )
        )
        assert added is True
        assert reasons == ["finding_added"]

    def test_semantic_replace_fires_finding_updated(self):
        state = self._state()
        assert state.add_finding(
            VulnerabilityFinding(
                title="login SQLi",
                vuln_type="SQLi",
                description="https://t.com/api/login?u=1 vulnerable",
            )
        )
        reasons: list[str] = []
        state.set_checkpoint_callback(lambda _s, reason: reasons.append(reason))
        # Semantically the same finding but with stronger evidence (verified) —
        # add_finding replaces the weaker one and must checkpoint the update.
        stronger = VulnerabilityFinding(
            title="登录处 SQL 注入",
            vuln_type="SQL注入",
            description="https://t.com/api/login?u=2 注入",
            verified=True,
        )
        assert state.add_finding(stronger) is False  # replaced, not appended
        assert len(state.findings) == 1
        assert "finding_updated" in reasons

    def test_exact_duplicate_skip_fires_no_checkpoint(self):
        state = self._state()
        finding = VulnerabilityFinding(
            title="login SQLi",
            vuln_type="SQLi",
            description="https://t.com/api/login?u=1 vulnerable",
        )
        assert state.add_finding(finding) is True
        reasons: list[str] = []
        state.set_checkpoint_callback(lambda _s, reason: reasons.append(reason))
        # Re-adding the same finding id is a pure skip — no durable state change.
        assert state.add_finding(finding) is False
        assert reasons == []


class TestPersistentReconReset:
    def _agent(self) -> AgentCore:
        return AgentCore(config=VulnClawConfig())

    def test_persistent_cycle_preserves_recon_progress(self):
        agent = self._agent()
        agent._reset_runtime_state(
            user_input="侦察 example.com 收集情报", detected_phase=PentestPhase.RECON
        )
        agent.context.state.recon_dimensions_completed["server"] = True
        agent.context.state.recon_dimension4_active = True

        agent._reset_runtime_state(
            user_input="[Persistent Cycle 2] 继续对目标 example.com 进行渗透测试。",
            detected_phase=PentestPhase.RECON,
        )

        assert agent.context.state.recon_dimensions_completed["server"] is True
        assert agent.context.state.recon_dimension4_active is True

    def test_fresh_task_resets_recon_progress(self):
        agent = self._agent()
        agent._reset_runtime_state(
            user_input="侦察 example.com 收集情报", detected_phase=PentestPhase.RECON
        )
        agent.context.state.recon_dimensions_completed["server"] = True
        agent.context.state.recon_dimension4_active = True

        agent._reset_runtime_state(
            user_input="scan other-target.com", detected_phase=PentestPhase.RECON
        )

        assert agent.context.state.recon_dimensions_completed["server"] is False
        assert agent.context.state.recon_dimension4_active is False


class TestBuiltinToolSchemaSet:
    # The exact set of built-in tools the schema factory must expose. Intel and
    # traffic tools are appended elsewhere, so this pins only the built-in core.
    EXPECTED = {
        "submit_finding",
        "load_skill_reference",
        "memory_search",
        "evidence_list",
        "evidence_view",
        "evidence_search",
        "source_extract",
        "runtime_diff_probe",
        "http_probe_batch",
        "python_execute",
        "shell_command",
        "nmap_scan",
        "subdomain_enum",
        "js_recon",
        "space_search",
        "crypto_decode",
        "brute_force_login",
        "unauth_test",
        "dir_enum",
        "vault_archive",
        "vault_restore",
        "vault_search",
        "vault_status",
    }

    def test_append_builtin_tool_schemas_exposes_stable_set(self):
        from vulnclaw.agent.tool_schemas import append_builtin_tool_schemas

        collected: list[dict] = []
        append_builtin_tool_schemas(collected.append)
        names = {tool["function"]["name"] for tool in collected}
        assert names == self.EXPECTED
        # Every schema is a well-formed OpenAI function tool.
        for tool in collected:
            assert tool.get("type") == "function"
            assert isinstance(tool["function"].get("parameters"), dict)

    def test_build_openai_tools_includes_all_builtins(self):
        from vulnclaw.agent.builtin_tools import build_openai_tools

        names = {tool["function"]["name"] for tool in build_openai_tools(None)}
        missing = self.EXPECTED - names
        assert not missing, f"build_openai_tools dropped built-ins: {missing}"

    def test_role_filter_can_drop_builtins(self):
        # The role gate still applies on top of the extracted schema list.
        from vulnclaw.agent.builtin_tools import build_openai_tools

        recon_names = {t["function"]["name"] for t in build_openai_tools(None, active_role="recon")}
        full_names = {t["function"]["name"] for t in build_openai_tools(None)}
        assert recon_names <= full_names


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
