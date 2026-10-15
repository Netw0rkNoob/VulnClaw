from __future__ import annotations

from vulnclaw.config.schema import SessionConfig, VulnClawConfig
from vulnclaw.plugins import (
    PluginContext,
    PluginResult,
    PluginRuntime,
    PluginStage,
    VulnPlugin,
    create_builtin_runtime,
    registry,
)


def test_global_registry_registers_and_finds_builtin_plugin():
    plugin_id = "test.integration.registry"

    class IntegrationPlugin(VulnPlugin):
        plugin_id = "test.integration.registry"

        def run(self, context: PluginContext) -> PluginResult:
            return PluginResult(plugin_id=self.plugin_id, stage=context.stage)

    registry.unregister(plugin_id)
    registry.register(IntegrationPlugin)

    assert registry.get("builtin.web.headers") is not None
    assert registry.get(plugin_id) is IntegrationPlugin

    registry.unregister(plugin_id)


async def test_runtime_executes_builtin_plugin():
    runtime = create_builtin_runtime(VulnClawConfig())

    result = await runtime.execute(
        "builtin.web.headers",
        {
            "target": "https://example.com",
            "options": {"headers": {"server": "nginx"}},
        },
    )

    assert result.ok is True
    assert result.plugin_id == "builtin.web.headers"
    assert result.stage == PluginStage.DISCOVERY
    assert result.findings


def test_config_defaults_expose_plugin_runtime_and_budget_fields():
    config = SessionConfig()

    assert config.plugin_runtime_enabled is True
    assert config.plugin_default_timeout == 10
    assert config.plugin_max_requests_per_target == 30


def test_plugin_observations_retain_sources_without_registering_candidates():
    from vulnclaw.agent.context import SessionState
    from vulnclaw.plugins.integration import record_plugin_result
    from vulnclaw.plugins.result import PluginFinding, PluginResult, RiskLevel

    finding = PluginFinding(title="Weak CSP", risk=RiskLevel.LOW, vuln_type="security_headers")
    result = PluginResult(plugin_id="builtin.web.headers", findings=[finding])
    session = SessionState(target="https://example.com")
    context = PluginContext(target=session.target, options={"headers": {"server": "nginx"}})
    first = record_plugin_result(session, result, context)
    second = record_plugin_result(session, result, context)
    assert first != second
    assert session.findings == []
    assert len(session.agent_state.evidence) == 2
    assert session.agent_state.evidence[1].duplicate_of == first
    assert session.agent_state.evidence[0].arguments["options"] == context.options


def test_plugin_observations_cannot_be_attached_to_another_target():
    import pytest

    from vulnclaw.agent.context import SessionState
    from vulnclaw.plugins.integration import record_plugin_result

    session = SessionState(target="https://one.test")
    with pytest.raises(ValueError, match="another session target"):
        record_plugin_result(session, PluginResult(plugin_id="test"),
                             PluginContext(target="https://two.test"))
    assert session.agent_state.evidence == []


async def test_disabled_runtime_does_not_execute_plugin():
    calls = 0

    class DisabledPlugin(VulnPlugin):
        plugin_id = "test.integration.disabled"

        def run(self, context: PluginContext) -> PluginResult:
            nonlocal calls
            calls += 1
            return PluginResult(plugin_id=self.plugin_id, stage=context.stage)

    config = VulnClawConfig()
    config.session.plugin_runtime_enabled = False
    plugin_registry = type(registry)()
    plugin_registry.register(DisabledPlugin)
    runtime = PluginRuntime(plugin_registry, config=config)

    result = await runtime.execute("test.integration.disabled", {"target": "https://example.com"})

    assert result.ok is False
    assert result.skipped is True
    assert result.error_type == "disabled"
    assert calls == 0
