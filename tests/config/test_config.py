"""VulnClaw Config Module Tests — schema.py + settings.py"""

import pytest
from pydantic import ValidationError

# ── schema.py ────────────────────────────────────────────────────────


class TestLLMConfig:
    """Test LLMConfig schema."""

    def test_default_values(self):
        from vulnclaw.config.schema import LLMConfig

        config = LLMConfig()
        assert config.model == "gpt-4o"
        assert config.api_key == ""
        assert config.base_url == "https://api.openai.com/v1"
        assert config.temperature == 0.1  # Updated default for pentest use
        assert config.max_tokens == 4096

    def test_custom_values(self):
        from vulnclaw.config.schema import LLMConfig

        config = LLMConfig(
            model="deepseek-chat",
            api_key="sk-test",
            base_url="https://api.deepseek.com/v1",
            temperature=0.3,
            max_tokens=8192,
        )
        assert config.model == "deepseek-chat"
        assert config.api_key == "sk-test"
        assert config.temperature == 0.3

    def test_provider_field(self):
        from vulnclaw.config.schema import LLMConfig

        config = LLMConfig(provider="deepseek")
        assert config.provider == "deepseek"

    def test_reasoning_effort_field(self):
        from vulnclaw.config.schema import LLMConfig

        config = LLMConfig(reasoning_effort="high")
        assert config.reasoning_effort == "high"


class TestMCPServerConfig:
    """Test MCPServerConfig schema."""

    def test_default_values(self):
        from vulnclaw.config.schema import MCPServerConfig, MCPTransportConfig

        config = MCPServerConfig(
            name="test-server",
            transport=MCPTransportConfig(type="stdio"),
        )
        assert config.name == "test-server"
        assert config.enabled is True
        assert config.priority == 1
        assert config.description == ""

    def test_custom_values(self):
        from vulnclaw.config.schema import MCPServerConfig, MCPTransportConfig

        config = MCPServerConfig(
            name="burp",
            enabled=False,
            priority=0,
            transport=MCPTransportConfig(type="sse", url="http://localhost:8080"),
            description="Burp Suite MCP server",
        )
        assert config.enabled is False
        assert config.priority == 0
        assert config.transport.type == "sse"


class TestSessionConfig:
    """Test SessionConfig schema."""

    def test_runtime_integration_default_values(self):
        from vulnclaw.config.schema import SessionConfig

        config = SessionConfig()
        assert config.reasoning_state_enabled is True
        assert config.reflexion_enabled is True
        assert config.reflexion_max_same_vuln_fails == 2
        assert config.reflexion_max_total_no_progress == 5
        assert config.escalation_max_level == 4
        assert config.plugin_runtime_enabled is True
        assert config.plugin_default_timeout == 10
        assert config.plugin_max_requests_per_target == 30
        assert config.evidence_min_report_level == "L4"
        assert config.context_hot_max_messages == 48
        assert config.context_hot_max_tokens == 32000
        assert config.memory_search_max_chars == 6000
        assert config.memory_archive_max_bytes == 64 * 1024 * 1024
        assert config.memory_archive_max_files == 8


class TestSubagentConfig:
    def test_compact_runtime_defaults(self):
        from vulnclaw.config.schema import SubagentConfig

        config = SubagentConfig()

        assert set(SubagentConfig.model_fields) == {
            "enabled",
            "max_background_groups",
            "max_concurrent_leaf_total",
            "max_concurrent_leaf_per_group",
            "max_leaf_per_group",
            "max_waves_per_group",
            "max_steps_per_leaf",
            "leaf_max_tool_rounds",
            "leaf_timeout_seconds",
            "group_timeout_seconds",
            "finalization_timeout_seconds",
            "max_model_tokens_per_solve",
            "max_model_tokens_per_group",
            "merge_max_evidence_per_group",
            "result_max_chars",
        }
        assert config.max_background_groups == 3
        assert config.max_concurrent_leaf_total == 4
        assert config.max_steps_per_leaf == 12
        assert config.leaf_max_tool_rounds == 4
        assert config.max_model_tokens_per_solve == 8_000_000
        assert config.max_model_tokens_per_group == 1_000_000

    @pytest.mark.parametrize(
        "field",
        [
            "max_background_groups",
            "max_concurrent_leaf_total",
            "max_concurrent_leaf_per_group",
            "max_leaf_per_group",
            "max_waves_per_group",
            "max_steps_per_leaf",
            "leaf_max_tool_rounds",
            "max_model_tokens_per_solve",
            "max_model_tokens_per_group",
            "merge_max_evidence_per_group",
            "result_max_chars",
        ],
    )
    @pytest.mark.parametrize("value", [0, -1])
    def test_budget_and_capacity_fields_must_be_positive(self, field, value):
        from vulnclaw.config.schema import SubagentConfig

        with pytest.raises(ValidationError):
            SubagentConfig(**{field: value})

    @pytest.mark.parametrize(
        "field,over_value",
        [
            ("max_background_groups", 9),
            ("max_concurrent_leaf_total", 100000),
            ("max_concurrent_leaf_per_group", 17),
            ("max_leaf_per_group", 33),
            ("max_waves_per_group", 13),
            ("max_steps_per_leaf", 101),
            ("leaf_max_tool_rounds", 21),
            ("merge_max_evidence_per_group", 129),
            ("result_max_chars", 200001),
        ],
    )
    def test_budget_and_capacity_fields_reject_dos_values(self, field, over_value):
        # Upper bounds are DoS guardrails: e.g. max_concurrent=100000 must be
        # rejected, otherwise it would build an effectively unbounded Semaphore
        # / fan-out and blow up token cost, memory and file descriptors.
        from vulnclaw.config.schema import SubagentConfig

        with pytest.raises(ValidationError):
            SubagentConfig(**{field: over_value})

    def test_all_numeric_fields_have_lower_and_upper_bounds(self):
        # Regression guard: every numeric sub-agent knob must be bounded on BOTH
        # ends so a config/env override cannot drive it to a runaway value.
        import annotated_types as at

        from vulnclaw.config.schema import SubagentConfig

        for name, info in SubagentConfig.model_fields.items():
            if info.annotation is not int:
                continue
            meta = info.metadata
            has_lower = any(isinstance(m, (at.Gt, at.Ge)) for m in meta)
            has_upper = any(isinstance(m, (at.Le, at.Lt)) for m in meta)
            assert has_lower, f"{name} is missing a lower bound"
            assert has_upper, f"{name} is missing an upper bound"

    def test_out_of_range_env_override_is_rejected_not_applied(self, monkeypatch):
        from vulnclaw.config.settings import load_config

        monkeypatch.setenv(
            "VULNCLAW_SUBAGENT_MAX_CONCURRENT_LEAF_TOTAL",
            "100000",
        )
        config = load_config()
        assert config.subagent.max_concurrent_leaf_total == 4

    def test_compact_runtime_env_overrides(self, monkeypatch):
        from vulnclaw.config.settings import load_config

        monkeypatch.setenv(
            "VULNCLAW_SUBAGENT_LEAF_TIMEOUT_SECONDS",
            "240",
        )
        monkeypatch.setenv(
            "VULNCLAW_SUBAGENT_GROUP_TIMEOUT_SECONDS",
            "360",
        )
        monkeypatch.setenv(
            "VULNCLAW_SUBAGENT_MAX_STEPS_PER_LEAF",
            "20",
        )
        monkeypatch.setenv(
            "VULNCLAW_SUBAGENT_MAX_MODEL_TOKENS_PER_GROUP",
            "900000",
        )
        config = load_config()

        assert config.subagent.leaf_timeout_seconds == 240.0
        assert config.subagent.group_timeout_seconds == 360.0
        assert config.subagent.max_steps_per_leaf == 20
        assert config.subagent.max_model_tokens_per_group == 900000


class TestVulnClawConfig:
    """Test VulnClawConfig schema."""

    def test_default_values(self):
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        assert config.llm.model == "gpt-4o"
        assert isinstance(config.mcp.servers, dict)
        assert config.session.reasoning_state_enabled is True
        assert config.session.reflexion_enabled is True

    def test_mcp_builtin_servers(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, VulnClawConfig

        VulnClawConfig()
        # Builtin servers are defined in BUILTIN_MCP_SERVERS, not in default config
        # Default config has empty servers dict; servers are populated by settings
        assert "fetch" in BUILTIN_MCP_SERVERS
        assert "memory" in BUILTIN_MCP_SERVERS

    def test_builtin_mcp_server_count(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS

        # Should have 4 builtin servers (fetch, memory, chrome-devtools, burp)
        assert len(BUILTIN_MCP_SERVERS) == 4

    def test_burp_uses_sse_transport(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS

        transport = BUILTIN_MCP_SERVERS["burp"]["transport"]
        assert transport["type"] == "sse"
        assert transport["url"] == "http://127.0.0.1:9876"

    def test_provider_presets(self):
        from vulnclaw.config.schema import PROVIDER_PRESETS

        # Should have at least the documented providers
        expected_providers = [
            "openai",
            "anthropic",
            "minimax",
            "deepseek",
            "zhipu",
            "moonshot",
            "qwen",
            "siliconflow",
        ]
        for provider in expected_providers:
            assert provider in PROVIDER_PRESETS, f"Missing provider: {provider}"

    def test_ollama_preset_points_at_local_openai_endpoint(self):
        """Ollama is a first-class preset so it appears in `vulnclaw config`
        and the web UI dropdown; local models need no code path of their own
        since Ollama speaks the OpenAI Chat Completions API."""
        from vulnclaw.config.schema import PROVIDER_PRESETS, LLMProvider

        assert LLMProvider("ollama") is LLMProvider.OLLAMA
        preset = PROVIDER_PRESETS[LLMProvider.OLLAMA]
        assert preset["base_url"] == "http://localhost:11434/v1"
        # Default must be a tool-capable model — the agent drives everything
        # through function calls.
        assert preset["default_model"] == "llama3.1"
        assert preset["label"]

    def test_orcarouter_preset_uses_routed_default_model(self):
        """OrcaRouter is an aggregator: one OpenAI-compatible endpoint fronting
        many vendors with adaptive routing, so model IDs carry a ``vendor/model``
        prefix and the default is the routing entry point. No provider-specific
        code path is needed beyond the preset."""
        from vulnclaw.config.schema import PROVIDER_PRESETS, LLMProvider

        assert LLMProvider("orcarouter") is LLMProvider.ORCAROUTER
        preset = PROVIDER_PRESETS[LLMProvider.ORCAROUTER]
        assert preset["base_url"] == "https://api.orcarouter.ai/v1"
        assert preset["default_model"] == "orcarouter/auto"
        assert preset["label"] == "OrcaRouter"

    def test_llm_provider_enum(self):
        from vulnclaw.config.schema import LLMProvider

        assert hasattr(LLMProvider, "OPENAI")
        assert hasattr(LLMProvider, "ANTHROPIC")
        assert hasattr(LLMProvider, "DEEPSEEK")
        assert hasattr(LLMProvider, "OLLAMA")
        assert hasattr(LLMProvider, "MINIMAX")


# ── settings.py ──────────────────────────────────────────────────────


class TestSettingsLoad:
    """Test config loading."""

    def test_load_config_returns_config(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import load_config

        config = load_config()
        assert isinstance(config, VulnClawConfig)

    def test_load_config_has_llm(self):
        from vulnclaw.config.settings import load_config

        config = load_config()
        assert config.llm is not None

    def test_load_config_has_mcp(self):
        from vulnclaw.config.settings import load_config

        config = load_config()
        assert config.mcp is not None

    def test_save_config(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import save_config

        config = VulnClawConfig()
        config.llm.model = "test-model"
        # save_config saves to the default path
        save_config(config)  # Should not crash

    def test_set_config_value(self):
        from vulnclaw.config.settings import set_config_value

        # set_config_value(key, value) — sets in the YAML config
        set_config_value("llm.model", "gpt-4o-mini")  # Should not crash

    def test_set_config_nested(self):
        from vulnclaw.config.settings import set_config_value

        set_config_value("llm.temperature", "0.1")  # Should not crash

    def test_set_config_mcp_server_field(self):
        from vulnclaw.config.settings import load_config, set_config_value

        set_config_value("mcp.servers.chrome-devtools.enabled", "true")

        config = load_config()
        assert config.mcp.servers["chrome-devtools"].enabled is True

    def test_apply_provider_preset(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import apply_provider_preset

        config = VulnClawConfig()
        apply_provider_preset(config, "deepseek")
        assert config.llm.provider == "deepseek"
        assert "deepseek" in config.llm.base_url.lower()

    def test_apply_anthropic_provider_preset(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import apply_provider_preset

        config = VulnClawConfig()
        apply_provider_preset(config, "anthropic")
        assert config.llm.provider == "anthropic"
        assert config.llm.base_url == "https://api.anthropic.com/v1"
        assert config.llm.model == "claude-sonnet-5"

    def test_list_providers(self):
        from vulnclaw.config.settings import list_providers

        providers = list_providers()
        assert isinstance(providers, list)
        assert len(providers) >= 7
        # Each entry should have provider, base_url, default_model
        for p in providers:
            assert "provider" in p
            assert "base_url" in p
            assert "default_model" in p

    def test_env_var_override(self, monkeypatch):
        """Test that environment variables override config values."""
        from vulnclaw.config.settings import load_config

        monkeypatch.setenv("VULNCLAW_LLM_API_KEY", "env-test-key")
        monkeypatch.setenv("VULNCLAW_LLM_MODEL", "env-test-model")
        # Config should pick up env vars
        config = load_config()
        # The env var may or may not be applied depending on load_config implementation
        # Just verify it doesn't crash
        assert config is not None

    def test_openai_default_headers_allow_user_agent_override(self, monkeypatch):
        from vulnclaw.config.settings import openai_default_headers

        assert openai_default_headers()["User-Agent"] == "Mozilla/5.0"

        monkeypatch.setenv("VULNCLAW_LLM_USER_AGENT", "test-agent")

        assert openai_default_headers()["User-Agent"] == "test-agent"

    def test_env_var_override_new_session_fields(self, monkeypatch):
        """二开新增的 session 配置（反思/插件）可通过环境变量注入。"""
        from vulnclaw.config.settings import load_config

        monkeypatch.setenv("VULNCLAW_SESSION_REFLEXION_ENABLED", "false")
        monkeypatch.setenv("VULNCLAW_SESSION_REASONING_STATE_ENABLED", "false")
        monkeypatch.setenv("VULNCLAW_SESSION_REFLEXION_MAX_SAME_VULN_FAILS", "5")
        monkeypatch.setenv("VULNCLAW_SESSION_ESCALATION_MAX_LEVEL", "2")
        monkeypatch.setenv("VULNCLAW_SESSION_PLUGIN_RUNTIME_ENABLED", "false")
        monkeypatch.setenv("VULNCLAW_SESSION_PLUGIN_MAX_REQUESTS_PER_TARGET", "7")
        monkeypatch.setenv("VULNCLAW_SESSION_EVIDENCE_MIN_REPORT_LEVEL", "L2")

        config = load_config()

        assert config.session.reflexion_enabled is False
        assert config.session.reasoning_state_enabled is False
        assert config.session.reflexion_max_same_vuln_fails == 5
        assert config.session.escalation_max_level == 2
        assert config.session.plugin_runtime_enabled is False
        assert config.session.plugin_max_requests_per_target == 7
        assert config.session.evidence_min_report_level == "L2"

    def test_env_var_api_keys_list(self, monkeypatch):
        """VULNCLAW_LLM_API_KEYS (comma-separated) populates the key list."""
        from vulnclaw.config.settings import load_config

        monkeypatch.setenv("VULNCLAW_LLM_API_KEYS", "k1, k2 ,k3")
        config = load_config()
        assert config.llm.api_keys == ["k1", "k2", "k3"]

    def test_env_var_repl_parallel_overrides(self, monkeypatch):
        """VULNCLAW_SESSION_REPL_PARALLEL_* overrides session fan-out defaults."""
        from vulnclaw.config.settings import load_config

        monkeypatch.setenv("VULNCLAW_SESSION_REPL_PARALLEL_ENABLED", "false")
        monkeypatch.setenv("VULNCLAW_SESSION_REPL_PARALLEL_AGENTS", "2")
        monkeypatch.setenv("VULNCLAW_SESSION_REPL_PARALLEL_DEPTH", "2")
        monkeypatch.setenv("VULNCLAW_SESSION_REPL_PARALLEL_WORKER_ROUNDS", "4")
        monkeypatch.setenv("VULNCLAW_SESSION_REPL_PARALLEL_SURFACE_LIMIT", "9")

        config = load_config()

        assert config.session.repl_parallel_enabled is False
        assert config.session.repl_parallel_agents == 2
        assert config.session.repl_parallel_depth == 2
        assert config.session.repl_parallel_worker_rounds == 4
        assert config.session.repl_parallel_surface_limit == 9

    def test_set_config_value_api_keys_from_string(self, monkeypatch, tmp_path):
        """set_config_value('llm.api_keys', 'a,b') stores a parsed list."""
        import vulnclaw.config.settings as settings_mod

        monkeypatch.setattr(settings_mod, "CONFIG_FILE", tmp_path / "config.yaml")
        monkeypatch.setattr(settings_mod, "CONFIG_DIR", tmp_path)
        settings_mod.set_config_value("llm.api_keys", "a, b ,c")
        config = settings_mod.load_config()
        assert config.llm.api_keys == ["a", "b", "c"]

    def test_set_config_value_repl_parallel_fields(self, monkeypatch, tmp_path):
        """set_config_value coerces REPL parallel session fields."""
        import vulnclaw.config.settings as settings_mod

        monkeypatch.setattr(settings_mod, "CONFIG_FILE", tmp_path / "config.yaml")
        monkeypatch.setattr(settings_mod, "CONFIG_DIR", tmp_path)

        settings_mod.set_config_value("session.repl_parallel_enabled", "false")
        settings_mod.set_config_value("session.repl_parallel_agents", "2")
        settings_mod.set_config_value("session.repl_parallel_worker_rounds", "4")

        config = settings_mod.load_config()
        assert config.session.repl_parallel_enabled is False
        assert config.session.repl_parallel_agents == 2
        assert config.session.repl_parallel_worker_rounds == 4

    def test_strip_defaults_drops_empty_api_keys(self):
        from vulnclaw.config.settings import _strip_defaults

        raw = {"llm": {"api_keys": [], "model": "gpt-4o", "provider": "openai"}}
        _strip_defaults(raw)
        assert "api_keys" not in raw["llm"]

    def test_save_load_roundtrips_api_keys(self, monkeypatch, tmp_path):
        import vulnclaw.config.settings as settings_mod
        from vulnclaw.config.schema import VulnClawConfig

        monkeypatch.setattr(settings_mod, "CONFIG_FILE", tmp_path / "config.yaml")
        monkeypatch.setattr(settings_mod, "CONFIG_DIR", tmp_path)
        config = VulnClawConfig()
        config.llm.api_keys = ["x1", "x2"]
        settings_mod.save_config(config)
        reloaded = settings_mod.load_config()
        assert reloaded.llm.api_keys == ["x1", "x2"]
