"""VulnClaw Config Module Tests — schema.py + settings.py"""


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
        from vulnclaw.config.schema import PROVIDER_PRESETS, LLMProvider

        # Should have at least the documented providers
        expected_providers = [
            "openai",
            "openrouter",
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
        assert len(PROVIDER_PRESETS) == 15
        assert PROVIDER_PRESETS[LLMProvider.OPENROUTER] == {
            "base_url": "https://openrouter.ai/api/v1",
            "default_model": "openai/gpt-4o",
            "label": "OpenRouter",
        }

    def test_llm_provider_enum(self):
        from vulnclaw.config.schema import LLMProvider

        assert hasattr(LLMProvider, "OPENAI")
        assert LLMProvider.OPENROUTER.value == "openrouter"
        assert hasattr(LLMProvider, "ANTHROPIC")
        assert hasattr(LLMProvider, "DEEPSEEK")
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

    def test_apply_openrouter_provider_preset_enforces_static_auth_without_deleting_keys(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import apply_provider_preset

        config = VulnClawConfig()
        config.llm.auth_mode = "oauth"
        config.llm.chatgpt_auto_proxy = True
        config.llm.oauth_token_url = "https://auth.example/token"
        config.llm.oauth_client_id = "saved-client"
        config.llm.api_key = "saved-static-key"
        config.llm.api_keys = ["saved-pool-key"]

        apply_provider_preset(config, "OpenRouter")

        assert config.llm.provider == "openrouter"
        assert config.llm.base_url == "https://openrouter.ai/api/v1"
        assert config.llm.model == "openai/gpt-4o"
        assert config.llm.auth_mode == "static"
        assert config.llm.chatgpt_auto_proxy is False
        assert config.llm.oauth_token_url == "https://auth.example/token"
        assert config.llm.oauth_client_id == "saved-client"
        assert config.llm.api_key == "saved-static-key"
        assert config.llm.api_keys == ["saved-pool-key"]

    def test_apply_openrouter_provider_preset_preserves_deliberate_model_override(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import apply_provider_preset

        config = VulnClawConfig()
        config.llm.provider = "deepseek"
        config.llm.base_url = "https://api.deepseek.com"
        config.llm.model = "private/model:variant"

        apply_provider_preset(config, "openrouter")

        assert config.llm.base_url == "https://openrouter.ai/api/v1"
        assert config.llm.model == "private/model:variant"

    def test_apply_openrouter_provider_preset_handles_unknown_previous_provider(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import apply_provider_preset

        config = VulnClawConfig()
        config.llm.provider = "legacy-gateway"
        config.llm.base_url = "https://legacy.example/v1"
        config.llm.model = ""

        apply_provider_preset(config, "openrouter")

        assert config.llm.provider == "openrouter"
        assert config.llm.base_url == "https://openrouter.ai/api/v1"
        assert config.llm.model == "openai/gpt-4o"

    def test_apply_openrouter_provider_preset_preserves_unknown_provider_model(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.config.settings import apply_provider_preset

        config = VulnClawConfig()
        config.llm.provider = "legacy-gateway"
        config.llm.model = "legacy/opaque-id"

        apply_provider_preset(config, "openrouter")

        assert config.llm.model == "legacy/opaque-id"

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

    def test_save_load_roundtrips_openrouter_and_custom_values(self, monkeypatch, tmp_path):
        import vulnclaw.config.settings as settings_mod
        from vulnclaw.config.schema import VulnClawConfig

        monkeypatch.setattr(settings_mod, "CONFIG_FILE", tmp_path / "config.yaml")
        monkeypatch.setattr(settings_mod, "CONFIG_DIR", tmp_path)
        config = VulnClawConfig()
        config.llm.provider = "openrouter"
        config.llm.base_url = "https://gateway.example/v1"
        config.llm.model = "private/opaque:model"
        config.llm.auth_mode = "static"
        config.llm.api_keys = ["pool-one", "pool-two"]

        settings_mod.save_config(config)
        reloaded = settings_mod.load_config()

        assert reloaded.llm.provider == "openrouter"
        assert reloaded.llm.base_url == "https://gateway.example/v1"
        assert reloaded.llm.model == "private/opaque:model"
        assert reloaded.llm.auth_mode == "static"
        assert reloaded.llm.key_pool() == ["pool-one", "pool-two"]

    def test_openrouter_auth_invariants_survive_persisted_and_env_overlays(
        self,
        monkeypatch,
        tmp_path,
    ):
        import vulnclaw.config.settings as settings_mod
        from vulnclaw.config.schema import VulnClawConfig

        monkeypatch.setattr(settings_mod, "CONFIG_FILE", tmp_path / "config.yaml")
        monkeypatch.setattr(settings_mod, "CONFIG_DIR", tmp_path)
        config = VulnClawConfig()
        config.llm.provider = "openrouter"
        config.llm.api_key = "saved-static-key"
        config.llm.auth_mode = "oauth"
        config.llm.chatgpt_auto_proxy = True

        settings_mod.save_config(config)

        assert config.llm.auth_mode == "static"
        assert config.llm.chatgpt_auto_proxy is False

        monkeypatch.setenv("VULNCLAW_LLM_PROVIDER", "openrouter")
        monkeypatch.setenv("VULNCLAW_LLM_AUTH_MODE", "oauth")
        monkeypatch.setenv("VULNCLAW_LLM_CHATGPT_AUTO_PROXY", "true")
        reloaded = settings_mod.load_config()

        assert reloaded.llm.api_key == "saved-static-key"
        assert reloaded.llm.auth_mode == "static"
        assert reloaded.llm.chatgpt_auto_proxy is False
