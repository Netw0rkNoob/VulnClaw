"""VulnClaw configuration schema — Pydantic models for type-safe config."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

# ── LLM Provider Presets ────────────────────────────────────────────


class LLMProvider(str, Enum):
    """Supported LLM providers with OpenAI-compatible APIs."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    MINIMAX = "minimax"
    DEEPSEEK = "deepseek"
    ZHIPU = "zhipu"
    MOONSHOT = "moonshot"
    QWEN = "qwen"
    SILICONFLOW = "siliconflow"
    DOUBAO = "doubao"
    BAICHUAN = "baichuan"
    STEPFUN = "stepfun"
    SENSETIME = "sensetime"
    YI = "yi"
    CUSTOM = "custom"


# Provider preset definitions: base_url + default_model + notes
PROVIDER_PRESETS: dict[LLMProvider, dict[str, str]] = {
    LLMProvider.OPENAI: {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "label": "OpenAI",
    },
    LLMProvider.ANTHROPIC: {
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-sonnet-5",
        "label": "Anthropic Claude",
    },
    LLMProvider.MINIMAX: {
        "base_url": "https://api.minimaxi.com/v1",
        "default_model": "MiniMax-M3",
        "label": "MiniMax",
    },
    LLMProvider.DEEPSEEK: {
        "base_url": "https://api.deepseek.com",
        "default_model": "deepseek-v4-pro",
        "label": "DeepSeek",
    },
    LLMProvider.ZHIPU: {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-4.7",
        "label": "智谱 GLM",
    },
    LLMProvider.MOONSHOT: {
        "base_url": "https://api.moonshot.cn/v1",
        "default_model": "kimi-k2.6",
        "label": "Kimi (月之暗面)",
    },
    LLMProvider.QWEN: {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "default_model": "qwen3-max",
        "label": "通义千问",
    },
    LLMProvider.SILICONFLOW: {
        "base_url": "https://api.siliconflow.cn/v1",
        "default_model": "deepseek-ai/DeepSeek-V4-Flash",
        "label": "SiliconFlow",
    },
    LLMProvider.DOUBAO: {
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "default_model": "Doubao-Seed-2.0-Pro",
        "label": "豆包 (字节跳动)",
    },
    LLMProvider.BAICHUAN: {
        "base_url": "https://api.baichuan-ai.com/v1",
        "default_model": "Baichuan4-Turbo",
        "label": "百川",
    },
    LLMProvider.STEPFUN: {
        "base_url": "https://api.stepfun.com/v1",
        "default_model": "step-3.5-flash",
        "label": "阶跃星辰",
    },
    LLMProvider.SENSETIME: {
        "base_url": "https://api.sensenova.cn/v1",
        "default_model": "SenseNova-6.7-Flash-Lite",
        "label": "商汤 (日日新)",
    },
    LLMProvider.YI: {
        "base_url": "https://api.lingyiwanwu.com/v1",
        "default_model": "yi-lightning",
        "label": "零一万物 (Yi)",
    },
    LLMProvider.CUSTOM: {
        "base_url": "",
        "default_model": "",
        "label": "自定义",
    },
}


class LLMConfig(BaseModel):
    """LLM provider configuration."""

    provider: str = Field(
        default="openai",
        description="LLM provider name (openai/anthropic/minimax/deepseek/zhipu/moonshot/qwen/siliconflow/doubao/baichuan/stepfun/sensetime/yi/custom)",
    )
    api_key: str = Field(default="", description="Static API key for the chosen provider (auth_mode=static)")
    api_keys: list[str] = Field(
        default_factory=list,
        description="Optional list of API keys to fail over between when one is "
        "rate-limited, out of quota, or invalid. Overrides api_key when non-empty.",
    )
    auth_mode: str = Field(
        default="static",
        description="Credential mode: static (api_key) or oauth (browser sign-in via `vulnclaw login`).",
    )
    # ── OAuth (auth_mode=oauth) ─────────────────────────────────────────
    # Tokens are obtained by `vulnclaw login` and refreshed silently. These two
    # endpoints are set automatically by the login flow.
    oauth_token_url: str = Field(
        default="", description="OAuth token endpoint (code/refresh exchange)"
    )
    oauth_client_id: str = Field(
        default="", description="OAuth client_id used for token exchange/refresh"
    )
    chatgpt_auto_proxy: bool = Field(
        default=False,
        description=(
            "When signed in with a ChatGPT subscription, auto-start a built-in "
            "local proxy that bridges chat.completions to the ChatGPT backend "
            "(no external proxy needed)."
        ),
    )
    base_url: str = Field(
        default="https://api.openai.com/v1",
        description="OpenAI-compatible API base URL (auto-filled by provider)",
    )
    model: str = Field(default="gpt-4o", description="Model name to use (auto-filled by provider)")
    max_tokens: int = Field(default=4096, description="Max tokens per response")
    max_context_tokens: int = Field(
        default=128000, description="Max context window tokens before sliding-window truncation"
    )
    temperature: float = Field(default=0.1, description="Sampling temperature")
    reasoning_effort: str = Field(
        default="high", description="Reasoning effort level (OpenAI o-series only)"
    )

    def key_pool(self) -> list[str]:
        """Return the ordered, de-blanked list of usable static API keys.

        Prefers ``api_keys`` when it has any non-empty entry; otherwise falls
        back to the single ``api_key``. Whitespace-only entries are dropped.
        """
        candidates = self.api_keys or ([self.api_key] if self.api_key else [])
        return [k.strip() for k in candidates if k and k.strip()]

    def primary_key(self) -> str:
        """Return the first usable static API key, or an empty string if none."""
        pool = self.key_pool()
        return pool[0] if pool else ""


class MCPTransportConfig(BaseModel):
    """MCP server transport configuration."""

    type: str = Field(description="Transport type: stdio, sse, streamable-http")
    command: str | None = Field(default=None, description="Command to start the server (stdio)")
    args: list[str] | None = Field(default=None, description="Command arguments")
    url: str | None = Field(default=None, description="Server URL (sse / streamable-http)")
    env: dict[str, str] | None = Field(
        default=None, description="Environment variables (stdio) / HTTP headers (streamable-http)"
    )
    startup_timeout: int = Field(default=30000, description="Startup timeout in ms")
    tool_timeout: int = Field(default=300000, description="Tool call timeout in ms")


class MCPServerConfig(BaseModel):
    """Single MCP server configuration."""

    name: str = Field(description="Server identifier")
    enabled: bool = Field(default=True, description="Whether to auto-start this server")
    priority: int = Field(default=1, description="Priority: 0=critical, 1=normal, 2=optional")
    transport: MCPTransportConfig = Field(description="Transport configuration")
    description: str = Field(default="", description="Human-readable description")


class MCPServersConfig(BaseModel):
    """All MCP servers configuration."""

    servers: dict[str, MCPServerConfig] = Field(default_factory=dict)


class ReconConfig(BaseModel):
    """Information-gathering configuration: space-mapping API keys + recon knobs.

    Keys are read here OR from environment variables (FOFA_KEY, HUNTER_KEY,
    QUAKE_KEY, ZOOMEYE_KEY, SHODAN_KEY, ZEROZONE_KEY) — never hard-coded. Put real
    keys in ~/.vulnclaw/config.yaml (gitignored), not in source.
    """

    fofa_email: str = Field(default="", description="FOFA account email")
    fofa_key: str = Field(default="", description="FOFA API key")
    hunter_key: str = Field(default="", description="Hunter (奇安信鹰图) API key")
    quake_key: str = Field(default="", description="Quake (360) API token")
    zoomeye_key: str = Field(default="", description="ZoomEye (钟馗之眼) API key")
    shodan_key: str = Field(default="", description="Shodan API key")
    zerozone_key: str = Field(default="", description="零零信安 0.zone API key")
    http_timeout: float = Field(default=15.0, description="Per-request HTTP timeout (s)")
    max_concurrency: int = Field(default=20, description="Max concurrent recon requests")
    space_size: int = Field(default=100, description="Default result size per space-mapping query")
    dir_wordlist_path: str = Field(
        default="", description="Optional path to a custom directory-bruteforce wordlist"
    )
    dir_max_requests: int = Field(
        default=1500, description="Hard cap on requests per directory-enumeration call"
    )
    js_max_files: int = Field(
        default=30, description="Max JavaScript files fetched per js_recon call"
    )


class SafetyConfig(BaseModel):
    """Safety / sandbox configuration."""

    enable_python_execute: bool = Field(
        default=True,
        description="Enable the python_execute built-in tool (disable for safer runs)",
    )
    python_execute_restricted: bool = Field(
        default=False,
        description="Restricted mode: block file I/O and network in python_execute",
    )
    python_execute_mode: str = Field(
        default="trusted-local",
        description="Execution mode for python_execute: safe, lab, trusted-local",
    )
    python_execute_max_lines: int = Field(
        default=50,
        description="Max lines of code allowed per python_execute call",
    )
    python_execute_show_warning: bool = Field(
        default=True,
        description="Show a security warning before each python_execute invocation",
    )
    python_execute_max_output_chars: int = Field(
        default=0,
        description="Max stdout/stderr characters returned from a python_execute call; 0 means unlimited",
    )
    python_execute_audit_enabled: bool = Field(
        default=True,
        description="Write python_execute audit records to the local config directory",
    )
    tool_parallel: bool = Field(
        default=True,
        description="Execute independent tool calls in a single LLM turn concurrently",
    )
    tool_max_concurrent: int = Field(
        default=5,
        description="Max number of tool calls executed concurrently per round (1=serial)",
    )


class SessionConfig(BaseModel):
    """Session / output configuration."""

    output_dir: Path = Field(default=Path("./vulnclaw-output"), description="Output directory")
    runs_dir: Path | None = Field(
        default=None,
        description="Default run-directory root (defaults to ~/.vulnclaw/runs when unset)",
    )
    auto_save: bool = Field(default=True, description="Auto-save session state")
    report_format: str = Field(
        default="markdown", description="Default report format: markdown, html"
    )
    poc_language: str = Field(default="python", description="Default PoC language: python, bash")
    max_rounds: int = Field(default=15, description="Max autonomous pentest rounds (1-100)")
    # Autonomous engine: "solve" = model-led agent loop with evidence memory (default),
    # "team" = role-specialized supervisor, "rounds" = legacy fixed-round loop.
    engine: str = Field(
        default="solve",
        description=(
            "Autonomous engine: solve (model-led/evidence-memory), "
            "team (role-specialized), or rounds (legacy)"
        ),
    )
    # Solve-engine knobs
    solve_max_steps: int = Field(
        default=240,
        description="Runaway safety cap for model-led solve turns; not a planned workflow length",
    )
    solve_max_directions: int = Field(
        default=3,
        description="Deprecated compatibility field; model-led solve no longer plans research directions",
        validation_alias=AliasChoices("solve_max_directions", "solve_max_intents"),
    )
    solve_max_tool_rounds: int = Field(
        default=6,
        description=(
            "Compatibility safety cap for consecutive internal tool-call follow-ups "
            "inside one model turn; not a planned workflow length"
        ),
    )
    solve_max_parallel: int = Field(
        default=1,
        description="Deprecated for model-led solve; retained for team/legacy integrations",
    )
    solve_auto_compact: bool = Field(
        default=False,
        description="Auto-compact solve memory before context overflow; otherwise compact only on /compact",
    )
    solve_compact_trigger_ratio: float = Field(
        default=0.9,
        description="Context-window ratio that may trigger auto compact when solve_auto_compact is enabled",
    )
    solve_auto_report: bool = Field(
        default=True,
        description="Automatically generate a markdown replay report when model-led solve completes",
    )
    solve_report_show: bool = Field(
        default=True,
        description="Print the generated solve replay report in the terminal after completion",
    )
    show_thinking: bool = Field(
        default=False, description="Show LLM thinking/reasoning output (default: off)"
    )
    repl_parallel_enabled: bool = Field(
        default=True,
        description="Use bounded child-agent fan-out by default for REPL auto-mode "
        "(legacy 'rounds' engine only; the 'solve' engine uses solve_max_parallel)",
    )
    repl_parallel_agents: int = Field(
        default=3,
        description="Default child-agent count for REPL auto-mode fan-out",
    )
    repl_parallel_depth: int = Field(
        default=1,
        description="Default child-agent discovery depth for REPL auto-mode fan-out",
    )
    repl_parallel_worker_rounds: int = Field(
        default=3,
        description="Max rounds per REPL parallel worker",
    )
    repl_parallel_surface_limit: int = Field(
        default=20,
        description="Maximum discovered surfaces considered by REPL parallel auto-mode",
    )

    # ── Persisted TUI scope state ──
    tui_scope_only_host: str = Field(default="", description="Persisted TUI only-host scope")
    tui_scope_only_port: str = Field(default="", description="Persisted TUI only-port scope")
    tui_scope_only_path: str = Field(default="", description="Persisted TUI only-path scope")
    tui_scope_blocked_host: str = Field(default="", description="Persisted TUI blocked-host scope")
    tui_scope_blocked_path: str = Field(default="", description="Persisted TUI blocked-path scope")
    tui_scope_allow_actions: str = Field(default="", description="Persisted TUI allowed actions (comma-sep)")
    tui_scope_block_actions: str = Field(default="", description="Persisted TUI blocked actions (comma-sep)")
    tui_scope_mode: str = Field(default="standard", description="Persisted TUI check mode")
    tui_scope_resume: bool = Field(default=True, description="Persisted TUI resume flag")

    model_config = ConfigDict(populate_by_name=True)

    @property
    def solve_max_intents(self) -> int:
        """Backward-compatible alias for pre-direction configuration files."""

        return self.solve_max_directions

    @solve_max_intents.setter
    def solve_max_intents(self, value: int) -> None:
        self.solve_max_directions = int(value)

    # Dead-loop detection
    stale_rounds_threshold: int = Field(
        default=5,
        description="Consecutive rounds without progress before dead-loop warning (1-50)",
    )
    # Persistent pentest configuration
    persistent_rounds_per_cycle: int = Field(
        default=100, description="Rounds per persistent pentest cycle"
    )
    persistent_max_cycles: int = Field(
        default=10, description="Max cycles for persistent pentest (0=unlimited)"
    )
    persistent_auto_report: bool = Field(
        default=True, description="Auto-generate report after each cycle"
    )
    # Language configuration
    language: str = Field(
        default="auto", description="UI language: auto, zh, en"
    )
    reasoning_state_enabled: bool = Field(
        default=True, description="Enable reasoning state tracking"
    )
    reflexion_enabled: bool = Field(
        default=True, description="Enable reflexion feedback loop"
    )
    reflexion_max_same_vuln_fails: int = Field(
        default=2, description="Max repeated failures for the same vulnerability"
    )
    reflexion_max_total_no_progress: int = Field(
        default=5, description="Max total rounds without progress before reflexion"
    )
    escalation_max_level: int = Field(
        default=4, description="Max escalation level"
    )
    plugin_runtime_enabled: bool = Field(
        default=True, description="Enable plugin runtime"
    )
    plugin_default_timeout: int = Field(
        default=10, description="Default plugin timeout in seconds"
    )
    plugin_max_requests_per_target: int = Field(
        default=30, description="Max plugin requests per target"
    )
    evidence_min_report_level: str = Field(
        default="L4", description="Minimum evidence level for report inclusion"
    )

class VulnClawConfig(BaseModel):
    """Top-level VulnClaw configuration."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    mcp: MCPServersConfig = Field(default_factory=MCPServersConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)

    model_config = ConfigDict(
        env_prefix="VULNCLAW_",
        env_nested_delimiter="__",
    )


# ── Built-in MCP server definitions (MVP) ──────────────────────────

BUILTIN_MCP_SERVERS: dict[str, dict[str, Any]] = {
    "fetch": {
        "name": "fetch",
        "enabled": True,
        "priority": 0,
        "description": "HTTP request tool for API testing & web interaction",
        "transport": {
            "type": "stdio",
            "command": "uvx",
            "args": ["mcp-server-fetch"],
        },
    },
    "memory": {
        "name": "memory",
        "enabled": True,
        "priority": 0,
        "description": "Context memory & session state persistence",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory"],
        },
    },
    "chrome-devtools": {
        "name": "chrome-devtools",
        "enabled": False,
        "priority": 0,
        "description": "Browser automation for Web app pentest",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "chrome-devtools-mcp@latest"],
        },
    },
    "burp": {
        "name": "burp",
        "enabled": False,
        "priority": 0,
        "description": "Burp Suite proxy integration for HTTP interception via SSE",
        "transport": {
            "type": "sse",
            "url": "http://127.0.0.1:9876",
        },
    },
}
