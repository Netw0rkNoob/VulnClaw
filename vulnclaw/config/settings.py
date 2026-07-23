"""VulnClaw configuration management — load, save, and access settings."""

from __future__ import annotations

import json
import logging
import os
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import ValidationError

from .schema import (
    BUILTIN_MCP_SERVERS,
    PROVIDER_PRESETS,
    LLMProvider,
    MCPServerConfig,
    MCPServersConfig,
    MCPTransportConfig,
    VulnClawConfig,
    normalize_llm_model_id,
)

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────

CONFIG_DIR = Path(os.environ.get("VULNCLAW_CONFIG_DIR", str(Path.home() / ".vulnclaw")))
CONFIG_FILE = CONFIG_DIR / "config.yaml"
SESSIONS_DIR = CONFIG_DIR / "sessions"
TARGETS_DIR = CONFIG_DIR / "targets"
RUNS_DIR = CONFIG_DIR / "runs"
KB_DIR = CONFIG_DIR / "kb"
SKILLS_DIR = CONFIG_DIR / "skills"
WEB_TASKS_FILE = CONFIG_DIR / "web_tasks.json"
PYTHON_EXECUTE_AUDIT_FILE = CONFIG_DIR / "python_execute_audit.jsonl"
DEFAULT_OPENAI_USER_AGENT = "Mozilla/5.0"
OPENROUTER_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
OPENROUTER_MAX_SOURCE_MODELS = 5000
OPENROUTER_MAX_RETAINED_MODELS = 500
OPENROUTER_REQUIRED_PARAMETERS = frozenset({"tools", "max_tokens", "temperature"})


class ProviderModelDiscoveryStatus(str, Enum):
    """Stable, non-secret model-discovery outcome codes."""

    OK = "ok"
    MISSING_KEY = "missing_key"
    UNTRUSTED_URL = "untrusted_url"
    AUTHENTICATION_FAILED = "authentication_failed"
    TIMEOUT = "timeout"
    MALFORMED_RESPONSE = "malformed_response"
    RESPONSE_TOO_LARGE = "response_too_large"
    EMPTY_CATALOG = "empty_catalog"
    REDIRECT_BLOCKED = "redirect_blocked"
    UPSTREAM_ERROR = "upstream_error"


@dataclass(frozen=True)
class ProviderModelDiscoveryResult:
    """Models plus a safe status suitable for CLI, TUI, and Web callers."""

    models: list[str]
    status: ProviderModelDiscoveryStatus
    detail: str = ""


def ensure_dirs() -> None:
    """Create VulnClaw config directories if they don't exist."""
    for d in [CONFIG_DIR, SESSIONS_DIR, TARGETS_DIR, RUNS_DIR, KB_DIR, SKILLS_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def openai_default_headers() -> dict[str, str]:
    return {"User-Agent": os.environ.get("VULNCLAW_LLM_USER_AGENT", DEFAULT_OPENAI_USER_AGENT)}


def make_openai_client(api_key: str, base_url: str, timeout: float | None = None):
    from openai import OpenAI

    kwargs: dict[str, Any] = {
        "api_key": api_key,
        "base_url": base_url,
        "default_headers": openai_default_headers(),
    }
    if timeout is not None:
        kwargs["timeout"] = timeout
    return OpenAI(**kwargs)


# ── Load / Save ────────────────────────────────────────────────────


def _enforce_provider_auth_invariants(
    config: VulnClawConfig,
) -> VulnClawConfig:
    """Keep provider-specific credential boundaries safe after every overlay."""

    if str(config.llm.provider or "").strip().lower() == LLMProvider.OPENROUTER.value:
        config.llm.auth_mode = "static"
        config.llm.chatgpt_auto_proxy = False
    return config


def load_config() -> VulnClawConfig:
    """Load configuration from file + env vars.

    Priority: env vars > config file > built-in defaults.
    """
    ensure_dirs()

    # Start with built-in defaults + registered MCP servers
    servers: dict[str, MCPServerConfig] = {}
    for name, cfg in BUILTIN_MCP_SERVERS.items():
        servers[name] = _parse_mcp_server(name, cfg)

    config = VulnClawConfig(mcp=MCPServersConfig(servers=servers))

    # Overlay from config file
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            config = _merge_config(config, raw)
        except (yaml.YAMLError, ValidationError) as e:
            # Log warning but don't crash
            logger.warning("Failed to parse config file %s: %s", CONFIG_FILE, e)

    # Overlay from env vars
    config = _overlay_env(config)

    return _enforce_provider_auth_invariants(config)


def save_config(config: VulnClawConfig) -> None:
    """Save configuration to YAML file."""
    ensure_dirs()
    _enforce_provider_auth_invariants(config)
    raw = config.model_dump(mode="json")
    # Remove default values to keep config clean
    _strip_defaults(raw)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        yaml.dump(raw, f, default_flow_style=False, allow_unicode=True)


def set_config_value(key: str, value: str) -> None:
    """Set a nested config value using dot notation.

    Example: set_config_value("llm.api_key", "sk-xxx")

    Supports traversal through both Pydantic model attributes *and* plain dict
    nodes (e.g. ``mcp.servers.chrome-devtools.enabled``).
    """
    config = load_config()
    parts = key.split(".")
    obj: Any = config
    for part in parts[:-1]:
        obj = obj[part] if isinstance(obj, dict) else getattr(obj, part)
    field_name = parts[-1]

    if isinstance(obj, dict):
        # Dict node — infer type from the existing value if present
        existing = obj.get(field_name)
        if isinstance(existing, bool):
            value = value.lower() in ("true", "1", "yes")
        elif isinstance(existing, int):
            value = int(value)
        elif isinstance(existing, float):
            value = float(value)
        obj[field_name] = value
    else:
        # Pydantic model node — use field annotation for type coercion
        model_fields = getattr(type(obj), "model_fields", {})
        if field_name in model_fields:
            field_info = model_fields[field_name]
            annotation = field_info.annotation
            if annotation is int:
                value = int(value)
            elif annotation is float:
                value = float(value)
            elif annotation is bool:
                value = value.lower() in ("true", "1", "yes")
            elif getattr(annotation, "__origin__", None) is list:
                # Accept a list as-is, or split a comma/newline-separated string.
                if isinstance(value, str):
                    value = [p.strip() for p in value.replace("\n", ",").split(",") if p.strip()]
                else:
                    value = list(value)
        setattr(obj, field_name, value)
    save_config(config)


# ── Helpers ─────────────────────────────────────────────────────────


def _parse_mcp_server(name: str, raw: dict[str, Any]) -> MCPServerConfig:
    """Parse a raw dict into MCPServerConfig."""
    transport_raw = raw.get("transport", {})
    return MCPServerConfig(
        name=raw.get("name", name),
        enabled=raw.get("enabled", True),
        priority=raw.get("priority", 1),
        description=raw.get("description", ""),
        transport=MCPTransportConfig(
            type=transport_raw.get("type", "stdio"),
            command=transport_raw.get("command"),
            args=transport_raw.get("args"),
            url=transport_raw.get("url"),
            env=transport_raw.get("env"),
            startup_timeout=transport_raw.get("startup_timeout", 30000),
            tool_timeout=transport_raw.get("tool_timeout", 300000),
        ),
    )


def _merge_config(base: VulnClawConfig, raw: dict[str, Any]) -> VulnClawConfig:
    """Merge raw dict into existing config, preserving unset defaults."""
    data = base.model_dump(mode="json")

    # Deep merge
    _deep_merge(data, raw)
    _repair_merged_model_id(data, base)

    try:
        return VulnClawConfig(**data)
    except ValidationError:
        # If merged data is invalid, return base
        return base


def _repair_merged_model_id(
    data: dict[str, Any],
    base: VulnClawConfig,
) -> None:
    """Repair only an invalid persisted Model ID without dropping other config."""
    llm_data = data.get("llm")
    if not isinstance(llm_data, dict):
        return

    raw_model = llm_data.get("model")
    if isinstance(raw_model, str):
        try:
            llm_data["model"] = normalize_llm_model_id(raw_model)
            return
        except ValueError:
            pass

    provider_name = str(llm_data.get("provider") or "").strip().lower()
    try:
        provider = LLMProvider(provider_name)
    except ValueError:
        provider = None
    preset = PROVIDER_PRESETS.get(provider) if provider is not None else None
    fallback = str((preset or {}).get("default_model") or base.llm.model)
    llm_data["model"] = normalize_llm_model_id(fallback)


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base (mutates base)."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


def _overlay_env(config: VulnClawConfig) -> VulnClawConfig:
    """Overlay environment variables onto config.

    Supported env vars (prefix VULNCLAW_):
        LLM:        API_KEY, BASE_URL, MODEL, PROVIDER, MAX_TOKENS, MAX_CONTEXT_TOKENS, TEMPERATURE
        Session:    OUTPUT_DIR, AUTO_SAVE, REPORT_FORMAT, MAX_ROUNDS, SHOW_THINKING
        Safety:     PYTHON_EXECUTE_ENABLED, PYTHON_EXECUTE_RESTRICTED, PYTHON_EXECUTE_MODE,
                    PYTHON_EXECUTE_MAX_LINES, PYTHON_EXECUTE_SHOW_WARNING,
                    PYTHON_EXECUTE_MAX_OUTPUT_CHARS, PYTHON_EXECUTE_AUDIT_ENABLED
    """
    # ── LLM ──────────────────────────────────────────────────────────
    if v := os.environ.get("VULNCLAW_LLM_API_KEY"):
        config.llm.api_key = v
    if v := os.environ.get("VULNCLAW_LLM_API_KEYS"):
        keys = [k.strip() for k in v.split(",") if k.strip()]
        if keys:
            config.llm.api_keys = keys
    if v := os.environ.get("VULNCLAW_LLM_BASE_URL"):
        config.llm.base_url = v
    if v := os.environ.get("VULNCLAW_LLM_MODEL"):
        with suppress(ValueError):
            config.llm.model = normalize_llm_model_id(v)
    if v := os.environ.get("VULNCLAW_LLM_PROVIDER"):
        config.llm.provider = v
    if v := os.environ.get("VULNCLAW_LLM_MAX_TOKENS"):
        with suppress(ValueError):
            config.llm.max_tokens = int(v)
    if v := os.environ.get("VULNCLAW_LLM_MAX_CONTEXT_TOKENS"):
        with suppress(ValueError):
            config.llm.max_context_tokens = int(v)
    if v := os.environ.get("VULNCLAW_LLM_TEMPERATURE"):
        with suppress(ValueError):
            config.llm.temperature = float(v)

    # ── LLM auth mode (static / oauth) ──────────────────────────────────
    if v := os.environ.get("VULNCLAW_LLM_AUTH_MODE"):
        config.llm.auth_mode = v
    if v := os.environ.get("VULNCLAW_LLM_CHATGPT_AUTO_PROXY"):
        config.llm.chatgpt_auto_proxy = v.lower() in ("1", "true", "yes", "on")

    # ── Session ──────────────────────────────────────────────────────
    if v := os.environ.get("VULNCLAW_SESSION_OUTPUT_DIR"):
        config.session.output_dir = Path(v)
    if v := os.environ.get("VULNCLAW_RUNS_DIR"):
        config.session.runs_dir = Path(v)
    if v := os.environ.get("VULNCLAW_SESSION_RUNS_DIR"):
        config.session.runs_dir = Path(v)
    if v := os.environ.get("VULNCLAW_SESSION_AUTO_SAVE"):
        config.session.auto_save = v.lower() in ("1", "true", "yes", "on")
    if v := os.environ.get("VULNCLAW_SESSION_REPORT_FORMAT"):
        config.session.report_format = v
    if v := os.environ.get("VULNCLAW_SESSION_MAX_ROUNDS"):
        with suppress(ValueError):
            config.session.max_rounds = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_SHOW_THINKING"):
        config.session.show_thinking = v.lower() in ("1", "true", "yes", "on")
    if v := os.environ.get("VULNCLAW_SESSION_REPL_PARALLEL_ENABLED"):
        config.session.repl_parallel_enabled = v.lower() in ("1", "true", "yes", "on")
    if v := os.environ.get("VULNCLAW_SESSION_REPL_PARALLEL_AGENTS"):
        with suppress(ValueError):
            config.session.repl_parallel_agents = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_REPL_PARALLEL_DEPTH"):
        with suppress(ValueError):
            config.session.repl_parallel_depth = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_REPL_PARALLEL_WORKER_ROUNDS"):
        with suppress(ValueError):
            config.session.repl_parallel_worker_rounds = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_REPL_PARALLEL_SURFACE_LIMIT"):
        with suppress(ValueError):
            config.session.repl_parallel_surface_limit = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_STALE_ROUNDS_THRESHOLD"):
        with suppress(ValueError):
            config.session.stale_rounds_threshold = int(v)

    # ── Session: 推理状态 / 反思引擎 / 插件运行时 ──────────────
    _truthy = ("1", "true", "yes", "on")
    if v := os.environ.get("VULNCLAW_SESSION_REASONING_STATE_ENABLED"):
        config.session.reasoning_state_enabled = v.lower() in _truthy
    if v := os.environ.get("VULNCLAW_SESSION_REFLEXION_ENABLED"):
        config.session.reflexion_enabled = v.lower() in _truthy
    if v := os.environ.get("VULNCLAW_SESSION_REFLEXION_MAX_SAME_VULN_FAILS"):
        with suppress(ValueError):
            config.session.reflexion_max_same_vuln_fails = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_REFLEXION_MAX_TOTAL_NO_PROGRESS"):
        with suppress(ValueError):
            config.session.reflexion_max_total_no_progress = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_ESCALATION_MAX_LEVEL"):
        with suppress(ValueError):
            config.session.escalation_max_level = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_PLUGIN_RUNTIME_ENABLED"):
        config.session.plugin_runtime_enabled = v.lower() in _truthy
    if v := os.environ.get("VULNCLAW_SESSION_PLUGIN_DEFAULT_TIMEOUT"):
        with suppress(ValueError):
            config.session.plugin_default_timeout = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_PLUGIN_MAX_REQUESTS_PER_TARGET"):
        with suppress(ValueError):
            config.session.plugin_max_requests_per_target = int(v)
    if v := os.environ.get("VULNCLAW_SESSION_EVIDENCE_MIN_REPORT_LEVEL"):
        config.session.evidence_min_report_level = v

    # ── Safety ───────────────────────────────────────────────────────
    if v := os.environ.get("VULNCLAW_SAFETY_PYTHON_EXECUTE_ENABLED"):
        config.safety.enable_python_execute = v.lower() in ("1", "true", "yes", "on")
    if v := os.environ.get("VULNCLAW_SAFETY_PYTHON_EXECUTE_RESTRICTED"):
        config.safety.python_execute_restricted = v.lower() in ("1", "true", "yes", "on")
    if v := os.environ.get("VULNCLAW_SAFETY_PYTHON_EXECUTE_MODE"):
        config.safety.python_execute_mode = v
    if v := os.environ.get("VULNCLAW_SAFETY_PYTHON_EXECUTE_MAX_LINES"):
        with suppress(ValueError):
            config.safety.python_execute_max_lines = int(v)
    if v := os.environ.get("VULNCLAW_SAFETY_PYTHON_EXECUTE_SHOW_WARNING"):
        config.safety.python_execute_show_warning = v.lower() in ("1", "true", "yes", "on")
    if v := os.environ.get("VULNCLAW_SAFETY_PYTHON_EXECUTE_MAX_OUTPUT_CHARS"):
        with suppress(ValueError):
            config.safety.python_execute_max_output_chars = int(v)
    if v := os.environ.get("VULNCLAW_SAFETY_PYTHON_EXECUTE_AUDIT_ENABLED"):
        config.safety.python_execute_audit_enabled = v.lower() in ("1", "true", "yes", "on")

    # ── Recon: space-mapping API keys ────────────────────────────────
    # Accept both the short form (FOFA_KEY) and the prefixed form
    # (VULNCLAW_RECON_FOFA_KEY); short form wins if both are set.
    for field, names in {
        "fofa_email": ("FOFA_EMAIL", "VULNCLAW_RECON_FOFA_EMAIL"),
        "fofa_key": ("FOFA_KEY", "VULNCLAW_RECON_FOFA_KEY"),
        "hunter_key": ("HUNTER_KEY", "VULNCLAW_RECON_HUNTER_KEY"),
        "quake_key": ("QUAKE_KEY", "VULNCLAW_RECON_QUAKE_KEY"),
        "zoomeye_key": ("ZOOMEYE_KEY", "VULNCLAW_RECON_ZOOMEYE_KEY"),
        "shodan_key": ("SHODAN_KEY", "VULNCLAW_RECON_SHODAN_KEY"),
        "zerozone_key": ("ZEROZONE_KEY", "VULNCLAW_RECON_ZEROZONE_KEY"),
    }.items():
        for env_name in names:
            if v := os.environ.get(env_name):
                setattr(config.recon, field, v)
                break

    return config


def _strip_defaults(raw: dict) -> None:
    """Remove fields that match defaults to keep config file clean."""
    # Keep it simple — just strip known default values
    if raw.get("llm", {}).get("api_key") == "":
        raw["llm"].pop("api_key", None)
    if raw.get("llm", {}).get("api_keys") == []:
        raw["llm"].pop("api_keys", None)
    # Don't strip base_url/model if provider is set — they may be provider-specific
    # Only strip if still at OpenAI defaults
    if raw.get("llm", {}).get("provider") == "openai":
        if raw.get("llm", {}).get("base_url") == "https://api.openai.com/v1":
            raw["llm"].pop("base_url", None)
        if raw.get("llm", {}).get("model") == "gpt-4o":
            raw["llm"].pop("model", None)


# ── Provider Management ─────────────────────────────────────────────


def apply_provider_preset(config: VulnClawConfig, provider_name: str) -> VulnClawConfig:
    """Apply a provider preset, auto-filling base_url and model.

    Only fills fields that haven't been explicitly changed from the previous
    provider's defaults. This way, if the user manually set a model, we don't
    overwrite it unless the provider itself changed.
    """
    # Resolve provider enum
    normalized_provider = provider_name.strip().lower()
    try:
        provider = LLMProvider(normalized_provider)
    except ValueError:
        # Unknown provider — treat as custom, don't auto-fill
        config.llm.provider = provider_name
        return config

    preset = PROVIDER_PRESETS.get(provider)
    if not preset:
        return config

    old_provider = str(config.llm.provider or "").strip().lower()
    old_model = str(config.llm.model or "")
    config.llm.provider = provider.value

    # Auto-fill base_url and model only when switching providers
    # (or when they still match the old provider's defaults)
    try:
        old_provider_enum = LLMProvider(old_provider) if old_provider else None
    except ValueError:
        old_provider_enum = None
    old_preset = PROVIDER_PRESETS.get(old_provider_enum) if old_provider_enum else None

    # Fill base_url: always fill from preset on provider switch
    if preset.get("base_url"):
        config.llm.base_url = preset["base_url"]

    # Fill the model only when blank or still on the previous preset default.
    old_default = str((old_preset or {}).get("default_model", ""))
    if preset.get("default_model") and (not old_model.strip() or old_model == old_default):
        config.llm.model = preset["default_model"]

    # Stored OAuth metadata is left untouched, but provider credential
    # invariants are enforced even when callers bypass normal UI flows.
    return _enforce_provider_auth_invariants(config)


def list_providers() -> list[dict[str, str]]:
    """Return all available provider presets as a list of dicts."""
    result = []
    for provider, preset in PROVIDER_PRESETS.items():
        result.append(
            {
                "provider": provider.value,
                "label": preset.get("label", provider.value),
                "base_url": preset.get("base_url", ""),
                "default_model": preset.get("default_model", ""),
            }
        )
    return result


def _discovery_result(
    status: ProviderModelDiscoveryStatus,
    detail: str,
    models: list[str] | None = None,
) -> ProviderModelDiscoveryResult:
    return ProviderModelDiscoveryResult(models=models or [], status=status, detail=detail)


def _is_explicitly_expired(record: dict[str, Any]) -> bool:
    if record.get("expired") is True:
        return True

    raw_expiry = record.get("expiration_date", record.get("expires_at"))
    if raw_expiry in (None, "", False):
        return False
    if isinstance(raw_expiry, bool):
        return raw_expiry

    try:
        if isinstance(raw_expiry, (int, float)):
            timestamp = float(raw_expiry)
            if timestamp > 10_000_000_000:
                timestamp /= 1000
            expiry = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        elif isinstance(raw_expiry, str):
            normalized = raw_expiry.strip().replace("Z", "+00:00")
            expiry = datetime.fromisoformat(normalized)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        else:
            return False
    except (OverflowError, OSError, ValueError):
        return False

    return expiry <= datetime.now(timezone.utc)


def _filter_openrouter_models(records: list[Any]) -> list[str]:
    compatible: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue

        raw_id = record.get("id")
        if not isinstance(raw_id, str):
            continue
        try:
            model_id = normalize_llm_model_id(raw_id)
        except ValueError:
            continue

        architecture = record.get("architecture")
        if not isinstance(architecture, dict):
            continue
        output_modalities = architecture.get("output_modalities")
        if not isinstance(output_modalities, list) or "text" not in output_modalities:
            continue

        supported_parameters = record.get("supported_parameters")
        if not isinstance(supported_parameters, list):
            continue
        if not OPENROUTER_REQUIRED_PARAMETERS.issubset(
            {value for value in supported_parameters if isinstance(value, str)}
        ):
            continue
        if _is_explicitly_expired(record):
            continue

        compatible.add(model_id)

    default_model = str(PROVIDER_PRESETS[LLMProvider.OPENROUTER]["default_model"])
    ordered = sorted(compatible, key=lambda value: (value.casefold(), value))
    if default_model in compatible:
        ordered.remove(default_model)
        ordered.insert(0, default_model)
    return ordered[:OPENROUTER_MAX_RETAINED_MODELS]


def _discover_openrouter_models(
    base_url: str,
    api_key: str,
    timeout: float,
) -> ProviderModelDiscoveryResult:
    endpoint = f"{base_url.strip().rstrip('/')}/models/user"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
        **openai_default_headers(),
    }

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            with client.stream("GET", endpoint, headers=headers) as response:
                if response.is_redirect:
                    return _discovery_result(
                        ProviderModelDiscoveryStatus.REDIRECT_BLOCKED,
                        "The provider redirected model discovery; redirects are not followed.",
                    )
                if response.status_code == 401:
                    return _discovery_result(
                        ProviderModelDiscoveryStatus.AUTHENTICATION_FAILED,
                        "OpenRouter rejected the saved inference key.",
                    )
                if response.status_code >= 400:
                    return _discovery_result(
                        ProviderModelDiscoveryStatus.UPSTREAM_ERROR,
                        f"OpenRouter model discovery failed with HTTP {response.status_code}.",
                    )

                content_type = response.headers.get("content-type", "")
                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type != "application/json" and not media_type.endswith("+json"):
                    return _discovery_result(
                        ProviderModelDiscoveryStatus.MALFORMED_RESPONSE,
                        "OpenRouter returned a non-JSON model catalog.",
                    )

                content_length = response.headers.get("content-length")
                if content_length:
                    with suppress(ValueError):
                        if int(content_length) > OPENROUTER_MAX_RESPONSE_BYTES:
                            return _discovery_result(
                                ProviderModelDiscoveryStatus.RESPONSE_TOO_LARGE,
                                "OpenRouter returned a model catalog larger than the safety limit.",
                            )

                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > OPENROUTER_MAX_RESPONSE_BYTES:
                        return _discovery_result(
                            ProviderModelDiscoveryStatus.RESPONSE_TOO_LARGE,
                            "OpenRouter returned a model catalog larger than the safety limit.",
                        )
    except httpx.TimeoutException:
        return _discovery_result(
            ProviderModelDiscoveryStatus.TIMEOUT,
            "OpenRouter model discovery timed out.",
        )
    except httpx.RequestError:
        return _discovery_result(
            ProviderModelDiscoveryStatus.UPSTREAM_ERROR,
            "OpenRouter model discovery could not reach the configured endpoint.",
        )

    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return _discovery_result(
            ProviderModelDiscoveryStatus.MALFORMED_RESPONSE,
            "OpenRouter returned malformed model catalog data.",
        )

    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return _discovery_result(
            ProviderModelDiscoveryStatus.MALFORMED_RESPONSE,
            "OpenRouter returned an unexpected model catalog shape.",
        )
    records = payload["data"]
    if len(records) > OPENROUTER_MAX_SOURCE_MODELS:
        return _discovery_result(
            ProviderModelDiscoveryStatus.RESPONSE_TOO_LARGE,
            "OpenRouter returned more source models than the safety limit.",
        )

    models = _filter_openrouter_models(records)
    if not models:
        return _discovery_result(
            ProviderModelDiscoveryStatus.EMPTY_CATALOG,
            "OpenRouter returned no models compatible with VulnClaw's request contract.",
        )
    return _discovery_result(
        ProviderModelDiscoveryStatus.OK,
        f"Loaded {len(models)} compatible OpenRouter models.",
        models,
    )


def discover_provider_models(
    base_url: str,
    api_key: str,
    timeout: float = 10.0,
    *,
    provider: str | None = None,
) -> ProviderModelDiscoveryResult:
    """Fetch provider models with a typed, sanitized outcome."""
    if not api_key:
        return _discovery_result(
            ProviderModelDiscoveryStatus.MISSING_KEY,
            "No API key is configured for model discovery.",
        )
    if not base_url:
        return _discovery_result(
            ProviderModelDiscoveryStatus.UPSTREAM_ERROR,
            "No provider base URL is configured.",
        )
    if str(provider or "").strip().lower() == LLMProvider.OPENROUTER.value:
        return _discover_openrouter_models(base_url, api_key, timeout)

    try:
        client = make_openai_client(api_key=api_key, base_url=base_url, timeout=timeout)
        models_page = client.models.list()
        model_ids = sorted(
            m.id for m in models_page if getattr(m, "id", "")
        )
    except Exception:
        return _discovery_result(
            ProviderModelDiscoveryStatus.UPSTREAM_ERROR,
            "The provider model catalog could not be loaded.",
        )
    if not model_ids:
        return _discovery_result(
            ProviderModelDiscoveryStatus.EMPTY_CATALOG,
            "The provider returned no models.",
        )
    return _discovery_result(
        ProviderModelDiscoveryStatus.OK,
        f"Loaded {len(model_ids)} provider models.",
        model_ids,
    )


def fetch_provider_models(
    base_url: str,
    api_key: str,
    timeout: float = 10.0,
    *,
    provider: str | None = None,
) -> list[str]:
    """Compatibility wrapper returning only discovered Model IDs."""
    return discover_provider_models(
        base_url,
        api_key,
        timeout,
        provider=provider,
    ).models


def fetch_provider_models_async(
    base_url: str,
    api_key: str,
    timeout: float = 10.0,
    on_result: Any = None,
    *,
    provider: str | None = None,
):
    """Fetch provider models in a background thread.

    Calls ``fetch_provider_models()`` in a daemon thread.  When the
    fetch completes, *on_result* (if provided) is called with the
    model list on the **calling** thread via ``app.call_later()``-style
    scheduling — the caller is responsible for arranging thread-safe
    delivery (e.g. by passing a lambda that uses ``call_later``).

    Returns the ``Thread`` object so callers can track or join it.
    """
    import threading

    def _worker() -> None:
        models = fetch_provider_models(base_url, api_key, timeout, provider=provider)
        if on_result is not None:
            on_result(models)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t
