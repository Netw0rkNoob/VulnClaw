"""Config service for the Web UI backend."""

from __future__ import annotations

from pathlib import Path

from vulnclaw.config.settings import apply_provider_preset, load_config, save_config
from vulnclaw.web.schemas import ConfigUpdateRequest, ConfigView


def get_public_config() -> ConfigView:
    """Return a safe-to-display subset of configuration."""
    config = load_config()
    # `language` is a plain str in the on-disk config; clamp anything unexpected
    # to "auto" so a hand-edited value can't 500 the whole config endpoint.
    language = config.session.language if config.session.language in ("auto", "zh", "en") else "auto"
    return ConfigView(
        provider=config.llm.provider,
        model=config.llm.model,
        base_url=config.llm.base_url,
        api_key_configured=bool(config.llm.api_key),
        language=language,
        output_dir=str(config.session.output_dir),
        max_rounds=config.session.max_rounds,
        max_context_tokens=config.llm.max_context_tokens,
        context_auto_compact=config.session.context_auto_compact,
        context_compact_trigger_ratio=config.session.context_compact_trigger_ratio,
        context_compact_target_ratio=config.session.context_compact_target_ratio,
        context_recent_message_groups=config.session.context_recent_message_groups,
        context_summary_max_tokens=config.session.context_summary_max_tokens,
        context_output_reserve_tokens=config.session.context_output_reserve_tokens,
        context_compaction_mode=config.session.context_compaction_mode,
        context_compaction_audit_enabled=config.session.context_compaction_audit_enabled,
        persistent_rounds_per_cycle=config.session.persistent_rounds_per_cycle,
        persistent_max_cycles=config.session.persistent_max_cycles,
        show_thinking=config.session.show_thinking,
        poc_verify_enabled=config.session.poc_verify_enabled,
        python_execute_enabled=config.safety.enable_python_execute,
        python_execute_mode=config.safety.python_execute_mode,
        python_execute_max_lines=config.safety.python_execute_max_lines,
        python_execute_audit_enabled=config.safety.python_execute_audit_enabled,
    )


def update_public_config(payload: ConfigUpdateRequest) -> ConfigView:
    """Update a safe subset of config values and return the latest public config."""
    config = load_config()

    if payload.provider is not None:
        config = apply_provider_preset(config, payload.provider)
    if payload.model is not None:
        config.llm.model = payload.model
    if payload.base_url is not None:
        config.llm.base_url = payload.base_url
    if payload.language is not None:
        config.session.language = payload.language
    if payload.output_dir is not None:
        config.session.output_dir = Path(payload.output_dir)
    if payload.max_rounds is not None:
        config.session.max_rounds = payload.max_rounds
    if payload.max_context_tokens is not None:
        config.llm.max_context_tokens = payload.max_context_tokens
    if payload.context_auto_compact is not None:
        config.session.context_auto_compact = payload.context_auto_compact
    if payload.context_compact_trigger_ratio is not None:
        config.session.context_compact_trigger_ratio = payload.context_compact_trigger_ratio
    if payload.context_compact_target_ratio is not None:
        config.session.context_compact_target_ratio = payload.context_compact_target_ratio
    if payload.context_recent_message_groups is not None:
        config.session.context_recent_message_groups = payload.context_recent_message_groups
    if payload.context_summary_max_tokens is not None:
        config.session.context_summary_max_tokens = payload.context_summary_max_tokens
    if payload.context_output_reserve_tokens is not None:
        config.session.context_output_reserve_tokens = payload.context_output_reserve_tokens
    if payload.context_compaction_mode is not None:
        config.session.context_compaction_mode = payload.context_compaction_mode
    if payload.context_compaction_audit_enabled is not None:
        config.session.context_compaction_audit_enabled = payload.context_compaction_audit_enabled
    if payload.persistent_rounds_per_cycle is not None:
        config.session.persistent_rounds_per_cycle = payload.persistent_rounds_per_cycle
    if payload.persistent_max_cycles is not None:
        config.session.persistent_max_cycles = payload.persistent_max_cycles
    if payload.show_thinking is not None:
        config.session.show_thinking = payload.show_thinking
    if payload.poc_verify_enabled is not None:
        config.session.poc_verify_enabled = payload.poc_verify_enabled
    if payload.python_execute_enabled is not None:
        config.safety.enable_python_execute = payload.python_execute_enabled
    if payload.python_execute_mode is not None:
        config.safety.python_execute_mode = payload.python_execute_mode
    if payload.python_execute_max_lines is not None:
        config.safety.python_execute_max_lines = payload.python_execute_max_lines
    if payload.python_execute_audit_enabled is not None:
        config.safety.python_execute_audit_enabled = payload.python_execute_audit_enabled

    save_config(config)
    return get_public_config()
