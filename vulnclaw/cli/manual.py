"""Full CLI manual rendering for VulnClaw."""

from __future__ import annotations

from vulnclaw import __version__
from vulnclaw.config.cli_constants import (
    ACTION_NAMES,
    COMMANDS,
    COMMON_TASK_FLAGS,
    ROOT_OPTIONS,
    TASK_COMMAND_NAMES,
    ManualTopic,
)
from vulnclaw.config.schema import PROVIDER_PRESETS


def render_manual(output_format: str = "text", topic: str | None = None) -> str:
    """Render the VulnClaw manual in text, markdown, or roff man-page format."""

    fmt = output_format.strip().lower()
    if fmt not in {"text", "markdown", "man"}:
        raise ValueError("manual format must be one of: text, markdown, man")

    topics = _select_topics(topic)
    normalized_topic = _normalize_topic(topic)
    if fmt == "markdown":
        return _render_markdown(topics, normalized_topic)
    if fmt == "man":
        return _render_man(topics, normalized_topic)
    return _render_text(topics, normalized_topic)


def available_topics() -> list[str]:
    """Return the user-facing topic names accepted by the manual command."""

    return [topic.name for topic in COMMANDS]


def _select_topics(topic: str | None) -> tuple[ManualTopic, ...]:
    normalized = _normalize_topic(topic)
    if not normalized:
        return COMMANDS

    by_name = {item.name: item for item in COMMANDS}
    for item in COMMANDS:
        by_name.update({alias: item for alias in item.aliases})

    selected = by_name.get(normalized)
    if not selected:
        raise ValueError(
            f"unknown manual topic '{topic}'. Available topics: {', '.join(available_topics())}"
        )
    return (selected,)


def _normalize_topic(topic: str | None) -> str:
    return (topic or "").strip().lower().replace("_", "-")


def _provider_names() -> str:
    return ", ".join(provider.value for provider in PROVIDER_PRESETS)


def _render_text(topics: tuple[ManualTopic, ...], topic: str) -> str:
    lines: list[str] = [
        "VULNCLAW(1) - VulnClaw CLI Manual",
        f"Version: {__version__}",
        "",
        "SYNOPSIS",
        "  vulnclaw [--help] [--version] [--man] [COMMAND] [ARGS]...",
        "  vulnclaw manual [TOPIC] [--format text|markdown|man]",
        "",
        "DESCRIPTION",
        "  VulnClaw is an AI-assisted CLI for authorized security testing. It combines",
        "  natural-language tasking, scoped autonomous loops, target history, reports,",
        "  MCP/built-in tools, a terminal workbench, and an optional local Web UI.",
        "",
        "ROOT OPTIONS",
    ]
    lines.extend(_render_text_pairs(ROOT_OPTIONS, indent_spaces=2))
    lines.extend(
        [
            "",
            "FAST START",
            "  vulnclaw init",
            "  vulnclaw config provider openrouter",
            "  vulnclaw config set llm.api_key <key>",
            "  vulnclaw doctor",
            "  vulnclaw run https://authorized-target.example --allow-actions recon,scan",
            "",
            "COMMAND MAP",
        ]
    )
    for item in COMMANDS:
        lines.append(f"  {item.name:<13} {item.summary}")

    if not topic or any(item.name in TASK_COMMAND_NAMES for item in topics):
        lines.extend(_common_sections_text())

    lines.extend(["", "COMMAND DETAILS"])
    for item in topics:
        lines.extend(_topic_text(item))

    lines.extend(
        [
            "",
            "CONFIG AND ENVIRONMENT",
            f"  Provider presets: {_provider_names()}",
            "  Config directory: ~/.vulnclaw by default, or VULNCLAW_CONFIG_DIR when set.",
            "  High-value env vars: VULNCLAW_LLM_API_KEY, VULNCLAW_LLM_API_KEYS,",
            "  VULNCLAW_LLM_PROVIDER, VULNCLAW_LLM_BASE_URL, VULNCLAW_LLM_MODEL,",
            "  VULNCLAW_SESSION_OUTPUT_DIR, VULNCLAW_SESSION_MAX_ROUNDS,",
            "  VULNCLAW_SESSION_SHOW_THINKING, VULNCLAW_SAFETY_PYTHON_EXECUTE_ENABLED.",
            "",
            "SAFETY",
            "  VulnClaw is for authorized testing only. Scope flags and action constraints",
            "  are there to make allowed boundaries explicit and enforceable, but they do",
            "  not replace written authorization or a clear rules-of-engagement document.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _common_sections_text() -> list[str]:
    lines = [
        "",
        "COMMON TASK FLAGS",
    ]
    lines.extend(_render_text_pairs(COMMON_TASK_FLAGS, indent_spaces=2))
    lines.extend(
        [
            "",
            "ACTION CONSTRAINTS",
            f"  Recognized action names: {', '.join(ACTION_NAMES)}.",
            "  Example: --allow-actions recon,scan blocks direct exploit/report commands",
            "  and also constrains tool and phase transitions during agent execution.",
        ]
    )
    return lines


def _topic_text(topic: ManualTopic) -> list[str]:
    lines = [
        "",
        topic.name.upper(),
        f"  {topic.summary}",
        "",
        "  Usage:",
    ]
    for usage_line in topic.usage.splitlines():
        lines.append(f"    {usage_line}")

    if topic.flags:
        lines.extend(["", "  Arguments and flags:"])
        lines.extend(_render_text_pairs(topic.flags, indent_spaces=4))
    if topic.notes:
        lines.extend(["", "  Notes:"])
        lines.extend(f"    - {note}" for note in topic.notes)
    if topic.examples:
        lines.extend(["", "  Examples:"])
        lines.extend(f"    {example}" for example in topic.examples)
    return lines


def _render_text_pairs(pairs: tuple[tuple[str, str], ...], indent_spaces: int) -> list[str]:
    pad = " " * indent_spaces
    lines: list[str] = []
    for name, description in pairs:
        lines.append(f"{pad}{name}")
        lines.append(f"{pad}  {description}")
    return lines


def _render_markdown(topics: tuple[ManualTopic, ...], topic: str) -> str:
    lines: list[str] = [
        "# VulnClaw CLI Manual",
        "",
        f"Version: `{__version__}`",
        "",
        "## Synopsis",
        "",
        "```bash",
        "vulnclaw [--help] [--version] [--man] [COMMAND] [ARGS]...",
        "vulnclaw manual [TOPIC] [--format text|markdown|man]",
        "```",
        "",
        "## Description",
        "",
        "VulnClaw is an AI-assisted CLI for authorized security testing. It combines natural-language tasking, scoped autonomous loops, target history, reports, MCP/built-in tools, a terminal workbench, and an optional local Web UI.",
        "",
        "## Root Options",
        "",
    ]
    lines.extend(_markdown_table(["Option", "Meaning"], ROOT_OPTIONS))
    lines.extend(
        [
            "",
            "## Fast Start",
            "",
            "```bash",
            "vulnclaw init",
            "vulnclaw config provider openrouter",
            "vulnclaw config set llm.api_key <key>",
            "vulnclaw doctor",
            "vulnclaw run https://authorized-target.example --allow-actions recon,scan",
            "```",
            "",
            "## Command Map",
            "",
        ]
    )
    lines.extend(_markdown_table(["Command", "Summary"], tuple((c.name, c.summary) for c in COMMANDS)))

    if not topic or any(item.name in TASK_COMMAND_NAMES for item in topics):
        lines.extend(
            [
                "",
                "## Common Task Flags",
                "",
            ]
        )
        lines.extend(_markdown_table(["Flag", "Meaning"], COMMON_TASK_FLAGS))
        lines.extend(
            [
                "",
                "## Action Constraints",
                "",
                f"Recognized action names: `{', '.join(ACTION_NAMES)}`.",
                "",
                "Example: `--allow-actions recon,scan` blocks direct exploit/report commands and also constrains tool and phase transitions during agent execution.",
            ]
        )

    lines.extend(["", "## Command Details", ""])
    for item in topics:
        lines.extend(_topic_markdown(item))

    lines.extend(
        [
            "",
            "## Config And Environment",
            "",
            f"Provider presets: `{_provider_names()}`.",
            "",
            "Config directory: `~/.vulnclaw` by default, or `VULNCLAW_CONFIG_DIR` when set.",
            "",
            "High-value env vars: `VULNCLAW_LLM_API_KEY`, `VULNCLAW_LLM_API_KEYS`, `VULNCLAW_LLM_PROVIDER`, `VULNCLAW_LLM_BASE_URL`, `VULNCLAW_LLM_MODEL`, `VULNCLAW_SESSION_OUTPUT_DIR`, `VULNCLAW_SESSION_MAX_ROUNDS`, `VULNCLAW_SESSION_SHOW_THINKING`, `VULNCLAW_SAFETY_PYTHON_EXECUTE_ENABLED`.",
            "",
            "## Safety",
            "",
            "VulnClaw is for authorized testing only. Scope flags and action constraints make allowed boundaries explicit and enforceable, but they do not replace written authorization or a clear rules-of-engagement document.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _topic_markdown(topic: ManualTopic) -> list[str]:
    lines = [
        f"### `{topic.name}`",
        "",
        topic.summary,
        "",
        "```bash",
        *topic.usage.splitlines(),
        "```",
    ]
    if topic.flags:
        lines.extend(["", "Arguments and flags:", ""])
        lines.extend(_markdown_table(["Name", "Meaning"], topic.flags))
    if topic.notes:
        lines.extend(["", "Notes:", ""])
        lines.extend(f"- {note}" for note in topic.notes)
    if topic.examples:
        lines.extend(["", "Examples:", "", "```bash", *topic.examples, "```"])
    lines.append("")
    return lines


def _markdown_table(headers: list[str], rows: tuple[tuple[str, str], ...]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for left, right in rows:
        lines.append(f"| `{left}` | {right} |")
    return lines


def _render_man(topics: tuple[ManualTopic, ...], topic: str) -> str:
    lines = [
        f'.TH VULNCLAW 1 "" "VulnClaw {__version__}" "VulnClaw Manual"',
        ".SH NAME",
        "vulnclaw \\- AI-assisted authorized security-testing CLI",
        ".SH SYNOPSIS",
        ".B vulnclaw",
        "[--help] [--version] [--man] [COMMAND] [ARGS]...",
        ".br",
        ".B vulnclaw manual",
        "[TOPIC] [--format text|markdown|man]",
        ".SH DESCRIPTION",
        "VulnClaw combines natural-language tasking, scoped autonomous loops, target history, reports, MCP and built-in tools, a terminal workbench, and an optional local Web UI.",
        ".SH ROOT OPTIONS",
    ]
    lines.extend(_roff_pairs(ROOT_OPTIONS))
    lines.extend(
        [
            ".SH COMMAND MAP",
        ]
    )
    lines.extend(_roff_pairs(tuple((item.name, item.summary) for item in COMMANDS)))

    if not topic or any(item.name in TASK_COMMAND_NAMES for item in topics):
        lines.extend([".SH COMMON TASK FLAGS"])
        lines.extend(_roff_pairs(COMMON_TASK_FLAGS))
        lines.extend(
            [
                ".SH ACTION CONSTRAINTS",
                f"Recognized action names: {', '.join(ACTION_NAMES)}.",
            ]
        )

    lines.append(".SH COMMAND DETAILS")
    for item in topics:
        lines.extend(_topic_roff(item))

    lines.extend(
        [
            ".SH CONFIG AND ENVIRONMENT",
            f"Provider presets: {_provider_names()}.",
            ".PP",
            "Config directory: ~/.vulnclaw by default, or VULNCLAW_CONFIG_DIR when set.",
            ".PP",
            "High-value env vars: VULNCLAW_LLM_API_KEY, VULNCLAW_LLM_API_KEYS, VULNCLAW_LLM_PROVIDER, VULNCLAW_LLM_BASE_URL, VULNCLAW_LLM_MODEL, VULNCLAW_SESSION_OUTPUT_DIR, VULNCLAW_SESSION_MAX_ROUNDS, VULNCLAW_SESSION_SHOW_THINKING, VULNCLAW_SAFETY_PYTHON_EXECUTE_ENABLED.",
            ".SH SAFETY",
            "VulnClaw is for authorized testing only. Scope flags and action constraints make allowed boundaries explicit and enforceable, but they do not replace written authorization or a clear rules-of-engagement document.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _topic_roff(topic: ManualTopic) -> list[str]:
    lines = [
        ".SS " + _roff_escape(topic.name),
        _roff_escape(topic.summary),
        ".PP",
        ".B Usage:",
    ]
    for usage_line in topic.usage.splitlines():
        lines.extend([".br", _roff_escape(usage_line)])
    if topic.flags:
        lines.extend([".PP", ".B Arguments and flags:"])
        lines.extend(_roff_pairs(topic.flags))
    if topic.notes:
        lines.extend([".PP", ".B Notes:"])
        for note in topic.notes:
            lines.extend([".IP \\[bu] 2", _roff_escape(note)])
    if topic.examples:
        lines.extend([".PP", ".B Examples:"])
        for example in topic.examples:
            lines.extend([".br", _roff_escape(example)])
    return lines


def _roff_pairs(pairs: tuple[tuple[str, str], ...]) -> list[str]:
    lines: list[str] = []
    for name, description in pairs:
        lines.extend(
            [
                f".TP\n.B {_roff_escape(name)}",
                _roff_escape(description),
            ]
        )
    return lines


def _roff_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("-", "\\-")
