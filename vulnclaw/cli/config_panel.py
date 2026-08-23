"""Pure state model for the classic-REPL configuration panel.

This module deliberately imports no UI library and performs no I/O, so the
whole panel's behavior can be tested without a terminal.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from vulnclaw.config.schema import (
    BUILTIN_MCP_SERVERS,
    ENGINE_CHOICES,
    MCPServerConfig,
    MCPTransportConfig,
    VulnClawConfig,
)
from vulnclaw.config.settings import apply_provider_preset, list_providers

TEXT = "text"
SECRET = "secret"
SECRET_LIST = "secret_list"
BOOL = "bool"
CHOICE = "choice"
INT = "int"
FLOAT = "float"
LIST = "list"
ENV = "env"
MODEL = "model"
PATH = "path"


class _Keep:
    """Sentinel: blank input leaves the current value alone."""


_KEEP = _Keep()


@dataclass(frozen=True)
class FieldSpec:
    """One editable config value and how the panel edits it."""

    path: str
    label_key: str
    kind: str
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class SectionSpec:
    """A collapsible group of fields."""

    name: str
    label_key: str
    fields: tuple[FieldSpec, ...]


LLM_FIELDS = (
    FieldSpec("llm.provider", "tui.config_panel.llm_provider", CHOICE),
    FieldSpec("llm.base_url", "tui.config_panel.llm_base_url", TEXT),
    FieldSpec("llm.auth_mode", "tui.config_panel.llm_auth_mode", CHOICE, ("static", "oauth")),
    FieldSpec("llm.api_keys", "tui.config_panel.llm_api_keys", SECRET_LIST),
    FieldSpec("llm.api_key", "tui.config_panel.llm_api_key", SECRET),
    FieldSpec("llm.model", "tui.config_panel.llm_model", MODEL),
    FieldSpec("llm.chatgpt_auto_proxy", "tui.config_panel.llm_chatgpt_auto_proxy", BOOL),
    FieldSpec("llm.max_tokens", "tui.config_panel.llm_max_tokens", INT),
    FieldSpec("llm.max_context_tokens", "tui.config_panel.llm_max_context_tokens", INT),
    FieldSpec("llm.temperature", "tui.config_panel.llm_temperature", FLOAT),
    FieldSpec("llm.reasoning_effort", "tui.config_panel.llm_reasoning_effort", TEXT),
)

SESSION_FIELDS = (
    FieldSpec("session.output_dir", "tui.config_panel.session_output_dir", PATH),
    FieldSpec("session.auto_save", "tui.config_panel.session_auto_save", BOOL),
    FieldSpec(
        "session.report_format",
        "tui.config_panel.session_report_format",
        CHOICE,
        ("markdown", "html"),
    ),
    FieldSpec(
        "session.poc_language",
        "tui.config_panel.session_poc_language",
        CHOICE,
        ("python", "bash"),
    ),
    FieldSpec(
        "session.engine",
        "tui.config_panel.session_engine",
        CHOICE,
        tuple(ENGINE_CHOICES),
    ),
    FieldSpec("session.max_rounds", "tui.config_panel.session_max_rounds", INT),
    FieldSpec("session.show_thinking", "tui.config_panel.session_show_thinking", BOOL),
    FieldSpec(
        "session.context_auto_compact",
        "tui.config_panel.session_context_auto_compact",
        BOOL,
    ),
    FieldSpec(
        "session.context_compact_trigger_ratio",
        "tui.config_panel.session_context_compact_trigger_ratio",
        FLOAT,
    ),
    FieldSpec(
        "session.context_compact_target_ratio",
        "tui.config_panel.session_context_compact_target_ratio",
        FLOAT,
    ),
    FieldSpec(
        "session.context_recent_message_groups",
        "tui.config_panel.session_context_recent_message_groups",
        INT,
    ),
    FieldSpec(
        "session.context_summary_max_tokens",
        "tui.config_panel.session_context_summary_max_tokens",
        INT,
    ),
    FieldSpec(
        "session.context_output_reserve_tokens",
        "tui.config_panel.session_context_output_reserve_tokens",
        INT,
    ),
    FieldSpec(
        "session.context_compaction_audit_enabled",
        "tui.config_panel.session_context_compaction_audit_enabled",
        BOOL,
    ),
    FieldSpec(
        "session.persistent_rounds_per_cycle",
        "tui.config_panel.session_persistent_rounds_per_cycle",
        INT,
    ),
    FieldSpec(
        "session.persistent_max_cycles",
        "tui.config_panel.session_persistent_max_cycles",
        INT,
    ),
    FieldSpec(
        "session.persistent_auto_report",
        "tui.config_panel.session_persistent_auto_report",
        BOOL,
    ),
    FieldSpec(
        "session.language",
        "tui.config_panel.session_language",
        CHOICE,
        ("auto", "en", "zh"),
    ),
)

SAFETY_FIELDS = (
    FieldSpec(
        "safety.enable_python_execute",
        "tui.config_panel.safety_enable_python_execute",
        BOOL,
    ),
    FieldSpec(
        "safety.python_execute_restricted",
        "tui.config_panel.safety_python_execute_restricted",
        BOOL,
    ),
    FieldSpec(
        "safety.python_execute_mode",
        "tui.config_panel.safety_python_execute_mode",
        CHOICE,
        ("safe", "lab", "trusted-local"),
    ),
    FieldSpec(
        "safety.python_execute_max_lines",
        "tui.config_panel.safety_python_execute_max_lines",
        INT,
    ),
    FieldSpec(
        "safety.python_execute_show_warning",
        "tui.config_panel.safety_python_execute_show_warning",
        BOOL,
    ),
    FieldSpec(
        "safety.python_execute_max_output_chars",
        "tui.config_panel.safety_python_execute_max_output_chars",
        INT,
    ),
    FieldSpec(
        "safety.python_execute_audit_enabled",
        "tui.config_panel.safety_python_execute_audit_enabled",
        BOOL,
    ),
    FieldSpec("safety.tool_parallel", "tui.config_panel.safety_tool_parallel", BOOL),
    FieldSpec(
        "safety.tool_max_concurrent",
        "tui.config_panel.safety_tool_max_concurrent",
        INT,
    ),
)

RECON_FIELDS = (
    FieldSpec("recon.fofa_email", "tui.config_panel.recon_fofa_email", TEXT),
    FieldSpec("recon.fofa_key", "tui.config_panel.recon_fofa_key", SECRET),
    FieldSpec("recon.hunter_key", "tui.config_panel.recon_hunter_key", SECRET),
    FieldSpec("recon.quake_key", "tui.config_panel.recon_quake_key", SECRET),
    FieldSpec("recon.zoomeye_key", "tui.config_panel.recon_zoomeye_key", SECRET),
    FieldSpec("recon.shodan_key", "tui.config_panel.recon_shodan_key", SECRET),
    FieldSpec("recon.zerozone_key", "tui.config_panel.recon_zerozone_key", SECRET),
    FieldSpec("recon.http_timeout", "tui.config_panel.recon_http_timeout", FLOAT),
    FieldSpec("recon.max_concurrency", "tui.config_panel.recon_max_concurrency", INT),
    FieldSpec("recon.space_size", "tui.config_panel.recon_space_size", INT),
    FieldSpec(
        "recon.dir_wordlist_path",
        "tui.config_panel.recon_dir_wordlist_path",
        TEXT,
    ),
    FieldSpec("recon.dir_max_requests", "tui.config_panel.recon_dir_max_requests", INT),
    FieldSpec("recon.js_max_files", "tui.config_panel.recon_js_max_files", INT),
)

MCP_SERVER_FIELDS = (
    FieldSpec("enabled", "tui.config_panel.mcp_enabled", BOOL),
    FieldSpec("priority", "tui.config_panel.mcp_priority", INT),
    FieldSpec("description", "tui.config_panel.mcp_description", TEXT),
    FieldSpec(
        "transport.type",
        "tui.config_panel.mcp_transport_type",
        CHOICE,
        ("stdio", "sse", "streamable-http"),
    ),
    FieldSpec("transport.command", "tui.config_panel.mcp_transport_command", TEXT),
    FieldSpec("transport.args", "tui.config_panel.mcp_transport_args", LIST),
    FieldSpec("transport.url", "tui.config_panel.mcp_transport_url", TEXT),
    FieldSpec("transport.env", "tui.config_panel.mcp_transport_env", ENV),
    FieldSpec(
        "transport.startup_timeout",
        "tui.config_panel.mcp_transport_startup_timeout",
        INT,
    ),
    FieldSpec("transport.tool_timeout", "tui.config_panel.mcp_transport_tool_timeout", INT),
)

SECTIONS = (
    SectionSpec("llm", "tui.config_panel.section_llm", LLM_FIELDS),
    SectionSpec("session", "tui.config_panel.section_session", SESSION_FIELDS),
    SectionSpec("safety", "tui.config_panel.section_safety", SAFETY_FIELDS),
    SectionSpec("recon", "tui.config_panel.section_recon", RECON_FIELDS),
    SectionSpec("mcp", "tui.config_panel.section_mcp", ()),
)


@dataclass
class Row:
    """One visible line in the panel."""

    key: str
    kind: str  # "group" | "field" | "action"
    label_key: str
    depth: int
    value_kind: str = ""
    path: str = ""
    expanded: bool = False
    choices: tuple[str, ...] = ()


def mask_secret(value: str) -> str:
    """Mask a secret so only a hint of it reaches the terminal."""
    value = (value or "").strip()
    if not value:
        return "(not set)"
    if len(value) <= 8:
        return "…" + value[-2:]
    return f"{value[:2]}…{value[-4:]}"


def mask_key_list(keys: list[str]) -> str:
    """Summarise a list of API keys without printing any in the clear."""
    usable = [key for key in keys if key and key.strip()]
    if not usable:
        return "(none)"
    plural = "s" if len(usable) != 1 else ""
    return f"{mask_secret(usable[0])} ({len(usable)} key{plural})"


def split_csv_items(raw: str) -> list[str]:
    """Split a comma/newline separated string into cleaned items."""
    return [item.strip() for item in raw.replace("\n", ",").split(",") if item.strip()]


def parse_env_items(raw: str) -> dict[str, str]:
    """Parse `KEY=value, KEY=value` into a dict, raising ValueError on junk."""
    result: dict[str, str] = {}
    for item in split_csv_items(raw):
        if "=" not in item:
            raise ValueError("Environment entries must look like KEY=value")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("Environment keys cannot be blank")
        result[key] = value.strip()
    return result


class ConfigPanelModel:
    """Draft-editing state machine behind the classic-REPL config panel."""

    def __init__(self, config: VulnClawConfig) -> None:
        self.draft = copy.deepcopy(config)
        self._expanded: set[str] = set()
        self._focus_key = "llm"
        self._edit: dict[str, Any] | None = None
        self._reveal = False
        self.row_error = ""
        self._dropdown: dict[str, Any] | None = None
        self.dropdown_index = 0
        self.generation = 0
        self.models: list[str] = []
        self.fetch_state = "idle"
        self.fetch_message = ""
        self.save_error = ""
        self._url_warning_acknowledged = False
        # Viewport: None means "show every row" (tests / unlimited height).
        self.viewport_height: int | None = None
        self._scroll_offset = 0

    STALE_PATHS = ("llm.provider", "llm.base_url", "llm.api_key", "llm.api_keys")

    # -- row tree ---------------------------------------------------------

    def rows(self) -> list[Row]:
        rows: list[Row] = []
        for section in SECTIONS:
            expanded = section.name in self._expanded
            rows.append(
                Row(
                    key=section.name,
                    kind="group",
                    label_key=section.label_key,
                    depth=0,
                    expanded=expanded,
                )
            )
            if not expanded:
                continue
            rows.extend(self._section_rows(section))
        rows.append(
            Row(key="action.save", kind="action", label_key="tui.config_panel.save", depth=0)
        )
        return rows

    def _section_rows(self, section: SectionSpec) -> list[Row]:
        if section.name == "mcp":
            return self._mcp_rows()
        rows = [
            Row(
                key=spec.path,
                kind="field",
                label_key=spec.label_key,
                depth=1,
                value_kind=spec.kind,
                path=spec.path,
                choices=spec.choices,
            )
            for spec in section.fields
        ]
        if section.name == "llm":
            rows.append(
                Row(
                    key="action.fetch_models",
                    kind="action",
                    label_key="tui.config_panel.fetch_models",
                    depth=1,
                )
            )
        return rows

    def _mcp_rows(self) -> list[Row]:
        rows: list[Row] = []
        for name in self.draft.mcp.servers:
            server_key = f"mcp.{name}"
            expanded = server_key in self._expanded
            rows.append(
                Row(
                    key=server_key,
                    kind="group",
                    label_key="",
                    depth=1,
                    expanded=expanded,
                )
            )
            if not expanded:
                continue
            for spec in MCP_SERVER_FIELDS:
                rows.append(
                    Row(
                        key=f"{server_key}.{spec.path}",
                        kind="field",
                        label_key=spec.label_key,
                        depth=2,
                        value_kind=spec.kind,
                        path=f"{server_key}.{spec.path}",
                        choices=spec.choices,
                    )
                )
            rows.append(
                Row(
                    key=f"{server_key}.action.delete",
                    kind="action",
                    label_key="tui.config_panel.delete_server",
                    depth=2,
                )
            )
        rows.append(
            Row(
                key="action.add_server",
                kind="action",
                label_key="tui.config_panel.add_server",
                depth=1,
            )
        )
        return rows

    # -- focus / viewport -------------------------------------------------

    @property
    def focused(self) -> Row:
        rows = self.rows()
        for row in rows:
            if row.key == self._focus_key:
                return row
        self._focus_key = rows[0].key
        return rows[0]

    def _editing_row(self) -> Row | None:
        """The row an in-progress edit began on, located by its stored key."""
        if self._edit is None:
            return None
        for row in self.rows():
            if row.key == self._edit["key"]:
                return row
        return None

    def _focus_index(self) -> int:
        rows = self.rows()
        for index, row in enumerate(rows):
            if row.key == self._focus_key:
                return index
        return 0

    @property
    def scroll_offset(self) -> int:
        return self._scroll_offset

    def set_viewport_height(self, height: int | None) -> None:
        """Limit how many logical rows are drawn; keeps the focused row in view."""
        if height is None or height < 1:
            self.viewport_height = None
            self._scroll_offset = 0
            return
        self.viewport_height = height
        self._ensure_focus_in_view()

    def _ensure_focus_in_view(self) -> None:
        height = self.viewport_height
        if height is None:
            return
        rows = self.rows()
        n = len(rows)
        if n == 0:
            self._scroll_offset = 0
            return
        focus_idx = self._focus_index()
        if focus_idx < self._scroll_offset:
            self._scroll_offset = focus_idx
        elif focus_idx >= self._scroll_offset + height:
            self._scroll_offset = focus_idx - height + 1
        max_offset = max(0, n - height)
        self._scroll_offset = max(0, min(self._scroll_offset, max_offset))

    def visible_rows(self) -> list[Row]:
        """Rows to paint for the current viewport (full list when unbounded)."""
        rows = self.rows()
        self._ensure_focus_in_view()
        height = self.viewport_height
        if height is None:
            return rows
        return rows[self._scroll_offset : self._scroll_offset + height]

    def focus_next(self) -> None:
        rows = self.rows()
        self._focus_key = rows[min(self._focus_index() + 1, len(rows) - 1)].key
        self._ensure_focus_in_view()

    def focus_prev(self) -> None:
        rows = self.rows()
        self._focus_key = rows[max(self._focus_index() - 1, 0)].key
        self._ensure_focus_in_view()

    # -- expansion --------------------------------------------------------

    def toggle_expand(self) -> None:
        row = self.focused
        if row.kind != "group":
            return
        if row.key in self._expanded:
            self._expanded.discard(row.key)
        else:
            self._expanded.add(row.key)
        self._ensure_focus_in_view()

    def expand(self) -> None:
        row = self.focused
        if row.kind == "group":
            self._expanded.add(row.key)
            self._ensure_focus_in_view()

    def collapse(self) -> None:
        row = self.focused
        if row.kind == "group":
            self._expanded.discard(row.key)
            self._ensure_focus_in_view()
            return
        parent = self._parent_key(row)
        if parent is not None:
            self._expanded.discard(parent)
            self._focus_key = parent
            self._ensure_focus_in_view()

    def _parent_key(self, row: Row) -> str | None:
        if row.key == "action.fetch_models":
            return "llm"
        if row.key == "action.add_server":
            return "mcp"
        if row.key.startswith("mcp."):
            parts = row.key.split(".")
            return f"mcp.{parts[1]}" if len(parts) > 2 else "mcp"
        if row.path:
            return row.path.split(".", 1)[0]
        return None

    # -- values -----------------------------------------------------------

    def _resolve(self, path: str) -> tuple[Any, str]:
        """Return (owner, attribute) for a dotted path, hopping the MCP server dict."""
        parts = path.split(".")
        if parts[0] == "mcp":
            target: Any = self.draft.mcp.servers[parts[1]]
            parts = parts[2:]
        else:
            target = self.draft
        for part in parts[:-1]:
            target = getattr(target, part)
        return target, parts[-1]

    def raw_value(self, row: Row) -> Any:
        owner, attribute = self._resolve(row.path)
        return getattr(owner, attribute)

    def _set_value(self, row: Row, value: Any) -> None:
        owner, attribute = self._resolve(row.path)
        setattr(owner, attribute, value)

    def display_value(self, row: Row) -> str:
        if row.kind != "field":
            return ""
        value = self.raw_value(row)
        if row.value_kind == SECRET:
            return value if self._reveal else mask_secret(value)
        if row.value_kind == SECRET_LIST:
            return ", ".join(value) if self._reveal else mask_key_list(value)
        if row.value_kind == BOOL:
            return "yes" if value else "no"
        if row.value_kind == LIST:
            return ", ".join(value or [])
        if row.value_kind == ENV:
            items = sorted((value or {}).items())
            if self._reveal:
                return ", ".join(f"{k}={v}" for k, v in items)
            # Env values routinely hold tokens/passwords — keep keys, hide values.
            return ", ".join(f"{k}={mask_secret(v)}" for k, v in items)
        return str(value)

    def _edit_seed(self, row: Row) -> str:
        """Text the editor opens with. Secrets always open empty."""
        if row.value_kind in (SECRET, SECRET_LIST):
            return ""
        return self.display_value(row)

    # -- editing ----------------------------------------------------------

    @property
    def editing(self) -> bool:
        return self._edit is not None

    @property
    def edit_text(self) -> str:
        return self._edit["text"] if self._edit else ""

    def edit_display(self, row: Row) -> str:
        """Editor text as it should appear on screen.

        Secret fields are echoed as bullets so a typed API/recon key is never
        rendered in the clear, mirroring how stored secrets are masked.
        """
        text = self.edit_text
        if row.value_kind in (SECRET, SECRET_LIST) and not self._reveal:
            return "•" * len(text)
        return text

    def set_edit_text(self, text: str) -> None:
        if self._edit is not None:
            self._edit["text"] = text

    def cancel_edit(self) -> None:
        self._edit = None
        self.row_error = ""

    def toggle_reveal(self) -> None:
        self._reveal = not self._reveal

    def activate(self) -> None:
        row = self.focused
        self.row_error = ""
        if row.kind == "group":
            self.toggle_expand()
            return
        if row.kind != "field":
            return
        if row.value_kind == BOOL:
            self._set_value(row, not self.raw_value(row))
            return
        options = self.options_for(row)
        if row.value_kind == CHOICE or (row.value_kind == MODEL and options):
            self._dropdown = {"options": options}
            current = self.raw_value(row)
            self.dropdown_index = options.index(current) if current in options else 0
            return
        self._edit = {"key": row.key, "text": self._edit_seed(row)}

    def commit_edit(self) -> None:
        if self._edit is None:
            return
        row = self._editing_row()
        if row is None or row.kind != "field":
            # Focus moved off the edited field before commit; drop the edit.
            self._edit = None
            self.row_error = ""
            return
        raw = self._edit["text"].strip()
        try:
            value = self._parse(row, raw)
        except ValueError as exc:
            self.row_error = str(exc)
            return
        if value is not _KEEP:
            self._set_value(row, value)
            if row.path in self.STALE_PATHS:
                self._invalidate_models()
        self._edit = None
        self.row_error = ""

    def _parse(self, row: Row, raw: str) -> Any:
        kind = row.value_kind
        if raw == "!clear":
            return {
                SECRET_LIST: [],
                LIST: [],
                ENV: {},
            }.get(kind, "")
        if raw == "":
            return _KEEP
        if kind in (TEXT, SECRET, MODEL):
            return raw
        if kind == PATH:
            from pathlib import Path

            return Path(raw)
        if kind in (SECRET_LIST, LIST):
            return split_csv_items(raw)
        if kind == ENV:
            return parse_env_items(raw)
        if kind == INT:
            try:
                return int(raw)
            except ValueError:
                raise ValueError("Enter a whole number.") from None
        if kind == FLOAT:
            try:
                return float(raw)
            except ValueError:
                raise ValueError("Enter a number.") from None
        return raw

    # -- dropdowns --------------------------------------------------------

    def provider_choices(self) -> list[str]:
        return [item["provider"] for item in list_providers()]

    def options_for(self, row: Row) -> list[str]:
        if row.path == "llm.provider":
            return self.provider_choices()
        if row.value_kind == MODEL:
            return list(self.models)
        return list(row.choices)

    @property
    def dropdown_open(self) -> bool:
        return self._dropdown is not None

    @property
    def dropdown_options(self) -> list[str]:
        return self._dropdown["options"] if self._dropdown else []

    def select_option(self, delta: int) -> None:
        if self._dropdown is None:
            return
        limit = len(self._dropdown["options"]) - 1
        self.dropdown_index = max(0, min(self.dropdown_index + delta, limit))

    def cancel_option(self) -> None:
        self._dropdown = None
        self.dropdown_index = 0

    def commit_option(self) -> None:
        if self._dropdown is None:
            return
        row = self.focused
        choice = self._dropdown["options"][self.dropdown_index]
        self._dropdown = None
        self.dropdown_index = 0
        if row.path == "llm.provider":
            if choice != self.draft.llm.provider:
                self.draft = apply_provider_preset(self.draft, choice)
                self.draft.llm.provider = choice
                self._invalidate_models()
            return
        self._set_value(row, choice)

    def _invalidate_models(self) -> None:
        """Any credential change makes a fetched model list stale."""
        self.generation += 1
        self.models = []
        self.fetch_state = "idle"
        self.fetch_message = ""

    # -- model fetch ------------------------------------------------------

    def _usable_key(self) -> str:
        for key in self.draft.llm.api_keys:
            if key and key.strip():
                return key
        return self.draft.llm.api_key.strip()

    def can_fetch(self) -> bool:
        return bool(self.draft.llm.base_url.strip() and self._usable_key())

    def begin_fetch(self) -> int:
        """Mark a fetch in flight and return the generation the worker must echo back."""
        self.generation += 1
        self.models = []
        self.fetch_state = "loading"
        self.fetch_message = ""
        return self.generation

    def apply_fetch_result(
        self, generation: int, models: list[str], error: str | None
    ) -> None:
        if generation != self.generation:
            return
        if error:
            self.models = []
            self.fetch_state = "error"
            self.fetch_message = error
            return
        if not models:
            self.models = []
            self.fetch_state = "error"
            self.fetch_message = "No models returned; enter a model id manually."
            return
        self.models = list(models)
        self.fetch_state = "ok"
        self.fetch_message = f"{len(models)} models loaded."

    # -- MCP mutations ----------------------------------------------------

    def add_server(self, name: str) -> None:
        name = name.strip()
        if not name:
            self.row_error = "Server name cannot be blank."
            return
        # Row paths are dotted (mcp.<name>.transport…), so a dot in the name
        # would make _resolve() split on it and raise KeyError later.
        if "." in name:
            self.row_error = "Server name cannot contain '.'."
            return
        if name in self.draft.mcp.servers:
            self.row_error = f"Server '{name}' already exists."
            return
        self.draft.mcp.servers[name] = MCPServerConfig(
            name=name,
            enabled=True,
            priority=1,
            transport=MCPTransportConfig(type="stdio"),
        )
        self.row_error = ""
        self._expanded.update({"mcp", f"mcp.{name}"})
        self._focus_key = f"mcp.{name}"
        self._ensure_focus_in_view()

    def delete_server(self) -> None:
        row = self.focused
        parts = row.key.split(".")
        if len(parts) < 2 or parts[0] != "mcp":
            return
        name = parts[1]
        if name in BUILTIN_MCP_SERVERS:
            self.row_error = "Built-in servers cannot be deleted here."
            return
        self.draft.mcp.servers.pop(name, None)
        self._expanded.discard(f"mcp.{name}")
        self._focus_key = "mcp"
        self.row_error = ""
        self._ensure_focus_in_view()

    # -- validation / save / summary --------------------------------------

    def validate(self) -> list[str]:
        """Blocking problems, in the order they should be shown."""
        errors: list[str] = []
        llm = self.draft.llm
        if llm.auth_mode == "static" and not self._usable_key():
            errors.append("An API key is required for static auth mode.")
        if llm.provider == "custom" and not llm.base_url.strip():
            errors.append("A base URL is required for the custom provider.")
        for name, server in self.draft.mcp.servers.items():
            if not name.strip():
                errors.append("MCP server names cannot be blank.")
            if server.transport.type == "stdio" and not (server.transport.command or "").strip():
                errors.append(f"MCP server '{name}' needs a command for stdio transport.")
            if server.transport.type != "stdio" and not (server.transport.url or "").strip():
                errors.append(f"MCP server '{name}' needs a URL for {server.transport.type}.")
        try:
            VulnClawConfig.model_validate(self.draft.model_dump())
        except Exception as exc:  # pydantic ValidationError
            errors.append(str(exc).splitlines()[1].strip() if "\n" in str(exc) else str(exc))
        return errors

    def _base_url_is_suspicious(self) -> bool:
        url = self.draft.llm.base_url.strip()
        return bool(url) and not url.startswith(("http://", "https://"))

    def request_save(self) -> bool:
        """True when the shell should call save_config(model.draft)."""
        errors = self.validate()
        if errors:
            self.save_error = errors[0]
            return False
        if self._base_url_is_suspicious() and not self._url_warning_acknowledged:
            self._url_warning_acknowledged = True
            self.save_error = "Base URL may be malformed; press Save again to continue."
            return False
        self.save_error = ""
        return True

    def summary(self, section_name: str) -> str:
        llm = self.draft.llm
        if section_name == "llm":
            parts = [llm.provider, llm.model, f"key {mask_secret(llm.api_key)}"]
            if [key for key in llm.api_keys if key.strip()]:
                parts.append("failover pool takes precedence")
            return " · ".join(parts)
        if section_name == "session":
            return " · ".join(
                [
                    self.draft.session.engine,
                    f"{self.draft.session.max_rounds} rounds",
                    self.draft.session.language,
                ]
            )
        if section_name == "safety":
            state = "on" if self.draft.safety.enable_python_execute else "off"
            return f"python exec {state} · {self.draft.safety.python_execute_mode}"
        if section_name == "recon":
            keys = [
                self.draft.recon.fofa_key,
                self.draft.recon.hunter_key,
                self.draft.recon.quake_key,
                self.draft.recon.zoomeye_key,
                self.draft.recon.shodan_key,
                self.draft.recon.zerozone_key,
            ]
            return f"{len([key for key in keys if key.strip()])} keys set"
        if section_name == "mcp":
            count = len(self.draft.mcp.servers)
            return f"{count} server{'s' if count != 1 else ''}"
        # Nested MCP server group: "mcp.<name>"
        if section_name.startswith("mcp."):
            name = section_name.split(".", 1)[1]
            server = self.draft.mcp.servers.get(name)
            if server is None:
                return ""
            state = "enabled" if server.enabled else "disabled"
            return f"{server.transport.type} · {state}"
        return ""
