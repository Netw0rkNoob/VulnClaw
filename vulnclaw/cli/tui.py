"""TUI helpers for the VulnClaw CLI."""

# [修改] 重大重构: 从 Rich 数字菜单驱动改为 prompt_toolkit + slash 命令系统
# - 新增 opencode 风格色彩调色板 (C_PRIMARY / C_SECONDARY 等)
# - 新增 slash 命令系统 (/target /mode /scope /start /config 等)
# - 新增 prompt 状态机 (input / choice / confirm / chain)
# - 新增 _run_pt_tui 函数提供 prompt_toolkit 应用主循环
# - 旧 Rich Prompt 保留在 _prompt_* 函数中作为兼容
# - 原 run_tui() 改为桥接至 tui_textual.run_tui_textual()

from __future__ import annotations

import io
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

# [修改] 2026-06-10 Nyaecho - 将 prompt_toolkit 导入移到 _run_pt_tui() 函数内部，避免硬性依赖
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from vulnclaw.config.settings import apply_provider_preset, list_providers, load_config, save_config
from vulnclaw.i18n import _, init_i18n
from vulnclaw.target_state.store import get_target_state_preview, list_target_snapshots

# ── opencode-inspired colour palette ──
# [修改] 替换 Rich 默认配色为统一色彩变量, 便于后续主题切换
C_PRIMARY = "#fab283"         # warm peach  – key indicators, selections
C_SECONDARY = "#5c9cf5"       # soft blue   – info, mode labels
C_ACCENT = "#9d7cd8"          # purple      – titles, headings
C_SUCCESS = "#7fd88f"         # green       – ok / configured
C_WARNING = "#f5a742"         # orange      – attention needed
C_ERROR = "#e06c75"           # red         – errors
C_MUTED = "#808080"           # muted gray  – secondary / dim text
C_TEXT = "#eeeeee"            # near-white  – body text
C_BORDER = "#484848"          # mid-gray    – panel borders
C_BORDER_SUBTLE = "#3c3c3c"   # dark-gray   – inner / subtle borders

# ── i18n boot ──
_config_holder = [None]


def _init_tui_i18n() -> None:
    """Initialize i18n for TUI with config language setting."""
    config = load_config()
    _config_holder[0] = config
    session_lang = getattr(config.session, "language", "auto") if config else "auto"
    init_i18n(lang=session_lang if session_lang != "auto" else None, config=config)


_init_tui_i18n()

CheckMode = Literal["quick", "standard", "deep", "continuous"]
TaskCommand = Literal["recon", "run", "scan", "persistent"]


@dataclass(frozen=True)
class TuiMode:
    key: CheckMode
    label: str
    command: TaskCommand
    description: str
    allow_actions: tuple[str, ...]
    block_actions: tuple[str, ...] = ()
    needs_extra_confirm: bool = False


@dataclass
class TuiState:
    target: str = ""
    mode: CheckMode = "standard"
    only_host: str = ""
    only_port: str = ""
    only_path: str = ""
    blocked_host: str = ""
    blocked_path: str = ""
    allow_actions: list[str] = field(default_factory=list)
    block_actions: list[str] = field(default_factory=list)
    resume: bool = True


@dataclass(frozen=True)
class TuiTargetOverview:
    """Small, safe-to-render summary of the selected target history."""

    target: str
    has_history: bool
    snapshot_count: int = 0
    phase: str = "unknown"
    findings_count: int = 0
    verified_count: int = 0
    pending_count: int = 0
    constraints_summary: str = "Not recorded"
    violations_count: int = 0
    last_command: str = ""
    error: str = ""


@dataclass(frozen=True)
class TuiRuntimeDiagnostic:
    """Runtime readiness summary shown inside the TUI."""

    python_version: str
    node_version: str = "missing"
    npx_status: str = "missing"
    uvx_status: str = "missing"
    nmap_status: str = "optional/missing"
    provider: str = "unknown"
    model: str = "unknown"
    api_key_configured: bool = False
    mcp_total_services: int = 0
    mcp_running_services: int = 0
    mcp_local_services: int = 0
    mcp_placeholder_services: int = 0
    mcp_tool_count: int = 0
    mcp_error: str = ""


@dataclass(frozen=True)
class TuiTaskDraft:
    command: TaskCommand
    target: str
    only_host: str | None = None
    only_port: int | None = None
    only_path: str | None = None
    blocked_host: str | None = None
    blocked_path: str | None = None
    allow_actions: tuple[str, ...] = ()
    block_actions: tuple[str, ...] = ()
    resume: bool = True

    @property
    def command_line(self) -> str:
        """Return a copyable command line for the current draft."""
        return " ".join(build_command_preview_args(self))


TaskLauncher = Callable[[TuiTaskDraft], None]


def _build_modes() -> dict[CheckMode, TuiMode]:
    """Build MODES dict with translated labels and descriptions."""
    return {
        "quick": TuiMode(
            key="quick",
            label=_("tui.mode_quick"),
            command="recon",
            description=_("tui.mode_quick_desc"),
            allow_actions=("recon",),
            block_actions=("exploit", "persistent", "post_exploitation"),
        ),
        "standard": TuiMode(
            key="standard",
            label=_("tui.mode_standard"),
            command="run",
            description=_("tui.mode_standard_desc"),
            allow_actions=("recon", "scan"),
            block_actions=("post_exploitation",),
        ),
        "deep": TuiMode(
            key="deep",
            label=_("tui.mode_deep"),
            command="scan",
            description=_("tui.mode_deep_desc"),
            allow_actions=("recon", "scan", "exploit"),
            needs_extra_confirm=True,
        ),
        "continuous": TuiMode(
            key="continuous",
            label=_("tui.mode_continuous"),
            command="persistent",
            description=_("tui.mode_continuous_desc"),
            allow_actions=("recon", "scan"),
            block_actions=("post_exploitation",),
            needs_extra_confirm=True,
        ),
    }


def _build_menu_items() -> dict[str, str]:
    """Build MENU_ITEMS dict with translated labels."""
    return {
        "1": _("tui.menu_set_target"),
        "2": _("tui.menu_select_mode"),
        "3": _("tui.menu_set_scope"),
        "4": _("tui.menu_start"),
        "5": _("tui.menu_history"),
        "6": _("tui.menu_report"),
        "7": _("tui.menu_diagnostic"),
        "8": _("tui.menu_config"),
        "q": _("tui.menu_exit"),
    }


MODES: dict[CheckMode, TuiMode] = _build_modes()
MENU_ITEMS: dict[str, str] = _build_menu_items()


def render_tui_home(state: TuiState | None = None, *, width: int = 110) -> str:
    """Render the TUI home surface into plain text for tests and dry-runs."""
    console = Console(
        file=io.StringIO(),
        record=True,
        width=width,
        force_terminal=False,
        color_system=None,
    )
    config = load_config()
    console.print(build_dashboard(config, state or TuiState()))
    return console.export_text()


def build_state_from_options(
    *,
    target: str = "",
    mode: CheckMode = "standard",
    only_host: str = "",
    only_port: str | int | None = "",
    only_path: str = "",
    blocked_host: str = "",
    blocked_path: str = "",
    allow_actions: str | tuple[str, ...] | list[str] | None = None,
    block_actions: str | tuple[str, ...] | list[str] | None = None,
    resume: bool = True,
) -> TuiState:
    """Build a TUI state object from CLI flags or tests."""
    return TuiState(
        target=target.strip(),
        mode=mode,
        only_host=only_host.strip(),
        only_port=str(only_port or "").strip(),
        only_path=only_path.strip(),
        blocked_host=blocked_host.strip(),
        blocked_path=blocked_path.strip(),
        allow_actions=_parse_action_csv(allow_actions),
        block_actions=_parse_action_csv(block_actions),
        resume=resume,
    )


def build_dashboard(config, state: TuiState) -> Group:
    """Build the first-screen VulnClaw TUI dashboard."""
    mode = MODES[state.mode]
    provider = getattr(config.llm, "provider", "unknown")
    model = getattr(config.llm, "model", "unknown")
    api_ready = bool(getattr(config.llm, "api_key", ""))
    overview = build_target_overview(state.target)

    title = Text(" VulnClaw TUI", style=f"bold {C_ACCENT}")
    subtitle = Text(f"  {_('tui.desc')}", style=f"{C_MUTED}")
    header = Panel(
        Group(title, subtitle),
        border_style=C_BORDER,
        box=box.ROUNDED,
        padding=(1, 2),
    )

    status = Table.grid(expand=True)
    status.add_column(ratio=1)
    status.add_column(ratio=1)
    status.add_column(ratio=1)
    status.add_row(
        _metric_panel(_("tui.authorized_target"), state.target or _("tui.target_not_set"), C_WARNING if not state.target else C_SUCCESS),
        _metric_panel(_("tui.check_mode"), f"{mode.label}  ·  {mode.command}", C_SECONDARY),
        _metric_panel(_("tui.ai_model"), f"{provider}  ·  {model}", C_SUCCESS if api_ready else C_WARNING),
    )

    scope_table = Table(box=box.ROUNDED, expand=True, show_header=True, border_style=C_BORDER_SUBTLE)
    scope_table.add_column(_("tui.test_scope"), style=f"bold {C_PRIMARY}")
    scope_table.add_column(_("tui.current_value"), style=C_TEXT)
    scope_table.add_row(_("tui.only_host"), state.only_host or _("tui.only_host_default"))
    scope_table.add_row(_("tui.only_port"), state.only_port or _("tui.only_port_default"))
    scope_table.add_row(_("tui.only_path"), state.only_path or _("tui.only_path_default"))
    scope_table.add_row(_("tui.blocked_host"), state.blocked_host or _("tui.blocked_host_default"))
    scope_table.add_row(_("tui.blocked_path"), state.blocked_path or _("tui.blocked_path_default"))
    scope_table.add_row(_("tui.allowed_actions"), ", ".join(_effective_allow_actions(state)) or _("tui.not_set"))
    scope_table.add_row(_("tui.blocked_actions"), ", ".join(_effective_block_actions(state)) or _("tui.not_set"))

    overview_table = Table(box=box.ROUNDED, expand=True, show_header=True, border_style=C_BORDER_SUBTLE)
    overview_table.add_column(_("tui.workbench_overview"), style=f"bold {C_PRIMARY}")
    overview_table.add_column(_("tui.current_status"), style=C_TEXT)
    overview_table.add_row(_("tui.model_key"), _("tui.model_key_configured") if api_ready else _("tui.model_key_not_configured"))
    overview_table.add_row(_("tui.history_resume"), _("tui.history_resume_on") if state.resume else _("tui.history_resume_off"))
    overview_table.add_row(_("tui.target_history"), _format_target_history_line(overview))
    overview_table.add_row(_("tui.risk_overview"), _format_findings_line(overview))
    overview_table.add_row(_("tui.persistent_constraints"), overview.constraints_summary)
    overview_table.add_row(_("tui.constraints_violations"), f"{overview.violations_count} {_('tui.times')}")
    if overview.last_command:
        overview_table.add_row(_("tui.last_command"), overview.last_command)
    if overview.error:
        overview_table.add_row(_("tui.history_error"), overview.error)

    command_preview = _draft_from_state(state).command_line
    # [修改] 这里改用 Rich Text 逐段上色，避免把 markup 当普通字符串显示出来
    footer_body = Text()
    footer_body.append(_("tui.command_preview"), style=f"bold {C_TEXT}")
    footer_body.append("\n")
    footer_body.append("┃  ", style=C_MUTED)
    footer_body.append(command_preview, style=C_MUTED)
    footer_body.append("\n\n")
    footer_body.append(_("tui.cli_note"), style=C_MUTED)

    footer = Panel(
        footer_body,
        title=_("tui.confirm_title"),
        title_align="left",
        border_style=C_SUCCESS if state.target else C_WARNING,
        box=box.ROUNDED,
    )

    return Group(
        header,
        Text(),
        status,
        Text(),
        Panel(overview_table, title=_("tui.overview_title"), title_align="left", border_style=C_BORDER, box=box.ROUNDED),
        Panel(scope_table, title=_("tui.boundary_title"), title_align="left", border_style=C_BORDER, box=box.ROUNDED),
        footer,
    )


def run_tui(
    *,
    launcher: TaskLauncher | None = None,
    once: bool = False,
    initial_state: TuiState | None = None,
) -> None:
    """Run the interactive terminal UI loop (Textual-powered)."""
    # [修改] 原 Rich 主循环替换为 Textual 后端, 桥接至 tui_textual.run_tui_textual()
    from vulnclaw.cli.tui_textual import run_tui_textual
    run_tui_textual(launcher=launcher, once=once, initial_state=initial_state)


def _run_pt_tui(session: dict[str, Any]) -> Optional[str]:
    """Run one cycle of the prompt_toolkit dashboard.

    Returns 'quit', 'launch', or None (interrupted).
    """
    # [修改] 2026-06-10 Nyaecho - 将 prompt_toolkit 导入移到函数内部，避免硬性依赖
    from prompt_toolkit import Application
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.formatted_text import ANSI
    from prompt_toolkit.key_binding import KeyBindings, merge_key_bindings
    from prompt_toolkit.layout import Float, FloatContainer, HSplit, Layout, Window
    from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
    from prompt_toolkit.styles import Style
    session["_action"] = None
    session["_prompt"] = None
    session["_message"] = ""

    def _render_status_bar() -> list[tuple[str, str]]:
        """Only show prompt/message when active; empty otherwise."""
        prompt = session.get("_prompt")
        msg = session.get("_message", "")

        if prompt is not None:
            ptype = prompt[0]
            if ptype == "input":
                return [(f"fg:{C_MUTED}", f"  {prompt[1]} ")]
            elif ptype == "choice":
                return [(f"fg:{C_MUTED}", f"  {prompt[1]} [")
                        ] + [(f"fg:{C_PRIMARY} bold", f"{c}") for c in prompt[2]
                        ] + [(f"fg:{C_MUTED}", "] ")]
            elif ptype == "confirm":
                return [(f"fg:{C_MUTED}", f"  {prompt[1]} "),
                        (f"fg:{C_SUCCESS} bold", "y"), (f"fg:{C_MUTED}", "/"),
                        (f"fg:{C_ERROR} bold", "n"), (f"fg:{C_MUTED}", " ")]
            elif ptype == "message":
                return [(f"fg:{C_MUTED}", f"  {prompt[1]}  "),
                        (f"fg:{C_BORDER}", "[Enter]")]
            elif ptype == "chain":
                _, fields, idx, _cb = prompt
                if idx < len(fields):
                    return [(f"fg:{C_MUTED}", f"  [{idx+1}/{len(fields)}] {fields[idx][1]} ")]
        elif msg:
            return [(f"fg:{C_WARNING}", f"  {msg}")]

        return []

    def _handle_input(buff: Buffer) -> bool:
        text = buff.text.strip()
        buff.text = ""
        session["_message"] = ""

        prompt = session.get("_prompt")
        if prompt is not None:
            _handle_prompt_response(session, prompt, text)
        elif text.startswith("/"):
            _dispatch_slash(text, session)
            action = session.get("_action")
            if action in ("quit", "launch"):
                app.exit()
        elif text:
            session["_message"] = _("tui.slash_hint")
        return False

    def _get_dashboard() -> ANSI:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=None, color_system="truecolor")
        console.print(build_dashboard(session["config"], session["state"]))
        return ANSI(buf.getvalue().rstrip("\n"))

    input_buffer = Buffer(
        accept_handler=_handle_input,
        multiline=False,
        enable_history_search=False,
        completer=_build_slash_completer(),
        complete_while_typing=True,
    )

    session["_palette_idx"] = 0

    def _palette_visible() -> bool:
        text = input_buffer.text
        if not text.startswith("/"):
            return False
        word = text.lstrip("/")
        if " " in word:
            return False
        return True

    def _palette_filtered() -> list[tuple[str, str]]:
        word = input_buffer.text.lstrip("/")
        return [(cmd, desc) for cmd, desc in SLASH_COMMANDS.items()
                if cmd.startswith(word)]

    def _palette_content() -> list[tuple[str, str]]:
        items = _palette_filtered()
        if not items:
            return []
        sel = session["_palette_idx"] % len(items)
        result: list[tuple[str, str]] = []
        result.append((f"fg:{C_BORDER} bg:#1e1e1e", "╭" + "─" * 46 + "╮\n"))
        for i, (cmd, desc) in enumerate(items):
            prefix = "▸" if i == sel else " "
            if i == sel:
                result.append((f"fg:{C_PRIMARY} bold bg:#2a2a2a", f" {prefix} /{cmd:<12}"))
                result.append((f"fg:{C_MUTED} bg:#2a2a2a", f" {desc[:32]}\n"))
            else:
                result.append((f"fg:{C_PRIMARY} bold bg:#1e1e1e", f" {prefix} /{cmd:<12}"))
                result.append((f"fg:{C_MUTED} bg:#1e1e1e", f" {desc[:32]}\n"))
        result.append((f"fg:{C_BORDER} bg:#1e1e1e", "╰" + "─" * 46 + "╯"))
        return result

    def _select_palette(_buff: Buffer | None = None) -> None:
        if not _palette_visible():
            return
        items = _palette_filtered()
        if items:
            sel = session["_palette_idx"] % len(items)
            input_buffer.text = "/" + items[sel][0]
            input_buffer.cursor_position = len(input_buffer.text)

    body = HSplit([
        Window(content=FormattedTextControl(_get_dashboard), wrap_lines=False),
        Window(height=1, char="─", style=f"fg:{C_BORDER}"),
        Window(content=FormattedTextControl(_render_status_bar), height=1, style="class:status-bar", dont_extend_height=True),
        Window(content=BufferControl(buffer=input_buffer), height=1, style="class:input"),
    ])

    palette_window = Window(
        content=FormattedTextControl(_palette_content),
        dont_extend_width=True,
        dont_extend_height=True,
    )

    root = FloatContainer(
        content=body,
        floats=[
            Float(
                content=palette_window,
                left=0,
                bottom=2,
                z_index=100,
            ),
        ],
    )

    kb = KeyBindings()

    @kb.add("c-c")
    @kb.add("c-d")
    def _exit(event: Any) -> None:
        session["_action"] = "quit"
        event.app.exit()

    @kb.add("escape")
    def _escape(event: Any) -> None:
        if session.get("_prompt") is not None:
            _cancel_prompt(session)
        else:
            session["_action"] = "quit"
            event.app.exit()

    @kb.add("up")
    def _palette_up(event: Any) -> None:
        if _palette_visible():
            session["_palette_idx"] = max(0, session["_palette_idx"] - 1)

    @kb.add("down")
    def _palette_down(event: Any) -> None:
        if _palette_visible():
            session["_palette_idx"] = max(0, session["_palette_idx"] + 1)

    @kb.add("tab")
    def _palette_tab(event: Any) -> None:
        if _palette_visible():
            _select_palette()

    style = Style.from_dict({
        "divider": f"fg:{C_BORDER}",
        "status-bar": f"bg:{C_BORDER_SUBTLE}",
        "input": f"bg:#1e1e1e fg:{C_TEXT}",
    })

    app = Application(
        layout=Layout(root),
        key_bindings=merge_key_bindings([kb, _load_default_bindings()]),
        style=style,
        full_screen=True,
        mouse_support=True,
    )

    try:
        app.run()
    except (KeyboardInterrupt, EOFError):
        session["_action"] = "quit"

    return session.get("_action")


_DEFAULT_BINDINGS: Any = None


def _load_default_bindings() -> Any:
    global _DEFAULT_BINDINGS
    if _DEFAULT_BINDINGS is None:
        from prompt_toolkit.key_binding.defaults import load_key_bindings as _load
        _DEFAULT_BINDINGS = _load()
    return _DEFAULT_BINDINGS


# ── Prompt state machine ──
# [修改] 新增 prompt 状态机, 支持 input / choice / confirm / chain 四种交互模式
# 用于替换 Rich 的 Prompt.ask / Confirm.ask, 与 prompt_toolkit 深度集成

PromptCallback = Callable[[str], None]


def _set_prompt_input(session: dict[str, Any], label: str, callback: PromptCallback, default: str = "") -> None:
    session["_prompt"] = ("input", label, callback, default)


def _set_prompt_choice(session: dict[str, Any], label: str, choices: list[str], callback: PromptCallback) -> None:
    session["_prompt"] = ("choice", label, choices, callback)


def _set_prompt_confirm(session: dict[str, Any], label: str, callback: Callable[[bool], None]) -> None:
    session["_prompt"] = ("confirm", label, callback)


def _set_prompt_message(session: dict[str, Any], text: str) -> None:
    session["_prompt"] = ("message", text, None)


def _set_prompt_chain(session: dict[str, Any], fields: list, idx: int, callback: Callable[[], None]) -> None:
    session["_prompt"] = ("chain", fields, idx, callback)


def _cancel_prompt(session: dict[str, Any]) -> None:
    """Cancel current prompt and return to normal mode."""
    prompt = session.get("_prompt")
    session["_prompt"] = None
    if prompt and prompt[0] == "chain":
        prompt[3]()  # call the final callback


def _handle_prompt_response(session: dict[str, Any], prompt: tuple, text: str) -> None:
    ptype = prompt[0]
    if ptype == "message":
        session["_prompt"] = None
    elif ptype == "input":
        _label, callback, default = prompt[1], prompt[2], prompt[3]
        value = text if text else default
        session["_prompt"] = None
        callback(value)
    elif ptype == "choice":
        _label, choices, callback = prompt[1], prompt[2], prompt[3]
        if text in choices:
            session["_prompt"] = None
            callback(text)
        else:
            session["_message"] = f"Invalid choice: {text}. Options: {', '.join(choices)}"
    elif ptype == "confirm":
        _label, callback = prompt[1], prompt[2]
        if text.lower() in ("y", "yes"):
            session["_prompt"] = None
            callback(True)
        elif text.lower() in ("n", "no"):
            session["_prompt"] = None
            callback(False)
        # else: stay in confirm state, let user try again
    elif ptype == "chain":
        _fields, idx, cb = prompt[1], prompt[2], prompt[3]
        if idx >= len(_fields):
            session["_prompt"] = None
            cb()
            return
        fld, fld_title, fld_default = _fields[idx]
        if fld == "__allow_actions":
            session["state"].allow_actions = _parse_action_csv(text) if text else []
        elif fld == "__block_actions":
            session["state"].block_actions = _parse_action_csv(text) if text else []
        elif fld == "only_port":
            if text:
                try:
                    _parse_optional_port(text)
                    session["state"].only_port = text
                except ValueError as e:
                    session["_message"] = str(e)
                    return
            else:
                session["state"].only_port = ""
        else:
            setattr(session["state"], fld, text if text else "")
        _set_prompt_chain(session, _fields, idx + 1, cb)


# ── Slash command system ──
# [修改] 新增 slash 命令系统替代数字菜单, 支持补全、快捷键注册
# 命令映射关系: /target→原1, /mode→原2, /scope→原3, /start→原4...
# /history→原5, /report→原6, /diag→原7, /config→原8, /quit→原q

SLASH_COMMANDS: dict[str, str] = {
    "target": "Set authorized target URL / domain / IP",
    "mode": "Select check mode (quick / standard / deep / continuous)",
    "scope": "Configure test scope boundaries",
    "run": "Start authorized security check",
    # [新增] 2026-06-10 Nyaecho - TUI命令面板新增 /continue 斜杠命令入口
    "continue": "Resume previous execution",
    "history": "View target history summary",
    "report": "Generate target report",
    "diag": "Run environment diagnostic",
    "config": "Configure LLM provider / model / API key",
    "quit": "Exit TUI",
}


def _build_slash_completer() -> Any:
    from prompt_toolkit.completion import Completer, Completion

    class _SlashCompleter(Completer):
        def get_completions(self, document, complete_event):
            pass  # async path is used instead

        async def get_completions_async(self, document, _complete_event):
            text = document.text_before_cursor
            if not text.startswith("/"):
                return

            word = text.lstrip("/")

            if not word:
                for cmd, desc in SLASH_COMMANDS.items():
                    yield Completion(
                        cmd,
                        start_position=0,
                        display=[(f"fg:{C_PRIMARY} bold", f"/{cmd}"), ("", "  "), (f"fg:{C_MUTED}", desc)],
                    )
                return

            parts = word.split(maxsplit=1)
            typed_cmd = parts[0]

            if len(parts) == 1 and not text.endswith(" "):
                for cmd, desc in SLASH_COMMANDS.items():
                    if cmd.startswith(typed_cmd):
                        yield Completion(
                            cmd,
                            start_position=-len(typed_cmd),
                            display=[(f"fg:{C_PRIMARY} bold", f"/{cmd}"), ("", "  "), (f"fg:{C_MUTED}", desc)],
                        )

    return _SlashCompleter()


def _dispatch_slash(text: str, session: dict[str, Any]) -> None:
    parts = text.lstrip("/").strip().split(maxsplit=1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    handler = _SLASH_HANDLERS.get(cmd)
    if handler:
        handler(session, args)
    else:
        session["_message"] = f"Unknown command: /{cmd}"


_SLASH_HANDLERS: dict[str, Callable[[dict[str, Any], str], None]] = {}


def _register_handler(cmd: str):
    def deco(fn: Callable[[dict[str, Any], str], None]):
        _SLASH_HANDLERS[cmd] = fn
        return fn
    return deco


@_register_handler("quit")
@_register_handler("exit")
@_register_handler("q")
def _cmd_quit(session: dict[str, Any], args: str) -> None:
    session["_action"] = "quit"


@_register_handler("target")
@_register_handler("t")
def _cmd_target(session: dict[str, Any], args: str) -> None:
    state: TuiState = session["state"]
    if args:
        state.target = args.strip()
        return

    def _on_value(value: str) -> None:
        if value:
            state.target = value

    _set_prompt_input(session, "Target URL / domain / IP:", _on_value, default=state.target)


@_register_handler("mode")
@_register_handler("m")
def _cmd_mode(session: dict[str, Any], args: str) -> None:
    state: TuiState = session["state"]
    if args and args in MODES:
        state.mode = args
        return
    choices = list(MODES.keys())

    def _on_choice(value: str) -> None:
        state.mode = value

    _set_prompt_choice(session, "Select mode:", choices, _on_choice)


@_register_handler("scope")
@_register_handler("s")
def _cmd_scope(session: dict[str, Any], args: str) -> None:
    state: TuiState = session["state"]
    if args:
        _parse_scope_args(state, args)
        return
    fields = [
        ("only_host", "Only Test Host", state.only_host or ""),
        ("only_port", "Only Test Port (1-65535, empty=unrestricted)", state.only_port),
        ("only_path", "Only Test Path", state.only_path or ""),
        ("blocked_host", "Blocked Host", state.blocked_host or ""),
        ("blocked_path", "Blocked Path", state.blocked_path or ""),
        ("__allow_actions", "Allowed Actions (comma-sep)", ",".join(state.allow_actions)),
        ("__block_actions", "Blocked Actions (comma-sep)", ",".join(state.block_actions)),
    ]

    def _on_resume_confirm(yes: bool) -> None:
        state.resume = yes

    def _ask_resume() -> None:
        _set_prompt_confirm(session, f"Resume? (y/n, current: {'yes' if state.resume else 'no'})", _on_resume_confirm)

    _set_prompt_chain(session, fields, 0, _ask_resume)


def _parse_scope_args(state: TuiState, args: str) -> None:
    for pair in args.split():
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k == "host":
                state.only_host = v
            elif k == "port":
                try:
                    _parse_optional_port(v)
                    state.only_port = v
                except ValueError:
                    pass
            elif k == "path":
                state.only_path = v
            elif k == "blocked_host":
                state.blocked_host = v
            elif k == "blocked_path":
                state.blocked_path = v
            elif k == "allow":
                state.allow_actions = _parse_action_csv(v)
            elif k == "block":
                state.block_actions = _parse_action_csv(v)
            elif k == "resume":
                state.resume = v.lower() in ("true", "yes", "1", "on")


@_register_handler("run")
def _cmd_start(session: dict[str, Any], args: str) -> None:
    state: TuiState = session["state"]
    if not state.target.strip():
        session["_message"] = _("tui.please_set_target")
        return

    mode = MODES[state.mode]
    if args == "-f" or args == "--force":
        _do_launch(session)
    elif mode.needs_extra_confirm:

        def _on_deep_confirm(yes: bool) -> None:
            if yes:
                _do_launch(session)
        _set_prompt_confirm(session, _("tui.confirm_deep_mode", mode=mode.label), _on_deep_confirm)
    else:
        _do_launch(session)


def _do_launch(session: dict[str, Any]) -> None:
    session["_action"] = "launch"


@_register_handler("history")
@_register_handler("hist")
def _cmd_history(session: dict[str, Any], args: str) -> None:
    state: TuiState = session["state"]
    if not state.target.strip():
        if args:
            state.target = args.strip()
        else:
            session["_message"] = _("tui.please_set_target")
            return

    preview = get_target_state_preview(state.target)
    snapshots = list_target_snapshots(state.target)
    if preview is None:
        _set_prompt_message(session, _("tui.no_history_for_target"))
    else:
        text = (
            f"Target: {preview.get('target', state.target)} | "
            f"Phase: {preview.get('phase', '?')} | "
            f"Findings: {preview.get('findings_count', 0)} | "
            f"Snapshots: {len(snapshots)}"
        )
        _set_prompt_message(session, text)


@_register_handler("report")
def _cmd_report(session: dict[str, Any], args: str) -> None:
    state: TuiState = session["state"]
    target = args.strip() if args else state.target.strip()
    if not target:
        session["_message"] = _("tui.please_set_target")
        return

    from vulnclaw.cli.main import _generate_report_for_target
    report_path = _generate_report_for_target(target)
    _set_prompt_message(session, f"{_('tui.report_generated')}: {report_path}")


@_register_handler("diag")
@_register_handler("diagnostic")
def _cmd_diagnostic(session: dict[str, Any], args: str) -> None:
    diag = build_runtime_diagnostic(session["config"])
    text = (
        f"Python {diag.python_version} | Node {diag.node_version} | "
        f"npx {diag.npx_status} | uvx {diag.uvx_status} | "
        f"Provider: {diag.provider} | Model: {diag.model} | "
        f"API Key: {'yes' if diag.api_key_configured else 'no'} | "
        f"MCP: {diag.mcp_total_services}s/{diag.mcp_tool_count}t"
    )
    _set_prompt_message(session, text)


@_register_handler("config")
@_register_handler("cfg")
def _cmd_config(session: dict[str, Any], args: str) -> None:
    config = session["config"]
    providers = [item["provider"] for item in list_providers()]
    current_provider = config.llm.provider

    def _on_provider(value: str) -> None:
        if value and value != current_provider:
            nonlocal config
            session["config"] = apply_provider_preset(config, value)
            config = session["config"]
        _set_prompt_input(session, f"Model (current: {config.llm.model}):", _on_model, default=config.llm.model)

    def _on_model(value: str) -> None:
        if value:
            config.llm.model = value.strip()
        key_status = _("tui.api_key_configured") if config.llm.api_key else _("tui.api_key_not_configured")
        _set_prompt_input(session, f"API Key ({key_status}, enter to keep):", _on_apikey)

    def _on_apikey(value: str) -> None:
        if value:
            config.llm.api_key = value.strip()
        save_config(config)
        _set_prompt_message(session, f"{_('tui.config_saved')}: {config.llm.provider}/{config.llm.model}")

    _set_prompt_choice(session, f"Provider (current: {current_provider}):", providers, _on_provider)


# ── (kept for backward compatibility) ──
# [修改] 以下旧 Rich/Prompt 函数保留供测试和 CLI 直接调用, 新代码应使用 slash 命令系统


def render_task_summary(draft: TuiTaskDraft, *, width: int = 100) -> str:
    """Render a launch summary for dry-run output and tests."""
    console = Console(
        file=io.StringIO(),
        record=True,
        width=width,
        force_terminal=False,
        color_system=None,
    )
    console.print(_build_task_summary_panel(draft))
    return console.export_text()


def build_task_draft(state: TuiState) -> TuiTaskDraft:
    """Public wrapper for converting TUI state into an executable task draft."""
    return _draft_from_state(state)


def build_target_overview(target: str) -> TuiTargetOverview:
    """Build a safe target-history overview for the TUI dashboard."""
    normalized = target.strip()
    if not normalized:
        return TuiTargetOverview(target="", has_history=False)

    try:
        preview = get_target_state_preview(normalized)
        snapshots = list_target_snapshots(normalized)
    except Exception as exc:
        return TuiTargetOverview(
            target=normalized,
            has_history=False,
            error=f"读取失败: {exc}",
        )

    if preview is None:
        return TuiTargetOverview(target=normalized, has_history=False)

    violations = preview.get("constraint_violations", [])
    if not isinstance(violations, list):
        violations = []

    return TuiTargetOverview(
        target=str(preview.get("target") or normalized),
        has_history=True,
        snapshot_count=len(snapshots),
        phase=str(preview.get("phase") or "unknown"),
        findings_count=_safe_int(preview.get("findings_count")),
        verified_count=_safe_int(preview.get("verified_count")),
        pending_count=_safe_int(preview.get("pending_count")),
        constraints_summary=_format_constraints_summary(preview.get("constraints")),
        violations_count=len(violations),
        last_command=str(preview.get("last_command") or ""),
    )


def build_runtime_diagnostic(config) -> TuiRuntimeDiagnostic:
    """Collect runtime readiness without leaving the TUI."""
    provider = str(getattr(config.llm, "provider", "unknown"))
    model = str(getattr(config.llm, "model", "unknown"))
    api_key_configured = bool(getattr(config.llm, "api_key", ""))

    node_version = _command_version("node", "--version") or "missing"
    npx_status = "installed" if shutil.which("npx") else "missing"
    uvx_status = "installed" if shutil.which("uvx") else "missing"
    nmap_status = "installed" if shutil.which("nmap") else "optional/missing"

    try:
        from vulnclaw.web.services.mcp_service import get_mcp_diagnostics

        mcp_diag = get_mcp_diagnostics()
        return TuiRuntimeDiagnostic(
            python_version=sys.version.split()[0],
            node_version=node_version,
            npx_status=npx_status,
            uvx_status=uvx_status,
            nmap_status=nmap_status,
            provider=provider,
            model=model,
            api_key_configured=api_key_configured,
            mcp_total_services=mcp_diag.total_services,
            mcp_running_services=mcp_diag.running_services,
            mcp_local_services=mcp_diag.local_services,
            mcp_placeholder_services=mcp_diag.placeholder_services,
            mcp_tool_count=mcp_diag.tool_count,
        )
    except Exception as exc:
        return TuiRuntimeDiagnostic(
            python_version=sys.version.split()[0],
            node_version=node_version,
            npx_status=npx_status,
            uvx_status=uvx_status,
            nmap_status=nmap_status,
            provider=provider,
            model=model,
            api_key_configured=api_key_configured,
            mcp_error=f"MCP 诊断失败: {exc}",
        )


def build_runtime_diagnostic_panel(config) -> Panel:
    """Render the runtime diagnostic panel used by menu item 7."""
    diagnostic = build_runtime_diagnostic(config)
    table = Table(box=box.ROUNDED, expand=True, show_header=True, border_style=C_BORDER_SUBTLE)
    table.add_column(_("tui.diagnostic_item"), style=f"bold {C_PRIMARY}")
    table.add_column(_("tui.diagnostic_status"), style=C_TEXT)
    table.add_row("Python", diagnostic.python_version)
    table.add_row("Node.js", diagnostic.node_version)
    table.add_row("npx", diagnostic.npx_status)
    table.add_row("uvx", diagnostic.uvx_status)
    table.add_row("nmap", diagnostic.nmap_status)
    table.add_row("LLM Provider", diagnostic.provider)
    table.add_row("LLM Model", diagnostic.model)
    table.add_row("API Key", _("tui.model_key_configured") if diagnostic.api_key_configured else _("tui.model_key_not_configured"))
    table.add_row(
        "MCP Services",
        (
            f"{diagnostic.mcp_total_services} registered / "
            f"{diagnostic.mcp_running_services} running / "
            f"{diagnostic.mcp_local_services} local / "
            f"{diagnostic.mcp_placeholder_services} placeholder"
        ),
    )
    table.add_row("MCP Tools", str(diagnostic.mcp_tool_count))
    if diagnostic.mcp_error:
        table.add_row("MCP Error", diagnostic.mcp_error)

    footer = _("tui.diagnostic_footer")
    return Panel(
        Group(table, Text(f"\n[{C_MUTED}]{footer}[/]")),
        title=_("tui.diagnostic_title"),
        title_align="left",
        border_style=C_BORDER,
        box=box.ROUNDED,
    )


def _command_version(command: str, *args: str) -> str:
    path = shutil.which(command)
    if not path:
        return ""
    try:
        result = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return "check failed"
    return (result.stdout or result.stderr).strip() or "installed"


def _metric_panel(label: str, value: str, style: str) -> Panel:
    return Panel(
        f"[{C_MUTED}]{label}[/]\n[bold {style}]{value}[/]",
        box=box.ROUNDED,
        border_style=C_BORDER_SUBTLE,
        padding=(1, 2),
    )


def _safe_int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _format_target_history_line(overview: TuiTargetOverview) -> str:
    if not overview.target:
        return _("tui.no_target")
    if overview.error:
        return _("tui.read_error_short")
    if not overview.has_history:
        return _("tui.no_history")
    return f"{overview.snapshot_count} {_('tui.snapshots')} / {_('tui.phase')} {overview.phase}"


def _format_findings_line(overview: TuiTargetOverview) -> str:
    if not overview.has_history:
        return _("tui.no_findings")
    return (
        f"{overview.findings_count} {_('tui.risks')}"
        f"({_('tui.verified')} {overview.verified_count} / {_('tui.pending')} {overview.pending_count})"
    )


def _format_constraints_summary(raw: object) -> str:
    if not isinstance(raw, dict) or not raw:
        return _("tui.constraints_not_recorded")

    parts: list[str] = []
    mapping = [
        ("allowed_hosts", _("tui.allowed_hosts")),
        ("allowed_ports", _("tui.allowed_ports")),
        ("allowed_paths", _("tui.allowed_paths")),
        ("blocked_hosts", _("tui.blocked_hosts")),
        ("blocked_paths", _("tui.blocked_paths")),
        ("allowed_actions", _("tui.allowed_actions")),
        ("blocked_actions", _("tui.blocked_actions")),
    ]
    for key, label in mapping:
        value = raw.get(key)
        if isinstance(value, list) and value:
            parts.append(f"{label}: {', '.join(str(item) for item in value)}")
        elif value:
            parts.append(f"{label}: {value}")

    if raw.get("strict_mode"):
        parts.append(_("tui.strict_mode"))

    return "；".join(parts) if parts else _("tui.constraints_not_recorded")


def _effective_allow_actions(state: TuiState) -> tuple[str, ...]:
    return tuple(state.allow_actions) or MODES[state.mode].allow_actions


def _effective_block_actions(state: TuiState) -> tuple[str, ...]:
    return tuple(state.block_actions) or MODES[state.mode].block_actions


def _parse_action_csv(value: str | tuple[str, ...] | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item).strip() for item in value if str(item).strip()]


def _parse_optional_port(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError("端口必须是 1-65535 之间的数字") from exc
    if port < 1 or port > 65535:
        raise ValueError("端口必须是 1-65535 之间的数字")
    return port


def _draft_from_state(state: TuiState) -> TuiTaskDraft:
    mode = MODES[state.mode]
    return TuiTaskDraft(
        command=mode.command,
        target=state.target.strip() or "<target>",
        only_host=state.only_host.strip() or None,
        only_port=_parse_optional_port(state.only_port),
        only_path=state.only_path.strip() or None,
        blocked_host=state.blocked_host.strip() or None,
        blocked_path=state.blocked_path.strip() or None,
        allow_actions=_effective_allow_actions(state),
        block_actions=_effective_block_actions(state),
        resume=state.resume,
    )


def _build_command_preview_args(draft: TuiTaskDraft) -> list[str]:
    return build_command_preview_args(draft)


def build_command_preview_args(draft: TuiTaskDraft, nl_text: str | None = None) -> list[str]:
    """Build a copyable CLI command from a TUI task draft."""
    # [修改] 2026-06-10 Nyaecho - TUI自然语言驱动: 支持 nl_text 传入并通过 --prompt 传递给CLI子进程
    # [修改] 2026-06-10 Nyaecho - 添加安全风险提示：通过命令行传递prompt可能暴露给其他本地用户
    args = ["vulnclaw", draft.command, draft.target]
    if nl_text:
        args.extend(["--prompt", nl_text])
    if not draft.resume:
        args.append("--no-resume")
    if draft.only_port is not None:
        args.extend(["--only-port", str(draft.only_port)])
    if draft.only_host:
        args.extend(["--only-host", draft.only_host])
    if draft.only_path:
        args.extend(["--only-path", draft.only_path])
    if draft.blocked_host:
        args.extend(["--blocked-host", draft.blocked_host])
    if draft.blocked_path:
        args.extend(["--blocked-path", draft.blocked_path])
    if draft.allow_actions:
        args.extend(["--allow-actions", ",".join(draft.allow_actions)])
    if draft.block_actions:
        args.extend(["--block-actions", ",".join(draft.block_actions)])
    return args


def _prompt_target(state: TuiState) -> None:
    state.target = Prompt.ask(_("tui.enter_target"), default=state.target).strip()


def _prompt_mode(state: TuiState) -> None:
    choices = list(MODES.keys())
    table = Table(title=_("tui.check_mode"), box=box.ROUNDED, border_style=C_BORDER_SUBTLE)
    table.add_column("Key", style=f"bold {C_PRIMARY}")
    table.add_column(_("tui.name"), style=C_TEXT)
    table.add_column(_("tui.description"), style=C_MUTED)
    for key in choices:
        mode = MODES[key]
        table.add_row(key, mode.label, mode.description)
    Console().print(table)
    state.mode = Prompt.ask(_("tui.select_mode"), choices=choices, default=state.mode)  # type: ignore[assignment]


def _prompt_llm_config(screen: Console, config):
    provider_table = Table(title=_("tui.available_providers"), box=box.ROUNDED, border_style=C_BORDER_SUBTLE)
    provider_table.add_column("Provider", style=f"bold {C_PRIMARY}")
    provider_table.add_column("Default Model", style=C_TEXT)
    provider_table.add_column("Base URL", style=C_MUTED)
    for item in list_providers():
        marker = " *" if item["provider"] == config.llm.provider else ""
        provider_table.add_row(
            f"{item['provider']}{marker}",
            item.get("default_model", ""),
            item.get("base_url", ""),
        )
    screen.print(provider_table)

    provider = Prompt.ask(
        _("tui.select_provider"),
        default=config.llm.provider,
    ).strip()
    if provider and provider != config.llm.provider:
        config = apply_provider_preset(config, provider)

    base_url = Prompt.ask("Base URL", default=config.llm.base_url).strip()
    model = Prompt.ask("Model", default=config.llm.model).strip()
    current_key = _("tui.api_key_configured") if config.llm.api_key else _("tui.api_key_not_configured")
    api_key = Prompt.ask(_("tui.enter_api_key"), default="").strip()

    if base_url:
        config.llm.base_url = base_url
    if model:
        config.llm.model = model
    if api_key:
        config.llm.api_key = api_key
    save_config(config)

    screen.print(
        Panel(
            f"Provider: [bold {C_PRIMARY}]{config.llm.provider}[/]\n"
            f"Base URL: [{C_MUTED}]{config.llm.base_url}[/]\n"
            f"Model: [{C_MUTED}]{config.llm.model}[/]\n"
            f"API Key: {_('tui.updated') if api_key else current_key}",
            title=_("tui.config_saved"),
            border_style=C_SUCCESS,
            box=box.ROUNDED,
        )
    )
    Prompt.ask(_("tui.press_enter"), default="")
    return config


def _prompt_scope(state: TuiState) -> None:
    state.only_host = Prompt.ask(_("tui.enter_only_host"), default=state.only_host).strip()
    while True:
        state.only_port = Prompt.ask(_("tui.enter_only_port"), default=state.only_port).strip()
        try:
            _parse_optional_port(state.only_port)
            break
        except ValueError as exc:
            Console().print(f"[{C_ERROR}]{exc}[/]")
    state.only_path = Prompt.ask(_("tui.enter_only_path"), default=state.only_path).strip()
    state.blocked_host = Prompt.ask(_("tui.enter_blocked_host"), default=state.blocked_host).strip()
    state.blocked_path = Prompt.ask(_("tui.enter_blocked_path"), default=state.blocked_path).strip()
    state.allow_actions = _parse_action_csv(
        Prompt.ask(
            _("tui.enter_allowed_actions"),
            default=",".join(state.allow_actions),
        )
    )
    state.block_actions = _parse_action_csv(
        Prompt.ask(
            _("tui.enter_blocked_actions"),
            default=",".join(state.block_actions),
        )
    )
    state.resume = Confirm.ask(_("tui.resume_history"), default=state.resume)


def _confirm_and_launch(state: TuiState, launcher: TaskLauncher) -> None:
    if not state.target.strip():
        Console().print(Panel(_("tui.please_set_target"), border_style=C_WARNING, box=box.ROUNDED))
        Prompt.ask(_("tui.press_enter"), default="")
        return

    mode = MODES[state.mode]
    if mode.needs_extra_confirm:
        ok = Confirm.ask(
            _("tui.confirm_deep_mode", mode=mode.label),
            default=False,
        )
        if not ok:
            return

    draft = _draft_from_state(state)
    Console().print(_build_task_summary_panel(draft, title=_("tui.launch_summary")))
    if Confirm.ask(_("tui.start_check"), default=False):
        Console().print(_("tui.enter_task_mode"))
        launcher(draft)
        Prompt.ask(_("tui.task_returned"), default="")


def _build_task_summary_panel(draft: TuiTaskDraft, *, title: str = "启动摘要") -> Panel:
    lines = [
        f"{_('tui.target')}: [bold {C_PRIMARY}]{draft.target}[/]",
        f"{_('tui.command')}: [bold {C_SECONDARY}]{draft.command}[/]",
        f"{_('tui.resume_history')}: {_('tui.yes') if draft.resume else _('tui.no')}",
        f"{_('tui.only_host')}: {draft.only_host or _('tui.unrestricted')}",
        f"{_('tui.only_port')}: {draft.only_port if draft.only_port is not None else _('tui.unrestricted')}",
        f"{_('tui.only_path')}: {draft.only_path or _('tui.unrestricted')}",
        f"{_('tui.blocked_host')}: {draft.blocked_host or _('tui.not_set')}",
        f"{_('tui.blocked_path')}: {draft.blocked_path or _('tui.not_set')}",
        f"{_('tui.allowed_actions')}: {', '.join(draft.allow_actions) or _('tui.not_set')}",
        f"{_('tui.blocked_actions')}: {', '.join(draft.block_actions) or _('tui.not_set')}",
        "",
        f"[bold {C_TEXT}]{_('tui.copyable_command')}[/]",
        f"[{C_MUTED}]  {draft.command_line}[/]",
    ]
    return Panel("\n".join(lines), title=title, title_align="left", border_style=C_WARNING, box=box.ROUNDED)


def _show_target_history(screen: Console, state: TuiState) -> None:
    if not state.target.strip():
        screen.print(Panel(_("tui.please_set_target"), border_style=C_WARNING, box=box.ROUNDED))
        Prompt.ask(_("tui.press_enter"), default="")
        return

    preview = get_target_state_preview(state.target)
    snapshots = list_target_snapshots(state.target)
    if preview is None:
        screen.print(Panel(_("tui.no_history_for_target"), title=_("tui.history_status"), border_style=C_WARNING, box=box.ROUNDED))
    else:
        screen.print(
            Panel(
                f"{_('tui.target')}: [bold {C_PRIMARY}]{preview.get('target', state.target)}[/]\n"
                f"{_('tui.phase')}: [bold {C_SECONDARY}]{preview.get('phase', 'unknown')}[/]\n"
                f"{_('tui.findings_count')}: [bold {C_TEXT}]{preview.get('findings_count', 0)}[/]\n"
                f"{_('tui.snapshot_count')}: [bold {C_TEXT}]{len(snapshots)}[/]",
                title=_("tui.history_status"),
                title_align="left",
                border_style=C_BORDER,
                box=box.ROUNDED,
            )
        )
    Prompt.ask(_("tui.press_enter"), default="")


def _generate_target_report(screen: Console, state: TuiState) -> None:
    if not state.target.strip():
        screen.print(Panel(_("tui.please_set_target"), border_style=C_WARNING, box=box.ROUNDED))
        Prompt.ask(_("tui.press_enter"), default="")
        return

    from vulnclaw.cli.main import _generate_report_for_target

    report_path = _generate_report_for_target(state.target)
    screen.print(Panel(report_path, title=_("tui.report_generated"), title_align="left", border_style=C_SUCCESS, box=box.ROUNDED))
    Prompt.ask(_("tui.press_enter"), default="")


def _default_launcher(draft: TuiTaskDraft) -> None:
    from vulnclaw.cli import main as cli_main

    allow_actions = ",".join(draft.allow_actions) if draft.allow_actions else None
    block_actions = ",".join(draft.block_actions) if draft.block_actions else None

    common = {
        "target": draft.target,
        "only_port": draft.only_port,
        "only_host": draft.only_host,
        "only_path": draft.only_path,
        "blocked_host": draft.blocked_host,
        "blocked_path": draft.blocked_path,
        "allow_actions": allow_actions,
        "block_actions": block_actions,
        "resume": draft.resume,
        "snapshot": None,
    }

    if draft.command == "recon":
        cli_main.recon(**common)
    elif draft.command == "scan":
        cli_main.scan(ports=None, **common)
    elif draft.command == "persistent":
        cli_main.persistent(rounds=0, cycles=0, no_report=False, **common)
    else:
        cli_main.run(scope="full", output=None, **common)
