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
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Optional

# [修改] 2026-06-10 Nyaecho - 将 prompt_toolkit 导入移到 _run_pt_tui() 函数内部，避免硬性依赖
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from vulnclaw.config.schema import (
    BUILTIN_MCP_SERVERS,
    MCPServerConfig,
    MCPTransportConfig,
)
from vulnclaw.config.settings import (
    ProviderModelDiscoveryResult,
    apply_provider_preset,
    discover_provider_models,
    list_providers,
    load_config,
    save_config,
)
from vulnclaw.i18n import _, init_i18n
from vulnclaw.skills.dispatcher import SkillDispatcher
from vulnclaw.skills.flag_skills import (
    apply_flag_skill_to_tui_state,
    complete_flag_skills,
    find_flag_skill,
    parse_flag_skill_command,
    render_flag_skill,
    render_flag_skill_compact,
)
from vulnclaw.skills.loader import load_skill_by_name
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


def _model_discovery_failure_message(result: ProviderModelDiscoveryResult) -> str:
    """Return localized discovery feedback without exposing upstream data."""
    return _(f"tui.model_discovery_{result.status.value}")


# ── @ skill reference boundary detection ──
# [新增] 2026-07-08 Nyaecho - 新增 @ 符号用于 skill 资料引用，支持任意位置触发补全
# 边界字符：空白、中英文标点、行尾、特殊符号
SKILL_BOUNDARY_RE = re.compile(r'[\s，。；：、！？）】》,.:;!?)]}@/]')


def _is_skill_boundary(ch: str) -> bool:
    """Check if a character is a skill name boundary."""
    return bool(SKILL_BOUNDARY_RE.match(ch))


def find_at_context(text: str, cursor: int) -> tuple[str, str] | None:
    """Find the nearest @ before cursor and extract the skill word for completion.

    Returns (prefix_before_at, word) or None if no valid @ found.
    The @ must be at start of line or preceded by a boundary character.
    """
    before = text[:cursor]
    at_pos = before.rfind("@")
    if at_pos == -1:
        return None
    # @ 前面必须是边界字符或行首
    if at_pos > 0 and not _is_skill_boundary(before[at_pos - 1]):
        return None
    # 提取 @ 后面的 word（到光标位置）
    word = before[at_pos + 1:]
    # word 中不能有边界字符（说明 skill name 已输入完毕，光标在后面）
    if SKILL_BOUNDARY_RE.search(word):
        return None
    return (before[:at_pos], word)


def expand_at_skills(text: str) -> str:
    """Expand all @skillname references in text to 'Use VulnClaw skill skillname.'.

    Only expands valid skills (loaded by load_skill_by_name). Invalid @ references
    are left unchanged.
    """
    if "@" not in text:
        return text

    result = []
    i = 0
    while i < len(text):
        if text[i] == "@":
            # @ 前面必须是边界字符或行首
            if i > 0 and not _is_skill_boundary(text[i - 1]):
                result.append(text[i])
                i += 1
                continue

            # 提取 skill name
            name_start = i + 1
            name_end = name_start
            while name_end < len(text) and not _is_skill_boundary(text[name_end]):
                name_end += 1

            skill_name = text[name_start:name_end]
            if skill_name and load_skill_by_name(skill_name):
                result.append(f"Use VulnClaw skill {skill_name}.")
            else:
                result.append(text[i:name_end])
            i = name_end
        else:
            result.append(text[i])
            i += 1

    return "".join(result)


# ── i18n boot ──
_config_holder = [None]


def _init_tui_i18n() -> None:
    """Initialize i18n for TUI with config language setting."""
    config = load_config()
    _config_holder[0] = config
    session_lang = getattr(config.session, "language", "auto") if config else "auto"
    init_i18n(lang=session_lang if session_lang != "auto" else None, config=config)


_init_tui_i18n()


def rebuild_translations() -> None:
    """Rebuild MODES, SLASH_COMMANDS, MENU_ITEMS after i18n language switch.

    Call this after init_i18n() with a new language to update all
    module-level globals that were built with _() translations.
    """
    global MODES, MENU_ITEMS, SLASH_COMMANDS, REPL_COMMANDS
    MODES = _build_modes()
    MENU_ITEMS = _build_menu_items()
    SLASH_COMMANDS = _build_slash_commands()
    REPL_COMMANDS = _build_repl_commands()


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
    constraints_summary: str = field(default_factory=lambda: _("tui.constraints_not_recorded"))
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
    # [隐藏] 隐藏一个调试时文字提示
    #footer_body.append(_("tui.cli_note"), style=C_MUTED)

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

    # [修改] 2026-07-08 Nyaecho - 修改原因：提交时展开 @ skill 引用为完整 prompt
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
            # 展开 @ skill 引用后作为自然语言 prompt
            expanded = expand_at_skills(text)
            session["_nl_text"] = expanded
            session["_nl_history"] = text  # 保留原始输入用于 /continue
            session["_action"] = "launch"
            app.exit()
        return False

    def _get_dashboard() -> ANSI:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=None, color_system="truecolor")
        console.print(build_dashboard(session["config"], session["state"]))
        return ANSI(buf.getvalue().rstrip("\n"))

    # [修改] 2026-07-08 Nyaecho - 修改原因：合并 slash 和 at 两个补全器
    from prompt_toolkit.completion import merge_completers

    input_buffer = Buffer(
        accept_handler=_handle_input,
        multiline=False,
        enable_history_search=False,
        completer=merge_completers([_build_slash_completer(), _build_at_completer()]),
        complete_while_typing=True,
    )

    session["_palette_idx"] = 0

    # [修改] 2026-07-08 Nyaecho - 修改原因：新增 "at" kind 支持任意位置的 @ skill 引用补全
    def _palette_context() -> tuple[str, str] | None:
        text = input_buffer.text
        cursor = input_buffer.cursor_position
        if text.startswith("/."):
            word = text[2:]
            if " " in word:
                return None
            return "flag", word
        if text.startswith("/"):
            word = text.lstrip("/")
            if " " in word:
                return None
            return "slash", word
        # 检测任意位置的 @
        ctx = find_at_context(text, cursor)
        if ctx is not None:
            _, word = ctx
            return "at", word
        return None

    def _palette_visible() -> bool:
        return _palette_context() is not None

    # [修改] 2026-07-08 Nyaecho - 修改原因：at kind 调用 build_at_palette_entries获取 skills
    def _palette_filtered() -> list[tuple[str, str]]:
        context = _palette_context()
        if context is None:
            return []
        kind, word = context
        if kind == "flag":
            return [(skill.name, skill.summary) for skill in complete_flag_skills(word)]
        if kind == "at":
            return build_at_palette_entries(word)
        return build_slash_palette_entries(word)

    # [修改] 2026-07-08 Nyaecho - 修改原因：at kind 返回 "@" 前缀
    def _palette_prefix() -> str:
        context = _palette_context()
        if context and context[0] == "flag":
            return "/."
        if context and context[0] == "at":
            return "@"
        return "/"

    def _palette_content() -> list[tuple[str, str]]:
        items = _palette_filtered()
        if not items:
            return []
        sel = session["_palette_idx"] % len(items)
        # Calculate dynamic box width: prefix (3) + cmd padded to 12 (12) + space (1) + max desc length
        max_desc = max((len(desc) for _, desc in items), default=32)
        box_inner = max(46, max_desc + 16)  # 46 is legacy minimum, 16 = prefix + cmd column + space
        result: list[tuple[str, str]] = []
        result.append((f"fg:{C_BORDER} bg:#1e1e1e", "╭" + "─" * box_inner + "╮\n"))
        for i, (cmd, desc) in enumerate(items):
            prefix = "▸" if i == sel else " "
            if i == sel:
                result.append((f"fg:{C_PRIMARY} bold bg:#2a2a2a", f" {prefix} {_palette_prefix()}{cmd:<12}"))
                result.append((f"fg:{C_MUTED} bg:#2a2a2a", f" {desc}\n"))
            else:
                result.append((f"fg:{C_PRIMARY} bold bg:#1e1e1e", f" {prefix} {_palette_prefix()}{cmd:<12}"))
                result.append((f"fg:{C_MUTED} bg:#1e1e1e", f" {desc}\n"))
        result.append((f"fg:{C_BORDER} bg:#1e1e1e", "╰" + "─" * box_inner + "╯"))
        return result

    def _select_palette(_buff: Buffer | None = None) -> None:
        if not _palette_visible():
            return
        items = _palette_filtered()
        if items:
            sel = session["_palette_idx"] % len(items)
            input_buffer.text = _palette_prefix() + items[sel][0]
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
        **slash_completion_style_rules(),
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
            session["_message"] = _("tui.invalid_choice", choice=text, options=", ".join(choices))
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

def _build_slash_commands() -> dict[str, str]:
    """Build SLASH_COMMANDS dict with translated descriptions."""
    return {
        "target": _("tui.slash_target"),
        "mode": _("tui.slash_mode"),
        "scope": _("tui.slash_scope"),
        "run": _("tui.slash_run"),
        # [新增] 2026-06-10 Nyaecho - TUI命令面板新增 /continue 斜杠命令入口
        "continue": _("tui.slash_continue"),
        "history": _("tui.slash_history"),
        "report": _("tui.slash_report"),
        "diag": _("tui.slash_diag"),
        "config": _("tui.slash_config"),
        "language": _("tui.slash_lang"),
        "quit": _("tui.slash_quit"),
    }


SLASH_COMMANDS: dict[str, str] = _build_slash_commands()


def _build_repl_commands() -> dict[str, str]:
    """Built-in commands the classic REPL implements itself (not skills).

    These have real handlers in ``_run_repl`` — unlike the wider Textual-TUI
    ``SLASH_COMMANDS`` set, which the classic REPL cannot dispatch.
    """
    return {
        "config": _("tui.slash_config"),
        "language": _("tui.slash_lang"),
    }


REPL_COMMANDS: dict[str, str] = _build_repl_commands()

# Short aliases → canonical classic-REPL command name.
_REPL_COMMAND_ALIASES: dict[str, str] = {"cfg": "config", "lang": "language"}


def _resolve_repl_command(name: str) -> str:
    """Return the canonical REPL command for ``name`` (or an alias), else ``""``."""
    key = name.strip().lower()
    key = _REPL_COMMAND_ALIASES.get(key, key)
    return key if key in REPL_COMMANDS else ""


def skill_display_description(skill: dict[str, Any]) -> str:
    """Localized description for a skill's palette / help entry.

    Skill frontmatter descriptions are authored in Chinese. When a localized
    override exists in the i18n catalog for the active language (key
    ``skill.<name>.description``, e.g. the English strings in ``en.json``),
    prefer it; otherwise fall back to the frontmatter description.
    """
    name = skill.get("name", "")
    key = f"skill.{name}.description"
    localized = _(key)
    if localized and localized != key:
        return localized
    return skill.get("description", "") or f"{skill.get('type', 'skill')} skill"


def list_skill_palette_entries(prefix: str = "") -> list[tuple[str, str]]:
    """Return palette entries for available skills only (no built-in commands).

    Used by the classic REPL, whose ``/`` menu lists skills exclusively.
    """
    normalized = prefix.strip().lower()
    entries: list[tuple[str, str]] = []
    for skill in SkillDispatcher().list_all_skills():
        name = skill["name"]
        if normalized and not name.lower().startswith(normalized):
            continue
        description = skill_display_description(skill)
        refs = skill.get("references", "0")
        entries.append((name, f"Skill · {description} · {refs} refs"))
    return entries


def build_at_palette_entries(prefix: str = "") -> list[tuple[str, str]]:
    """Return palette entries for @ skill references.

    [新增] 2026-07-08 Nyaecho - @ 符号用于 skill 资料引用，补全时只显示 skills。
    """
    return list_skill_palette_entries(prefix)


def list_repl_palette_entries(prefix: str = "") -> list[tuple[str, str]]:
    """Classic-REPL ``/`` palette: built-in commands first, then skills.

    The Textual TUI's other slash commands (``/mode`` etc.) are still excluded —
    only the commands the classic REPL actually handles are offered here.
    """
    normalized = prefix.strip().lower()
    entries: list[tuple[str, str]] = []
    for cmd, desc in REPL_COMMANDS.items():
        if normalized and not cmd.startswith(normalized):
            continue
        entries.append((cmd, f"Command · {desc}"))
    entries.extend(list_skill_palette_entries(prefix))
    return entries


# [修改] 2026-07-08 Nyaecho - 修改原因：斜杠命令只保留内置命令，skills 改用 @ 引用
def build_slash_palette_entries(prefix: str = "") -> list[tuple[str, str]]:
    """Return command-palette entries for built-in slash commands only (no skills)."""
    normalized = prefix.strip().lower()
    entries: list[tuple[str, str]] = []

    for cmd, desc in SLASH_COMMANDS.items():
        if normalized and not cmd.startswith(normalized):
            continue
        entries.append((cmd, desc))

    return entries


def _build_slash_completer() -> Any:
    from prompt_toolkit.completion import Completer, Completion

    class _SlashCompleter(Completer):
        def get_completions(self, document, complete_event):
            pass  # async path is used instead

        async def get_completions_async(self, document, _complete_event):
            text = document.text_before_cursor
            if not text.startswith("/"):
                return

            if text.startswith("/."):
                word = text[2:]
                if " " in word:
                    return
                for skill in complete_flag_skills(word):
                    start_position = -len(word) if word else 0
                    yield Completion(
                        skill.name,
                        start_position=start_position,
                        display=[
                            (f"fg:{C_PRIMARY} bold", f"/.{skill.name}"),
                            ("", "  "),
                            (f"fg:{C_MUTED}", skill.summary),
                        ],
                    )
                return

            word = text.lstrip("/")

            if not word:
                for cmd, desc in build_slash_palette_entries():
                    yield Completion(
                        cmd,
                        start_position=0,
                        display=[(f"fg:{C_PRIMARY} bold", f"/{cmd}"), ("", "  "), (f"fg:{C_MUTED}", desc)],
                    )
                return

            parts = word.split(maxsplit=1)
            typed_cmd = parts[0]

            if len(parts) == 1 and not text.endswith(" "):
                for cmd, desc in build_slash_palette_entries(typed_cmd):
                    yield Completion(
                        cmd,
                        start_position=-len(typed_cmd),
                        display=[(f"fg:{C_PRIMARY} bold", f"/{cmd}"), ("", "  "), (f"fg:{C_MUTED}", desc)],
                    )

    return _SlashCompleter()


# [新增] 2026-07-08 Nyaecho - 新增 @ 补全器，支持任意位置触发 skill 资料引用补全
def _build_at_completer() -> Any:
    from prompt_toolkit.completion import Completer, Completion

    class _AtCompleter(Completer):
        def get_completions(self, document, complete_event):
            pass  # async path is used instead

        async def get_completions_async(self, document, _complete_event):
            text = document.text
            cursor = document.cursor_position
            ctx = find_at_context(text, cursor)
            if ctx is None:
                return

            _, word = ctx
            for name, desc in build_at_palette_entries(word):
                start_position = -len(word) if word else 0
                yield Completion(
                    name,
                    start_position=start_position,
                    display=[
                        (f"fg:{C_PRIMARY} bold", f"@{name}"),
                        ("", "  "),
                        (f"fg:{C_MUTED}", desc),
                    ],
                )

    return _AtCompleter()


def build_repl_slash_completer() -> Any:
    """Completer for the classic REPL: ``/`` lists commands+skills, ``/.`` flag skills.

    The ``/`` menu offers the classic REPL's built-in commands (``/config``,
    ``/language``) followed by skills. The Textual TUI's other slash commands
    (``/mode`` etc.) are still excluded — they have no handler here.
    """
    from prompt_toolkit.completion import Completer, Completion

    class _ReplSlashCompleter(Completer):
        def get_completions(self, document, _complete_event):
            text = document.text_before_cursor
            if not text.startswith("/"):
                return

            if text.startswith("/."):
                word = text[2:]
                if " " in word:
                    return
                for skill in complete_flag_skills(word):
                    start_position = -len(word) if word else 0
                    yield Completion(
                        skill.name,
                        start_position=start_position,
                        display=[
                            (f"fg:{C_PRIMARY} bold", f"/.{skill.name}"),
                            ("", "  "),
                            (f"fg:{C_MUTED}", skill.summary),
                        ],
                    )
                return

            word = text[1:]
            if " " in word:
                # A command/skill is already chosen; the rest is free-text input.
                return
            for name, desc in list_repl_palette_entries(word):
                start_position = -len(word) if word else 0
                yield Completion(
                    name,
                    start_position=start_position,
                    display=[
                        (f"fg:{C_PRIMARY} bold", f"/{name}"),
                        ("", "  "),
                        (f"fg:{C_MUTED}", desc),
                    ],
                )

    return _ReplSlashCompleter()


def slash_completion_style_rules() -> dict[str, str]:
    """Prompt_toolkit completion styles that inherit the terminal background."""
    return {
        "completion-menu": "bg:default",
        "completion-menu.completion": "bg:default",
        "completion-menu.completion.current": f"fg:{C_PRIMARY} bg:default bold noreverse",
        "completion-menu.meta.completion": f"fg:{C_MUTED} bg:default",
        "completion-menu.meta.completion.current": f"fg:{C_MUTED} bg:default noreverse",
        "completion-menu.multi-column-meta": f"fg:{C_MUTED} bg:default",
        "completion-toolbar": "bg:default",
        "completion-toolbar.arrow": "bg:default",
        "completion-toolbar.completion": "bg:default",
        "completion-toolbar.completion.current": f"fg:{C_PRIMARY} bg:default bold noreverse",
        "scrollbar.background": "",
        "scrollbar.button": f"fg:{C_BORDER_SUBTLE}",
    }


def build_repl_slash_style() -> Any:
    """Style classic REPL slash completions without forcing a menu background."""
    from prompt_toolkit.styles import Style

    return Style.from_dict(slash_completion_style_rules())


@dataclass
class ReplSlashResult:
    """Outcome of dispatching a ``/`` line in the classic REPL.

    ``kind`` is one of:
    - ``"run"``     — feed ``text`` to the agent as a natural-language prompt.
    - ``"message"`` — print ``text`` and keep looping.
    - ``"target"``  — set the REPL target to ``value`` (restore behaviour), then loop.
    - ``"command"`` — run built-in command ``value`` with arguments ``text``.
    """

    kind: Literal["run", "message", "target", "command"]
    text: str = ""
    value: str = ""


def dispatch_repl_slash(text: str) -> ReplSlashResult:
    """Resolve a ``/`` or ``/.`` line into a request for the classic REPL.

    Pure: performs no I/O and mutates no state, so the loop stays in control of
    printing and target restoration. See :class:`ReplSlashResult`.
    """
    stripped = text.strip()

    if stripped.startswith("/."):
        return _dispatch_repl_flag_skill(stripped)

    body = stripped[1:].strip()
    if not body:
        return ReplSlashResult("message", "Type a skill name after '/', e.g. /recon <task>.")

    parts = body.split(maxsplit=1)
    name = parts[0]
    task = parts[1].strip() if len(parts) > 1 else ""

    # Built-in REPL commands (/config, /language) take precedence over skills.
    command = _resolve_repl_command(name)
    if command:
        return ReplSlashResult("command", value=command, text=task)

    skill = load_skill_by_name(name)
    if skill is None:
        return ReplSlashResult("message", f"Unknown skill: /{name}")

    if task:
        return ReplSlashResult("run", f"Use VulnClaw skill {skill['name']}. {task}")

    return ReplSlashResult("message", render_slash_skill_help(skill))


def _dispatch_repl_flag_skill(text: str) -> ReplSlashResult:
    """Light (B1) flag-skill wiring for the classic REPL.

    Only ``--target`` and ``--resume``/``--no-resume`` change REPL state; every
    other flag skill is rendered as guidance, since the classic REPL keeps no
    persistent mode/scope to apply them to.
    """
    command = parse_flag_skill_command(text)
    skill = find_flag_skill(command.query)
    if skill is None:
        return ReplSlashResult("message", f"Unknown flag skill: /.{command.query}")

    if skill.tui_action == "target":
        if not command.value:
            return ReplSlashResult("message", f"{skill.canonical} needs a host value, e.g. /.target example.com")
        return ReplSlashResult("target", value=command.value)

    # Everything else (mode/scope/action flags, resume, and guidance-only flags)
    # has no persistent home in the classic REPL, so we render it as guidance.
    return ReplSlashResult("message", render_flag_skill(skill))


def _dispatch_slash(text: str, session: dict[str, Any]) -> None:
    if text.startswith("/."):
        _dispatch_flag_skill(text, session)
        return

    parts = text.lstrip("/").strip().split(maxsplit=1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    handler = _SLASH_HANDLERS.get(cmd)
    if handler:
        handler(session, args)
    elif not dispatch_skill_slash_command(cmd, args, session):
        session["_message"] = f"Unknown command: /{cmd}"


_SLASH_HANDLERS: dict[str, Callable[[dict[str, Any], str], None]] = {}


def _register_handler(cmd: str):
    def deco(fn: Callable[[dict[str, Any], str], None]):
        _SLASH_HANDLERS[cmd] = fn
        return fn
    return deco


def _dispatch_flag_skill(text: str, session: dict[str, Any]) -> None:
    command = parse_flag_skill_command(text)
    skill = find_flag_skill(command.query)
    if skill is None:
        session["_message"] = f"Unknown flag skill: /.{command.query}"
        return

    if command.value or skill.tui_action in {"resume_true", "resume_false"}:
        result = apply_flag_skill_to_tui_state(skill, command.value, session["state"])
        if result.applied or result.error:
            session["_message"] = result.message
            return

    _set_prompt_message(session, render_flag_skill_compact(skill))

def dispatch_skill_slash_command(cmd: str, args: str, session: dict[str, Any]) -> bool:
    """Dispatch `/skill-name [task text]` commands from the TUI."""
    skill = load_skill_by_name(cmd)
    if skill is None:
        return False

    if args:
        state: TuiState = session["state"]
        if not state.target.strip():
            # Skills that need a preset target still warn when none is set.
            if skill.get("requires_target", True):
                session["_message"] = _("tui.please_set_target")
                return True
            # Self-discovering skills (frontmatter ``requires_target: false``,
            # e.g. ``hackerone``) derive their target from ``args`` — a scope
            # link. Adopt it as the draft target so the launched subprocess
            # records a real target instead of the ``<target>`` placeholder.
            state.target = args.strip()
        prompt = f"Use VulnClaw skill {skill['name']}. {args.strip()}"
        session["_nl_text"] = prompt
        session["_nl_history"] = prompt
        session["_action"] = "launch"
        return True

    _set_prompt_message(session, render_slash_skill_help(skill))
    return True


def render_slash_skill_help(skill: dict[str, Any]) -> str:
    """Render compact help for a selected slash skill."""
    refs = skill.get("references", [])
    lines = [
        f"/{skill['name']} skill",
        skill_display_description(skill) or "No description available.",
        f"Format: {skill.get('format', 'unknown')}",
    ]
    if refs:
        ref_list = ", ".join(refs[:5])
        if len(refs) > 5:
            ref_list += f", ... ({len(refs)} total)"
        lines.append(f"References: {ref_list}")
    lines.append(f"Run with this skill: /{skill['name']} <task>")
    return " | ".join(lines)


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

    _set_prompt_input(session, _("tui.prompt_target"), _on_value, default=state.target)


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

    _set_prompt_choice(session, _("tui.prompt_select_mode"), choices, _on_choice)


@_register_handler("scope")
@_register_handler("s")
def _cmd_scope(session: dict[str, Any], args: str) -> None:
    state: TuiState = session["state"]
    if args:
        _parse_scope_args(state, args)
        return
    fields = [
        ("only_host", _("tui.prompt_only_host"), state.only_host or ""),
        ("only_port", _("tui.prompt_only_port"), state.only_port),
        ("only_path", _("tui.prompt_only_path"), state.only_path or ""),
        ("blocked_host", _("tui.prompt_blocked_host"), state.blocked_host or ""),
        ("blocked_path", _("tui.prompt_blocked_path"), state.blocked_path or ""),
        ("__allow_actions", _("tui.prompt_allowed_actions"), ",".join(state.allow_actions)),
        ("__block_actions", _("tui.prompt_blocked_actions"), ",".join(state.block_actions)),
    ]

    def _on_resume_confirm(yes: bool) -> None:
        state.resume = yes

    def _ask_resume() -> None:
        _set_prompt_confirm(session, _("tui.prompt_resume", state=_("tui.on") if state.resume else _("tui.off")), _on_resume_confirm)

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


_SUPPORTED_LANGUAGES = ["auto", "zh", "en"]


def _get_language_labels() -> dict[str, str]:
    """Return {lang_key: translated_label} for supported languages."""
    return {c: _(f"tui.language_{c}") for c in _SUPPORTED_LANGUAGES}


@_register_handler("config")
@_register_handler("cfg")
def _cmd_config(session: dict[str, Any], args: str) -> None:
    # [修改] 2026-07-08 Nyaecho - 修改原因：custom 提供商新增 Base URL 输入步骤
    # 流程：选择提供商 → (custom) 输入 Base URL → 输入 API Key → 获取模型列表 → 选择/输入模型
    config = session["config"]
    providers = [item["provider"] for item in list_providers()]
    current_provider = config.llm.provider

    def _on_provider(value: str) -> None:
        if value and value != current_provider:
            nonlocal config
            session["config"] = apply_provider_preset(config, value)
            config = session["config"]
        # custom 提供商需要先输入 Base URL
        if value == "custom":
            _set_prompt_input(session,
                            _("tui.prompt_enter_baseurl", url=config.llm.base_url or ""),
                            _on_baseurl)
        else:
            # 非 custom：直接输入 API Key
            key_status = _("tui.api_key_configured") if config.llm.key_pool() else _("tui.api_key_not_configured")
            if config.llm.provider == "openrouter":
                key_status = f"{key_status}. {_('tui.openrouter_warning')}"
            _set_prompt_input(session, _("tui.prompt_enter_apikey", status=key_status), _on_apikey)

    def _on_baseurl(value: str) -> None:
        if value:
            config.llm.base_url = value.strip()
        # 输入完 Base URL 后继续输入 API Key
        key_status = _("tui.api_key_configured") if config.llm.api_key else _("tui.api_key_not_configured")
        _set_prompt_input(session, _("tui.prompt_enter_apikey", status=key_status), _on_apikey)

    def _on_apikey(value: str) -> None:
        if value:
            config.llm.api_key = value.strip()
        base_url = config.llm.base_url
        api_key = config.llm.primary_key()
        # 缺少 base_url/api_key 时跳过获取，直接手动输入
        if not base_url or not api_key:
            _set_prompt_input(session, _("tui.prompt_enter_model_fallback", model=config.llm.model), _on_model_input, default=config.llm.model)
            return
        # prompt_toolkit 版本：同步获取模型列表
        _set_prompt_message(session, _("tui.fetching_models"))
        # Note: 在 prompt_toolkit 同步循环中，消息不会立即渲染
        # 直接同步获取模型列表
        result = discover_provider_models(
            base_url,
            api_key,
            provider=config.llm.provider,
        )
        if result.models:
            _set_prompt_choice(session, _("tui.prompt_select_model", model=config.llm.model), result.models, _on_model_selected)
        else:
            fallback = (
                f"{_model_discovery_failure_message(result)} "
                f"{_('tui.prompt_enter_model_fallback', model=config.llm.model)}"
            )
            _set_prompt_input(session, fallback, _on_model_input, default=config.llm.model)

    def _on_model_selected(value: str) -> None:
        if value:
            config.llm.model = value.strip()
        save_config(config)
        _set_prompt_message(session, f"{_('tui.config_saved')}: {config.llm.provider}/{config.llm.model}")

    def _on_model_input(value: str) -> None:
        if value:
            config.llm.model = value.strip()
        save_config(config)
        _set_prompt_message(session, f"{_('tui.config_saved')}: {config.llm.provider}/{config.llm.model}")

    _set_prompt_choice(session, _("tui.prompt_select_provider", provider=current_provider), providers, _on_provider)


@_register_handler("language")
@_register_handler("lang")
def _cmd_language(session: dict[str, Any], args: str) -> None:
    lang = args.strip().lower() if args else ""
    if lang in ("auto", "zh", "en"):
        _apply_language_pt(session, lang)
    else:
        choices = list(_SUPPORTED_LANGUAGES)
        labels = _get_language_labels()
        choice_labels = [labels[c] for c in choices]

        def _on_choice(value: str) -> None:
            idx = choice_labels.index(value) if value in choice_labels else 0
            _apply_language_pt(session, choices[idx])

        _set_prompt_choice(session, _("tui.prompt_select_language"), choice_labels, _on_choice)


def _apply_language_pt(session: dict[str, Any], lang: str) -> None:
    """Apply language switch (prompt_toolkit backend)."""
    session["config"].session.language = lang
    save_config(session["config"])
    init_i18n(lang=lang if lang != "auto" else None, config=session["config"])
    rebuild_translations()

    lang_labels = _get_language_labels()
    session["_message"] = _("tui.language_switched", lang=lang_labels.get(lang, lang))


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
        # 修改者: Nyaecho
        # 修改时间: 2026-07-08
        # 修改原因: V6 修复 — 从 mcp/diagnostics 导入，消除 CLI→Web 依赖。
        from vulnclaw.mcp.diagnostics import get_mcp_diagnostics

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
        raise ValueError(_("tui.error_invalid_port")) from exc
    if port < 1 or port > 65535:
        raise ValueError(_("tui.error_invalid_port"))
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


def _build_task_summary_panel(draft: TuiTaskDraft, *, title: str | None = None) -> Panel:
    if title is None:
        title = _("tui.launch_summary_title")
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


# ── Interactive config editor ──────────────────────────────────────
# [新增] 从 VulnBot 移植的交互式配置编辑器, 适配 VulnClaw 的 schema
# (新增 recon 分区, api_key 掩码, 三种 MCP transport, OAuth 字段只读)


class _ConfigTuiExit(Exception):
    """Raised when the interactive config editor should return immediately."""


def _is_escape_input(value: str) -> bool:
    return value == "\x1b"


def _read_config_prompt_raw(
    label: str,
    *,
    default: str = "",
    choices: list[str] | None = None,
    console: Console | None = None,
) -> str:
    """Read config-editor input, letting a bare Escape cancel immediately."""
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            from prompt_toolkit import prompt
            from prompt_toolkit.completion import WordCompleter
            from prompt_toolkit.key_binding import KeyBindings
        except Exception:
            pass
        else:
            kb = KeyBindings()

            @kb.add("escape", eager=True)
            def _escape(event: Any) -> None:
                event.app.exit(result="\x1b")

            hint = ""
            if choices:
                hint += f" ({'/'.join(choices)})"
            if default:
                hint += f" [{default}]"
            completer = WordCompleter(choices or [], ignore_case=True) if choices else None
            return prompt(
                f"{label}{hint}: ",
                default=default,
                completer=completer,
                complete_while_typing=bool(completer),
                key_bindings=kb,
            )

    value = Prompt.ask(label, default=default, choices=choices, console=console).strip()
    if _is_escape_input(value):
        raise _ConfigTuiExit
    return value


def _config_prompt_ask(
    screen: Console,
    label: str,
    *,
    default: str = "",
    choices: list[str] | None = None,
) -> str:
    """Prompt inside the config editor, with Escape mapped to editor exit."""
    while True:
        value = _read_config_prompt_raw(
            label,
            default=default,
            choices=choices,
            console=screen,
        ).strip()
        if _is_escape_input(value):
            raise _ConfigTuiExit
        if not choices or value in choices:
            return value
        screen.print(f"[{C_ERROR}]Choose one of: {', '.join(choices)}[/]")


def _config_confirm_ask(screen: Console, label: str, *, default: bool = False) -> bool:
    """Confirm inside the config editor, with Escape mapped to editor exit."""
    default_text = "y" if default else "n"
    while True:
        value = _config_prompt_ask(screen, label, default=default_text).lower()
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False
        screen.print(f"[{C_ERROR}]Enter y or n.[/]")


def _split_csv_items(raw: str) -> list[str]:
    """Split a comma/newline separated string into cleaned items."""
    return [item.strip() for item in raw.replace("\n", ",").split(",") if item.strip()]


def _mask_secret(value: str) -> str:
    """Mask a secret so only a hint of it reaches the terminal."""
    value = (value or "").strip()
    if not value:
        return "(not set)"
    if len(value) <= 8:
        return "…" + value[-2:]
    return f"{value[:2]}…{value[-4:]}"


def _mask_key_list(keys: list[str]) -> str:
    """Summarise a list of API keys without printing any in the clear."""
    usable = [k for k in keys if k and k.strip()]
    if not usable:
        return "(none)"
    return f"{_mask_secret(usable[0])} ({len(usable)} key{'s' if len(usable) != 1 else ''})"


def _prompt_text_value(screen: Console, label: str, current: str) -> str:
    """Prompt for a string value, keeping the current value on blank input."""
    raw = _config_prompt_ask(screen, label, default=current)
    if raw == "!clear":
        return ""
    return current if raw == "" else raw


def _prompt_choice_value(screen: Console, label: str, choices: list[str], current: str) -> str:
    """Prompt for a choice value with a stable default."""
    default = current if current in choices else choices[0]
    return _config_prompt_ask(screen, label, choices=choices, default=default)


def _prompt_bool_value(screen: Console, label: str, current: bool) -> bool:
    """Prompt for a boolean value."""
    return _config_confirm_ask(screen, label, default=current)


def _prompt_int_value(screen: Console, label: str, current: int) -> int:
    """Prompt for an integer value, keeping the current value on blank input."""
    while True:
        raw = _config_prompt_ask(screen, label, default=str(current))
        if not raw:
            return current
        try:
            return int(raw)
        except ValueError:
            screen.print(f"[{C_ERROR}]Enter a whole number.[/]")


def _prompt_float_value(screen: Console, label: str, current: float) -> float:
    """Prompt for a float value, keeping the current value on blank input."""
    while True:
        raw = _config_prompt_ask(screen, label, default=str(current))
        if not raw:
            return current
        try:
            return float(raw)
        except ValueError:
            screen.print(f"[{C_ERROR}]Enter a number.[/]")


def _prompt_list_value(screen: Console, label: str, current: list[str]) -> list[str]:
    """Prompt for a comma-separated list value."""
    raw = _config_prompt_ask(screen, label, default=", ".join(current))
    if raw == "!clear":
        return []
    if not raw:
        return current
    return _split_csv_items(raw)


def _prompt_env_value(
    screen: Console, label: str, current: dict[str, str] | None
) -> dict[str, str]:
    """Prompt for key=value pairs separated by commas."""
    current_text = ", ".join(f"{k}={v}" for k, v in sorted((current or {}).items()))
    raw = _config_prompt_ask(screen, label, default=current_text)
    if raw == "!clear":
        return {}
    if not raw:
        return current or {}

    result: dict[str, str] = {}
    for item in _split_csv_items(raw):
        if "=" not in item:
            raise ValueError("Environment entries must look like KEY=value")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("Environment keys cannot be blank")
        result[key] = value.strip()
    return result


def _prompt_secret_text_value(screen: Console, label: str, current: str) -> str:
    """Prompt for a secret value without putting the current secret in the input buffer."""
    status = _mask_secret(current)
    raw = _config_prompt_ask(screen, f"{label} [{status}]", default="")
    if raw == "!clear":
        return ""
    return current if raw == "" else raw


def _prompt_secret_list_value(screen: Console, label: str, current: list[str]) -> list[str]:
    """Prompt for comma-separated secrets without printing existing values."""
    status = _mask_key_list(current)
    raw = _config_prompt_ask(screen, f"{label} [{status}]", default="")
    if raw == "!clear":
        return []
    if not raw:
        return current
    return _split_csv_items(raw)


def _render_model_choices(screen: Console, models: list[str], current: str) -> None:
    table = Table(title="Available Models", box=box.ROUNDED, border_style=C_BORDER_SUBTLE)
    table.add_column("#", style=f"bold {C_PRIMARY}", width=4)
    table.add_column("Model", style=C_TEXT)
    for idx, model in enumerate(models, 1):
        marker = " *" if model == current else ""
        table.add_row(str(idx), f"{model}{marker}")
    screen.print(table)


def _prompt_model_value(screen: Console, config) -> str:
    """Prompt for an LLM model, showing provider models when credentials can fetch them."""
    current = config.llm.model
    discovery: ProviderModelDiscoveryResult | None = None
    models: list[str] = []
    base_url = config.llm.base_url
    api_key = config.llm.primary_key()

    if base_url and api_key:
        screen.print(f"[{C_MUTED}]{_('tui.fetching_models')}[/]")
        discovery = discover_provider_models(
            base_url,
            api_key,
            provider=config.llm.provider,
        )
        models = discovery.models

    if models:
        if current and current not in models:
            screen.print(
                f"[{C_WARNING}]"
                f"{_('tui.model_discovery_selected_incompatible')}[/]"
            )
        _render_model_choices(screen, models, current)
        raw = _config_prompt_ask(screen, f"Model [current: {current}]", default="")
        if not raw:
            return current
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(models):
                return models[idx - 1]
            screen.print(f"[{C_WARNING}]Model number out of range; using '{raw}' as a custom model id.[/]")
        return raw

    if discovery is not None:
        screen.print(
            f"[{C_WARNING}]{_model_discovery_failure_message(discovery)}[/]"
        )
    raw = _config_prompt_ask(screen, f"Model [current: {current}]", default="")
    if raw == "!clear":
        return ""
    return current if raw == "" else raw


def _render_config_summary(screen: Console, config) -> None:
    """Render a compact summary of the editable config sections."""
    llm = Table(title="LLM", box=box.ROUNDED, border_style=C_BORDER_SUBTLE)
    llm.add_column("Field", style=f"bold {C_PRIMARY}")
    llm.add_column("Value", style=C_TEXT)
    llm.add_row("Provider", config.llm.provider)
    llm.add_row("Model", config.llm.model)
    llm.add_row("Base URL", config.llm.base_url)
    llm.add_row("Auth mode", config.llm.auth_mode)
    llm.add_row("API key", _mask_secret(config.llm.api_key))
    llm.add_row("API keys", _mask_key_list(config.llm.api_keys))
    llm.add_row("ChatGPT auto-proxy", "yes" if config.llm.chatgpt_auto_proxy else "no")
    llm.add_row("OAuth token URL", config.llm.oauth_token_url or "(login-managed)")
    llm.add_row("OAuth client id", config.llm.oauth_client_id or "(login-managed)")
    llm.add_row("Reasoning", config.llm.reasoning_effort)

    session = Table(title="Session", box=box.ROUNDED, border_style=C_BORDER_SUBTLE)
    session.add_column("Field", style=f"bold {C_SECONDARY}")
    session.add_column("Value", style=C_TEXT)
    session.add_row("Output dir", str(config.session.output_dir))
    session.add_row("Engine", config.session.engine)
    session.add_row("Max rounds", str(config.session.max_rounds))
    session.add_row("Report format", config.session.report_format)
    session.add_row("PoC language", config.session.poc_language)
    session.add_row("Language", config.session.language)
    session.add_row("Show thinking", "yes" if config.session.show_thinking else "no")
    session.add_row("Persistent cycles", str(config.session.persistent_max_cycles))

    safety = Table(title="Safety", box=box.ROUNDED, border_style=C_BORDER_SUBTLE)
    safety.add_column("Field", style=f"bold {C_ACCENT}")
    safety.add_column("Value", style=C_TEXT)
    safety.add_row("Python execute", "yes" if config.safety.enable_python_execute else "no")
    safety.add_row("Restricted", "yes" if config.safety.python_execute_restricted else "no")
    safety.add_row("Mode", config.safety.python_execute_mode)
    safety.add_row("Parallel tools", "yes" if config.safety.tool_parallel else "no")

    recon = Table(title="Recon", box=box.ROUNDED, border_style=C_BORDER_SUBTLE)
    recon.add_column("Field", style=f"bold {C_PRIMARY}")
    recon.add_column("Value", style=C_TEXT)
    recon.add_row("FOFA email", config.recon.fofa_email or "(not set)")
    recon.add_row("FOFA key", _mask_secret(config.recon.fofa_key))
    recon.add_row("Hunter key", _mask_secret(config.recon.hunter_key))
    recon.add_row("Quake key", _mask_secret(config.recon.quake_key))
    recon.add_row("ZoomEye key", _mask_secret(config.recon.zoomeye_key))
    recon.add_row("Shodan key", _mask_secret(config.recon.shodan_key))
    recon.add_row("0.zone key", _mask_secret(config.recon.zerozone_key))
    recon.add_row("Max concurrency", str(config.recon.max_concurrency))

    mcp = Table(title="MCP Servers", box=box.ROUNDED, border_style=C_BORDER_SUBTLE)
    mcp.add_column("Name", style=f"bold {C_PRIMARY}")
    mcp.add_column("Status", style=C_TEXT)
    mcp.add_column("Transport", style=C_MUTED)
    for name, server in config.mcp.servers.items():
        transport = server.transport
        if transport.type == "stdio":
            details = " ".join(
                part for part in [transport.command or "", " ".join(transport.args or [])] if part
            ).strip()
            summary = f"stdio {details}".strip()
        else:
            summary = f"{transport.type} {transport.url or ''}".strip()
        status = "enabled" if server.enabled else "disabled"
        if name in BUILTIN_MCP_SERVERS:
            status += ", builtin"
        mcp.add_row(name, status, summary)

    screen.print(
        Panel(
            Group(llm, session, safety, recon, mcp),
            title="Config Draft",
            border_style=C_BORDER,
            box=box.ROUNDED,
        )
    )


def _edit_llm_config(screen: Console, config):
    """Edit LLM configuration fields in-place."""
    screen.print(Panel("Edit LLM settings", border_style=C_BORDER_SUBTLE, box=box.ROUNDED))
    providers = [item["provider"] for item in list_providers()]
    provider = _prompt_choice_value(screen, "Provider", providers, config.llm.provider)
    if provider != config.llm.provider:
        config = apply_provider_preset(config, provider)

    config.llm.base_url = _prompt_text_value(screen, "Base URL", config.llm.base_url)
    is_openrouter = config.llm.provider == "openrouter"
    if is_openrouter:
        config.llm.auth_mode = "static"
        config.llm.chatgpt_auto_proxy = False
        screen.print(
            f"[{C_MUTED}]OpenRouter uses static inference keys; OAuth and "
            "the ChatGPT auto-proxy are disabled.[/]"
        )
    else:
        config.llm.auth_mode = _prompt_choice_value(
            screen, "Auth mode", ["static", "oauth"], config.llm.auth_mode
        )
    config.llm.api_keys = _prompt_secret_list_value(
        screen,
        "API keys (comma-separated, !clear to empty)",
        config.llm.api_keys,
    )
    config.llm.api_key = _prompt_secret_text_value(
        screen,
        "Single API key fallback (!clear to empty)",
        config.llm.api_key,
    )
    config.llm.model = _prompt_model_value(screen, config)
    if not is_openrouter:
        config.llm.chatgpt_auto_proxy = _prompt_bool_value(
            screen, "ChatGPT auto-proxy", config.llm.chatgpt_auto_proxy
        )
    config.llm.max_tokens = _prompt_int_value(screen, "Max tokens", config.llm.max_tokens)
    config.llm.max_context_tokens = _prompt_int_value(
        screen, "Max context tokens", config.llm.max_context_tokens
    )
    config.llm.temperature = _prompt_float_value(screen, "Temperature", config.llm.temperature)
    config.llm.reasoning_effort = _prompt_text_value(
        screen, "Reasoning effort", config.llm.reasoning_effort
    )
    screen.print(
        f"[{C_MUTED}]OAuth endpoints are managed by `vulnclaw login` and are not edited here.[/]"
    )
    return config


def _edit_session_config(screen: Console, config):
    """Edit the commonly-tuned session fields in-place.

    Deep engine/reflexion/plugin knobs are left to `vulnclaw config set`.
    """
    screen.print(Panel("Edit session settings", border_style=C_BORDER_SUBTLE, box=box.ROUNDED))
    config.session.output_dir = Path(
        _prompt_text_value(screen, "Output directory", str(config.session.output_dir))
    )
    config.session.auto_save = _prompt_bool_value(screen, "Auto save", config.session.auto_save)
    config.session.report_format = _prompt_choice_value(
        screen, "Report format", ["markdown", "html"], config.session.report_format
    )
    config.session.poc_language = _prompt_choice_value(
        screen, "PoC language", ["python", "bash"], config.session.poc_language
    )
    config.session.engine = _prompt_choice_value(
        screen, "Autonomous engine", ["solve", "team", "rounds"], config.session.engine
    )
    config.session.max_rounds = _prompt_int_value(screen, "Max rounds", config.session.max_rounds)
    config.session.show_thinking = _prompt_bool_value(
        screen, "Show thinking", config.session.show_thinking
    )
    config.session.persistent_rounds_per_cycle = _prompt_int_value(
        screen, "Persistent rounds per cycle", config.session.persistent_rounds_per_cycle
    )
    config.session.persistent_max_cycles = _prompt_int_value(
        screen, "Persistent max cycles", config.session.persistent_max_cycles
    )
    config.session.persistent_auto_report = _prompt_bool_value(
        screen, "Persistent auto report", config.session.persistent_auto_report
    )
    config.session.language = _prompt_choice_value(
        screen, "Language", ["auto", "en", "zh"], config.session.language
    )
    return config


def _edit_safety_config(screen: Console, config):
    """Edit safety configuration fields in-place."""
    screen.print(Panel("Edit safety settings", border_style=C_BORDER_SUBTLE, box=box.ROUNDED))
    config.safety.enable_python_execute = _prompt_bool_value(
        screen, "Enable python execute", config.safety.enable_python_execute
    )
    config.safety.python_execute_restricted = _prompt_bool_value(
        screen, "Python execute restricted", config.safety.python_execute_restricted
    )
    config.safety.python_execute_mode = _prompt_choice_value(
        screen,
        "Python execute mode",
        ["safe", "lab", "trusted-local"],
        config.safety.python_execute_mode,
    )
    config.safety.python_execute_max_lines = _prompt_int_value(
        screen, "Python execute max lines", config.safety.python_execute_max_lines
    )
    config.safety.python_execute_show_warning = _prompt_bool_value(
        screen, "Show python execute warning", config.safety.python_execute_show_warning
    )
    config.safety.python_execute_max_output_chars = _prompt_int_value(
        screen,
        "Python execute max output chars",
        config.safety.python_execute_max_output_chars,
    )
    config.safety.python_execute_audit_enabled = _prompt_bool_value(
        screen, "Python execute audit enabled", config.safety.python_execute_audit_enabled
    )
    config.safety.tool_parallel = _prompt_bool_value(
        screen, "Parallel tool calls", config.safety.tool_parallel
    )
    config.safety.tool_max_concurrent = _prompt_int_value(
        screen, "Max concurrent tools", config.safety.tool_max_concurrent
    )
    return config


def _edit_recon_config(screen: Console, config):
    """Edit recon / space-mapping configuration fields in-place."""
    screen.print(Panel("Edit recon settings", border_style=C_BORDER_SUBTLE, box=box.ROUNDED))
    config.recon.fofa_email = _prompt_text_value(
        screen, "FOFA email", config.recon.fofa_email
    )
    config.recon.fofa_key = _prompt_text_value(
        screen, "FOFA key (!clear to empty)", config.recon.fofa_key
    )
    config.recon.hunter_key = _prompt_text_value(
        screen, "Hunter key (!clear to empty)", config.recon.hunter_key
    )
    config.recon.quake_key = _prompt_text_value(
        screen, "Quake key (!clear to empty)", config.recon.quake_key
    )
    config.recon.zoomeye_key = _prompt_text_value(
        screen, "ZoomEye key (!clear to empty)", config.recon.zoomeye_key
    )
    config.recon.shodan_key = _prompt_text_value(
        screen, "Shodan key (!clear to empty)", config.recon.shodan_key
    )
    config.recon.zerozone_key = _prompt_text_value(
        screen, "0.zone key (!clear to empty)", config.recon.zerozone_key
    )
    config.recon.http_timeout = _prompt_float_value(
        screen, "HTTP timeout (s)", config.recon.http_timeout
    )
    config.recon.max_concurrency = _prompt_int_value(
        screen, "Max concurrency", config.recon.max_concurrency
    )
    config.recon.space_size = _prompt_int_value(
        screen, "Space-mapping result size", config.recon.space_size
    )
    config.recon.dir_wordlist_path = _prompt_text_value(
        screen, "Directory wordlist path (!clear to empty)", config.recon.dir_wordlist_path
    )
    config.recon.dir_max_requests = _prompt_int_value(
        screen, "Directory enumeration max requests", config.recon.dir_max_requests
    )
    config.recon.js_max_files = _prompt_int_value(
        screen, "Max JS files per js_recon", config.recon.js_max_files
    )
    return config


def _prompt_mcp_transport(screen: Console, transport: MCPTransportConfig) -> MCPTransportConfig:
    """Edit transport settings for an MCP server."""
    transport.type = _prompt_choice_value(
        screen, "Transport type", ["stdio", "sse", "streamable-http"], transport.type
    )
    transport.command = _prompt_text_value(screen, "Transport command", transport.command or "")
    transport.args = _prompt_list_value(
        screen,
        "Transport args (comma-separated, !clear to empty)",
        transport.args or [],
    )
    transport.url = _prompt_text_value(screen, "Transport URL", transport.url or "")
    transport.env = _prompt_env_value(
        screen, "Transport env / headers (KEY=value, !clear to empty)", transport.env
    )
    transport.startup_timeout = _prompt_int_value(
        screen, "Transport startup timeout", transport.startup_timeout
    )
    transport.tool_timeout = _prompt_int_value(
        screen, "Transport tool timeout", transport.tool_timeout
    )
    return transport


def _prompt_mcp_server(
    screen: Console, config, *, server: MCPServerConfig | None = None
) -> tuple[str, MCPServerConfig]:
    """Create or edit a single MCP server definition."""
    is_new = server is None
    current_name = server.name if server else ""
    while True:
        if is_new:
            name = _prompt_text_value(screen, "Server name", current_name)
            if not name:
                screen.print(f"[{C_ERROR}]Server name cannot be blank.[/]")
                continue
            if name in config.mcp.servers:
                screen.print(f"[{C_ERROR}]Server '{name}' already exists.[/]")
                continue
        else:
            name = current_name
        break

    current = server or MCPServerConfig(
        name=name,
        enabled=True,
        priority=1,
        transport=MCPTransportConfig(type="stdio"),
    )
    current.name = name
    current.enabled = _prompt_bool_value(screen, f"Enabled [{name}]", current.enabled)
    current.priority = _prompt_int_value(screen, f"Priority [{name}]", current.priority)
    current.description = _prompt_text_value(screen, f"Description [{name}]", current.description)
    current.transport = _prompt_mcp_transport(screen, current.transport)
    return name, current


def _edit_mcp_config(screen: Console, config):
    """Edit MCP server configuration."""
    while True:
        screen.print(Panel("Edit MCP servers", border_style=C_BORDER_SUBTLE, box=box.ROUNDED))
        table = Table(box=box.SIMPLE, border_style=C_BORDER_SUBTLE)
        table.add_column("Server", style=f"bold {C_PRIMARY}")
        table.add_column("Enabled", style=C_TEXT)
        table.add_column("Priority", style=C_TEXT)
        table.add_column("Transport", style=C_MUTED)
        for name, server in config.mcp.servers.items():
            marker = "builtin" if name in BUILTIN_MCP_SERVERS else "custom"
            table.add_row(
                name,
                "yes" if server.enabled else "no",
                str(server.priority),
                f"{server.transport.type} / {marker}",
            )
        screen.print(table)

        action = _prompt_choice_value(
            screen,
            "Action",
            ["add", "edit", "delete", "back"],
            "back",
        )

        if action == "back":
            return config
        if action == "add":
            name, server = _prompt_mcp_server(screen, config)
            config.mcp.servers[name] = server
            continue
        if action == "edit":
            if not config.mcp.servers:
                screen.print(f"[{C_WARNING}]No MCP servers to edit.[/]")
                continue
            name = _prompt_choice_value(
                screen,
                "Server to edit",
                list(config.mcp.servers.keys()),
                next(iter(config.mcp.servers)),
            )
            current = config.mcp.servers[name]
            _, server = _prompt_mcp_server(screen, config, server=current)
            config.mcp.servers[name] = server
            continue
        if action == "delete":
            if not config.mcp.servers:
                screen.print(f"[{C_WARNING}]No MCP servers to delete.[/]")
                continue
            name = _prompt_choice_value(
                screen,
                "Server to delete",
                list(config.mcp.servers.keys()),
                next(iter(config.mcp.servers)),
            )
            if name in BUILTIN_MCP_SERVERS:
                screen.print(
                    f"[{C_WARNING}]Built-in servers are seeded defaults and cannot be deleted here.[/]"
                )
                continue
            if _prompt_bool_value(screen, f"Delete MCP server '{name}'?", False):
                config.mcp.servers.pop(name, None)
            continue


def run_config_tui() -> None:
    """Run the interactive config editor."""
    screen = Console()
    config = load_config()

    try:
        while True:
            screen.print()
            screen.print(Panel("VulnClaw Config", border_style=C_BORDER, box=box.ROUNDED))
            _render_config_summary(screen, config)
            action = _prompt_choice_value(
                screen,
                "Section",
                ["llm", "session", "safety", "recon", "mcp", "save", "quit"],
                "save",
            )

            if action == "llm":
                config = _edit_llm_config(screen, config)
            elif action == "session":
                config = _edit_session_config(screen, config)
            elif action == "safety":
                config = _edit_safety_config(screen, config)
            elif action == "recon":
                config = _edit_recon_config(screen, config)
            elif action == "mcp":
                config = _edit_mcp_config(screen, config)
            elif action == "save":
                save_config(config)
                screen.print(Panel("Config saved.", border_style=C_SUCCESS, box=box.ROUNDED))
                return
            elif action == "quit":
                screen.print(Panel("Discarded changes.", border_style=C_WARNING, box=box.ROUNDED))
                return
    except _ConfigTuiExit:
        screen.print()
        screen.print(Panel("Discarded changes.", border_style=C_WARNING, box=box.ROUNDED))
        return
