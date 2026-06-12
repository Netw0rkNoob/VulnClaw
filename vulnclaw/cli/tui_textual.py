"""Textual-powered TUI workbench for VulnClaw."""

# [新增] 2026-06-10
# 目的: 用 Textual 框架构建现代化全屏 TUI 工作台, 替代旧的 Rich 数字菜单循环
# 实现:
#   - CommandPalette: slash 命令模糊搜索 + 键盘导航面板
#   - SecondaryPopup: 辅助信息弹窗(历史快照/诊断报告)
#   - DashboardScreen: 主导航仪表盘, 集成命令输入行与状态栏
#   - VulnClawApp: Textual App 入口, CSS 主题化样式
#   - run_tui_textual(): 事件循环入口, 支持 launch 动作后自动重新加载配置

from __future__ import annotations

import threading
from queue import Queue
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Key
from textual.screen import Screen
from textual.widgets import Input, ListItem, ListView, RichLog, Static

# [新增] 2026-06-10 Nyaecho - 自然语言驱动 / 响应式侧边栏: 新增颜色常量和动作辅助函数导入
from vulnclaw.cli.tui import (
    C_ACCENT,
    C_ERROR,
    C_MUTED,
    C_PRIMARY,
    C_SECONDARY,
    C_SUCCESS,
    C_TEXT,
    C_WARNING,
    MODES,
    SLASH_COMMANDS,
    TuiState,
    _default_launcher,
    _draft_from_state,
    _effective_allow_actions,
    _effective_block_actions,
    _parse_action_csv,
    _parse_optional_port,
    build_dashboard,
    build_runtime_diagnostic,
)
from vulnclaw.config.settings import apply_provider_preset, list_providers, load_config, save_config
from vulnclaw.i18n import _
from vulnclaw.target_state.store import get_target_state_preview, list_target_snapshots

# ── Slash dispatch ──

_SLASH_HANDLERS: dict[str, Any] = {}


def _register_handler(cmd: str):
    def deco(fn):
        _SLASH_HANDLERS[cmd] = fn
        return fn
    return deco


def _dispatch(session: dict[str, Any], text: str) -> str | None:
    """Dispatch slash command. Returns 'quit', 'launch', or None."""
    # [修改] 2026-06-10 Nyaecho - 修复空 parts 导致 IndexError 的问题
    parts = text.lstrip("/").strip().split(maxsplit=1)
    if not parts:
        return None
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    handler = _SLASH_HANDLERS.get(cmd)
    if handler:
        return handler(session, args)
    return None


def _set_prompt(session: dict[str, Any], ptype: str, *args: Any) -> None:
    session["_prompt"] = (ptype,) + args
    session["_show_popup"] = True


def _cancel_prompt(session: dict[str, Any]) -> None:
    prompt = session.get("_prompt")
    session["_prompt"] = None
    if prompt and prompt[0] == "chain":
        prompt[3]()


# ── Command palette widget ──

class CommandPalette(ListView):
    """Dropdown slash-command palette shown on '/' input."""

    def __init__(self, **kwargs: Any):
        kwargs.setdefault("id", "cmd-palette")
        super().__init__(**kwargs)
        self._commands: list[str] = []

    def show_commands(self, prefix: str = "") -> None:
        for item in self.query_children(ListItem):
            item.remove()
        self._commands.clear()
        for cmd, desc in SLASH_COMMANDS.items():
            if cmd.startswith(prefix):
                item = ListItem(Static(
                    f"[bold {C_PRIMARY}]/{cmd}[/]  [{C_MUTED}]{desc}[/]"
                ))
                self.mount(item)
                self._commands.append(cmd)
        if self._commands:
            self.add_class("open")
            self.index = 0

    def hide_palette(self) -> None:
        self.remove_class("open")
        for item in self.query_children(ListItem):
            item.remove()
        self._commands.clear()

    @property
    def selected(self) -> str | None:
        if self.index is not None and 0 <= self.index < len(self._commands):
            return self._commands[self.index]
        return None


# ── Secondary popup widget ──

class SecondaryPopup(Vertical):
    """Secondary popup for parameter input when a slash command needs arguments.

    Supports input / choice / confirm / message / chain modes.
    """

    def __init__(self, **kwargs: Any):
        kwargs.setdefault("id", "sec-popup")
        super().__init__(**kwargs)
        self._cb: Any = None
        self._ptype: str = ""
        self._choices: list[str] = []
        self._chain_fields: list = []
        self._chain_idx: int = 0
        self._session: dict[str, Any] | None = None
        self._on_done: Any = None

    def compose(self) -> ComposeResult:
        yield Static(id="popup-desc", markup=True)

    def show_for_prompt(self, session: dict[str, Any], *, on_done: Any = None) -> None:
        prompt = session.get("_prompt")
        if not prompt:
            return
        self._session = session
        self._on_done = on_done
        ptype = prompt[0]
        if ptype == "input":
            _, label, cb = prompt[:3]
            default = prompt[3] if len(prompt) > 3 else ""
            self._show_input(label, cb, default)
        elif ptype == "choice":
            _, label, choices, cb = prompt
            self._show_choice(label, choices, cb)
        elif ptype == "confirm":
            _, label, cb = prompt
            self._show_confirm(label, cb)
        elif ptype == "message":
            text = prompt[1]
            self._show_message(text)
        elif ptype == "chain":
            _, fields, idx, cb = prompt
            self._show_chain(fields, idx, cb)

    def _show_input(self, label: str, callback: Any, default: str) -> None:
        self._clear_dynamic()
        self._ptype = "input"
        self._cb = callback
        self.query_one("#popup-desc", Static).update(
            f"[bold {C_PRIMARY}]{label}[/]"
        )
        inp = Input(value=default, id="popup-input")
        self.mount(inp)
        self.add_class("open")
        inp.focus()

    def _show_choice(self, label: str, choices: list[str], callback: Any) -> None:
        self._clear_dynamic()
        self._ptype = "choice"
        self._cb = callback
        self._choices = choices
        self.query_one("#popup-desc", Static).update(
            f"[bold {C_PRIMARY}]{label}[/]"
        )
        items = [ListItem(Static(f"  {c}  ")) for c in choices]
        lv = ListView(*items, id="popup-list")
        self.mount(lv)
        self.add_class("open")
        lv.focus()

    def _show_confirm(self, label: str, callback: Any) -> None:
        self._clear_dynamic()
        self._ptype = "confirm"
        self._cb = callback
        self.query_one("#popup-desc", Static).update(
            f"[bold {C_PRIMARY}]{label}[/]"
        )
        hint = Static(
            f"  [{C_SUCCESS}]y[/] / [{C_ERROR}]n[/]  [/]",
            id="popup-hint",
        )
        self.mount(hint)
        self.add_class("open")
        self.focus()

    def _show_message(self, text: str) -> None:
        self._clear_dynamic()
        self._ptype = "message"
        self._cb = None
        self.query_one("#popup-desc", Static).update(
            f"[{C_MUTED}]{text}[/]"
        )
        hint = Static(
            f"  [{C_MUTED}]{_('tui.enter_to_dismiss')}[/]",
            id="popup-hint",
        )
        self.mount(hint)
        self.add_class("open")
        self.focus()

    def _show_chain(self, fields: list, idx: int, callback: Any) -> None:
        self._clear_dynamic()
        self._ptype = "chain"
        self._cb = callback
        self._chain_fields = fields
        self._chain_idx = idx
        self._render_chain_step()

    def _render_chain_step(self) -> None:
        idx = self._chain_idx
        fields = self._chain_fields
        if idx >= len(fields):
            cb = self._cb
            self._cb = None
            self._dismiss()
            if cb:
                cb()
            if self._on_done:
                on_done = self._on_done
                self._on_done = None
                on_done()
            return
        fld, fld_title, fld_default = fields[idx]
        self.query_one("#popup-desc", Static).update(
            f"[bold {C_PRIMARY}][{idx + 1}/{len(fields)}] {fld_title}[/]"
        )
        inp = Input(value=fld_default, id="popup-input")
        self.mount(inp)
        self.add_class("open")
        inp.focus()

    def _handle_chain_step(self, value: str) -> None:
        idx = self._chain_idx
        fields = self._chain_fields
        fld, fld_title, _default = fields[idx]
        if self._session:
            state = self._session["state"]
            if fld == "__allow_actions":
                state.allow_actions = _parse_action_csv(value) if value else []
            elif fld == "__block_actions":
                state.block_actions = _parse_action_csv(value) if value else []
            elif fld == "only_port":
                if value:
                    try:
                        _parse_optional_port(value)
                        state.only_port = value
                    except ValueError:
                        self.query_one("#popup-desc", Static).update(
                            f"[bold {C_ERROR}]{_('tui.invalid_port_label')}[/]\n  [{C_MUTED}]{fld_title}[/]"
                        )
                        inp = self.query_one("#popup-input", Input)
                        inp.value = ""
                        inp.focus()
                        return
                else:
                    state.only_port = ""
            else:
                setattr(state, fld, value if value else "")
        self._clear_dynamic()
        self._chain_idx += 1
        self._render_chain_step()

    def _resolve(self, value: Any = None) -> None:
        cb = self._cb
        self._cb = None
        self._dismiss()
        if cb:
            cb(value)
        if self._on_done:
            on_done = self._on_done
            self._on_done = None
            on_done()

    def _cancel(self) -> None:
        self._cb = None
        self._dismiss()
        if self._on_done:
            on_done = self._on_done
            self._on_done = None
            on_done()

    def _dismiss(self) -> None:
        self.remove_class("open")
        self._clear_dynamic()
        self._cb = None
        self._choices.clear()
        if self._session:
            self._session["_prompt"] = None
            self._session["_show_popup"] = False

    def _clear_dynamic(self) -> None:
        for w in self.query_children():
            if w.id not in ("popup-desc",):
                w.remove()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "popup-input":
            return
        value = (event.value or "").strip()
        event.stop()

        if self._ptype == "input":
            self._resolve(value if value else None)
        elif self._ptype == "chain":
            self._handle_chain_step(value)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id != "popup-list":
            return
        event.stop()
        index = event.list_view.index
        if index is not None and 0 <= index < len(self._choices):
            self._resolve(self._choices[index])

    def on_key(self, event: Key) -> None:
        if not self.has_class("open"):
            return
        if self._ptype == "confirm":
            if event.key in ("y", "Y"):
                event.stop()
                self._resolve(True)
            elif event.key in ("n", "N", "escape"):
                event.stop()
                self._resolve(False)
        elif self._ptype == "message":
            if event.key in ("enter", "escape"):
                event.stop()
                self._cancel()
        elif event.key == "escape":
            event.stop()
            self._cancel()


# ── Handlers ──

@_register_handler("quit")
@_register_handler("exit")
@_register_handler("q")
def _h_quit(session: dict[str, Any], args: str) -> str:
    return "quit"


@_register_handler("target")
@_register_handler("t")
def _h_target(session: dict[str, Any], args: str) -> str | None:
    state = session["state"]
    if args:
        state.target = args.strip()
        return None
    def cb(v): state.target = v if v else state.target
    _set_prompt(session, "input", _("tui.prompt_target"), cb, state.target)
    return None


@_register_handler("mode")
@_register_handler("m")
def _h_mode(session: dict[str, Any], args: str) -> str | None:
    state = session["state"]
    if args and args in MODES:
        state.mode = args
        return None
    def cb(v): state.mode = v
    _set_prompt(session, "choice", _("tui.prompt_select_mode"), list(MODES.keys()), cb)
    return None


@_register_handler("scope")
@_register_handler("s")
def _h_scope(session: dict[str, Any], args: str) -> str | None:
    # [修改] 2026-06-10 Nyaecho - 修复 /scope port 验证问题，添加端口验证防止 ValueError
    state = session["state"]
    if args:
        for pair in args.split():
            if "=" in pair:
                k, v = pair.split("=", 1)
                if k == "host":
                    state.only_host = v
                elif k == "port":
                    try:
                        _parse_optional_port(v)
                        state.only_port = v
                    except ValueError as e:
                        session["_message"] = str(e)
                        return None
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
        return None
    fields = [
        ("only_host", _("tui.prompt_only_host"), state.only_host or ""),
        ("only_port", _("tui.prompt_only_port"), state.only_port),
        ("only_path", _("tui.prompt_only_path"), state.only_path or ""),
        ("blocked_host", _("tui.prompt_blocked_host"), state.blocked_host or ""),
        ("blocked_path", _("tui.prompt_blocked_path"), state.blocked_path or ""),
        ("__allow_actions", _("tui.prompt_allowed_actions"), ",".join(state.allow_actions)),
        ("__block_actions", _("tui.prompt_blocked_actions"), ",".join(state.block_actions)),
    ]
    def on_resume(yes): state.resume = yes
    def ask(): _set_prompt(session, "confirm", _("tui.prompt_resume", state=_("tui.on") if state.resume else _("tui.off")), on_resume)
    _set_prompt(session, "chain", fields, 0, ask)
    return None


@_register_handler("run")
def _h_start(session: dict[str, Any], args: str) -> str | None:
    state = session["state"]
    if not state.target.strip():
        session["_message"] = _("tui.please_set_target")
        return None
    mode = MODES[state.mode]
    if args in ("-f", "--force"):
        return "launch"
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: /run <text> 将 text 作为 NL prompt 直接 launch
    if args:
        session["_nl_text"] = args
        session["_nl_history"] = args
        return "launch"
    if mode.needs_extra_confirm:
        def cb(yes):
            if yes:
                session["_action"] = "launch"
        _set_prompt(session, "confirm", _("tui.confirm_deep_mode", mode=mode.label), cb)
        return None
    return "launch"


@_register_handler("history")
@_register_handler("hist")
def _h_history(session: dict[str, Any], args: str) -> str | None:
    state = session["state"]
    target = args.strip() if args else state.target.strip()
    if not target:
        session["_message"] = _("tui.please_set_target")
        return None
    preview = get_target_state_preview(target)
    snapshots = list_target_snapshots(target)
    if preview is None:
        _set_prompt(session, "message", _("tui.no_history_for_target"))
    else:
        t = f"Target:{preview.get('target',target)} | Phase:{preview.get('phase','?')} | Findings:{preview.get('findings_count',0)} | Snap:{len(snapshots)}"
        _set_prompt(session, "message", t)
    return None


@_register_handler("report")
def _h_report(session: dict[str, Any], args: str) -> str | None:
    state = session["state"]
    target = args.strip() if args else state.target.strip()
    if not target:
        session["_message"] = _("tui.please_set_target")
        return None
    from vulnclaw.cli.main import _generate_report_for_target
    path = _generate_report_for_target(target)
    _set_prompt(session, "message", f"{_('tui.report_generated')}: {path}")
    return None


@_register_handler("diag")
@_register_handler("diagnostic")
def _h_diag(session: dict[str, Any], args: str) -> str | None:
    d = build_runtime_diagnostic(session["config"])
    t = f"Py:{d.python_version} Node:{d.node_version} npx:{d.npx_status} uvx:{d.uvx_status} API:{'yes' if d.api_key_configured else 'no'} MCP:{d.mcp_total_services}s/{d.mcp_tool_count}t"
    _set_prompt(session, "message", t)
    return None


@_register_handler("config")
@_register_handler("cfg")
def _h_config(session: dict[str, Any], args: str) -> str | None:
    # [修改] 2026-06-10 Nyaecho - 修复 config 变量引用问题，使用 nonlocal 更新闭包变量
    config = session["config"]
    providers = [item["provider"] for item in list_providers()]
    cur = config.llm.provider

    def on_provider(v):
        nonlocal config
        if v and v != cur:
            config = apply_provider_preset(config, v)
            session["config"] = config
        _set_prompt(session, "input", _("tui.prompt_enter_model", model=config.llm.model), on_model, config.llm.model)

    def on_model(v):
        if v:
            session["config"].llm.model = v.strip()
        ks = _("tui.api_key_configured") if session["config"].llm.api_key else _("tui.api_key_not_configured")
        _set_prompt(session, "input", _("tui.prompt_enter_apikey", status=ks), on_apikey)

    def on_apikey(v):
        if v:
            session["config"].llm.api_key = v.strip()
        save_config(session["config"])
        _set_prompt(session, "message", f"{_('tui.config_saved')}: {session['config'].llm.provider}/{session['config'].llm.model}")

    _set_prompt(session, "choice", _("tui.prompt_select_provider", provider=cur), providers, on_provider)
    return None


@_register_handler("continue")
@_register_handler("cont")
def _h_continue(session: dict[str, Any], args: str) -> str | None:
    if session.get("_last_draft") is not None:
        # [修改] 2026-06-10 Nyaecho - 方案A累积拼接: /continue [text] 追加到 _nl_history, 无参则复用
        history = session.get("_nl_history", "")
        if args:
            history = f"{history}; {args}" if history else args
            session["_nl_history"] = history
        session["_nl_text"] = history if history else None
        session["_continuing"] = True
        return "launch"
    session["_message"] = _("tui.no_previous_execution")
    return None


# ── Dashboard screen ──

class DashboardScreen(Screen):

    BINDINGS = [
        Binding("ctrl+c", "quit_app", "Quit", show=False),
        Binding("tab", "palette_tab", "", show=False),
        Binding("escape", "palette_esc", "", show=False),
        Binding("ctrl+shift+c", "copy_output", "Copy log", show=False),
    ]

    def __init__(self, session: dict[str, Any]):
        super().__init__()
        self._s = session
        self._completing = False
        self._worker_running = False
        self._output_queue: Queue = Queue()
        self._output_lines: list[str] = []
        # [新增] 2026-06-10 Nyaecho - 状态栏消息自动消失: 用递增计数器区分新旧消息定时器
        self._bar_msg_id: int = 0

    def compose(self) -> ComposeResult:
        # [修改] 2026-06-10 Nyaecho - 响应式分栏布局: #output-log 移入 Horizontal #exec-row 与 #exec-sidebar 并排
        with Vertical(id="body"):
            yield Static(id="dashboard")
            with Horizontal(id="exec-row"):
                yield Static(id="exec-sidebar")
                yield RichLog(id="output-log", markup=True, wrap=True, auto_scroll=True)
        yield SecondaryPopup()
        yield CommandPalette(id="cmd-palette")
        yield Static(id="status-bar")
        with Horizontal(id="input-row"):
            yield Static("> ", id="input-prefix")
            yield Static(id="exec-spinner")
            yield Input(id="cmd-input", placeholder=_("tui.slash_hint"))
        yield Static(id="exec-hint")

    def on_mount(self) -> None:
        self._refresh_dash()
        self.query_one("#cmd-input").focus()

    def _refresh_dash(self) -> None:
        state = self._s["state"]
        if state.mode is None:
            state.mode = "standard"
        dash = build_dashboard(self._s["config"], state)
        self.query_one("#dashboard").update(dash)

    def _set_bar(self, text: str = "", style: str = "") -> None:
        # [修改] 2026-06-10 Nyaecho - 状态栏消息4秒自动消失: msg_id 计数器防止旧定时器错误清除新消息
        self._bar_msg_id += 1
        msg_id = self._bar_msg_id
        bar = self.query_one("#status-bar")
        if text:
            bar.update(f"[{style}]{text}[/]")
            bar.add_class("-active")
            self.set_timer(4.0, lambda: self._dismiss_bar(msg_id))
        else:
            bar.remove_class("-active")

    def _dismiss_bar(self, msg_id: int) -> None:
        # [新增] 2026-06-10 Nyaecho - 仅当前消息ID匹配时才关闭状态栏, 防止旧定时器覆盖新消息
        if self._bar_msg_id == msg_id:
            self.query_one("#status-bar").remove_class("-active")

    # ── Input events ──

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._completing:
            return
        text = event.value or ""
        palette = self.query_one(CommandPalette)
        if text.startswith("/"):
            word = text.lstrip("/")
            if " " not in word:
                palette.show_commands(word)
                return
        palette.hide_palette()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = (event.value or "").strip()
        palette = self.query_one(CommandPalette)

        if palette.has_class("open"):
            cmd = palette.selected
            if cmd:
                self._completing = True
                self.query_one("#cmd-input").value = "/" + cmd + " "
                self.query_one("#cmd-input").action_end()
                self._completing = False
            palette.hide_palette()
            return

        prompt = self._s.get("_prompt")
        if prompt is not None:
            self._handle_prompt(text)
            return

        if text.startswith("/"):
            result = _dispatch(self._s, text)
            if result == "quit":
                self.app.exit()
            elif result == "launch":
                self._s["_launch"] = False
                draft = self._s.get("_last_draft")
                continuing = self._s.pop("_continuing", False)
                # [修改] 2026-06-10 Nyaecho - 携带 NL 文本传递给子进程, /continue 时携带累积的历史 NL
                nl_text = self._s.pop("_nl_text", None)
                self._start_execution(draft, continuing=continuing, nl_text=nl_text)
                return
            elif result is None:
                if self._s.pop("_show_popup", False):
                    popup = self.query_one(SecondaryPopup)
                    popup.show_for_prompt(self._s, on_done=self._post_popup_refresh)
                    return
                if self._s.get("_message"):
                    self._set_bar(self._s.pop("_message", ""), C_WARNING)
        elif text:
            # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 无斜杠前缀的纯文本直接作为NL prompt启动
            state = self._s["state"]
            if not state.target.strip():
                self._set_bar(_("tui.please_set_target"), C_WARNING)
            else:
                self._s["_launch"] = False
                self._s["_nl_history"] = text
                draft = _draft_from_state(state)
                self._start_execution(draft, nl_text=text)
                return

        self._refresh_dash()
        self.query_one("#cmd-input").clear()

    # ── Palette actions (bound to keys) ──

    def action_palette_tab(self) -> None:
        p = self.query_one(CommandPalette)
        if p.has_class("open"):
            cmd = p.selected
            if cmd:
                self._completing = True
                self.query_one("#cmd-input").value = "/" + cmd + " "
                self.query_one("#cmd-input").action_end()
                self._completing = False
            p.hide_palette()

    def action_palette_esc(self) -> None:
        popup = self.query_one(SecondaryPopup)
        if popup.has_class("open"):
            popup._cancel()
            return
        if self._worker_running and self._proc is not None:
            self._interrupted = True
            try:
                self._proc.terminate()
            except Exception:
                pass
            return
        p = self.query_one(CommandPalette)
        if p.has_class("open"):
            p.hide_palette()
        elif self._s.get("_prompt") is not None:
            _cancel_prompt(self._s)
            self._set_bar("")
            self._refresh_dash()

    def action_quit_app(self) -> None:
        self._s["_action"] = "quit"
        self.app.exit()

    def action_copy_output(self) -> None:
        if not self._output_lines:
            return
        text = "".join(self._output_lines)
        import subprocess
        import sys as _sys
        try:
            if _sys.platform == "win32":
                subprocess.run("clip", input=text, text=True, shell=True)
            elif _sys.platform == "darwin":
                subprocess.run("pbcopy", input=text, text=True)
            else:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text, text=True,
                )
        except Exception:
            pass

    def _start_execution(self, draft: Any = None, *, continuing: bool = False, nl_text: str | None = None) -> None:
        # [修改] 2026-06-10 Nyaecho - 响应式分栏布局: 隐藏仪表盘, 显示 exec-row, 根据终端宽度动态显隐侧边栏
        self.query_one("#dashboard").add_class("-hidden")
        log = self.query_one("#output-log", RichLog)
        if not continuing:
            log.clear()
        log.add_class("-active")
        self.query_one("#exec-row").add_class("-active")
        self.query_one("#exec-spinner").add_class("-active")
        self.query_one("#cmd-input", Input).disabled = True
        self.query_one("#exec-hint", Static).remove_class("-active")
        self._output_queue = Queue()
        self._output_lines.clear()
        self._worker_running = True
        self._interrupted = False
        self._spinner_pos = 0
        self._spinner_dir = 1
        if draft is None:
            draft = _draft_from_state(self._s["state"])
        self._s["_last_draft"] = draft
        self._proc = None
        # [新增] 2026-06-10 Nyaecho - 根据终端宽度决定是否显示侧边栏 (宽度>=100列时显示)
        self._apply_responsive_layout()
        threading.Thread(
            target=self._run_subprocess, args=(draft, nl_text), daemon=True
        ).start()
        self._start_polling()
        self._tick_spinner()

    def _run_subprocess(self, draft: Any, nl_text: str | None = None) -> None:
        # [修改] 2026-06-10 Nyaecho - 将 NL 文本通过 --prompt 传递给 CLI 子进程
        import subprocess
        import sys

        from vulnclaw.cli.tui import build_command_preview_args

        cmd_args = build_command_preview_args(draft, nl_text=nl_text)
        args = [sys.executable, "-m", "vulnclaw.cli.main"] + cmd_args[1:]
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding="utf-8",
                errors="replace",
                creationflags=creationflags,
            )
            self._proc = proc
            for line in proc.stdout:
                self._output_queue.put(line)
            proc.wait()
        except Exception as exc:
            self._output_queue.put(f"\n[{C_ERROR}]Execution error: {exc}[/]\n")
        finally:
            self._output_queue.put(None)

    def _tick_spinner(self) -> None:
        if not self._worker_running:
            return
        pos = self._spinner_pos
        direction = self._spinner_dir
        pos += direction
        if pos >= 4:
            direction = -1
            pos = 3
        elif pos <= 0:
            direction = 1
            pos = 1
        self._spinner_pos = pos
        self._spinner_dir = direction
        blocks: list[str] = ["□"] * 5
        blocks[pos] = f"[bold {C_PRIMARY}]■[/]"
        t1 = pos - direction
        if 0 <= t1 < 5:
            blocks[t1] = f"[{C_PRIMARY}]■[/]"
        t2 = pos - 2 * direction
        if 0 <= t2 < 5:
            blocks[t2] = f"[{C_MUTED}]■[/]"
        self.query_one("#exec-spinner", Static).update("".join(blocks))
        self.set_timer(0.12, self._tick_spinner)

    def _apply_responsive_layout(self) -> None:
        # [新增] 2026-06-10 Nyaecho - 响应式分栏: 终端宽度>=100列时显示侧边栏摘要, 否则仅显示输出日志
        threshold = 100
        show_sidebar = self.app.size.width >= threshold
        sidebar = self.query_one("#exec-sidebar")
        if show_sidebar:
            if not sidebar.has_class("-active"):
                sidebar.update(self._build_exec_sidebar())
                sidebar.add_class("-active")
        else:
            sidebar.remove_class("-active")

    def _check_responsive_resize(self) -> None:
        # [新增] 2026-06-10 Nyaecho - 执行期间每0.3秒检测终端宽度变化, 动态切换分栏模式
        if not self._worker_running:
            return
        self._apply_responsive_layout()

    def _poll_output(self) -> None:
        while not self._output_queue.empty():
            chunk = self._output_queue.get()
            if chunk is None:
                self._worker_running = False
                self._on_execution_done()
                return
            if chunk:
                self.query_one("#output-log", RichLog).write(chunk)
                self._output_lines.append(chunk)

    def _start_polling(self) -> None:
        self._poll_output()
        # [新增] 2026-06-10 Nyaecho - 轮询同时检测终端宽度变化, 实现响应式分栏
        self._check_responsive_resize()
        if self._worker_running:
            self.set_timer(0.3, self._start_polling)

    def _on_execution_done(self) -> None:
        self.query_one("#exec-spinner").remove_class("-active")
        inp = self.query_one("#cmd-input", Input)
        inp.disabled = False
        inp.focus()
        if self._interrupted:
            self.query_one("#output-log", RichLog).write(
                f"\n[{C_WARNING}]{_('tui.execution_interrupted')}[/]\n"
            )
        hint = self.query_one("#exec-hint", Static)
        hint.update(f"[{C_MUTED}]{_('tui.exec_hint')}[/]")
        hint.add_class("-active")
        config = load_config()
        if config:
            self._s["config"] = config

    def on_key(self, event: Key) -> None:
        p = self.query_one(CommandPalette)
        if not p.has_class("open"):
            return
        if event.key == "up":
            p.action_cursor_up()
            event.stop()
        elif event.key == "down":
            p.action_cursor_down()
            event.stop()

    # ── Prompt state machine ──

    def _handle_prompt(self, text: str) -> None:
        p = self._s.get("_prompt")
        if not p:
            return
        ptype = p[0]

        if ptype == "message":
            self._s["_prompt"] = None
            self._set_bar("")
        elif ptype == "input":
            _, label, cb, default = p
            self._s["_prompt"] = None
            self._set_bar("")
            cb(text if text else default)
        elif ptype == "choice":
            _, label, choices, cb = p
            if text in choices:
                self._s["_prompt"] = None
                self._set_bar("")
                cb(text)
            else:
                self._set_bar(_("tui.invalid_choice", choice=text, options=", ".join(choices)), C_ERROR)
                return
        elif ptype == "confirm":
            _, label, cb = p
            if text.lower() in ("y", "yes"):
                self._s["_prompt"] = None
                self._set_bar("")
                cb(True)
            elif text.lower() in ("n", "no"):
                self._s["_prompt"] = None
                self._set_bar("")
                cb(False)
            else:
                return
        elif ptype == "chain":
            _, fields, idx, cb = p
            if idx >= len(fields):
                self._s["_prompt"] = None
                self._set_bar("")
                cb()
                self._refresh_dash()
                return
            fld, fld_title, fld_default = fields[idx]
            state = self._s["state"]
            if fld == "__allow_actions":
                state.allow_actions = _parse_action_csv(text) if text else []
            elif fld == "__block_actions":
                state.block_actions = _parse_action_csv(text) if text else []
            elif fld == "only_port":
                if text:
                    try:
                        _parse_optional_port(text)
                        state.only_port = text
                    except ValueError as e:
                        self._set_bar(str(e), C_ERROR)
                        return
                else:
                    state.only_port = ""
            else:
                setattr(state, fld, text if text else "")
            self._s["_prompt"] = ("chain", fields, idx + 1, cb)
            self._show_chain_status()
        self._refresh_dash()

    def _show_chain_status(self) -> None:
        p = self._s.get("_prompt")
        if p and p[0] == "chain":
            _, fields, idx, _cb = p
            if idx < len(fields):
                self._set_bar(f"[{idx+1}/{len(fields)}] {fields[idx][1]}", C_MUTED)
                return
        self._set_bar("")

    def _build_exec_sidebar(self) -> str:
        # [新增] 2026-06-10 Nyaecho - 构建执行时侧边栏摘要: Target/Mode/Scope/Allow-Block/Resume/LLM 信息
        state = self._s["state"]
        mode = MODES[state.mode]

        lines: list[str] = []
        lines.append(f"[bold {C_ACCENT}]Target[/]")
        lines.append(f"[{C_PRIMARY}]{state.target or _('tui.not_set_sidebar')}[/]")
        lines.append("")
        lines.append(f"[bold {C_ACCENT}]Mode[/]")
        lines.append(f"[{C_SECONDARY}]{mode.label}[/]")
        lines.append("")

        scope_parts: list[str] = []
        if state.only_host:
            scope_parts.append(f"Host [{C_TEXT}]{state.only_host}[/]")
        if state.only_port:
            scope_parts.append(f"Port [{C_TEXT}]{state.only_port}[/]")
        if state.only_path:
            scope_parts.append(f"Path [{C_TEXT}]{state.only_path}[/]")
        if state.blocked_host:
            scope_parts.append(f"XHost [{C_ERROR}]{state.blocked_host}[/]")
        if state.blocked_path:
            scope_parts.append(f"XPath [{C_ERROR}]{state.blocked_path}[/]")

        if scope_parts:
            lines.append(f"[bold {C_ACCENT}]Scope[/]")
            for part in scope_parts:
                lines.append(f" {part}")
            lines.append("")

        allow = _effective_allow_actions(state)
        block = _effective_block_actions(state)
        if allow:
            lines.append(f"[bold {C_ACCENT}]Allow[/]")
            lines.append(f"[{C_SUCCESS}]{', '.join(allow)}[/]")
            lines.append("")
        if block:
            lines.append(f"[bold {C_ACCENT}]Block[/]")
            lines.append(f"[{C_ERROR}]{', '.join(block)}[/]")
            lines.append("")

        res_color = "green" if state.resume else C_WARNING
        lines.append(f"Resume [{res_color}]{_('tui.on') if state.resume else _('tui.off')}[/]")

        provider = getattr(self._s["config"].llm, "provider", "?")
        model = getattr(self._s["config"].llm, "model", "?")
        lines.append(f"LLM [{C_MUTED}]{provider}/{model}[/]")

        return "\n".join(lines)

    def _post_popup_refresh(self) -> None:
        self._refresh_dash()
        self.query_one("#cmd-input").clear()
        self.query_one("#cmd-input").focus()
        if self._s.get("_show_popup"):
            popup = self.query_one(SecondaryPopup)
            popup.show_for_prompt(self._s, on_done=self._post_popup_refresh)


# ── CSS ──

# [修改] 2026-06-10 Nyaecho - 新增 #exec-row 分栏容器 + #exec-sidebar 30列侧边栏, 支持终端宽度>=100列时分栏显示
CSS = """
#body {
    height: 1fr;
    overflow-y: auto;
    padding: 0 1;
}

#status-bar {
    height: 1;
    padding: 0 1;
    display: none;
}
#status-bar.-active {
    display: block;
}

#input-row {
    height: auto;
    min-height: 1;
    padding: 0 1;
    margin-bottom: 0;
    width: 95%;
    background: $surface;
}

#input-prefix {
    width: 2;
    color: #fab283;
    content-align: center middle;
}

#cmd-input {
    width: 1fr;
    border: none;
    padding: 0;
    background: $surface;
}
#cmd-input:focus {
    border: none;
}

#exec-hint {
    height: 1;
    padding: 0 1;
    display: none;
}
#exec-hint.-active {
    display: block;
}

#dashboard.-hidden {
    display: none;
}

#exec-row {
    display: none;
    height: 1fr;
}
#exec-row.-active {
    display: block;
}

#exec-sidebar {
    display: none;
    width: 30;
    overflow-y: auto;
    border: solid #484848;
    padding: 0 1;
    margin-right: 1;
    background: $surface;
}
#exec-sidebar.-active {
    display: block;
}

#output-log {
    display: none;
    height: 1fr;
    min-height: 5;
}
#output-log.-active {
    display: block;
}

#exec-spinner {
    display: none;
    width: 8;
    margin-right: 1;
}
#exec-spinner.-active {
    display: block;
}

#cmd-palette {
    display: none;
    height: auto;
    max-height: 12;
    overflow-y: auto;
    scrollbar-size: 0 0;
    border: solid #fab283;
}
#cmd-palette.open {
    display: block;
}
#cmd-palette ListItem.-highlight {
    color: white;
    background: #fab283 30%;
}
#cmd-palette ListItem.-highlight Static {
    color: white;
}

#sec-popup {
    display: none;
    height: auto;
    min-height: 3;
    padding: 0 1;
    border: solid #fab283;
}
#sec-popup.open {
    display: block;
}
#popup-desc {
    padding: 1 0;
    height: auto;
}
#popup-input {
    width: 100%;
    margin-bottom: 1;
}
#popup-hint {
    padding-bottom: 1;
}
#popup-list {
    height: auto;
    max-height: 10;
    margin-bottom: 1;
}
#popup-list ListItem.-highlight {
    color: white;
    background: #fab283 30%;
}
#popup-list ListItem.-highlight Static {
    color: white;
}
"""


# ── Application ──

class VulnClawApp(App):
    CSS = CSS

    def __init__(self, session: dict[str, Any]):
        super().__init__()
        self._s = session

    def on_mount(self) -> None:
        self.push_screen(DashboardScreen(self._s))


# ── Entry point ──

def run_tui_textual(*, launcher=None, once=False, initial_state=None) -> None:
    """Run the Textual-powered TUI workbench."""
    state = initial_state or TuiState()
    config = load_config()
    active_launcher = launcher or _default_launcher

    if once:
        from rich.console import Console
        Console().print(build_dashboard(config, state))
        return

    while True:
        session: dict[str, Any] = {
            "config": config,
            "state": state,
            "launcher": active_launcher,
            "_action": None,
            "_prompt": None,
            "_message": "",
            "_launch": False,
        }

        app = VulnClawApp(session)
        try:
            app.run()
        except Exception as exc:
            from rich.console import Console
            Console().print(f"\n[{C_ERROR}]TUI crashed: {exc}[/]")
            import traceback
            traceback.print_exc()
            break

        action = session.get("_action")
        if action == "quit":
            break
        if session.get("_launch"):
            draft = _draft_from_state(state)
            active_launcher(draft)
            config = load_config()
            session["_launch"] = False

    from rich.console import Console
    Console().print(f"[{C_MUTED}]{_('tui.exited_textual')}[/]")
