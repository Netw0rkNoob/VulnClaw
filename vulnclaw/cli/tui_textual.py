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

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Click, Key
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Input, ListItem, ListView, RichLog, Static

import vulnclaw.cli.tui as _tui
from vulnclaw.agent.constraint_policy import PHASE_TO_ACTION

# [新增] 2026-06-10 Nyaecho - 自然语言驱动 / 响应式侧边栏: 新增颜色常量和动作辅助函数导入
# [修改] 2026-07-08 Nyaecho - 修改原因：新增 @ skill 引用相关函数导入
from vulnclaw.cli.tui import (
    C_ACCENT,
    C_ERROR,
    C_MUTED,
    C_PRIMARY,
    C_SECONDARY,
    C_SUCCESS,
    C_TEXT,
    C_WARNING,
    TuiState,
    _default_launcher,
    _draft_from_state,
    _effective_allow_actions,
    _effective_block_actions,
    _parse_action_csv,
    _parse_optional_port,
    build_at_palette_entries,
    build_dashboard,
    build_runtime_diagnostic,
    expand_at_skills,
    find_at_context,
    rebuild_translations,
)
from vulnclaw.config.settings import (
    apply_provider_preset,
    fetch_provider_models,
    list_providers,
    load_config,
    save_config,
)
from vulnclaw.i18n import _, init_i18n
from vulnclaw.skills.flag_skills import complete_flag_skills, render_flag_skill
from vulnclaw.target_state.store import get_target_state_preview, list_target_snapshots

# ── Slash dispatch ──

_SLASH_HANDLERS: dict[str, Any] = {}

# /scope 动作约束弹窗中"动作"行的固定来源: 从 PHASE_TO_ACTION 派生, 去重后顺序保留,
# 不含 report (报告由 run/persistent 完成后自动生成, 与动作范围解耦)。
# 注: inline ``/scope allow=report`` 与旧 TUI 的允许动作/禁止动作文本字段仍允许写入,
# 作为给熟悉动作命名空间的进阶用户的逃生口; 这些值会原样进入 --allow-actions / --block-actions。
_ACTION_MATRIX_OPTIONS = [
    a for a in dict.fromkeys(PHASE_TO_ACTION.values()) if a != "report"
]


def _register_handler(cmd: str):
    def deco(fn):
        _SLASH_HANDLERS[cmd] = fn
        return fn
    return deco


def _persist_scope(session: dict[str, Any], state: Any) -> None:
    config = session.get("config")
    if config:
        _tui._persist_scope_state(state, config)


def _dispatch(session: dict[str, Any], text: str) -> str | None:
    """Dispatch slash command. Returns 'quit', 'launch', or None."""
    if text.startswith("/."):
        _dispatch_flag_skill(session, text)
        return None

    # [修改] 2026-06-10 Nyaecho - 修复空 parts 导致 IndexError 的问题
    parts = text.lstrip("/").strip().split(maxsplit=1)
    if not parts:
        return None
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    handler = _SLASH_HANDLERS.get(cmd)
    if handler:
        return handler(session, args)
    if _tui.dispatch_skill_slash_command(cmd, args, session):
        return session.get("_action")
    return None


def _set_prompt(session: dict[str, Any], ptype: str, *args: Any) -> None:
    session["_prompt"] = (ptype,) + args
    session["_show_popup"] = True


def _cancel_prompt(session: dict[str, Any]) -> None:
    prompt = session.get("_prompt")
    session["_prompt"] = None
    if prompt and prompt[0] == "chain":
        prompt[3]()


def _dispatch_flag_skill(session: dict[str, Any], text: str) -> None:
    command = _tui.parse_flag_skill_command(text)
    skill = _tui.find_flag_skill(command.query)
    if skill is None:
        session["_message"] = f"Unknown flag skill: /.{command.query}"
        return

    if command.value or skill.tui_action in {"resume_true", "resume_false"}:
        result = _tui.apply_flag_skill_to_tui_state(skill, command.value, session["state"])
        if result.applied or result.error:
            session["_message"] = result.message
            return

    _set_prompt(session, "message", render_flag_skill(skill))


# ── Command palette widget ──

class CommandPalette(ListView):
    """Dropdown slash-command palette shown on '/' input."""

    def __init__(self, **kwargs: Any):
        kwargs.setdefault("id", "cmd-palette")
        super().__init__(**kwargs)
        self._commands: list[str] = []
        self._completion_prefix = "/"

    def show_commands(
        self,
        prefix: str = "",
        *,
        entries: list[tuple[str, str]] | None = None,
        completion_prefix: str = "/",
    ) -> None:
        for item in self.query_children(ListItem):
            item.remove()
        self._commands.clear()
        self._completion_prefix = completion_prefix
        source_entries = entries if entries is not None else list(_tui.SLASH_COMMANDS.items())
        for cmd, desc in source_entries:
            if cmd.startswith(prefix):
                item = ListItem(Static(
                    f"[bold {C_PRIMARY}]{completion_prefix}{cmd}[/]  [{C_MUTED}]{desc}[/]"
                ))
                self.mount(item)
                self._commands.append(cmd)
        if self._commands:
            self.add_class("open")
            self.index = 0
        else:
            self.remove_class("open")

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

    @property
    def completion_prefix(self) -> str:
        return self._completion_prefix


# ── Secondary popup widget ──

class _ActionMatrixCell(Static):
    """Clickable cell that reports its matrix row and column."""

    class Selected(Message):
        def __init__(self, row_index: int, role: str) -> None:
            self.row_index = row_index
            self.role = role
            super().__init__()

    def __init__(
        self,
        content: str,
        *,
        row_index: int,
        role: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(content, markup=True, **kwargs)
        self._row_index = row_index
        self._role = role

    def on_click(self, event: Click) -> None:
        event.stop()
        self.post_message(self.Selected(self._row_index, self._role))


class SecondaryPopup(Vertical):
    """Secondary popup for parameter input when a slash command needs arguments.

    Supports input / choice / confirm / message / chain / loading modes.
    """
    can_focus = True
    # [修改] 2026-07-18 - action_matrix 行状态切换: 只在 允许↔禁止 间往复,
    # 不约束行首次空格进入允许, 不会再被切回不约束
    _MATRIX_CYCLE = {"none": "allow", "allow": "block", "block": "allow"}

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
        self._loading_dots: int = 0
        self._loading_timer: Any = None
        self._matrix_options: list = []
        self._matrix_states: list = []

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
        elif ptype == "action_matrix":
            _, label, options, allow_checked, block_checked, cb = prompt
            self._show_action_matrix(label, options, allow_checked, block_checked, cb)
        elif ptype == "confirm":
            _, label, cb = prompt
            self._show_confirm(label, cb)
        elif ptype == "message":
            text = prompt[1]
            self._show_message(text)
        elif ptype == "chain":
            _, fields, idx, cb = prompt
            self._show_chain(fields, idx, cb)
        elif ptype == "loading":
            _, label, cb = prompt[:3]
            self._show_loading(label, cb)
            # If the session has fetch args, start the background model fetch
            fetch_args = session.get("_fetch_models_args")
            if fetch_args:
                base_url, api_key = fetch_args
                session.pop("_fetch_models_args", None)

                def _bg_fetch() -> None:
                    models = fetch_provider_models(base_url, api_key)
                    # Schedule completion on the main thread
                    self.app.call_later(lambda: self._finish_model_fetch(models))

                threading.Thread(target=_bg_fetch, daemon=True).start()

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

    def _show_action_matrix(self, label, options, allow_checked, block_checked, cb):
        # /scope 动作约束弹窗: 三列表格(动作 / 允许 / 禁止), 单行点击切换, 回车汇总提交。
        # 同行允许/禁止互斥, 重叠按禁止优先预填; 空格在 allow ↔ block 间往复 (不约束仅作初始态)。
        # [修改] 2026-07-21 - 顶部摘要 + 清晰符号 (✓/✗/· 配主题色), 让用户一眼看清当前约束
        self._clear_dynamic()
        self._ptype = "action_matrix"
        self._cb = cb
        self._matrix_options = list(options)
        self._matrix_states = [
            "block" if opt in block_checked else "allow" if opt in allow_checked else "none"
            for opt in self._matrix_options
        ]
        self.query_one("#popup-desc", Static).update(
            f"[bold {C_PRIMARY}]{label}[/]\n  [{C_MUTED}]{_('tui.action_matrix_hint')}[/]"
        )
        # 顶部摘要: 始终显示当前 allow/block 汇总, 不依赖用户翻看每行
        self._matrix_summary = Static(id="matrix-summary", markup=True)
        self._update_matrix_summary()
        self.mount(self._matrix_summary)
        header = Horizontal(
            Static("", classes="matrix-action"),
            Static(
                f"[bold {C_SUCCESS}]{_('tui.allowed_actions_short')}[/]",
                classes="matrix-column matrix-header-allow",
                markup=True,
            ),
            Static(
                f"[bold {C_ERROR}]{_('tui.blocked_actions_short')}[/]",
                classes="matrix-column matrix-header-block",
                markup=True,
            ),
            id="popup-hint",
        )
        self.mount(header)
        items = [
            ListItem(
                _ActionMatrixCell(
                    f"  {opt}",
                    row_index=i,
                    role="action",
                    id=f"matrix-action-{i}",
                    classes="matrix-action",
                ),
                _ActionMatrixCell(
                    self._matrix_mark(i, "allow"),
                    row_index=i,
                    role="allow",
                    id=f"matrix-allow-{i}",
                    classes="matrix-column matrix-allow-cell",
                ),
                _ActionMatrixCell(
                    self._matrix_mark(i, "block"),
                    row_index=i,
                    role="block",
                    id=f"matrix-block-{i}",
                    classes="matrix-column matrix-block-cell",
                ),
            )
            for i, opt in enumerate(self._matrix_options)
        ]
        lv = ListView(*items, id="popup-list")
        self.mount(lv)
        self.add_class("open")
        lv.focus()
        lv.index = 0

    def _matrix_mark(self, idx: int, state: str) -> str:
        """Render a single allow/block cell with a colored unicode marker.

        当前状态列: ✓/✗ 加粗配主题色; 其余列: 中点 · 灰色, 避免视觉抢占。
        """
        cur = self._matrix_states[idx]
        if cur != state:
            return f"[{C_MUTED}]·[/]"
        if state == "allow":
            return f"[bold {C_SUCCESS}]✓[/]"
        return f"[bold {C_ERROR}]✗[/]"

    def _matrix_refresh_row(self, idx: int) -> None:
        self.query_one(f"#matrix-allow-{idx}", _ActionMatrixCell).update(
            self._matrix_mark(idx, "allow")
        )
        self.query_one(f"#matrix-block-{idx}", _ActionMatrixCell).update(
            self._matrix_mark(idx, "block")
        )

    def _update_matrix_summary(self) -> None:
        """Refresh the top summary line: 当前: ✓ recon,scan / ✗ post_exploitation.

        每次状态变更后调用, 让用户无需逐行核对也能看到生效约束。
        """
        allow = [
            o for o, s in zip(self._matrix_options, self._matrix_states) if s == "allow"
        ]
        block = [
            o for o, s in zip(self._matrix_options, self._matrix_states) if s == "block"
        ]
        pieces: list[str] = []
        if allow:
            pieces.append(f"[{C_SUCCESS}]✓[/] [bold]{', '.join(allow)}[/]")
        if block:
            pieces.append(f"[{C_ERROR}]✗[/] [bold]{', '.join(block)}[/]")
        body = "   ".join(pieces) if pieces else (
            f"[{C_MUTED}]" + _("tui.action_matrix_unconstrained") + "[/]"
        )
        self._matrix_summary.update(
            f"[bold {C_TEXT}]" + _("tui.action_matrix_current") + f"[/] {body}"
        )

    def _matrix_set(self, idx: int, state: str) -> None:
        if not 0 <= idx < len(self._matrix_states):
            return
        if state not in ("allow", "block"):
            return
        self._matrix_states[idx] = state
        self._matrix_refresh_row(idx)
        self._update_matrix_summary()

    def _matrix_toggle(self, idx: int) -> None:
        if not 0 <= idx < len(self._matrix_states):
            return
        self._matrix_set(idx, self._MATRIX_CYCLE[self._matrix_states[idx]])

    def _submit_action_matrix(self) -> None:
        allow = [o for o, s in zip(self._matrix_options, self._matrix_states) if s == "allow"]
        block = [o for o, s in zip(self._matrix_options, self._matrix_states) if s == "block"]
        self._resolve((allow, block))

    def _show_confirm(self, label: str, callback: Any) -> None:
        self._clear_dynamic()
        self._ptype = "confirm"
        self._cb = callback
        self.query_one("#popup-desc", Static).update(
            f"[bold {C_PRIMARY}]{label}[/]"
        )
        hint = Static(
            f"  [{C_SUCCESS}]y[/] / [{C_ERROR}]n[/]",
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
        # Create the Input widget once for the entire chain lifecycle.
        # This eliminates the try/except workaround in _render_chain_step()
        # and prevents focus-loss issues on Windows from widget destruction/recreation.
        if idx < len(fields):
            fld_default = fields[idx][2]
            inp = Input(value=fld_default if fld_default else "", id="popup-input")
            self.mount(inp)
        self._render_chain_step()

    def _show_loading(self, label: str, callback: Any) -> None:
        """Show a loading indicator with animated dots.

        The popup stays open until ``complete_loading()`` is called
        from an external source (typically a background thread via
        ``app.call_later()``).
        """
        self._clear_dynamic()
        self._ptype = "loading"
        self._cb = callback
        self._loading_dots = 0
        self.query_one("#popup-desc", Static).update(
            f"[bold {C_PRIMARY}]{label}[/]"
        )
        hint = Static("  ●", id="popup-hint")
        self.mount(hint)
        self.add_class("open")
        self.focus()
        # Start dot animation timer
        self._tick_loading()

    def _tick_loading(self) -> None:
        """Animate loading dots."""
        if self._ptype != "loading":
            return
        self._loading_dots = (self._loading_dots + 1) % 4
        dots = "●" + " ○" * self._loading_dots
        try:
            self.query_one("#popup-hint", Static).update(
                f"  [{C_MUTED}]{dots}[/]"
            )
        except Exception:
            return
        self._loading_timer = self.set_timer(0.5, self._tick_loading)

    def complete_loading(self, result: Any = None) -> None:
        """Complete a loading prompt and trigger the callback with *result*.

        Typically called via ``app.call_later()`` from a background
        thread after the async operation finishes.
        """
        # Stop the animation timer
        if self._loading_timer is not None:
            self._loading_timer.stop()
            self._loading_timer = None
        cb = self._cb
        self._cb = None
        self._dismiss()
        if cb:
            cb(result)
        if self._on_done:
            on_done = self._on_done
            self._on_done = None
            self.app.call_later(on_done)

    def _finish_model_fetch(self, models: list[str]) -> None:
        """Called on the main thread after background model fetch completes.

        Completes the loading prompt, triggers the callback, then shows
        the next prompt (model choice or fallback input).
        """
        # Complete the loading — this calls on_models_loaded(models)
        # and then _on_done (which is _post_popup_refresh)
        self.complete_loading(models)

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
                # Same rationale as _resolve: defer on_done so pending
                # async Widget.remove() calls can finish first.
                self.app.call_later(on_done)
            return
        fld, fld_title, fld_default = fields[idx]
        self.query_one("#popup-desc", Static).update(
            f"[bold {C_PRIMARY}][{idx + 1}/{len(fields)}] {fld_title}[/]"
        )
        inp = self.query_one("#popup-input", Input)
        inp.value = fld_default if fld_default else ""
        self.add_class("open")
        inp.focus()

    def _handle_chain_step(self, value: str) -> None:
        idx = self._chain_idx
        fields = self._chain_fields
        fld, fld_title, _default = fields[idx]
        if self._session:
            state = self._session["state"]
            if fld == "only_port":
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
            # Defer on_done so that async Widget.remove() triggered by
            # _dismiss() → _clear_dynamic() can complete the actual DOM
            # removal before we try to mount a new widget with the same ID.
            # Without this, Textual raises DuplicateIds because the old
            # widget is still in _nodes_by_id when mount() runs.
            self.app.call_later(on_done)

    def _cancel(self) -> None:
        self._cb = None
        self._dismiss()
        if self._on_done:
            on_done = self._on_done
            self._on_done = None
            # Same rationale as _resolve: defer on_done so pending
            # async Widget.remove() calls can finish first.
            self.app.call_later(on_done)

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

    @on(_ActionMatrixCell.Selected)
    def _on_action_matrix_cell_selected(self, event: _ActionMatrixCell.Selected) -> None:
        event.stop()
        if self._ptype != "action_matrix" or not self.has_class("open"):
            return
        if not 0 <= event.row_index < len(self._matrix_states):
            return

        lv = self.query_one("#popup-list", ListView)
        lv.index = event.row_index
        if event.role in ("allow", "block"):
            self._matrix_set(event.row_index, event.role)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id != "popup-list":
            return
        event.stop()
        # [新增] 2026-07-18 - action_matrix: 回车直接提交整个表格, 不走单项 choice 逻辑
        if self._ptype == "action_matrix":
            self._submit_action_matrix()
            return
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
        elif self._ptype == "loading":
            # Loading cannot be cancelled by user — ignore all keys
            event.stop()
        elif self._ptype == "action_matrix":
            if event.key == "space":
                event.stop()
                lv = self.query_one("#popup-list", ListView)
                if lv.index is not None:
                    self._matrix_toggle(lv.index)
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
    if args and args in _tui.MODES:
        state.mode = args
        _persist_scope(session, state)
        return None
    def cb(v):
        state.mode = v
        _persist_scope(session, state)
    _set_prompt(session, "choice", _("tui.prompt_select_mode"), list(_tui.MODES.keys()), cb)
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
        _persist_scope(session, state)
        return None
    # [修改] 2026-07-18 - 动作约束改为 action_matrix 表格勾选, chain 只保留 5 个文本字段
    fields = [
        ("only_host", _("tui.prompt_only_host"), state.only_host or ""),
        ("only_port", _("tui.prompt_only_port"), state.only_port),
        ("only_path", _("tui.prompt_only_path"), state.only_path or ""),
        ("blocked_host", _("tui.prompt_blocked_host"), state.blocked_host or ""),
        ("blocked_path", _("tui.prompt_blocked_path"), state.blocked_path or ""),
    ]
    def on_resume(yes): state.resume = yes
    def ask():
        _persist_scope(session, state)
        _set_prompt(session, "confirm", _("tui.prompt_resume", state=_("tui.on") if state.resume else _("tui.off")), on_resume)
    def on_matrix(result):
        allow, block = result
        state.allow_actions = allow
        state.block_actions = block
        ask()
    def ask_matrix():
        _set_prompt(
            session,
            "action_matrix",
            _("tui.prompt_action_matrix"),
            list(_ACTION_MATRIX_OPTIONS),
            list(_effective_allow_actions(state)),
            list(_effective_block_actions(state)),
            on_matrix,
        )
    _set_prompt(session, "chain", fields, 0, ask_matrix)
    return None


@_register_handler("run")
def _h_start(session: dict[str, Any], args: str) -> str | None:
    state = session["state"]
    if not state.target.strip():
        session["_message"] = _("tui.please_set_target")
        return None
    mode = _tui.MODES[state.mode]
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
    # [修改] 2026-07-08 Nyaecho - 修改原因：custom 提供商新增 Base URL 输入步骤
    # 流程：选择提供商 → (custom) 输入 Base URL → 输入 API Key → 获取模型列表 → 选择/输入模型
    config = session["config"]
    providers = [item["provider"] for item in list_providers()]
    cur = config.llm.provider

    def on_provider(v):
        nonlocal config
        if v and v != cur:
            config = apply_provider_preset(config, v)
            session["config"] = config
        # custom 提供商需要先输入 Base URL
        if v == "custom":
            _set_prompt(session, "input",
                       _("tui.prompt_enter_baseurl", url=session["config"].llm.base_url or ""),
                       on_baseurl)
        else:
            # 非 custom：直接输入 API Key
            ks = _("tui.api_key_configured") if session["config"].llm.api_key else _("tui.api_key_not_configured")
            _set_prompt(session, "input", _("tui.prompt_enter_apikey", status=ks), on_apikey)

    def on_baseurl(v):
        if v:
            session["config"].llm.base_url = v.strip()
        # 输入完 Base URL 后继续输入 API Key
        ks = _("tui.api_key_configured") if session["config"].llm.api_key else _("tui.api_key_not_configured")
        _set_prompt(session, "input", _("tui.prompt_enter_apikey", status=ks), on_apikey)

    def on_apikey(v):
        if v:
            session["config"].llm.api_key = v.strip()
        base_url = session["config"].llm.base_url
        api_key = session["config"].llm.api_key
        # 缺少 base_url 或 api_key 时跳过获取，直接手动输入
        if not base_url or not api_key:
            _set_prompt(session, "input", _("tui.prompt_enter_model_fallback", model=session["config"].llm.model), on_model_input, session["config"].llm.model)
            return
        # 显示 loading，后台获取模型列表
        session["_fetch_models_args"] = (base_url, api_key)
        _set_prompt(session, "loading", _("tui.fetching_models"), on_models_loaded)

    def on_models_loaded(models):
        if models:
            _set_prompt(session, "choice", _("tui.prompt_select_model", model=session["config"].llm.model), models, on_model_selected)
        else:
            _set_prompt(session, "input", _("tui.prompt_enter_model_fallback", model=session["config"].llm.model), on_model_input, session["config"].llm.model)

    def on_model_selected(v):
        if v:
            session["config"].llm.model = v.strip()
        save_config(session["config"])
        _set_prompt(session, "message", f"{_('tui.config_saved')}: {session['config'].llm.provider}/{session['config'].llm.model}")

    def on_model_input(v):
        if v:
            session["config"].llm.model = v.strip()
        save_config(session["config"])
        _set_prompt(session, "message", f"{_('tui.config_saved')}: {session['config'].llm.provider}/{session['config'].llm.model}")

    _set_prompt(session, "choice", _("tui.prompt_select_provider", provider=cur), providers, on_provider)
    return None


# ── Language switch handler ──

_SUPPORTED_LANGUAGES = ["auto", "zh", "en"]


def _get_language_labels_textual() -> dict[str, str]:
    """Return {lang_key: translated_label} for supported languages."""
    return {c: _(f"tui.language_{c}") for c in _SUPPORTED_LANGUAGES}


def _apply_language_textual(session: dict[str, Any], lang: str) -> None:
    """Apply language switch and mark for UI recompose."""
    session["config"].session.language = lang
    save_config(session["config"])
    init_i18n(lang=lang if lang != "auto" else None, config=session["config"])
    rebuild_translations()
    lang_labels = _get_language_labels_textual()
    session["_message"] = _("tui.language_switched", lang=lang_labels.get(lang, lang))
    session["_needs_recompose"] = True


@_register_handler("language")
@_register_handler("lang")
def _h_language(session: dict[str, Any], args: str) -> str | None:
    """Handle /language command — switch UI language at runtime.

    /language         → popup with three choices (auto/zh/en)
    /language zh      → direct switch to Chinese
    /lang en          → direct switch to English
    """
    lang = args.strip().lower() if args else ""
    if lang in _SUPPORTED_LANGUAGES:
        _apply_language_textual(session, lang)
        return None
    # No valid direct arg → show choice popup
    labels = _get_language_labels_textual()
    choice_labels = [labels[c] for c in _SUPPORTED_LANGUAGES]
    # Build reverse lookup dict for robust label → lang_key resolution
    label_to_lang = dict(zip(choice_labels, _SUPPORTED_LANGUAGES))

    def _on_choice(value: str) -> None:
        _apply_language_textual(session, label_to_lang.get(value, "auto"))

    _set_prompt(session, "choice", _("tui.prompt_select_language"), choice_labels, _on_choice)
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

    # [修改] 2026-07-08 Nyaecho - 修改原因：添加上下键优先级绑定，用于 CommandPalette 导航
    BINDINGS = [
        Binding("ctrl+c", "quit_app", "Quit", show=False),
        Binding("tab", "palette_tab", "", show=False),
        Binding("escape", "palette_esc", "", show=False),
        Binding("ctrl+shift+c", "copy_output", "Copy log", show=False),
        Binding("up", "cursor_up", "", show=False, priority=True),
        Binding("down", "cursor_down", "", show=False, priority=True),
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
        msg = self._s.pop("_message", None)
        if msg:
            self._set_bar(msg, C_SUCCESS)

    def _refresh_dash(self) -> None:
        state = self._s["state"]
        if state.mode is None:
            state.mode = "standard"
        dash = build_dashboard(self._s["config"], state)
        self.query_one("#dashboard").update(dash)

    # [新增] 2026-07-08 Nyaecho - 修改原因：支持上下键导航 CommandPalette 和 SecondaryPopup
    def action_cursor_up(self) -> None:
        """Move highlight up in CommandPalette or SecondaryPopup."""
        # 优先处理 SecondaryPopup 中的 ListView
        popup = self.query_one(SecondaryPopup)
        if popup.has_class("open"):
            try:
                lv = popup.query_one("#popup-list", ListView)
                if lv.index is not None and lv.index > 0:
                    lv.index -= 1
            except Exception:
                pass
            return
        # 处理 CommandPalette
        p = self.query_one(CommandPalette)
        if p.has_class("open") and p._commands:
            if p.index is None:
                p.index = 0
            elif p.index > 0:
                p.index -= 1

    def action_cursor_down(self) -> None:
        """Move highlight down in CommandPalette or SecondaryPopup."""
        # 优先处理 SecondaryPopup 中的 ListView
        popup = self.query_one(SecondaryPopup)
        if popup.has_class("open"):
            try:
                lv = popup.query_one("#popup-list", ListView)
                if lv.index is not None and lv.index < len(lv.query_children(ListItem)) - 1:
                    lv.index += 1
            except Exception:
                pass
            return
        # 处理 CommandPalette
        p = self.query_one(CommandPalette)
        if p.has_class("open") and p._commands:
            if p.index is None:
                p.index = 0
            elif p.index < len(p._commands) - 1:
                p.index += 1

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

    # [修改] 2026-07-08 Nyaecho - 修改原因：新增任意位置 @ skill 引用补全支持
    def on_input_changed(self, event: Input.Changed) -> None:
        if self._completing:
            return
        text = event.value or ""
        cursor = event.input.cursor_position
        palette = self.query_one(CommandPalette)
        if text.startswith("/."):
            word = text[2:]
            if " " not in word:
                entries = [(skill.name, skill.summary) for skill in complete_flag_skills(word)]
                palette.show_commands(word, entries=entries, completion_prefix="/.")
                return
        elif text.startswith("/"):
            word = text.lstrip("/")
            if " " not in word:
                palette.show_commands(
                    word,
                    entries=_tui.build_slash_palette_entries(),
                    completion_prefix="/",
                )
                return
        # 检测任意位置的 @
        ctx = find_at_context(text, cursor)
        if ctx is not None:
            _, word = ctx
            palette.show_commands(
                word,
                entries=build_at_palette_entries(word),
                completion_prefix="@",
            )
            return
        palette.hide_palette()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = (event.value or "").strip()
        palette = self.query_one(CommandPalette)

        # [修改] 2026-07-08 Nyaecho - 修改原因：Enter 键选择 CommandPalette 高亮项（不提交），焦点保持在输入框
        if palette.has_class("open") and palette.selected is not None:
            cmd = palette.selected
            self._completing = True
            self.query_one("#cmd-input").value = palette.completion_prefix + cmd + " "
            self.query_one("#cmd-input").action_end()
            self._completing = False
            palette.hide_palette()
            return  # 选择高亮项，不提交

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
                if self._s.pop("_needs_recompose", False):
                    self._refresh_dash()
                    self.query_one("#cmd-input").clear()
                    self.query_one("#cmd-input").placeholder = _("tui.slash_hint")
                    self.app.recompose()
                    return
        elif text:
            # [修改] 2026-07-08 Nyaecho - 修改原因：提交时展开 @ skill 引用为完整 prompt
            state = self._s["state"]
            if not state.target.strip():
                self._set_bar(_("tui.please_set_target"), C_WARNING)
            else:
                expanded = expand_at_skills(text)
                self._s["_launch"] = False
                self._s["_nl_history"] = text  # 保留原始输入用于 /continue
                draft = _draft_from_state(state)
                self._start_execution(draft, nl_text=expanded)
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
                self.query_one("#cmd-input").value = p.completion_prefix + cmd + " "
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
            # [修改] 2026-07-08 Nyaecho - 修改原因：关闭 CommandPalette 后焦点回到输入框
            self.query_one("#cmd-input").focus()
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

    # [删除] 2026-07-08 Nyaecho - 修改原因：上下键由 Input key_bindings 处理，不再需要 on_key 拦截

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
                # [修改] 2026-07-17 - 确认回调可能异步请求 launch (deep/continuous /run), 在此消费
                if self._consume_launch_action():
                    return
            elif text.lower() in ("n", "no"):
                self._s["_prompt"] = None
                self._set_bar("")
                cb(False)
            else:
                return
        elif ptype == "action_matrix":
            # [新增] 2026-07-18 - 旧路径兜底: 弹窗打开时主输入框提交,
            # 文本按 CSV 解析为 allow, block 保持初始值, 防止 prompt 悬置卡死
            _, label, options, allow_checked, block_checked, cb = p
            self._s["_prompt"] = None
            self._set_bar("")
            cb((_parse_action_csv(text), list(block_checked)))
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
            if fld == "only_port":
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
        mode = _tui.MODES[state.mode]

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

    def _consume_launch_action(self) -> bool:
        # [新增] 2026-07-17 - 修复 deep/continuous 模式 /run 确认后不启动的问题:
        # 确认弹窗回调是异步执行的, 此时 _dispatch 早已返回 None,
        # on_input_submitted 永远看不到 session["_action"] == "launch",
        # 因此必须在弹窗/提示收尾处消费它并启动执行
        if self._s.get("_action") != "launch":
            return False
        self._s["_action"] = None
        self._s["_launch"] = False
        self._start_execution()
        return True

    def _post_popup_refresh(self) -> None:
        if self._consume_launch_action():
            return
        # If language was switched via popup, refresh dashboard text immediately
        # then recompose the whole UI for full hot-reload (commit 201e8ec pattern).
        if self._s.pop("_needs_recompose", False):
            self._refresh_dash()
            self.query_one("#cmd-input").clear()
            self.query_one("#cmd-input").placeholder = _("tui.slash_hint")
            self.app.recompose()
            return
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
    background: $surface;
}
#cmd-palette.open {
    display: block;
}
#cmd-palette ListItem {
    background: $surface;
}
#cmd-palette ListItem.-highlight {
    color: #fab283;
    background: $surface-lighten-1;
}
#cmd-palette ListItem.-highlight Static {
    color: #fab283;
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
    height: 1;
}
#popup-list {
    height: auto;
    max-height: 10;
    margin-bottom: 1;
}
#popup-list ListItem {
    layout: horizontal;
    height: 1;
}
.matrix-action {
    /* 固定宽度, 不再用 1fr; 否则会撑满整行, 让右侧的允许/禁止选择被推到屏幕最右 */
    width: 20;
}
.matrix-column {
    width: 16;
}
.matrix-header-allow {
    color: #7fd88f;
}
.matrix-header-block {
    color: #e06c75;
}
.matrix-allow-cell {
    color: #7fd88f;
}
.matrix-block-cell {
    color: #e06c75;
}
#matrix-summary {
    height: 1;
    padding: 0 1;
    margin-bottom: 1;
    color: #eeeeee;
    text-style: bold;
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
    _tui._restore_scope_state(state, config)
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
