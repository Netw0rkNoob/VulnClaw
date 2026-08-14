"""VulnClaw CLI main entry point with REPL and sub-commands."""

# ruff: noqa: E402

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Any, Optional


def _configure_windows_console() -> None:
    """Force UTF-8 console I/O on Windows for reliable Unicode output."""
    if sys.platform != "win32":
        return

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleCP(65001)
        kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


_configure_windows_console()

import typer
from rich.panel import Panel
from rich.text import Text

from vulnclaw import __version__, headless
from vulnclaw.agent.constraint_policy import validate_action_constraints
from vulnclaw.agent.input_analysis import extract_task_constraints

# === Stream Output Renderer ===
# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: S2 修复 — 共享辅助函数已移至 cli/_helpers.py。
from vulnclaw.cli._helpers import (
    TerminalStreamSink,
    _append_action_constraints,
    _append_cli_constraints_compat,
    _generate_report_for_target,
    _make_solve_event_printer,
    _print_agent_output,
    _print_banner,
    _run_cli_orchestrated_task,
    console,
    err_console,
)
from vulnclaw.cli.manual import available_topics, render_manual
from vulnclaw.config.schema import ENGINE_CHOICES, resolve_engine
from vulnclaw.config.settings import (
    RUNS_DIR,
    apply_provider_preset,
    list_providers,
    load_config,
    save_config,
    set_config_value,
)
from vulnclaw.config.token_provider import has_llm_credentials
from vulnclaw.i18n import _
from vulnclaw.i18n.phases import localized_phase_name
from vulnclaw.repl_runner import run_repl_call
from vulnclaw.target_state.store import (
    apply_target_state_to_agent,
    clear_target_state,
    diff_target_state_snapshots,
    get_target_state_preview,
    list_target_snapshots,
    load_target_state,
    rollback_target_state,
)


def _emit_solve_report_if_completed(agent: Any, config: Any) -> str:
    """Generate and optionally print the replay report for a completed solve run."""

    state = getattr(getattr(getattr(agent, "context", None), "state", None), "agent_state", None)
    if state is None or not getattr(state, "completed", False):
        return ""
    session = getattr(config, "session", None)
    if session is not None and not getattr(session, "solve_auto_report", True):
        return ""
    try:
        from vulnclaw.report.solve_report import generate_solve_report

        report_path = generate_solve_report(state)
        report_text = report_path.read_text(encoding="utf-8")
    except Exception as exc:
        console.print(Panel(f"{_('cli.auto_solve_report_generation_failed')}: {exc}", title="Solve Report", border_style="red"))
        return ""

    console.print(
        Panel(
            f"{_('cli.auto_review_report_saved')}:\n{report_path}",
            title="Solve Report",
            border_style="cyan",
        )
    )
    if session is None or getattr(session, "solve_report_show", True):
        console.print(Text(report_text), soft_wrap=True)
    return str(report_path)

# 鈹€鈹€ REPL 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def _prepare_repl_target(
    agent, requested_target: str, current_target: Optional[str], current_phase: str
) -> tuple[str, str, bool]:
    """Prepare REPL state for a target switch and optionally restore history."""
    target = requested_target.strip()
    if not target:
        return current_target or "", current_phase, False

    if current_target and current_target != target:
        console.print(
            _("cli.target_switch").format(from_target = current_target,to_target = target) #数据库存在i18n字符串 未使用
        )
        agent.reset_context()
        current_phase = agent.session_state.phase.value

    restore_result = apply_target_state_to_agent(agent, target)
    current_phase = restore_result.phase or agent.session_state.phase.value
    return target, current_phase, restore_result.restored


async def _run_repl_agent_call(agent, *, call, after_result) -> None:
    """Run a REPL agent call and hand each result back to a caller hook."""
    await run_repl_call(call=call, after_result=after_result)


def _localized_phase_label(phase: Any) -> str:
    """Return a display-only phase label for the active UI language."""
    raw = getattr(phase, "value", phase)
    return localized_phase_name(str(raw or "").strip())


def _make_repl_prompt_session() -> Any:
    """Build a prompt_toolkit session with the skill palette, or None if unavailable.

    Returns None when stdin is not a TTY (pipes, CI, ``--once`` smoke tests) or
    prompt_toolkit cannot attach, so the REPL falls back to plain input.
    """
    debug = bool(os.environ.get("VULNCLAW_DEBUG_INPUT"))
    try:
        if not sys.stdin.isatty():
            if debug:
                console.print(f"[dim]({_('cli.slash_palette_off')})[/]")
            return None
        from prompt_toolkit import PromptSession

        from vulnclaw.cli.tui import build_repl_slash_completer, build_repl_slash_style

        session = PromptSession(
            completer=build_repl_slash_completer(),
            complete_while_typing=True,
            style=build_repl_slash_style(),
        )

        # `complete_while_typing` reopens the menu on insertion but not on
        # deletion, so backspacing to a bare '/' leaves it closed. Re-trigger
        # completion on any change while the line still starts with '/'.
        def _reopen_palette_on_edit(buff: Any) -> None:
            if buff.complete_state is None and buff.text.startswith("/"):
                buff.start_completion(select_first=False)

        session.default_buffer.on_text_changed += _reopen_palette_on_edit

        if debug:
            console.print(f"[dim]({_('cli.slash_palette_on')})[/]")
        return session
    except Exception as exc:
        # Surface the reason instead of silently dropping to plain input.
        from rich.markup import escape as _esc

        console.print(f"[yellow](slash palette unavailable: {_esc(str(exc))})[/]")
        return None


def _read_repl_line(
    pt_session: Any,
    target: Optional[str],
    phase: str,
    auto_mode: bool,
) -> str:
    """Read one REPL line, using the slash palette when a session is available."""
    phase_label = _localized_phase_label(phase)
    if pt_session is None:
        prompt_parts = []
        if target:
            prompt_parts.append(f"[bold cyan]{target}[/]")
        prompt_parts.append(f"[dim]{phase_label}[/]")
        if auto_mode:
            prompt_parts.append("[bold yellow]AUTO[/]")
        prompt_str = " | ".join(prompt_parts) if prompt_parts else "vulnclaw"
        return console.input(f"vulnclaw {prompt_str}> ")

    import html as _html

    from prompt_toolkit.formatted_text import HTML

    parts = []
    if target:
        parts.append(f"<ansicyan><b>{_html.escape(target)}</b></ansicyan>")
    parts.append(f"<ansibrightblack>{_html.escape(phase_label)}</ansibrightblack>")
    if auto_mode:
        parts.append("<ansiyellow><b>AUTO</b></ansiyellow>")
    body = " | ".join(parts) if parts else "vulnclaw"
    return pt_session.prompt(HTML(f"vulnclaw {body}<b>&gt; </b>"))


def _run_repl_command(name: str, args: str, agent: Any, config: Any) -> Any:
    """Execute a built-in classic-REPL slash command.

    Returns the (possibly reloaded) config so the caller can keep using it.
    """
    if name == "config":
        from vulnclaw.cli.tui import run_config_tui

        run_config_tui()
        # The editor writes to disk; reload and rebind the running agent so
        # provider/model/key changes take effect without restarting.
        new_config = load_config()
        agent.apply_config(new_config)
        console.print(
            f"[green]✓[/] {_('cli.config_reloaded')}: "
            f"{new_config.llm.provider}/{new_config.llm.model}"
        )
        return new_config

    if name == "language":
        return _repl_switch_language(args, agent, config)

    return config


def _repl_switch_language(args: str, agent: Any, config: Any) -> Any:
    """Switch the interface language from the classic REPL."""
    from vulnclaw.cli.tui import _SUPPORTED_LANGUAGES, rebuild_translations
    from vulnclaw.i18n import init_i18n

    lang = args.strip().lower()
    if lang not in _SUPPORTED_LANGUAGES:
        console.print(
            "[yellow]Usage:[/] /language <"
            + " | ".join(_SUPPORTED_LANGUAGES)
            + f">  (current: {config.session.language})"
        )
        return config

    config.session.language = lang
    save_config(config)
    init_i18n(lang=lang if lang != "auto" else None, config=config)
    rebuild_translations()
    agent.apply_config(config)
    console.print(f"[green]✓[/] {_('cli.language_set_to')} [bold]{lang}[/].")
    return config


def _run_repl() -> None:
    """Run the interactive REPL loop."""
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.mcp.lifecycle import MCPLifecycleManager

    _print_banner()

    config = load_config()
    if not has_llm_credentials(config.llm):
        console.print(_("cli.no_api_key"))
        console.print(_("cli.choose_provider"))
        console.print(_("cli.set_env_var"))
        console.print()
        console.print(_("cli.offline_mode"))

    # Initialize MCP lifecycle manager
    mcp_manager = MCPLifecycleManager(config)
    started = mcp_manager.start_enabled_servers()
    console.print(_("cli.mcp_registered", count=started))
    # Report any servers that failed to attach so the user knows immediately
    for srv_name, srv_state in mcp_manager.registry.get_all_servers().items():
        if srv_state.health_status in ("degraded", "unavailable") and srv_state.execution_mode in ("placeholder",):
            err_msg = getattr(srv_state, "error", "") or ""
            if err_msg:
                console.print(f"[yellow]  ⚠ {srv_name}: {err_msg[:120]}[/yellow]")

    # Initialize agent
    agent = AgentCore(config, mcp_manager)

    console.print(_("cli.welcome"))
    console.print()

    # Track current target
    current_target: Optional[str] = None
    current_phase: str = "Ready"
    exit_requested = False
    auto_mode_active = False
    _last_ctrlc_time = 0.0
    last_auto_input: str = ""

    # Interactive slash palette: skills under '/', flag skills under '/.'.
    # Falls back to plain input when there is no TTY (pipes, CI smoke tests).
    _pt_session = _make_repl_prompt_session()

    while True:
        try:
            # Read input (slash palette when interactive, plain prompt otherwise)
            user_input = _read_repl_line(
                _pt_session, current_target, current_phase, auto_mode_active
            ).strip()

            if not user_input:
                if last_auto_input:
                    user_input = last_auto_input
                    console.print(f"[dim]↻ f{_('cli.resuming_auto_pentest')}: {last_auto_input[:60]}...[/]")
                else:
                    continue

            if user_input.lower() in ("/compact", "compact"):
                summary = agent.context.compact_messages(note="User requested /compact.")
                console.print(
                    _("cli.compressed_earlier_context").format(var_001 = len(summary))
                )
                continue

            # Handle slash commands: '/' selects a skill, '/.' a flag skill.
            if user_input.startswith("/"):
                from vulnclaw.cli.tui import dispatch_repl_slash

                result = dispatch_repl_slash(user_input)
                if result.kind == "message":
                    console.print(result.text)
                    continue
                if result.kind == "target":
                    current_target, current_phase, restored_loaded = _prepare_repl_target(
                        agent, result.value, current_target, current_phase
                    )
                    if restored_loaded:
                        console.print(_("cli.target_restored", target=current_target))
                    console.print(_("cli.target_set", target=current_target))
                    continue
                if result.kind == "command":
                    config = _run_repl_command(result.value, result.text, agent, config)
                    continue
                # result.kind == "run": fall through with the rewritten prompt.
                user_input = result.text

            # Handle built-in commands
            cmd_lower = user_input.lower()

            if cmd_lower in ("exit", "quit", "q"):
                console.print(_("cli.bye"))
                break

            elif cmd_lower == "help":
                _print_help()
                continue

            elif cmd_lower == "status":
                _print_status(agent, mcp_manager, current_target, current_phase, config)
                continue

            elif cmd_lower.startswith("target "):
                current_target, current_phase, restored_loaded = _prepare_repl_target(
                    agent,
                    user_input[7:].strip(),
                    current_target,
                    current_phase,
                )
                if restored_loaded:
                    console.print(_("cli.target_restored", target=current_target))
                console.print(_("cli.target_set", target=current_target))
                continue

            elif cmd_lower == "clear":
                current_target = None
                current_phase = "Ready"
                auto_mode_active = False
                last_auto_input = ""
                agent.reset_context()
                console.print(_("cli.conversation_cleared"))
                continue

            elif cmd_lower == "tools":
                tools = mcp_manager.list_available_tools()
                if tools:
                    console.print(_("cli.available_tools"))
                    for tool in tools:
                        console.print(f"  - {tool}")
                else:
                    console.print(_("cli.no_tools"))
                continue

            elif cmd_lower.startswith("report"):
                report_target = user_input[len("report") :].strip() or current_target
                if not report_target:
                    console.print(_("cli.no_target_for_report"))
                    continue

                report_path = _generate_report_for_target(
                    report_target,
                    current_session=agent.session_state
                    if agent.session_state.target == report_target
                    else None,
                    report_format=config.session.report_format,
                )
                console.print(_("cli.report_generated", path=report_path))
                continue

            elif cmd_lower.startswith("persistent"):
                explicit_target = user_input[len("persistent") :].strip()
                persistent_target = explicit_target or current_target
                if not persistent_target:
                    console.print(
                        _("cli.host_no_set")
                    )
                    continue

                current_target, current_phase, restored_loaded = _prepare_repl_target(
                    agent,
                    persistent_target,
                    current_target,
                    current_phase,
                )
                persistent_target = current_target
                if restored_loaded:
                    console.print(_("cli.target_restored", target=persistent_target))

                from vulnclaw.agent.core import PersistentCycleResult

                rounds_per_cycle = config.session.persistent_rounds_per_cycle
                max_cycles = config.session.persistent_max_cycles
                auto_report = config.session.persistent_auto_report

                console.print(
                    Panel(
                        f"Target: [bold]{persistent_target}[/]\n"
                        f"Rounds per cycle: [bold]{rounds_per_cycle}[/]\n"
                        f"Max cycles: [bold]{max_cycles}[/]\n"
                        f"Auto report: {'[green]on[/]' if auto_report else '[yellow]off[/]'}",
                        title="Persistent Pentest",
                        border_style="cyan",
                    )
                )

                persistent_prompt = (
                    f"Perform an authorized persistent penetration test against {persistent_target}. "
                    + _("cli.target_within_range_and_explicitly_authorized")
                )

                all_cycle_results: list[PersistentCycleResult] = []

                def _on_persistent_step(round_num: int, cycle_num: int, result) -> None:
                    console.print(f"[dim]-- Cycle {cycle_num} | Round {round_num} --[/]")
                    # TerminalStreamSink 已实时流式显示，回调不重复打印
                    console.print()
                    nonlocal current_target, current_phase
                    if result.target:
                        current_target = result.target
                    if result.phase:
                        current_phase = result.phase

                def _on_persistent_cycle(
                    cycle_num: int, cycle_result: PersistentCycleResult
                ) -> None:
                    all_cycle_results.append(cycle_result)
                    console.print(
                        Panel(
                            f"Cycle {cycle_num} completed\n"
                            f"   Total findings: {cycle_result.total_findings}\n"
                            f"   New findings: {cycle_result.new_findings}\n"
                            f"   Report: {cycle_result.report_path or 'not generated'}",
                            title=f"Cycle {cycle_num}",
                            border_style="green" if cycle_result.new_findings == 0 else "red",
                        )
                    )
                    console.print()

                try:

                    async def _run_persistent():
                        await mcp_manager._preinit_chrome_devtools()
                        sink = TerminalStreamSink(console, config.session.show_thinking)
                        return await agent.persistent_pentest(
                            user_input=persistent_prompt,
                            target=persistent_target,
                            rounds_per_cycle=rounds_per_cycle,
                            max_cycles=max_cycles,
                            auto_report=auto_report,
                            on_cycle_step=_on_persistent_step,
                            on_cycle_complete=_on_persistent_cycle,
                            stream_sink=sink,
                        )

                    asyncio.run(_run_persistent())
                    if auto_report and not all_cycle_results:
                        partial_report = _generate_report_for_target(
                            persistent_target,
                            current_session=agent.session_state,
                            report_format=config.session.report_format,
                        )
                        console.print(_("cli.partial_report", path=partial_report))
                except KeyboardInterrupt:
                    console.print(f"\n{_('persistent.interrupted_message')}")
                    if agent.session_state.findings:
                        try:
                            final_report = _generate_report_for_target(
                                persistent_target,
                                current_session=agent.session_state,
                                report_format=config.session.report_format,
                            )
                            console.print(_("persistent.final_report", path=final_report))
                        except Exception as exc:
                            console.print(_("persistent.failed_final_report", exc=exc))

                # Summary
                tf = len(agent.session_state.findings)
                console.print(
                    _("persistent.finished_summary", cycles=len(all_cycle_results), findings=tf)
                )
                continue

            elif cmd_lower == "think":
                # Toggle think tag display
                config.session.show_thinking = not config.session.show_thinking
                state_str = (
                    "[green]shown[/]" if config.session.show_thinking else "[yellow]hidden[/]"
                )
                console.print(f"[*] Thinking visibility: {state_str}")
                console.print(_("cli.thinking_toggle_hint"))
                continue

            elif cmd_lower == "think on":
                config.session.show_thinking = True
                console.print(_("cli.thinking_shown"))
                continue

            elif cmd_lower == "think off":
                config.session.show_thinking = False
                console.print(_("cli.thinking_hidden"))
                continue

            # Handle auto mode persistence: exit auto mode on explicit commands
            if auto_mode_active and user_input.lower().strip() in (
                "chat", "manual", "exit auto", "单轮", "手动",
            ):
                auto_mode_active = False
                last_auto_input = ""
                console.print(_("cli.auto_mode_exited"))
                is_auto_mode = False
            elif auto_mode_active:
                is_auto_mode = True
            else:
                # Route to agent and detect whether this should be an autonomous loop
                is_auto_mode = _should_auto_pentest(user_input, current_target)

            # Detect target switch and reset context if the user mentions a new target
            new_target = _extract_target_from_input(user_input)
            if new_target and current_target and new_target != current_target:
                console.print(_("cli.target_switch", from_target=current_target, to_target=new_target))
                current_target = new_target
                current_phase = "Recon"
                agent.reset_context()
                # Reset auto mode on target switch
                auto_mode_active = False
                last_auto_input = ""

            # Save last auto input for resume on empty Enter
            if is_auto_mode:
                last_auto_input = user_input

            try:
                if is_auto_mode:
                    # Autonomous pentest loop
                    console.print(_("cli.enter_auto_mode"))
                    console.print()

                    # 默认走目标驱动 solve 引擎；engine=rounds 时回退到旧固定轮数循环
                    if getattr(config.session, "engine", "solve") == "solve":
                        async def _run_auto():
                            await mcp_manager._preinit_chrome_devtools()
                            sink = TerminalStreamSink(console, config.session.show_thinking)

                            async def call():
                                return await agent.solve(
                                    user_input,
                                    target=current_target,
                                    max_steps=config.session.solve_max_steps,
                                    max_tool_rounds=config.session.solve_max_tool_rounds,
                                    stream_sink=sink,
                                    on_event=_make_solve_event_printer(console),
                                )

                            async def after_result(result):
                                agent_state = agent.context.state.agent_state.get_summary()
                                done = agent_state.get("completed")
                                console.print()
                                console.print(
                                    Panel(
                                        f"{_('cli.goal_achieved') if done else _('cli.goal_not_achieved')} — "
                                        f"steps={agent_state.get('steps', 0)} "
                                        f"evidence={agent_state.get('evidence', 0)} "
                                        f"tools={agent_state.get('tool_calls', 0)}\n"
                                        f"{_('cli.reason')}: {agent_state.get('complete_reason') or _('cli.reason_not_complete')}",
                                        title="Solve",
                                        border_style="green" if done else "yellow",
                                    )
                                )
                                if done:
                                    _emit_solve_report_if_completed(agent, config)

                            await _run_repl_agent_call(agent, call=call, after_result=after_result)

                        asyncio.run(_run_auto())
                        auto_mode_active = True
                        console.print(_("cli.auto_mode_hint"))
                        continue

                    async def _run_auto():
                        sink = TerminalStreamSink(console, config.session.show_thinking)
                        async def call():
                            def on_step(round_num, result):
                                nonlocal current_target, current_phase
                                console.print(f"[dim]-- Round {round_num} --[/]")
                                console.print()
                                if result.target:
                                    current_target = result.target
                                if result.phase:
                                    current_phase = result.phase

                            return await agent.auto_pentest(
                                user_input,
                                target=current_target,
                                max_rounds=config.session.max_rounds,
                                on_step=on_step,
                                stream_sink=sink,
                            )

                        async def after_result(results):
                            if results:
                                total_findings = len(agent.session_state.findings)
                                total_steps = len(agent.session_state.executed_steps)
                                console.print()
                                console.print(
                                    Panel(
                                        f"{_('auto_pentest.finished')}\n"
                                        f"{_('auto_pentest.rounds', rounds=len(results))}\n"
                                        f"{_('auto_pentest.steps', steps=total_steps)}\n"
                                        f"{_('auto_pentest.findings', findings=total_findings)}",
                                        title=_("auto_pentest.title"),
                                        border_style="green" if total_findings == 0 else "red",
                                    )
                                )

                                if any(
                                    token in user_input.lower()
                                    for token in (
                                        "输出",
                                        "保存",
                                        "写到",
                                        "导出",
                                        "save",
                                        "write",
                                        "export",
                                    )
                                ):
                                    _auto_save_recon_report(agent, user_input, config)

                        await _run_repl_agent_call(agent, call=call, after_result=after_result)

                    asyncio.run(_run_auto())
                    auto_mode_active = True
                    console.print(_("cli.auto_mode_hint"))

                else:
                    # Single-turn chat
                    async def _run_agent():
                        await mcp_manager._preinit_chrome_devtools()
                        sink = TerminalStreamSink(console, config.session.show_thinking)
                        async def call():
                            return await agent.chat(user_input, target=current_target, stream_sink=sink)

                        async def after_result(result):
                            nonlocal current_target, current_phase
                            if result:
                                if result.target:
                                    current_target = result.target
                                if result.phase:
                                    current_phase = result.phase
                                # 注释掉: 流式输出已通过 TerminalStreamSink 实时显示，无需重复打印
                                # if result.output:
                                #     _print_agent_output(result.output, config)

                        await _run_repl_agent_call(agent, call=call, after_result=after_result)

                    asyncio.run(_run_agent())

            except KeyboardInterrupt:
                if is_auto_mode:
                    auto_mode_active = False
                    console.print()
                    console.print(_("cli.interrupted"))
                    console.print(_("cli.auto_resume_hint"))
                else:
                    console.print(f"\n{_('cli.interrupted')}")
            except Exception as e:
                # Escape Rich markup chars in exception message to prevent MarkupError
                from rich.markup import escape as rich_escape

                console.print(_("cli.error", msg=rich_escape(str(e))))

        except KeyboardInterrupt:
            now = time.monotonic()
            if exit_requested and (now - _last_ctrlc_time) < 3.0:
                console.print(_("cli.bye"))
                break
            exit_requested = True
            _last_ctrlc_time = now
            console.print(f"\n{_('cli.press_again')}")
        except EOFError:
            break

    # Cleanup — suppress SIGINT to prevent re-trigger during threading shutdown
    import signal

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    mcp_manager.stop_all()
    console.print("[dim]MCP services stopped.[/]")


def _print_help() -> None:
    """Print REPL help."""
    help_text = f"""
 [bold]{_("help.commands")}[/]:
  {_("help.target")}
  {_("help.status")}
  {_("help.tools")}
  {_("help.report")}
  {_("help.think")}
  {_("help.think_on_off")}
  {_("help.persistent")}
  {_("help.persistent_host")}
  {_("help.clear")}
  {_("help.chat")}
  {_("help.help")}
  {_("help.exit")}

 [bold]{_("help.auto_mode")}[/]:
  {_("help.auto_mode_desc")}
  {_("help.auto_mode_example")}
  {_("help.auto_mode_stays")}

 [bold]{_("help.persistent_mode")}[/]:
  {_("help.persistent_mode_desc")}
  {_("help.persistent_cli")}
  {_("help.persistent_repl")}

 [bold]{_("help.examples")}[/]:
  {_("help.example_pentest")}
  {_("help.example_scan")}
  {_("help.example_vuln")}
  {_("help.example_exploit")}
  {_("help.example_report")}
"""
    console.print(Panel(help_text, title=_("help.title"), border_style="cyan"))


def _print_status(agent, mcp_manager, target, phase, config) -> None:
    """Print current session status."""
    think_state = "[green]shown[/]" if config.session.show_thinking else "[yellow]hidden[/]"
    phase_label = _localized_phase_label(phase)
    console.print(
        Panel(
            f"{_('status.target', target=target or 'Not set')}\n"
            f"{_('status.phase', phase=phase_label)}\n"
            f"{_('status.mcp_services', count=mcp_manager.running_count())}\n"
            f"{_('status.tools', count=len(mcp_manager.list_available_tools()))}\n"
            f"{_('status.thinking', state=think_state)}",
            title=_("status.title"),
            border_style="green",
        )
    )


def _validate_headless_choices(
    scan_mode: str, fail_on: str, scope_mode: str
) -> Optional[str]:
    """Return an error message for a bad headless choice, else ``None``."""
    if scan_mode not in headless.SCAN_MODES:
        return f"--scan-mode must be one of: {', '.join(headless.SCAN_MODES)}"
    if fail_on not in headless.FAIL_ON_MODES:
        return f"--fail-on must be one of: {', '.join(headless.FAIL_ON_MODES)}"
    if scope_mode not in headless.SCOPE_MODES:
        return f"--scope-mode must be one of: {', '.join(headless.SCOPE_MODES)}"
    return None


def _run_non_interactive(
    *,
    target: str,
    output: Optional[str],
    profile: "headless.ScanProfile",
    scan_mode: str,
    scope_mode: str,
    fail_on: str,
    run_coro_factory,
    classification_holder: dict,
) -> None:
    """Drive a headless run: no prompts, structured output, exit-code contract.

    Any crash during the scan exits :data:`headless.EXIT_ERROR` (1) — a broken
    scan never exits 0. On completion the finding set is mapped to an exit code
    under ``--fail-on`` and a ``summary.json`` is written into the run directory.
    """
    from datetime import datetime

    try:
        asyncio.run(run_coro_factory())
    except typer.Exit:
        raise
    except BaseException as exc:  # noqa: BLE001 - CI must see a nonzero exit, not a traceback
        err_console.print(f"[!] Scan did not complete: {type(exc).__name__}: {exc}")
        raise typer.Exit(headless.EXIT_ERROR) from exc

    classification = classification_holder.get("classification") or headless.FindingClassification(
        verified=0, candidates=0
    )
    exit_code = headless.determine_exit_code(classification, fail_on)

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = headless.run_directory(RUNS_DIR, target, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    # Co-locate the report inside the run directory unless the caller pinned a
    # path with --output, so all structured output for a run lives in one place.
    report_output = output or str(run_dir / "report.md")
    report_path = _generate_report_for_target(target, output_path=report_output)

    summary = headless.build_run_summary(
        target=target,
        scan_mode=scan_mode,
        scope_mode=scope_mode,
        fail_on=fail_on,
        profile=profile,
        classification=classification,
        exit_code=exit_code,
        report_path=str(report_path),
    )
    summary_path = headless.write_run_artifacts(run_dir, summary)

    console.print(
        f"[*] findings: verified={classification.verified} "
        f"candidates={classification.candidates} | "
        f"exit={exit_code} ({headless.exit_code_meaning(exit_code)})"
    )
    console.print(f"[*] run artifacts: {summary_path}")
    console.print(_("cli.report_generated", path=report_path))
    raise typer.Exit(exit_code)


def _run_context_kwargs(
    *,
    run_name: Optional[str] = None,
    resume_run_name: Optional[str] = None,
    runs_dir: Optional[str] = None,
    additional_targets: Optional[list[str]] = None,
    target_type: Optional[str] = None,
    mount: bool = False,
    repair: bool = False,
    force_fresh: bool = False,
    no_import: bool = False,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if run_name:
        kwargs["run_name"] = run_name
    if resume_run_name:
        kwargs["resume_run_name"] = resume_run_name
    if runs_dir:
        kwargs["runs_dir"] = runs_dir
    if additional_targets:
        kwargs["additional_targets"] = additional_targets
    if target_type:
        kwargs["target_type"] = target_type
    if mount:
        kwargs["mount"] = mount
    if repair:
        kwargs["repair"] = repair
    if force_fresh:
        kwargs["force_fresh"] = force_fresh
    if no_import:
        kwargs["no_import"] = no_import
    return kwargs


def _print_run_completion_summary(summary: dict[str, Any]) -> None:
    run_name = summary.get("run_name")
    run_dir = summary.get("run_dir")
    if not run_name or not run_dir:
        return
    artifacts = summary.get("artifact_locations", {})
    console.print(
        Panel(
            f"Run: [bold]{run_name}[/]\n"
            f"Directory: [bold]{run_dir}[/]\n"
            f"Findings: [bold]{summary.get('verified_count', 0)} verified / "
            f"{summary.get('pending_count', 0)} pending / "
            f"{summary.get('candidate_count', 0)} candidate[/]\n"
            f"Artifacts: findings={artifacts.get('findings', '')} "
            f"reports={artifacts.get('reports', '')} evidence={artifacts.get('evidence', '')}\n"
            f"Resume: [bold]{summary.get('resume_command', '')}[/]\n"
            f"Exit: [bold]{summary.get('exit_code', 0)}[/] "
            f"({summary.get('exit_meaning', 'completed')})",
            title="Run Summary",
            border_style="green" if summary.get("exit_code", 0) == 0 else "yellow",
        )
    )


# 鈹€鈹€ Sub-commands 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


app = typer.Typer(
    name="vulnclaw",
    help="VulnClaw - AI-powered penetration testing CLI (run 'vulnclaw tui' for the TUI workbench)",
    no_args_is_help=False,
    add_completion=False,
)


@app.command()
def run(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    scope: str = typer.Option("full", help="Test scope: full, web, api, mobile"),
    output: Optional[str] = typer.Option(None, help="Output report file path"),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    engine: Optional[str] = typer.Option(
        None,
        "--engine",
        help="Autonomous engine for this run: solve, team, or rounds",
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    # ── Headless / CI knobs ────────────────────────────────────────────
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Headless mode: zero prompts, structured output to the run directory, "
        "and a distinct exit code (see --fail-on). Intended for CI.",
    ),
    scan_mode: str = typer.Option(
        headless.DEFAULT_SCAN_MODE,
        "--scan-mode",
        help="Depth preset over the effort knobs: quick | standard | deep. "
        "Explicit --max-* flags override the preset.",
    ),
    fail_on: str = typer.Option(
        headless.DEFAULT_FAIL_ON,
        "--fail-on",
        help="Which finding class trips a nonzero exit: verified | any | never.",
    ),
    scope_mode: str = typer.Option(
        headless.DEFAULT_SCOPE_MODE,
        "--scope-mode",
        help="Scope selection recorded for the run: full (whole surface, current "
        "behaviour) | auto (diff-scope to changed code — consumed by the Target "
        "diff-scope model, #35; falls back to full until that lands).",
    ),
    max_steps: Optional[int] = typer.Option(
        None, "--max-steps", help="Override the scan-mode explore-step cap"
    ),
    max_directions: Optional[int] = typer.Option(
        None,
        "--max-directions",
        help="Deprecated compatibility option; model-led solve ignores research-direction limits",
    ),
    max_tool_rounds: Optional[int] = typer.Option(
        None, "--max-tool-rounds", help="Override the scan-mode tool-use compatibility budget"
    ),
    max_parallel: Optional[int] = typer.Option(
        None, "--max-parallel", help="Override the scan-mode fan-out cap (1 = single agent)"
    ),
    max_rounds: Optional[int] = typer.Option(
        None, "--max-rounds", help="Override the scan-mode legacy-engine round cap"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(
        None, "--runs-dir", help="Run-directory root (overrides VULNCLAW_RUNS_DIR)"
    ),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(
        None, "--target-type", help="Override target type: local_repo, repo_url, web_url, domain, ip"
    ),
    mount: bool = typer.Option(
        False, "--mount", help="Use mount ingress mode for local repository targets"
    ),
    repair: bool = typer.Option(
        False, "--repair", help="Repair a corrupt run by rolling back to the last valid snapshot"
    ),
    force_fresh: bool = typer.Option(
        False, "--force-fresh", help="Start a fresh run without overwriting a corrupt one"
    ),
    no_import: bool = typer.Option(
        False, "--no-import", help="Read legacy target state without importing it into a run"
    ),
    stream: bool = typer.Option(
        False,
        "--stream",
        help="Emit newline-delimited JSON events (status/log/finding/complete) for the Rust TUI",
    ),
) -> None:
    """Run a full authorized pentest workflow.

    Interactive by default. Pass ``--non-interactive`` for a headless CI run: no
    prompts, a machine-readable ``summary.json`` in the run directory, and an
    exit code that lets a pipeline tell a clean scan (0) from a broken one (1)
    from one that confirmed a verified finding (2) or only candidates (3).
    Pass ``--stream`` to emit newline-delimited JSON events consumed by the
    Rust ratatui TUI (``vulnclaw tui``).
    """
    config = load_config()

    # A bad target / scan-mode / fail-on / scope-mode is a misconfiguration:
    # exit 1 (never a silent green run).
    if not target or not target.strip():
        err_console.print("[!] A non-empty target is required.")
        raise typer.Exit(headless.EXIT_ERROR)
    bad_choice = _validate_headless_choices(scan_mode, fail_on, scope_mode)
    if bad_choice is not None:
        err_console.print(f"[!] {bad_choice}")
        raise typer.Exit(headless.EXIT_ERROR)
    if not has_llm_credentials(config.llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(headless.EXIT_ERROR)
    if engine is not None and engine not in ENGINE_CHOICES:
        err_console.print(f"[!] --engine must be one of: {', '.join(ENGINE_CHOICES)}")
        raise typer.Exit(headless.EXIT_ERROR)

    profile = headless.resolve_scan_profile(
        config,
        scan_mode,
        max_steps=max_steps,
        max_directions=max_directions,
        max_tool_rounds=max_tool_rounds,
        max_parallel=max_parallel,
        max_rounds=max_rounds,
    )

    console.print(
        f"[*] Target: [bold]{target}[/] | Scope: [bold]{scope}[/] | "
        f"Mode: [bold]{profile.scan_mode}[/]"
        + (" | [bold]non-interactive[/]" if non_interactive else "")
    )

    task_prompt = prompt if prompt else (
        f"Perform an authorized {scope} pentest against {target}. "
        "This target is in scope and explicitly authorized."
    )
    task_prompt = _append_cli_constraints_compat(
        task_prompt, only_port, only_host, only_path, blocked_host, blocked_path
    )
    task_prompt = _append_action_constraints(task_prompt, allow_actions, block_actions)
    violation = validate_action_constraints("run", extract_task_constraints(task_prompt))
    if violation is not None:
        err_console.print(f"[!] {violation}")
        raise typer.Exit(headless.EXIT_ERROR)

    agent_state_holder: dict = {}
    classification_holder: dict = {}
    stream_out = sys.stdout if stream else None

    async def _run():
        async def runner(agent, shared_config):
            # Apply the resolved fan-out / round caps so solve/team/auto_pentest
            # (which read them off config.session) honour the scan-mode preset.
            shared_config.session.solve_max_parallel = profile.max_parallel
            shared_config.session.max_rounds = profile.max_rounds
            # In headless mode suppress streaming thinking so nothing blocks on a TTY.
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(stream_out, shared_config.session.show_thinking)

                def on_event(kind: str, payload: dict) -> None:
                    if kind == "agent_step":
                        sink._emit({"type": "log", "message": f"turn {payload.get('step', '?')}"})
                    elif kind == "error":
                        sink._emit({"type": "log", "message": f"error: {payload.get('error', '')}"})
                    elif kind == "ask_user":
                        sink._emit({"type": "log", "message": f"? {payload.get('question', '')}"})
                    elif kind == "completed":
                        sink._emit({"type": "status", "status": "goal reached"})
                    elif kind == "no_path":
                        sink._emit({"type": "log", "message": f"no path: {payload.get('reason', '')}"})
            else:
                sink = (
                    None
                    if non_interactive
                    else TerminalStreamSink(console, shared_config.session.show_thinking)
                )
                on_event = None if non_interactive else _make_solve_event_printer(console)
            selected_engine = resolve_engine(shared_config, engine)
            # 默认走目标驱动 solve 引擎；engine=team 启用角色团队；engine=rounds 回退旧循环
            if selected_engine == "solve":
                result = await agent.solve(
                    task_prompt,
                    target=target,
                    max_steps=profile.max_steps,
                    max_tool_rounds=profile.max_tool_rounds,
                    stream_sink=sink,
                    on_event=on_event,
                )
            elif selected_engine == "team":
                from vulnclaw.agent.team import run_team_pentest

                def agent_factory():
                    return agent.__class__(shared_config, getattr(agent, "mcp_manager", None))

                result = await run_team_pentest(
                    agent,
                    user_input=task_prompt,
                    target=target,
                    agent_factory=agent_factory,
                    max_steps=profile.max_steps,
                    max_directions=profile.max_directions,
                    max_tool_rounds=profile.max_tool_rounds,
                    # team fan-out reads its own cap (not config), so pass the
                    # resolved scan-mode profile explicitly or quick/--max-parallel
                    # would be ignored and it would fan out to every ready step.
                    max_parallel=profile.max_parallel,
                    stream_sink=sink,
                    on_event=on_event,
                )
            else:
                result = await agent.auto_pentest(
                    task_prompt,
                    target=target,
                    max_rounds=profile.max_rounds,
                    on_step=lambda r, res: (
                        _print_agent_output(
                            f"[dim]Round {r}[/]: {res.output[:200]}...", shared_config
                        )
                        if res.output and not non_interactive
                        else None
                    ),
                    stream_sink=sink,
                )
            agent_state = getattr(
                getattr(getattr(agent, "context", None), "state", None), "agent_state", None
            )
            if agent_state is not None:
                agent_state_holder["agent_state"] = agent_state.get_summary()
            classification_holder["classification"] = headless.classify_findings(
                getattr(agent, "session_state", None)
            )
            return result

        result = await _run_cli_orchestrated_task(
            command="run",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )
        return result

    if non_interactive:
        _run_non_interactive(
            target=target,
            output=output,
            profile=profile,
            scan_mode=scan_mode,
            scope_mode=scope_mode,
            fail_on=fail_on,
            run_coro_factory=_run,
            classification_holder=classification_holder,
        )
        return

    orchestrated = asyncio.run(_run())

    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        findings: list[dict[str, Any]] = []
        agent_state = agent_state_holder.get("agent_state") or {}
        summary = (
            f"{'✅ goal reached' if agent_state.get('completed') else '⊘ not reached'}"
            f" — steps={agent_state.get('steps', 0)} evidence={agent_state.get('evidence', 0)}"
        )
        # Verified claims map onto the Rust TUI finding list.
        for idx, claim in enumerate(
            (agent_state.get("verified_claims") or [])[:50], start=1
        ):
            if isinstance(claim, dict):
                findings.append(
                    {
                        "id": claim.get("id") or f"v{idx:03d}",
                        "severity": "high",
                        "title": str(claim.get("claim") or "")[:200],
                        "target": target,
                    }
                )
        emit_complete_event(stream_out, summary=summary, findings=findings)
        return

    if agent_state_holder.get("agent_state"):
        agent_state = agent_state_holder["agent_state"]
        status = _("cli.goal_achieved") if agent_state.get("completed") else _("cli.goal_not_achieved")
        console.print(
            f"\n[bold]{status}[/bold] — steps={agent_state.get('steps', 0)} "
            f"evidence={agent_state.get('evidence', 0)} "
            f"tools={agent_state.get('tool_calls', 0)} "
            f"{_('cli.reason')}: {agent_state.get('complete_reason') or _('cli.reason_not_complete')}"
        )
    else:
        total_findings = orchestrated.summary["findings_count"]
        console.print(_("cli.pentest_finished", findings=total_findings))

    report_path = _generate_report_for_target(target, output_path=output)
    console.print(_("cli.report_generated", path=report_path))


@app.command()
def solve(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    goal: Optional[str] = typer.Option(
        None, "--goal", help="Success condition, e.g. 'capture the flag' / 'get a shell'"
    ),
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom task description (overrides auto-generated)"
    ),
    max_steps: int = typer.Option(
        240, "--max-steps", help="Runaway safety budget for autonomous turns (not a planned round count)"
    ),
    max_directions: int = typer.Option(
        3,
        "--max-directions",
        help="Deprecated compatibility option; model-led solve ignores research-direction limits",
    ),
    max_tool_rounds: int = typer.Option(
        6, "--max-tool-rounds", help="Compatibility option; model-led solve decides tool use per step"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(None, "--snapshot", help="Resume from a snapshot id"),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """Model-led solve loop; runs until goal, user input, no path, or safety cap."""
    config = load_config()
    if not has_llm_credentials(config.llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(1)

    resolved_goal = goal or _("cli.default_goal")
    task_prompt = prompt or _("cli.task_prompt", target=target, goal=resolved_goal)
    console.print(f"[*] Target: [bold]{target}[/] | Goal: [bold]{resolved_goal}[/]")

    holder: dict = {}
    stream_out = sys.stdout if stream else None

    async def _run():
        async def runner(agent, shared_config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(stream_out, shared_config.session.show_thinking)

                def on_event(kind: str, payload: dict) -> None:
                    if kind == "agent_step":
                        sink._emit({"type": "log", "message": f"turn {payload.get('step', '?')}"})
                    elif kind == "error":
                        sink._emit({"type": "log", "message": f"error: {payload.get('error', '')}"})
                    elif kind == "ask_user":
                        sink._emit({"type": "log", "message": f"? {payload.get('question', '')}"})
                    elif kind == "completed":
                        sink._emit({"type": "status", "status": "goal reached"})
            else:
                sink = TerminalStreamSink(console, shared_config.session.show_thinking)
            result = await agent.solve(
                task_prompt,
                target=target,
                goal=resolved_goal,
                max_steps=max_steps,
                max_tool_rounds=max_tool_rounds,
                stream_sink=sink,
                on_event=on_event,
            )
            holder["agent_state"] = agent.context.state.agent_state.get_summary()
            holder["agent"] = agent
            return result

        return await _run_cli_orchestrated_task(
            command="solve",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )

    asyncio.run(_run())
    agent_state = holder.get("agent_state") or {}
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        findings: list[dict[str, Any]] = []
        for idx, claim in enumerate((agent_state.get("verified_claims") or [])[:50], start=1):
            if isinstance(claim, dict):
                findings.append(
                    {
                        "id": claim.get("id") or f"v{idx:03d}",
                        "severity": "high",
                        "title": str(claim.get("claim") or "")[:200],
                        "target": target,
                    }
                )
        summary = (
            f"{'✅ goal reached' if agent_state.get('completed') else '⊘ not reached'}"
            f" — steps={agent_state.get('steps', 0)} evidence={agent_state.get('evidence', 0)}"
        )
        emit_complete_event(stream_out, summary=summary, findings=findings)
        return

    status = _("cli.goal_achieved") if agent_state.get("completed") else _("cli.goal_not_achieved")
    console.print(
        f"\n[bold]{status}[/bold] — steps={agent_state.get('steps', 0)} "
        f"evidence={agent_state.get('evidence', 0)} "
        f"tools={agent_state.get('tool_calls', 0)} "
        f"{_('cli.reason')}: {agent_state.get('complete_reason') or _('cli.reason_not_complete')}"
    )
    if agent_state.get("completed"):
        # ``holder`` stores only the summary for status printing, so generate
        # from the live session state captured on the orchestrated agent below.
        live_agent = holder.get("agent")
        if live_agent is not None:
            _emit_solve_report_if_completed(live_agent, config)


@app.command()
def persistent(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    rounds: int = typer.Option(
        0, "--rounds", "-r", help="Rounds per cycle (0=use config, default 100)"
    ),
    cycles: int = typer.Option(0, "--cycles", "-c", help="Max cycles (0=use config, default 10)"),
    no_report: bool = typer.Option(
        False, "--no-report", help="Disable auto report after each cycle"
    ),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
) -> None:
    """Run a persistent authorized pentest across multiple cycles."""
    from vulnclaw.agent.core import PersistentCycleResult

    config = load_config()
    if not has_llm_credentials(config.llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(1)

    # Resolve parameters (CLI override -> config defaults)
    rounds_per_cycle = rounds if rounds > 0 else config.session.persistent_rounds_per_cycle
    max_cycles = cycles if cycles > 0 else config.session.persistent_max_cycles
    auto_report = config.session.persistent_auto_report and not no_report

    console.print(
        Panel(
            f"Target: [bold]{target}[/]\n"
            f"Rounds per cycle: [bold]{rounds_per_cycle}[/]\n"
            f"Max cycles: [bold]{max_cycles}[/] {'(unlimited)' if max_cycles == 0 else ''}\n"
            f"Auto report: {'[green]on[/]' if auto_report else '[yellow]off[/]'}\n"
            f"Max total rounds: [bold]{rounds_per_cycle * max_cycles if max_cycles > 0 else 'unlimited'}[/]",
            title="Persistent Pentest",
            border_style="cyan",
        )
    )

    task_prompt = prompt if prompt else (
        f"Perform an authorized persistent penetration test against {target}. "
        "This target is in scope and explicitly authorized."
    )
    task_prompt = _append_cli_constraints_compat(
        task_prompt, only_port, only_host, only_path, blocked_host, blocked_path
    )
    task_prompt = _append_action_constraints(task_prompt, allow_actions, block_actions)
    violation = validate_action_constraints("persistent", extract_task_constraints(task_prompt))
    if violation is not None:
        err_console.print(f"[!] {violation}")
        raise typer.Exit(1)

    # Track stats
    all_cycle_results: list[PersistentCycleResult] = []
    interrupted = False

    def _on_cycle_step(round_num: int, cycle_num: int, result) -> None:
        """Real-time output for each step within a cycle."""
        console.print(f"[dim]-- Cycle {cycle_num} | Round {round_num} --[/]")
        # TerminalStreamSink 已实时流式显示，回调不重复打印
        console.print()

    def _on_cycle_complete(cycle_num: int, cycle_result: PersistentCycleResult) -> None:
        """Callback after each cycle completes."""
        all_cycle_results.append(cycle_result)
        console.print(
            Panel(
                f"Cycle {cycle_num} completed\n"
                f"   Steps executed: {cycle_result.total_steps}\n"
                f"   Total findings: {cycle_result.total_findings}\n"
                f"   New findings: {cycle_result.new_findings}\n"
                f"   Report: {cycle_result.report_path or 'not generated'}",
                title=f"Cycle {cycle_num} Result",
                border_style="green" if cycle_result.new_findings == 0 else "red",
            )
        )
        console.print()

    async def _run():
        async def runner(agent, _config):
            sink = TerminalStreamSink(console, _config.session.show_thinking)
            return await agent.persistent_pentest(
                user_input=task_prompt,
                target=target,
                rounds_per_cycle=rounds_per_cycle,
                max_cycles=max_cycles,
                auto_report=auto_report,
                on_cycle_step=_on_cycle_step,
                on_cycle_complete=_on_cycle_complete,
                stream_sink=sink,
            )

        return await _run_cli_orchestrated_task(
            command="persistent",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )

    try:
        orchestrated = asyncio.run(_run())
    except KeyboardInterrupt:
        interrupted = True
        console.print("\n[!] User interrupted persistent pentest")
        orchestrated = None

    summary = (
        orchestrated.summary
        if orchestrated
        else {
            "findings_count": 0,
            "executed_steps": 0,
        }
    )
    total_findings = summary["findings_count"]
    total_steps = summary["executed_steps"]
    completed_cycles = len(all_cycle_results)

    console.print()
    console.print(
        Panel(
            f"{'Interrupted by user' if interrupted else 'Testing completed'}\n\n"
            f"  Completed cycles: [bold]{completed_cycles}[/]\n"
            f"  Steps executed: [bold]{total_steps}[/]\n"
            f"  Findings: [bold]{total_findings}[/]",
            title="Persistent Pentest Summary",
            border_style="red" if total_findings > 0 else "green",
        )
    )

    if auto_report and all_cycle_results:
        console.print("\n[bold]Cycle Reports[/]:")
        for cr in all_cycle_results:
            if cr.report_path and "failed" not in str(cr.report_path).lower():
                console.print(f"  Cycle {cr.cycle_num}: {cr.report_path}")


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """Run reconnaissance only."""
    task_prompt = prompt if prompt else f"Perform authorized reconnaissance against {target} without exploitation."
    task_prompt = _append_cli_constraints_compat(
        task_prompt, only_port, only_host, only_path, blocked_host, blocked_path
    )
    task_prompt = _append_action_constraints(task_prompt, allow_actions, block_actions)
    violation = validate_action_constraints("recon", extract_task_constraints(task_prompt))
    if violation is not None:
        err_console.print(f"[!] {violation}")
        raise typer.Exit(1)

    async def _run():
        async def runner(agent, _config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(sys.stdout, _config.session.show_thinking)
            else:
                sink = TerminalStreamSink(console, _config.session.show_thinking)
            # TerminalStreamSink 已实时流式显示，不重复 console.print
            return await agent.chat(task_prompt, target=target, stream_sink=sink)

        await _run_cli_orchestrated_task(
            command="recon",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )

    asyncio.run(_run())
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        emit_complete_event(sys.stdout, summary="recon done", findings=[])


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    ports: Optional[str] = typer.Option(None, help="Port range, e.g. 80,443,8080"),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """Run vulnerability scanning only."""
    port_hint = f", focusing on ports {ports}" if ports else ""
    task_prompt = prompt if prompt else f"Perform authorized vulnerability scanning against {target}{port_hint} without exploitation."
    task_prompt = _append_cli_constraints_compat(
        task_prompt, only_port, only_host, only_path, blocked_host, blocked_path
    )
    task_prompt = _append_action_constraints(task_prompt, allow_actions, block_actions)
    violation = validate_action_constraints("scan", extract_task_constraints(task_prompt))
    if violation is not None:
        err_console.print(f"[!] {violation}")
        raise typer.Exit(1)

    async def _run():
        async def runner(agent, _config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(sys.stdout, _config.session.show_thinking)
            else:
                sink = TerminalStreamSink(console, _config.session.show_thinking)
            # TerminalStreamSink 已实时流式显示，不重复 console.print
            return await agent.chat(task_prompt, target=target, stream_sink=sink)

        await _run_cli_orchestrated_task(
            command="scan",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )

    asyncio.run(_run())
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        emit_complete_event(sys.stdout, summary="scan done", findings=[])


@app.command("network-scan")
def network_scan(
    target: Optional[str] = typer.Argument(
        None, help="Target host/IP/CIDR; defaults to the currently connected Wi-Fi subnet"
    ),
    profile: str = typer.Option(
        "adaptive",
        "--profile",
        help="Network scan profile: adaptive, fast, thorough, stealth",
    ),
    ports: Optional[str] = typer.Option(None, "--ports", help="Port range, e.g. 80,443,1-1000"),
    max_rounds: int = typer.Option(
        0, "--max-rounds", help="Agent follow-up rounds (0 = use the configured default)"
    ),
    parallel_agents: int = typer.Option(
        1,
        "--parallel-agents",
        min=1,
        help="Number of sub-agents to fan out over discovered attack surfaces (1 disables parallelism)",
    ),
    parallel_depth: int = typer.Option(
        1,
        "--parallel-depth",
        min=1,
        help="Bounded number of attack-surface discovery waves for sub-agents",
    ),
    worker_rounds: int = typer.Option(
        3,
        "--worker-rounds",
        min=1,
        help="Execution rounds per sub-agent worker",
    ),
    surface_limit: int = typer.Option(
        20,
        "--surface-limit",
        min=1,
        help="Maximum number of attack surfaces to fan sub-agents out over",
    ),
    safe_probes: bool = typer.Option(
        True,
        "--safe-probes/--no-safe-probes",
        help="After the nmap scan, run only non-destructive verification probes by default",
    ),
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """Run an nmap-based network scan and follow up on weak links."""
    normalized_profile = profile.strip().lower()
    if normalized_profile not in {"adaptive", "fast", "thorough", "stealth"}:
        err_console.print(f"[!] {_('cli.invalid_profile')}")
        raise typer.Exit(1)

    detected_wifi = None
    scan_target = target.strip() if target else ""
    if not scan_target:
        from vulnclaw.agent.network_scan import detect_connected_wifi_target

        try:
            detected_wifi = detect_connected_wifi_target()
            scan_target = detected_wifi.cidr
        except RuntimeError as exc:
            err_console.print(f"[!] {exc}")
            raise typer.Exit(1)

    port_hint = f" limited to ports {ports}" if ports else ""
    follow_up = (
        "Then prioritize weak links and perform safe, non-destructive verification probes only."
        if safe_probes
        else "Then summarize weak links without running follow-up probes."
    )
    task_prompt = prompt if prompt else (
        f"Perform an authorized {normalized_profile} network scan against {scan_target}{port_hint}. "
        f"Use the nmap_scan tool with profile={normalized_profile}"
        f"{f' and ports={ports}' if ports else ''}. "
        f"{follow_up} Record open services and candidate weak-link findings in target state. "
        "Do not brute force credentials, run destructive payloads, or perform post-exploitation."
    )
    task_prompt = _append_cli_constraints_compat(
        task_prompt,
        only_port,
        only_host,
        None,
        blocked_host,
        None,
    )

    effective_allow_actions = allow_actions
    effective_block_actions = block_actions
    if safe_probes and not allow_actions and not block_actions:
        effective_allow_actions = "recon,scan"
    task_prompt = _append_action_constraints(
        task_prompt, effective_allow_actions, effective_block_actions
    )

    violation = validate_action_constraints("scan", extract_task_constraints(task_prompt))
    if violation is not None:
        err_console.print(f"[!] {violation}")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"{_('cli.scan.panel.target')}: [bold]{scan_target}[/]\n"
            + (
                f"{_('cli.scan.panel.wifi')}: [bold]{detected_wifi.interface}[/] "
                f"({detected_wifi.address})\n"
                if detected_wifi
                else ""
            )
            +
            f"{_('cli.scan.panel.profile')}: [bold]{normalized_profile}[/]\n"
            f"{_('cli.scan.panel.ports')}: [bold]{ports or _('cli.scan.panel.ports_default')}[/]\n"
            f"{_('cli.scan.panel.follow_up')}: "
            f"[bold]{_('cli.scan.panel.safe_probes') if safe_probes else _('cli.scan.panel.summary_only')}[/]\n"
            f"{_('cli.scan.panel.parallel_agents')}: [bold]{parallel_agents}[/]"
            + (
                _("cli.scan.panel.parallel_detail", depth=parallel_depth, rounds=worker_rounds)
                if parallel_agents > 1
                else ""
            ),
            title=_("cli.scan.panel.title"),
            border_style="cyan",
        )
    )

    async def _run():
        async def runner(agent, _config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(sys.stdout, _config.session.show_thinking)
            else:
                sink = TerminalStreamSink(console, _config.session.show_thinking)
            rounds = max_rounds if max_rounds > 0 else _config.session.max_rounds
            if parallel_agents > 1:
                from vulnclaw.agent.parallel_agents import run_parallel_pentest

                def agent_factory():
                    return agent.__class__(_config, getattr(agent, "mcp_manager", None))

                return await run_parallel_pentest(
                    agent,
                    agent_factory=agent_factory,
                    user_input=task_prompt,
                    target=scan_target,
                    discovery_rounds=rounds,
                    worker_rounds=worker_rounds,
                    max_agents=parallel_agents,
                    max_depth=parallel_depth,
                    surface_limit=surface_limit,
                    stream_sink=sink,
                )
            return await agent.auto_pentest(
                task_prompt,
                target=scan_target,
                max_rounds=rounds,
                stream_sink=sink,
            )

        await _run_cli_orchestrated_task(
            command="network-scan",
            target=scan_target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )

    asyncio.run(_run())
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        emit_complete_event(sys.stdout, summary="network scan done", findings=[])


@app.command()
def exploit(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    cve: Optional[str] = typer.Option(None, help="Specific CVE to exploit"),
    cmd: str = typer.Option("id", help="Command to execute for verification"),
    # [新增] 2026-06-10 Nyaecho - TUI自然语言驱动: 允许通过 --prompt 传入自定义提示词覆盖自动生成的prompt
    prompt: Optional[str] = typer.Option(
        None, "--prompt", help="Custom natural language prompt (overrides auto-generated prompt)"
    ),
    only_port: Optional[int] = typer.Option(
        None, "--only-port", help="Restrict testing to a single port"
    ),
    only_host: Optional[str] = typer.Option(
        None, "--only-host", help="Restrict testing to a single host"
    ),
    only_path: Optional[str] = typer.Option(
        None, "--only-path", help="Restrict testing to a single path"
    ),
    blocked_host: Optional[str] = typer.Option(
        None, "--blocked-host", help="Explicitly blocked host"
    ),
    blocked_path: Optional[str] = typer.Option(
        None, "--blocked-path", help="Explicitly blocked path"
    ),
    allow_actions: Optional[str] = typer.Option(
        None, "--allow-actions", help="Comma-separated allowed actions"
    ),
    block_actions: Optional[str] = typer.Option(
        None, "--block-actions", help="Comma-separated blocked actions"
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume previous target state"),
    snapshot: Optional[str] = typer.Option(
        None, "--snapshot", help="Resume from a specific target snapshot id"
    ),
    run_name: Optional[str] = typer.Option(
        None, "--run-name", help="Explicit name for a new run directory"
    ),
    resume_run: Optional[str] = typer.Option(
        None, "--resume-run", help="Resume an exact run by run name"
    ),
    runs_dir: Optional[str] = typer.Option(None, "--runs-dir", help="Run-directory root"),
    additional_targets: Optional[list[str]] = typer.Option(
        None, "--target", help="Additional target to include in this run"
    ),
    target_type: Optional[str] = typer.Option(None, "--target-type", help="Override target type"),
    mount: bool = typer.Option(False, "--mount", help="Use mount ingress mode"),
    repair: bool = typer.Option(False, "--repair", help="Repair a corrupt run"),
    force_fresh: bool = typer.Option(False, "--force-fresh", help="Start a fresh run"),
    no_import: bool = typer.Option(False, "--no-import", help="Do not import legacy state"),
    stream: bool = typer.Option(
        False, "--stream", help="Emit newline-delimited JSON events for the Rust TUI"
    ),
) -> None:
    """Run exploitation only."""
    cve_hint = f" using {cve}" if cve else ""
    task_prompt = prompt if prompt else (
        f"Attempt authorized exploitation against {target}{cve_hint} and verify with command: {cmd}"
    )
    task_prompt = _append_cli_constraints_compat(
        task_prompt, only_port, only_host, only_path, blocked_host, blocked_path
    )
    task_prompt = _append_action_constraints(task_prompt, allow_actions, block_actions)
    violation = validate_action_constraints("exploit", extract_task_constraints(task_prompt))
    if violation is not None:
        err_console.print(f"[!] {violation}")
        raise typer.Exit(1)

    async def _run():
        async def runner(agent, _config):
            if stream:
                from vulnclaw.cli._helpers import JsonlStreamSink

                sink = JsonlStreamSink(sys.stdout, _config.session.show_thinking)
            else:
                sink = TerminalStreamSink(console, _config.session.show_thinking)
            # TerminalStreamSink 已实时流式显示，不重复 console.print
            return await agent.chat(task_prompt, target=target, stream_sink=sink)

        await _run_cli_orchestrated_task(
            command="exploit",
            target=target,
            resume=resume,
            snapshot=snapshot,
            runner=runner,
            **_run_context_kwargs(
                run_name=run_name,
                resume_run_name=resume_run,
                runs_dir=runs_dir,
                additional_targets=additional_targets,
                target_type=target_type,
                mount=mount,
                repair=repair,
                force_fresh=force_fresh,
                no_import=no_import,
            ),
        )

    asyncio.run(_run())
    if stream:
        from vulnclaw.cli._helpers import emit_complete_event

        emit_complete_event(sys.stdout, summary="exploit done", findings=[])


@app.command()
def report(
    session: str = typer.Argument(
        ..., help="Path to session JSON file or target when used with --target"
    ),
    target_mode: bool = typer.Option(
        False, "--target", help="Interpret argument as target and generate report from target state"
    ),
    pdf: bool = typer.Option(
        False, "--pdf", help="Also export the report to PDF (requires the vulnclaw[pdf] extra)"
    ),
    pdf_out: str = typer.Option(
        "", "--pdf-out", help="PDF output path (default: the report path with a .pdf suffix)"
    ),
) -> None:
    """Generate a report from a session file or target state."""
    # Report bodies call _() for localized text; initialize i18n from the
    # configured language so non-interactive runs honor session.language
    # instead of falling back to the process locale (VULNCLAW_LANG/LANG).
    from vulnclaw.i18n import init_i18n

    report_config = load_config()
    init_i18n(config=report_config)

    if target_mode:
        from vulnclaw.report.generator import generate_report_from_target_state

        state = load_target_state(session)
        if not state:
            err_console.print(f"[!] Target state not found: {session}")
            raise typer.Exit(1)
        report_path = generate_report_from_target_state(state)
    else:
        from vulnclaw.report.generator import generate_report_from_file

        report_path = generate_report_from_file(session)
    console.print(f"[+] Report generated: {report_path}")

    if pdf:
        from pathlib import Path

        from vulnclaw.report.pdf_exporter import export_pdf

        out = Path(pdf_out) if pdf_out else Path(report_path).with_suffix(".pdf")
        try:
            markdown = Path(report_path).read_text(encoding="utf-8")
            export_pdf(markdown, out, title="VulnClaw Report")
        except RuntimeError as exc:
            err_console.print(f"[!] {exc}")
            raise typer.Exit(1) from exc
        console.print(f"[+] PDF exported: {out}")


def _print_cli_manual(topic: Optional[str], output_format: str) -> None:
    """Print the packaged CLI manual, normalizing user-facing errors."""
    try:
        console.out(render_manual(output_format, topic), end="")
    except ValueError as exc:
        err_console.print(f"[!] {exc}")
        err_console.print(f"    Available topics: {', '.join(available_topics())}")
        raise typer.Exit(1) from exc


@app.command("manual")
def manual_command(
    topic: Optional[str] = typer.Argument(
        None, help="Optional manual topic, e.g. run, solve, network-scan, config"
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, markdown, man",
    ),
) -> None:
    """Print the full VulnClaw CLI manual."""
    _print_cli_manual(topic, output_format)


@app.command("man")
def man_command(
    topic: Optional[str] = typer.Argument(
        None, help="Optional manual topic, e.g. run, solve, network-scan, config"
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, markdown, man",
    ),
) -> None:
    """Alias for 'vulnclaw manual'."""
    _print_cli_manual(topic, output_format)


# 鈹€鈹€ Config sub-command group 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

config_app = typer.Typer(help="Manage configuration")
app.add_typer(config_app, name="config")


@config_app.callback(invoke_without_command=True)
def config_root(ctx: typer.Context) -> None:
    """Open the interactive config editor when no subcommand is provided."""
    if ctx.resilient_parsing or ctx.invoked_subcommand is not None:
        return
    from vulnclaw.cli.tui import run_config_tui

    run_config_tui()


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key in dot notation, e.g. llm.api_key"),
    value: str = typer.Argument(..., help="Config value"),
) -> None:
    """Set a config value."""
    set_config_value(key, value)
    console.print(
        f"[+] Set {key} = {'***' if 'key' in key.lower() or 'pass' in key.lower() else value}"
    )


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key in dot notation"),
) -> None:
    """Get a config value."""
    config = load_config()
    parts = key.split(".")
    obj = config
    for part in parts:
        obj = getattr(obj, part)
    value = obj if not hasattr(obj, "model_dump") else obj.model_dump()
    if isinstance(value, str) and ("key" in key.lower() or "pass" in key.lower()):
        value = value[:8] + "..." if len(value) > 8 else "***"
    console.print(f"{key} = {value}")


@config_app.command("list")
def config_list() -> None:
    """List all configuration values."""
    import yaml as _yaml

    config = load_config()
    raw = config.model_dump(mode="json")
    console.print(_yaml.dump(raw, default_flow_style=False, allow_unicode=True))


@config_app.command("provider")
def config_provider(
    name: Optional[str] = typer.Argument(
        None, help="Provider name to switch to (e.g. minimax, deepseek)"
    ),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all available providers"),
) -> None:
    """View or switch the configured LLM provider."""
    if list_all or name is None:
        providers = list_providers()
        current_config = load_config()
        current_provider = current_config.llm.provider

        console.print("[bold]Available LLM Providers[/]")
        console.print()
        for p in providers:
            is_current = p["provider"] == current_provider
            marker = " [green](current)[/]" if is_current else ""
            console.print(f"  [bold cyan]{p['provider']}[/]{marker}")
            console.print(f"    Label: {p['label']}")
            console.print(f"    URL:  [dim]{p['base_url']}[/]")
            console.print(f"    Model: [dim]{p['default_model']}[/]")
            console.print()
        console.print("[dim]Use vulnclaw config provider <name> to switch providers.[/]")
        return

    # Switch provider
    from vulnclaw.config.schema import PROVIDER_PRESETS, LLMProvider

    # Validate provider name
    try:
        provider_enum = LLMProvider(name.lower())
    except ValueError:
        console.print(f"[!] Unknown provider: [bold]{name}[/]")
        console.print(f"    Available: {', '.join(p.value for p in LLMProvider)}")
        console.print("    Tip: use [bold]custom[/] for a manual base_url and model.")
        raise typer.Exit(1)

    config = load_config()
    config = apply_provider_preset(config, name.lower())
    save_config(config)

    preset = PROVIDER_PRESETS.get(provider_enum, {})
    label = preset.get("label", name)
    console.print(f"[+] Switched LLM provider to [bold cyan]{label}[/]")
    console.print(f"    Base URL: [dim]{config.llm.base_url}[/]")
    console.print(f"    Model:    [dim]{config.llm.model}[/]")

    if not has_llm_credentials(config.llm):
        console.print()
        console.print(
            "[yellow]Set credentials first: [bold]vulnclaw config set llm.api_key <your-key>[/] "
            "or configure keyless auth (llm.auth_mode = env/file/command/wif)[/]"
        )


# 鈹€鈹€ Init command 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


@app.command()
def init() -> None:
    """Initialize VulnClaw config."""
    from vulnclaw.config.settings import ensure_dirs

    ensure_dirs()

    config = load_config()
    save_config(config)
    console.print(_("cli.init.config_created"))
    console.print(_("cli.init.dirs_initialized"))
    console.print(_("cli.init.dir_sessions"))
    console.print(_("cli.init.dir_kb"))
    console.print(_("cli.init.dir_skills"))
    console.print()
    console.print(_("cli.init.next_steps"))
    console.print(_("cli.init.step_provider"))
    console.print(_("cli.init.step_api_key"))
    console.print(_("cli.init.step_cli"))
    console.print(_("cli.init.step_tui"))


# 鈹€鈹€ Login / Logout commands 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


@app.command()
def login(
    proxy_url: Optional[str] = typer.Option(
        None,
        "--proxy-url",
        help="External OpenAI-compatible proxy base_url (disables the built-in one)",
    ),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Print the URL instead of opening a browser"
    ),
    set_default: bool = typer.Option(
        True, "--set-default/--no-set-default", help="Set llm.auth_mode=oauth on success"
    ),
) -> None:
    """Sign in with your ChatGPT subscription (Codex "Sign in with ChatGPT").

    Opens the ChatGPT consent page in your browser, stores the resulting
    refreshable token, and enables the built-in proxy that bridges
    chat.completions to the ChatGPT backend — so VulnClaw just works afterwards.

    ⚠️ This reuses OpenAI's first-party Codex OAuth client. Using a ChatGPT
    subscription through a non-official client may violate OpenAI's Terms of
    Service and can get your account restricted. You proceed at your own risk.
    """
    from vulnclaw.config.token_provider import (
        CHATGPT_CLIENT_ID,
        CHATGPT_TOKEN_URL,
        OAuthError,
        perform_chatgpt_login,
    )

    llm = load_config().llm

    err_console.print(
        "[yellow][!] Sign in with ChatGPT reuses OpenAI's first-party Codex OAuth "
        "client. Using a ChatGPT subscription through a non-official client may "
        "violate OpenAI's Terms of Service and can get your account restricted. "
        "You are proceeding at your own risk.[/]"
    )
    try:
        bundle = perform_chatgpt_login(open_browser=not no_browser)
    except OAuthError as exc:
        err_console.print(f"[!] ChatGPT sign-in failed: {exc}")
        raise typer.Exit(1)

    # Wire config so resolve/refresh works against the Codex token endpoint.
    set_config_value("llm.oauth_token_url", CHATGPT_TOKEN_URL)
    set_config_value("llm.oauth_client_id", CHATGPT_CLIENT_ID)
    if set_default:
        set_config_value("llm.auth_mode", "oauth")
    # The ChatGPT backend serves its own model family — gpt-4o won't work.
    if (llm.model or "").lower() in ("", "gpt-4o", "gpt-5", "gpt-5-codex"):
        set_config_value("llm.model", "gpt-5.5")

    if proxy_url:
        # User supplied an external proxy: use it, disable the built-in one.
        set_config_value("llm.base_url", proxy_url.rstrip("/"))
        set_config_value("llm.chatgpt_auto_proxy", "false")
    else:
        # Default: built-in proxy auto-starts on demand — zero setup.
        set_config_value("llm.chatgpt_auto_proxy", "true")

    tok = bundle.get("access_token", "")
    masked = (tok[:6] + "…" + tok[-4:]) if len(tok) > 12 else "(received)"
    console.print("[green]Signed in with ChatGPT.[/]")
    console.print(f"  Access token: [dim]{masked}[/]  (refreshes automatically)")
    if bundle.get("account_id"):
        console.print(f"  Account id: [dim]{bundle['account_id']}[/]")
    console.print()
    if proxy_url:
        console.print(f"  base_url set to external proxy: [dim]{proxy_url.rstrip('/')}[/]")
    else:
        console.print(
            "  [green]Built-in ChatGPT proxy enabled — it starts automatically.[/]\n"
            "  [dim]No external proxy needed. The bridge to OpenAI's ChatGPT backend "
            "is experimental; if a call fails, the error shows the backend response "
            "so you can adjust llm.model or the VULNCLAW_CHATGPT_* env vars.[/]"
        )
    console.print("  Run [bold]vulnclaw[/] to start.")


@app.command()
def logout() -> None:
    """Remove stored OAuth tokens (browser sign-in)."""
    from vulnclaw.config.token_provider import logout_oauth

    if logout_oauth():
        console.print("[green]Signed out — stored OAuth tokens removed.[/]")
    else:
        console.print("[yellow]No stored OAuth tokens to remove.[/]")


# 鈹€鈹€ Doctor command 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


@app.command()
def doctor() -> None:
    """Inspect the VulnClaw runtime environment."""
    import shutil

    # 修改者: Nyaecho
    # 修改时间: 2026-07-08
    # 修改原因: V6 修复 — 从 mcp/diagnostics 导入，消除 CLI→Web 依赖。
    from vulnclaw.mcp.diagnostics import get_mcp_diagnostics

    console.print("[bold]VulnClaw Environment Check[/]")
    console.print()

    # Check Python
    console.print(f"  Python: [green]{sys.version.split()[0]}[/]")

    # Check Node.js
    node_path = shutil.which("node")
    if node_path:
        import subprocess

        try:
            result = subprocess.run(
                [node_path, "--version"], capture_output=True, text=True, timeout=5
            )
            console.print(f"  Node.js: [green]{result.stdout.strip()}[/]")
        except Exception:
            console.print("  Node.js: [yellow]check failed[/]")
    else:
        console.print("  Node.js: [red]not installed[/] (required for some MCP services)")

    # Check npx
    npx_path = shutil.which("npx")
    console.print(
        f"  npx: [{'green' if npx_path else 'red'}]{'installed' if npx_path else 'missing'}[/]"
    )

    # Check uvx
    uvx_path = shutil.which("uvx")
    console.print(
        f"  uvx: [{'green' if uvx_path else 'yellow'}]{'installed' if uvx_path else 'missing'}[/]"
    )

    # Check nmap
    nmap_path = shutil.which("nmap")
    console.print(
        f"  nmap: [{'green' if nmap_path else 'yellow'}]{'installed' if nmap_path else 'optional/missing'}[/]"
    )

    # Check config
    config = load_config()
    console.print()
    console.print("[bold]LLM Config[/]:")
    has_key = has_llm_credentials(config.llm)
    auth_mode = (config.llm.auth_mode or "static").lower()
    console.print(f"  Provider: [bold cyan]{config.llm.provider}[/]")
    console.print(f"  Auth Mode: [bold]{auth_mode}[/]")
    cred_label = "configured" if has_key else "not set"
    console.print(
        f"  Credentials: [{'green' if has_key else 'red'}]{cred_label}[/]"
    )
    console.print(f"  Base URL: [dim]{config.llm.base_url}[/]")
    console.print(f"  Model: [dim]{config.llm.model}[/]")

    # Check MCP servers
    console.print()
    console.print("[bold]MCP Services[/]:")
    mcp_diag = get_mcp_diagnostics()
    console.print(f"  Registered: [bold]{mcp_diag.total_services}[/] services")
    console.print(f"  Tools: [bold]{mcp_diag.tool_count}[/] exposed")

    for item in mcp_diag.services:
        status = "[green]enabled[/]" if item.enabled else "[dim]disabled[/]"
        priority_label = {0: "P0", 1: "P1", 2: "P2"}.get(item.priority, "??")
        running = "[green]running[/]" if item.running else "[yellow]registered[/]"
        capability = "[green]exec[/]" if item.can_execute else "[yellow]schema-only[/]"
        console.print(
            f"  {item.name}: {status} [{priority_label}] {running} mode={item.execution_mode} {capability} tools={item.tool_count}"
        )
        if item.error:
            label = item.last_error_type or "error"
            console.print(f"    [red]{label}[/]: {item.error}")

    console.print(
        "[dim]doctor shows MCP registration state and exposed tools. fetch/memory run in local mode; most other services are still placeholders.[/]"
    )
    console.print(
        "[yellow]python_execute is a high-risk experimental capability. It is not a strong sandbox; use it only in authorized or controlled environments.[/]"
    )
    console.print(
        "[dim]The knowledge-base update flow is live; retrieval enhancements can continue independently.[/]"
    )

    console.print()
    if has_key:
        console.print("[green]Environment ready. Run [bold]vulnclaw[/] to start.[/]")
    else:
        console.print(
            "[yellow]Set credentials first: [bold]vulnclaw config set llm.api_key <key>[/] "
            "or keyless auth (llm.auth_mode = env/file/command/wif)[/]"
        )


# 鈹€鈹€ KB command 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

kb_app = typer.Typer(help="Security knowledge base commands")
app.add_typer(kb_app, name="kb")

target_state_app = typer.Typer(help="Manage target history state")
app.add_typer(target_state_app, name="target-state")

plugins_app = typer.Typer(help="Inspect and run vulnerability detection plugins")
app.add_typer(plugins_app, name="plugins")


def _parse_kv_options(pairs: Optional[list[str]]) -> dict[str, object]:
    """把 --option key=value（可重复）解析为 dict，value 优先按 JSON 解析。"""
    import json as _json

    options: dict[str, object] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise typer.BadParameter(f"Expected key=value, got: {pair}")
        key, _, raw = pair.partition("=")
        key = key.strip()
        raw = raw.strip()
        try:
            options[key] = _json.loads(raw)
        except (ValueError, TypeError):
            options[key] = raw
    return options


@plugins_app.command("list")
def plugins_list(
    stage: Optional[str] = typer.Option(None, "--stage", help="Filter by stage"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag"),
) -> None:
    """List registered detection plugins."""
    from rich.table import Table

    from vulnclaw.plugins import registry

    plugin_classes = registry.list()
    if stage:
        try:
            plugin_classes = registry.by_stage(stage)
        except ValueError:
            err_console.print(f"[!] Unknown stage: {stage}")
            raise typer.Exit(1) from None
    if tag:
        tag_set = {p.plugin_id for p in registry.by_tag(tag)}
        plugin_classes = [p for p in plugin_classes if p.plugin_id in tag_set]

    if not plugin_classes:
        console.print("[yellow]No plugins match the filter.[/yellow]")
        return

    table = Table(title="VulnClaw Plugins", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Stages")
    table.add_column("Risk")
    table.add_column("Destructive", justify="center")
    for plugin_cls in sorted(plugin_classes, key=lambda p: p.plugin_id):
        meta = plugin_cls.metadata()
        table.add_row(
            meta["plugin_id"],
            meta["name"],
            ", ".join(meta["stages"]),
            meta["default_risk"],
            "⚠️" if meta["destructive"] else "-",
        )
    console.print(table)


@plugins_app.command("info")
def plugins_info(plugin_id: str = typer.Argument(..., help="Plugin id")) -> None:
    """Show full metadata for a single plugin."""
    import json as _json

    from vulnclaw.plugins import registry

    plugin_cls = registry.get(plugin_id)
    if plugin_cls is None:
        err_console.print(f"[!] Plugin not found: {plugin_id}")
        raise typer.Exit(1)
    console.print_json(_json.dumps(plugin_cls.metadata(), ensure_ascii=False))


@plugins_app.command("run")
def plugins_run(
    plugin_id: str = typer.Argument(..., help="Plugin id to run"),
    target: str = typer.Option("", "--target", help="Target host/IP/URL"),
    stage: str = typer.Option("discovery", "--stage", help="Plugin stage"),
    option: Optional[list[str]] = typer.Option(
        None, "--option", "-o", help="Plugin option key=value (repeatable, value parsed as JSON)"
    ),
    input_file: Optional[str] = typer.Option(
        None, "--input", help="JSON file merged into plugin options"
    ),
    allow_destructive: bool = typer.Option(
        False, "--allow-destructive", help="Permit destructive plugins"
    ),
    session_file: Optional[str] = typer.Option(
        None, "--session", help="Merge findings into this SessionState JSON and save it"
    ),
    as_json: bool = typer.Option(False, "--json", help="Print the raw PluginResult as JSON"),
) -> None:
    """Run a plugin against supplied data (builtin plugins only analyze provided input)."""
    import json as _json
    from pathlib import Path

    from rich.table import Table

    from vulnclaw.plugins import PluginContext, PluginStage, create_builtin_runtime
    from vulnclaw.plugins.integration import merge_plugin_results_into_session

    try:
        stage_value = PluginStage(stage)
    except ValueError:
        err_console.print(f"[!] Unknown stage: {stage}")
        raise typer.Exit(1) from None

    options = _parse_kv_options(option)
    if input_file:
        path = Path(input_file)
        if not path.exists():
            err_console.print(f"[!] Input file not found: {input_file}")
            raise typer.Exit(1)
        try:
            payload = _json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            err_console.print(f"[!] Failed to read input file: {exc}")
            raise typer.Exit(1) from None
        if isinstance(payload, dict):
            options.update(payload)
        else:
            options["input"] = payload

    config = load_config()
    runtime = create_builtin_runtime(config)
    context = PluginContext(
        target=target,
        stage=stage_value,
        options=options,
        allow_destructive=allow_destructive,
    )

    result = asyncio.run(runtime.execute(plugin_id, context))

    if as_json:
        console.print_json(result.model_dump_json())
    else:
        if result.skipped:
            console.print(f"[yellow]⊘ Skipped[/yellow] ({result.error_type}): {result.error}")
        elif result.error:
            console.print(f"[red]✗ Error[/red] ({result.error_type}): {result.error}")
        for message in result.messages:
            console.print(f"  [dim]{message}[/dim]")
        if result.findings:
            table = Table(title=f"{plugin_id} findings", show_lines=True)
            table.add_column("Risk", style="magenta", no_wrap=True)
            table.add_column("Title")
            table.add_column("Type")
            table.add_column("Confidence", justify="right")
            for finding in result.findings:
                table.add_row(
                    finding.risk.value,
                    finding.title,
                    finding.vuln_type or "-",
                    f"{finding.confidence:.2f}",
                )
            console.print(table)
        elif not result.error:
            console.print("[green]✓[/green] Plugin ran; no findings.")

    if session_file:
        session_path = Path(session_file)
        from vulnclaw.agent.context import SessionState

        session = SessionState.load(session_path) if session_path.exists() else SessionState()
        added = merge_plugin_results_into_session(session, result)
        session.save(session_path)
        console.print(f"[+] Merged {added} finding(s) into {session_file}")


@kb_app.command("update")
def kb_update() -> None:
    """Update the knowledge base."""
    console.print("[*] Updating knowledge base...")
    from vulnclaw.kb.store import KnowledgeStore
    from vulnclaw.kb.updater import seed_knowledge_base

    store = KnowledgeStore()
    before_stats = store.get_stats()
    seed_knowledge_base(store)
    after_stats = store.get_stats()

    before_total = sum(before_stats.values())
    after_total = sum(after_stats.values())
    delta = after_total - before_total
    category_summary = ", ".join(f"{cat}={count}" for cat, count in sorted(after_stats.items()))

    console.print(f"[+] Knowledge base updated: +{delta} entries")
    console.print(f"    Categories: {category_summary or 'empty'}")


@kb_app.command("status")
def kb_status() -> None:
    """Show the knowledge base retrieval backend status."""
    from vulnclaw.kb.retriever import KnowledgeRetriever, RetrieverStatus
    from vulnclaw.kb.store import KnowledgeStore

    store = KnowledgeStore()
    retriever = KnowledgeRetriever(store=store)
    status = retriever.get_status()
    detail = retriever.get_status_detail()
    stats = store.get_stats()
    total = sum(stats.values())
    category_summary = ", ".join(f"{cat}={count}" for cat, count in sorted(stats.items()))

    if status == RetrieverStatus.CHROMADB_ACTIVE:
        line = f"[green]{_('cli.kb_active')}[/green]"
    elif status == RetrieverStatus.KEYWORD_FALLBACK:
        line = f"[yellow]{_('cli.kb_fallback')}[/yellow]"
    else:
        line = f"[red]{_('cli.kb_disabled')}[/red]"

    console.print(
        Panel(
            f"{line}\n"
            f"Backend: [bold]{status.value}[/]\n"
            f"Detail: {detail or 'n/a'}\n"
            f"Entries: [bold]{total}[/] ({category_summary or 'empty'})\n"
            f"{_('cli.kb_semantic_hint')}",
            title="KB Status",
            border_style="cyan",
        )
    )


@target_state_app.command("list")
def target_state_list(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
) -> None:
    """List target snapshots."""
    snapshots = list_target_snapshots(target)
    if not snapshots:
        console.print(f"[-] No snapshots found for: {target}")
        raise typer.Exit(1)

    console.print(f"[bold]Target snapshots[/]: {target}")
    for item in snapshots[:20]:
        console.print(
            f"  {item['snapshot_id']} | v{item.get('schema_version', 1)} | {item['last_command']} | "
            f"steps={item['executed_steps']} verified={item['verified_findings']} pending={item['pending_findings']}"
        )


@target_state_app.command("preview")
def target_state_preview_cmd(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    snapshot_id: Optional[str] = typer.Option(
        None, "--snapshot", help="Preview a specific snapshot id"
    ),
) -> None:
    """Show a resume preview for the target state."""
    preview = get_target_state_preview(target, snapshot_id=snapshot_id)
    if not preview:
        console.print(f"[-] No target state found: {target}")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"Target: [bold]{preview['target']}[/]\n"
            f"Schema: [bold]v{preview['schema_version']}[/]\n"
            f"Phase: [bold]{preview['phase'] or 'unknown'}[/]\n"
            f"Resume strategy: [bold]{preview['resume_strategy'] or 'none'}[/]\n"
            f"Reason: {preview['resume_reason'] or 'n/a'}\n"
            f"Findings: {preview['verified_count']} verified / {preview['pending_count']} pending / {preview['findings_count']} total",
            title="Target Preview",
            border_style="cyan",
        )
    )

    if preview.get("priority_targets"):
        console.print("[bold]Priority targets[/]:")
        for item in preview["priority_targets"][:5]:
            console.print(f"  - {item}")
    if preview.get("priority_recon_assets"):
        console.print("[bold]Priority recon assets[/]:")
        for item in preview["priority_recon_assets"][:5]:
            console.print(f"  - {item}")
    if preview.get("next_actions"):
        console.print("[bold]Next actions[/]:")
        for item in preview["next_actions"][:5]:
            console.print(f"  - {item}")


@target_state_app.command("diff")
def target_state_diff_cmd(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    from_snapshot_id: str = typer.Argument(..., help="Base snapshot id"),
    to_snapshot_id: Optional[str] = typer.Option(
        None, "--to", help="Compare against another snapshot or current state"
    ),
) -> None:
    """Show differences between two target-state snapshots."""
    diff = diff_target_state_snapshots(target, from_snapshot_id, to_snapshot_id=to_snapshot_id)
    if not diff:
        console.print(f"[-] Unable to diff target state: {target}")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"Target: [bold]{diff['target']}[/]\n"
            f"From: [bold]{diff['from_snapshot_id']}[/] -> To: [bold]{diff['to_snapshot_id']}[/]\n"
            f"Schema: v{diff['schema_version_from']} -> v{diff['schema_version_to']}\n"
            f"Resume strategy: {diff['resume_strategy_from'] or 'none'} -> {diff['resume_strategy_to'] or 'none'}",
            title="Target Diff",
            border_style="magenta",
        )
    )

    for title, items in (
        ("Added findings", diff.get("added_findings", [])),
        ("Removed findings", diff.get("removed_findings", [])),
        ("Updated findings", diff.get("updated_findings", [])),
        ("Added recon assets", diff.get("added_recon_assets", [])),
        ("Removed recon assets", diff.get("removed_recon_assets", [])),
        ("Added steps", diff.get("added_steps", [])),
        ("Removed steps", diff.get("removed_steps", [])),
        ("Added notes", diff.get("added_notes", [])),
        ("Removed notes", diff.get("removed_notes", [])),
    ):
        if items:
            console.print(f"[bold]{title}[/]:")
            for item in items[:10]:
                console.print(f"  - {item}")


@target_state_app.command("rollback")
def target_state_rollback_cmd(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
    snapshot_id: str = typer.Argument(..., help="Snapshot id to restore"),
) -> None:
    """Rollback target state to a snapshot."""
    path = rollback_target_state(target, snapshot_id)
    if not path:
        console.print(f"[-] Snapshot not found: {snapshot_id}")
        raise typer.Exit(1)
    console.print(f"[+] Rolled back target state: {target}")
    console.print(f"    Snapshot: {snapshot_id}")


@target_state_app.command("clear")
def target_state_clear_cmd(
    target: str = typer.Argument(..., help="Target host/IP/URL"),
) -> None:
    """Clear target state."""
    ok = clear_target_state(target)
    if not ok:
        console.print(f"[-] No target state found: {target}")
        raise typer.Exit(1)
    console.print(f"[+] Cleared target state: {target}")


# Default command (no sub-command -> REPL)

# 鈹€鈹€ Auto-pentest detection 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


def _should_auto_pentest(user_input: str, current_target: Optional[str]) -> bool:
    """Determine if user input should trigger autonomous pentest loop.

    Triggers when:
    - User explicitly asks for a full pentest with a target
    - User mentions a target plus action keywords like "渗透测试" or "打一下"
    - User asks to solve a CTF / find a flag with a target
    - User asks for information gathering / recon / OSINT with a target
    - A target is present + multi-step task indicators
    """
    input_lower = user_input.lower()

    # Explicit auto-mode triggers
    auto_keywords = [
        "渗透测试",
        "进行渗透",
        "做渗透",
        "打一下",
        "全面测试",
        "pentest",
        "full test",
        "auto",
        "自主渗透模式",
        "自主模式",
        "找出flag",
        "找到flag",
        "拿flag",
        "get flag",
        "find flag",
        "解题",
        "做题",
        "挑战",
        "challenge",
        "ctf",
        "弱口令",
        "爆破",
        "绕过",
        "bypass",
        "brute",
        "搜集",
        "收集",
        "信息收集",
        "侦察",
        "recon",
        "reconnaissance",
        "社工",
        "osint",
        "情报",
        "intelligence",
        "分析目标",
        "目标分析",
        "资产发现",
        "目录扫描",
        "探测",
        "探索",
        "调查",
        "investigate",
        "enumerate",
        "全面分析",
        "深度分析",
        "详细分析",
        "全面扫描",
        "子域名",
        "subdomain",
    ]

    # Single-step queries should NOT trigger auto mode
    single_step_keywords = [
        "生成报告",
        "report",
        "help",
        "帮助",
    ]

    # If it's clearly a single-step query, don't auto-loop
    # But if it also has auto keywords, still go auto (e.g. "收集信息并生成报告")
    if any(kw in input_lower for kw in single_step_keywords) and not any(
        kw in input_lower for kw in auto_keywords
    ):
        return False

    # If it has auto-mode keywords, trigger auto loop
    if any(kw in input_lower for kw in auto_keywords):
        # Must have a target (either in input or already set)
        has_target = bool(current_target) or bool(_extract_target_from_input(user_input))
        return has_target

    # Fallback: has target + multi-step task -> auto
    has_target = bool(current_target) or bool(_extract_target_from_input(user_input))
    if has_target:
        multi_step_indicators = [
            "并",
            "然后",
            "输出",
            "保存",
            "写到",
            "导出",
            "所有",
            "全部",
            "完整",
            "详细",
        ]
        if any(ind in input_lower for ind in multi_step_indicators):
            return True

    return False


def _extract_target_from_input(user_input: str) -> Optional[str]:
    """Extract target from user input string."""
    import re

    # Try to find URL (with optional port)
    url_match = re.search(r"(https?://[a-zA-Z0-9][-a-zA-Z0-9.:]*)", user_input)
    if url_match:
        return url_match.group(1).rstrip("/")
    # Try to find IP address
    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", user_input)
    if ip_match:
        return ip_match.group(1)
    # Try to find domain
    domain_match = re.search(r"([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", user_input)
    if domain_match:
        return domain_match.group(1)
    return None


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Show version and exit.",
        is_eager=True,
    ),
    show_manual: bool = typer.Option(
        False,
        "--man",
        "--manual",
        help="Show the full CLI manual and exit.",
        is_eager=True,
    ),
    resume_run_name: Optional[str] = typer.Option(
        None,
        "--resume",
        help="Resume an exact saved run by run name.",
    ),
    runs_dir: Optional[str] = typer.Option(
        None,
        "--runs-dir",
        help="Run-directory root for --resume.",
    ),
    repair: bool = typer.Option(
        False,
        "--repair",
        help="Repair a corrupt run by rolling back to the last valid snapshot.",
    ),
) -> None:
    """Open the classic CLI/REPL by default."""
    if version:
        console.print(__version__)
        raise typer.Exit()
    if show_manual:
        _print_cli_manual(None, "text")
        raise typer.Exit()
    if ctx.invoked_subcommand is None and resume_run_name:
        _resume_saved_run(resume_run_name, runs_dir=runs_dir, repair=repair)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        _run_repl()


def _resume_saved_run(
    run_name: str,
    *,
    runs_dir: Optional[str] = None,
    repair: bool = False,
) -> None:
    from vulnclaw.run_context import RunCorruptError, load_run_context

    config = load_config()
    try:
        run_context = load_run_context(
            run_name,
            runs_dir=runs_dir,
            config=config,
            repair=repair,
        )
    except RunCorruptError as exc:
        err_console.print(f"[!] {exc}")
        raise typer.Exit(1) from exc

    targets = run_context.manifest.get("targets", [])
    first_target = targets[0] if isinstance(targets, list) and targets else {}
    if not isinstance(first_target, dict) or not first_target.get("input"):
        err_console.print(f"[!] Run {run_name} has no resumable target in run.json")
        raise typer.Exit(1)

    target = str(first_target["input"])
    command = str(run_context.manifest.get("command") or "run")
    if not has_llm_credentials(config.llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(1)

    async def _run():
        async def runner(agent, shared_config):
            sink = TerminalStreamSink(console, shared_config.session.show_thinking)
            prompt = (
                f"Continue the saved VulnClaw run {run_name} for {target}. "
                "Resume from the loaded checkpoint and continue the authorized task."
            )
            return await agent.chat(prompt, target=target, stream_sink=sink)

        return await _run_cli_orchestrated_task(
            command=command,
            target=target,
            resume=True,
            snapshot=None,
            runner=runner,
            resume_run_name=run_name,
            runs_dir=runs_dir,
            repair=repair,
        )

    asyncio.run(_run())


def _auto_save_recon_report(agent, user_input: str, config) -> None:
    """Auto-save a recon report after auto_pentest completes when user requested file output."""
    import re
    from datetime import datetime

    try:
        state = agent.session_state
        target = state.target or "unknown"

        # Determine output path
        # Check if user specified a path
        path_match = re.search(
            r"(?:保存到|写到|输出到|导出到|save to|write to|output to|export to)\s*([^\s,，]+)",
            user_input,
            re.IGNORECASE,
        )
        if path_match:
            output_path = path_match.group(1)
        else:
            safe_name = re.sub(r"[^\w]", "_", target)[:30]
            date_str = datetime.now().strftime("%Y%m%d_%H%M")
            output_path = str(config.session.output_dir / f"{safe_name}_recon_{date_str}.md")

        from vulnclaw.report.generator import generate_report

        generate_report(
            state,
            output_path,
            report_format=config.session.report_format,
        )

        console.print(f"\n[+] Recon report saved: {output_path}")

    except Exception as e:
        console.print(f"\n[!] Failed to auto-save report: {e}")


@app.command()
def repl() -> None:
    """Start the classic natural-language REPL."""
    _run_repl()


@app.command()
def tui(
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="Pre-fill the authorized target for the TUI.",
    ),
    mode: str = typer.Option(
        "standard",
        "--mode",
        "-m",
        help="Pre-fill check mode: quick, standard, deep, continuous.",
    ),
    only_port: Optional[int] = typer.Option(
        None,
        "--only-port",
        help="Pre-fill a single allowed test port.",
    ),
    only_host: Optional[str] = typer.Option(
        None,
        "--only-host",
        help="Pre-fill a single allowed host.",
    ),
    only_path: Optional[str] = typer.Option(
        None,
        "--only-path",
        help="Pre-fill a single allowed path.",
    ),
    blocked_host: Optional[str] = typer.Option(
        None,
        "--blocked-host",
        help="Pre-fill an explicitly blocked host.",
    ),
    blocked_path: Optional[str] = typer.Option(
        None,
        "--blocked-path",
        help="Pre-fill an explicitly blocked path.",
    ),
    allow_actions: Optional[str] = typer.Option(
        None,
        "--allow-actions",
        help="Pre-fill comma-separated allowed actions.",
    ),
    block_actions: Optional[str] = typer.Option(
        None,
        "--block-actions",
        help="Pre-fill comma-separated blocked actions.",
    ),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Resume target history."),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Render the launch summary and exit without starting a task.",
    ),
    once: bool = typer.Option(
        False,
        "--once",
        help="Render the TUI dashboard once and exit (useful for smoke tests).",
    ),
) -> None:
    """Open the terminal UI workbench."""
    from vulnclaw.cli.tui import (
        MODES,
        build_state_from_options,
        build_task_draft,
        render_task_summary,
        run_tui,
    )

    if mode not in MODES:
        err_console.print("[!] Unknown TUI mode. Use one of: quick, standard, deep, continuous")
        raise typer.Exit(1)

    state = build_state_from_options(
        target=target or "",
        mode=mode,  # type: ignore[arg-type]
        only_host=only_host or "",
        only_port=only_port,
        only_path=only_path or "",
        blocked_host=blocked_host or "",
        blocked_path=blocked_path or "",
        allow_actions=allow_actions,
        block_actions=block_actions,
        resume=resume,
    )

    if dry_run:
        console.out(render_task_summary(build_task_draft(state)), end="")
        return

    if once and target:
        from vulnclaw.cli.tui import render_tui_home

        console.out(render_tui_home(state), end="")
        return

    run_tui(once=once, initial_state=state)


@app.command()
def web(
    host: str = typer.Option(
        "127.0.0.1", "--host", help="Web server host (default: localhost only)"
    ),
    port: int = typer.Option(7788, "--port", help="Web server port"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Validate and print launch info without starting the server"
    ),
    allow_remote: bool = typer.Option(
        False, "--allow-remote", help="Explicitly allow binding the Web UI to a non-local address"
    ),
) -> None:
    """Run the local Web UI."""
    if not _is_loopback_bind_host(host):
        if not allow_remote:
            err_console.print(
                "[!] Refusing to bind the Web UI to a non-local address without --allow-remote."
            )
            raise typer.Exit(1)
        console.print(
            "[yellow]Warning: keep the Web UI bound to 127.0.0.1 unless you know what you're doing.[/]"
        )

    from vulnclaw.web.app import FASTAPI_AVAILABLE

    console.print(
        Panel(
            f"Host: [bold]{host}[/]\n"
            f"Port: [bold]{port}[/]\n"
            f"FastAPI: [{'green' if FASTAPI_AVAILABLE else 'yellow'}]{'installed' if FASTAPI_AVAILABLE else 'missing'}[/]\n"
            f"URL: [bold]http://{host}:{port}[/]",
            title="VulnClaw Web UI",
            border_style="cyan",
        )
    )

    if dry_run:
        console.print("[green]Web UI dry-run completed.[/]")
        return

    if not FASTAPI_AVAILABLE:
        err_console.print(
            "[!] FastAPI is missing. Install with [bold]pip install vulnclaw\\[web][/]."
        )
        raise typer.Exit(1)

    try:
        import uvicorn
    except ImportError:
        err_console.print(
            "[!] uvicorn is missing. Install with [bold]pip install vulnclaw\\[web][/]."
        )
        raise typer.Exit(1)

    from vulnclaw.web.app import create_app
    from vulnclaw.web.auth import generate_token

    token = generate_token()
    if allow_remote:
        # Non-loopback clients (which includes every browser reaching a
        # container through Docker's port NAT) must authenticate. The UI cannot
        # send a bearer header, so opening this URL once swaps the token for a
        # session cookie; the browser carries it from then on.
        browser_host = "127.0.0.1" if host in {"0.0.0.0", "::", "[::]"} else host
        console.print(
            Panel(
                f"Open this URL once to sign the browser in:\n"
                f"[bold]http://{browser_host}:{port}/?token={token}[/]\n\n"
                f"Token: [bold]{token}[/]\n"
                f"[dim]For API clients: Authorization: Bearer {token}[/]",
                title="Web UI Auth Token",
                border_style="yellow",
            )
        )

    uvicorn.run(create_app(), host=host, port=port, log_level="info")


def _is_loopback_bind_host(host: str) -> bool:
    """Return True when a requested bind host is loopback-only."""
    normalized = host.strip().strip("[]").lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        import ipaddress

        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":
    app()
