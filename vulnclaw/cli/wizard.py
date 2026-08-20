"""Interactive first-run setup wizard for VulnClaw.

Invoked from the classic REPL / Textual TUI via ``/wizard``. Configures the LLM,
UI language, Chrome remote debugging + chrome-devtools MCP (for Cloudflare and
real-browser recon), and optionally Burp MCP.

Already-configured stages are detected and skipped. Between stages the terminal
is cleared so only the current step remains visible.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

from vulnclaw.config.schema import MCPServerConfig, MCPTransportConfig, VulnClawConfig
from vulnclaw.config.settings import (
    CONFIG_DIR,
    apply_provider_preset,
    list_providers,
    load_config,
    save_config,
)
from vulnclaw.config.token_provider import has_llm_credentials

DEFAULT_DEBUG_PORT = 9222
DEFAULT_BURP_SSE = "http://127.0.0.1:9876"
BURP_SSE_PORT = 9876
WIZARD_ENV = CONFIG_DIR / "wizard.env"
CHROME_PROFILE = CONFIG_DIR / "chrome-debug"
TOOLS_DIR = CONFIG_DIR / "tools"
BURP_MCP_DIR = TOOLS_DIR / "burp-mcp"
BURP_JAR_NAME = "burp-mcp-all.jar"
BURP_REPO = "https://github.com/PortSwigger/mcp-server.git"

TOTAL_STAGES = 7
TOTAL_MINUTES = 20


@dataclass
class SetupStatus:
    """Detected local setup so stages that are already done can be skipped."""

    llm_ready: bool = False
    language: str = "en"
    chrome_path: Optional[str] = None
    debug_port: int = DEFAULT_DEBUG_PORT
    chrome_debug_live: bool = False
    chrome_devtools_enabled: bool = False
    chrome_devtools_url: str = f"http://127.0.0.1:{DEFAULT_DEBUG_PORT}"
    burp_enabled: bool = False
    burp_sse_url: str = DEFAULT_BURP_SSE
    burp_jar: Optional[Path] = None
    burp_sse_live: bool = False
    java: Optional[str] = None
    git: Optional[str] = None
    node: Optional[str] = None
    npx: Optional[str] = None
    nmap: Optional[str] = None


@dataclass
class WizardResult:
    """Outcome of a wizard run."""

    completed: bool = False
    messages: list[str] = field(default_factory=list)
    restarted_mcp: bool = False
    config: Optional[VulnClawConfig] = None
    skipped: list[str] = field(default_factory=list)


@dataclass
class _WizardUi:
    """Per-run progress + clear-between-stages state."""

    console: Console
    index: int = 0
    minutes_elapsed: int = 0

    def clear(self) -> None:
        """Hard-clear so prior answers do not linger in scrollback."""
        if not self.console.is_terminal:
            return
        # Windows CMD/PowerShell often ignore Rich's ANSI clear; force cls/clear.
        try:
            if platform.system() == "Windows":
                os.system("cls")  # noqa: S605 — intentional terminal clear
            else:
                os.system("clear")  # noqa: S605
        except Exception:
            pass
        try:
            self.console.clear()
        except Exception:
            self.console.print("\n" * 40)

    def banner(self, status: Optional[SetupStatus] = None) -> None:
        self.clear()
        self.console.print("[bold cyan]VulnClaw first-run wizard[/]")
        self.console.print(
            "[dim]Skips anything already configured · clears between steps · "
            "Ctrl+C cancels[/]"
        )
        self.console.print()
        if status is not None:
            plan = plan_from_status(status)
            if plan["ready"]:
                self.console.print(
                    "[green]Already configured:[/] " + ", ".join(plan["ready"])
                )
            if plan["todo"]:
                self.console.print(
                    "[yellow]Still needed:[/] " + ", ".join(plan["todo"])
                )
            else:
                self.console.print(
                    "[green]Everything looks set — wizard will mostly skip.[/]"
                )
            self.console.print()

    def begin(self, title: str, minutes: int = 2) -> None:
        self.clear()
        self.index += 1
        remaining = max(0, TOTAL_MINUTES - self.minutes_elapsed)
        self.minutes_elapsed += minutes
        self.console.print(
            f"[bold cyan]▸ {title}[/] "
            f"[dim](step {self.index} · ~{remaining} min left)[/]"
        )
        self.console.print()

    def finish(self, lines: list[str]) -> None:
        self.clear()
        for line in lines:
            self.console.print(line)
        self.console.print()


def plan_from_status(status: SetupStatus) -> dict[str, list[str]]:
    """Human-readable ready vs still-needed checklist."""
    ready: list[str] = []
    todo: list[str] = []
    (ready if status.llm_ready else todo).append("LLM credentials")
    lang_ok = status.language in {"en", "zh", "auto"}
    (ready if lang_ok else todo).append(f"language ({status.language})")
    (ready if status.chrome_debug_live else todo).append("Chrome remote debugging")
    (ready if status.chrome_devtools_enabled else todo).append("chrome-devtools MCP")
    burp_ok = status.burp_enabled and (status.burp_sse_live or status.burp_jar)
    (ready if burp_ok else todo).append("Burp MCP")
    return {"ready": ready, "todo": todo}


def detect_setup_status(
    config: Optional[VulnClawConfig] = None,
    *,
    debug_port: int = DEFAULT_DEBUG_PORT,
) -> SetupStatus:
    """Probe local tools + config to decide which wizard stages can skip."""
    cfg = config or load_config()
    st = SetupStatus()
    st.llm_ready = has_llm_credentials(cfg.llm)
    st.language = str(getattr(cfg.session, "language", "en") or "en")
    st.chrome_path = detect_chrome_path()
    st.debug_port = debug_port
    st.chrome_debug_live = port_open("127.0.0.1", debug_port)

    cd = cfg.mcp.servers.get("chrome-devtools")
    if cd is not None and cd.enabled:
        st.chrome_devtools_enabled = True
        for arg in cd.transport.args or []:
            if isinstance(arg, str) and arg.startswith("--browser-url="):
                st.chrome_devtools_url = arg.split("=", 1)[1]
                break

    burp = cfg.mcp.servers.get("burp")
    if burp is not None and burp.enabled:
        st.burp_enabled = True
        if burp.transport.url:
            st.burp_sse_url = burp.transport.url
    st.burp_jar = find_burp_jar()
    st.burp_sse_live = port_open("127.0.0.1", BURP_SSE_PORT)
    st.java = detect_java_path()
    st.git = shutil.which("git")
    st.node = shutil.which("node")
    st.npx = shutil.which("npx")
    st.nmap = shutil.which("nmap")
    return st


def detect_java_path() -> Optional[str]:
    """Find a Java 11+ binary: PATH, JAVA_HOME, then common install dirs."""
    which = shutil.which("java")
    if which:
        return which

    java_home = os.environ.get("JAVA_HOME", "").strip()
    if java_home:
        for name in ("java.exe", "java"):
            candidate = Path(java_home) / "bin" / name
            if candidate.is_file():
                return str(candidate)

    roots: list[Path] = []
    if platform.system() == "Windows":
        pf = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
        pf86 = Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        roots.extend(
            [
                pf / "Eclipse Adoptium",
                pf / "Java",
                pf / "Microsoft",
                pf / "Amazon Corretto",
                pf / "Zulu",
                pf / "Semeru",
                pf / "BellSoft",
                pf / "Android" / "Android Studio" / "jbr",
                pf86 / "Eclipse Adoptium",
                pf86 / "Java",
                local / "Programs" / "Eclipse Adoptium" if local.parts else Path(),
            ]
        )
    elif platform.system() == "Darwin":
        roots.extend(
            [
                Path("/Library/Java/JavaVirtualMachines"),
                Path("/opt/homebrew/opt/openjdk"),
                Path("/usr/local/opt/openjdk"),
            ]
        )
    else:
        roots.extend(
            [
                Path("/usr/lib/jvm"),
                Path("/usr/java"),
                Path("/opt/java"),
            ]
        )

    found: list[Path] = []
    for root in roots:
        if not root or not root.is_dir():
            continue
        for pattern in ("**/bin/java.exe", "**/bin/java"):
            try:
                found.extend(p for p in root.glob(pattern) if p.is_file())
            except OSError:
                continue

    # Prefer higher version folders by path name sort (jdk-17 > jdk-11 roughly).
    found = sorted(found, key=lambda p: str(p), reverse=True)
    for path in found:
        return str(path)
    return None


def java_home_from_binary(java_bin: str) -> Optional[str]:
    """Derive JAVA_HOME from …/bin/java(.exe)."""
    path = Path(java_bin).resolve()
    # …/bin/java → home is parent of bin
    if path.parent.name.lower() == "bin":
        return str(path.parent.parent)
    return None


def ensure_java(
    console: Console,
    status: SetupStatus,
) -> tuple[Optional[str], str]:
    """Ensure a Java runtime exists, installing Temurin 17 via winget when needed.

    Returns (java_binary_or_None, error_message).
    """
    java = status.java or detect_java_path()
    if java:
        status.java = java
        return java, ""

    console.print("  Java 11+ is required to build the Burp MCP extension.")
    winget = shutil.which("winget")
    if platform.system() == "Windows" and winget:
        if _confirm(
            console,
            "Install Eclipse Temurin JDK 17 now via winget? (recommended)",
            default=True,
        ):
            console.print("  Running winget install EclipseAdoptium.Temurin.17.JDK …")
            proc = subprocess.run(
                [
                    winget,
                    "install",
                    "-e",
                    "--id",
                    "EclipseAdoptium.Temurin.17.JDK",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                # winget sometimes returns non-zero even on success (already installed).
                tail = (proc.stderr or proc.stdout or "")[-400:]
                console.print(f"  [dim]winget exit {proc.returncode}: {tail}[/]")
            # Rescan common dirs (PATH may not refresh in this process).
            java = detect_java_path()
            if java:
                status.java = java
                console.print(f"  ✓ Java found: {java}")
                return java, ""
            console.print(
                "  [yellow]Java install finished but binary not visible yet. "
                "Close VulnClaw, open a new terminal, re-run /wizard.[/]"
            )
            return None, "Java installed; restart shell to refresh PATH"
        # User declined winget — offer browser download.
        console.print("  Download a JDK (Temurin 17+) and re-run /wizard.")
        if _confirm(console, "Open the Temurin download page?", default=True):
            _open_url("https://adoptium.net/temurin/releases/?version=17")
        _pause(console, "Install Java, then press Enter to re-scan")
        java = detect_java_path()
        if java:
            status.java = java
            console.print(f"  ✓ Java found: {java}")
            return java, ""
    else:
        console.print("  Download a JDK (Temurin 17+) and re-run /wizard.")
        if _confirm(console, "Open the Temurin download page?", default=True):
            _open_url("https://adoptium.net/temurin/releases/?version=17")
        _pause(console, "Install Java, then press Enter to re-scan")
        java = detect_java_path()
        if java:
            status.java = java
            console.print(f"  ✓ Java found: {java}")
            return java, ""

    return None, "java not found (need Java 11+). Install Temurin and re-run /wizard"


def run_setup_wizard(
    *,
    console: Optional[Console] = None,
    mcp_manager: Any = None,
    agent: Any = None,
) -> WizardResult:
    """Run the interactive first-run setup wizard."""
    con = console or Console()
    ui = _WizardUi(console=con)
    result = WizardResult()

    try:
        config = load_config()
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        status = detect_setup_status(config)

        ui.banner(status)
        if not _confirm(con, "Start setup?", default=True):
            result.messages.append("Setup cancelled.")
            return result

        status = _stage_prereqs(ui, status)
        config, status = _stage_llm(ui, config, status, result)
        config, status = _stage_language(ui, config, status, result)
        debug_port, chrome_path, profile, status = _stage_chrome(ui, status, result)
        config, status = _stage_chrome_devtools(ui, config, status, debug_port, result)
        config, status = _stage_burp(ui, config, status, result)

        save_config(config)
        _write_wizard_env(
            {
                "CHROME_PATH": chrome_path or "",
                "CHROME_DEBUG_PORT": str(debug_port),
                "CHROME_USER_DATA_DIR": str(profile),
                "BROWSER_URL": f"http://127.0.0.1:{debug_port}",
                "BURP_SSE_URL": status.burp_sse_url,
                "JAVA": status.java or "",
            }
        )

        if agent is not None:
            try:
                agent.apply_config(config)
            except Exception as exc:  # pragma: no cover
                con.print(f"[yellow]⚠ could not rebind agent config: {exc}[/]")

        restarted = _reload_mcp(ui, config, mcp_manager, result)
        result.restarted_mcp = restarted
        result.config = config
        result.completed = True

        summary = [
            "[bold green]✓ Setup complete[/]",
            f"[dim]Config: {CONFIG_DIR / 'config.yaml'}[/]",
        ]
        if result.skipped:
            summary.append(
                "[dim]Skipped (already configured): "
                + ", ".join(result.skipped)
                + "[/]"
            )
        summary.append("[dim]Keep debug Chrome open for browser recon.[/]")
        if status.burp_enabled and not status.burp_sse_live:
            jar = status.burp_jar
            summary.append(
                "[yellow]Burp JAR is ready, but the MCP SSE port is not up yet. "
                "Load the JAR in Burp (Extensions → Add) and enable the MCP tab.[/]"
            )
            if jar:
                summary.append(f"[dim]JAR path: {jar}[/]")
        if not restarted and (
            status.chrome_devtools_enabled or status.burp_enabled
        ):
            summary.append(
                "[yellow]Restart VulnClaw if MCP services did not attach live.[/]"
            )
        ui.finish(summary)
        result.messages.append("Setup complete.")
        return result
    except KeyboardInterrupt:
        con.print("\n[yellow]Wizard cancelled.[/]")
        result.messages.append("Cancelled.")
        return result


# ── Stages ───────────────────────────────────────────────────────────────


def _stage_prereqs(ui: _WizardUi, status: SetupStatus) -> SetupStatus:
    ui.begin("Prerequisites", 1)
    con = ui.console
    # Refresh probe after begin so progress is current.
    status.node = shutil.which("node")
    status.npx = shutil.which("npx")
    status.nmap = shutil.which("nmap")
    status.java = detect_java_path()
    status.git = shutil.which("git")
    status.chrome_path = detect_chrome_path()

    rows = [
        ("Python", sys.version.split()[0], True),
        ("Node.js", status.node or "missing", bool(status.node)),
        ("npx", status.npx or "missing", bool(status.npx)),
        ("nmap", status.nmap or "optional", True),
        ("Java", status.java or "missing (needed for Burp build)", bool(status.java)),
        ("git", status.git or "missing (needed for Burp build)", bool(status.git)),
        ("Chrome", status.chrome_path or "not found", bool(status.chrome_path)),
    ]
    for label, value, ok in rows:
        if ok:
            con.print(f"  ✓ {label}: {value}")
        else:
            con.print(f"  [yellow]· {label}: {value}[/]")

    if not status.node or not status.npx:
        con.print(
            "  [yellow]Install Node.js LTS — needed for chrome-devtools MCP.[/]"
        )
    _pause(con, "Continue")
    return status


def _stage_llm(
    ui: _WizardUi,
    config: VulnClawConfig,
    status: SetupStatus,
    result: WizardResult,
) -> tuple[VulnClawConfig, SetupStatus]:
    if status.llm_ready:
        result.skipped.append("LLM")
        return config, status

    ui.begin("LLM provider", 3)
    con = ui.console
    providers = [item["provider"] for item in list_providers()]
    con.print(f"  Available: {', '.join(providers)}")
    con.print(
        f"  Current: {config.llm.provider} / {config.llm.model or '(none)'} "
        "(no credentials detected)"
    )

    provider = _ask(
        con,
        "Provider",
        default=config.llm.provider or "openai",
    ).strip().lower()
    if provider:
        try:
            config = apply_provider_preset(config, provider)
            con.print(
                f"  ✓ {config.llm.provider} → {config.llm.base_url} "
                f"(model {config.llm.model})"
            )
        except Exception as exc:
            con.print(f"  [yellow]⚠ preset failed: {exc}[/]")
            config.llm.provider = provider

    if provider == "ollama":
        config.llm.api_key = config.llm.api_key or "ollama"
        con.print("  ✓ Ollama placeholder API key set")
    else:
        key = _ask_secret(con, "API key (hidden, Enter to skip)")
        if key:
            config.llm.api_key = key
            con.print("  ✓ stored llm.api_key")
        else:
            con.print("  [yellow]No API key — agent will not run until you set one.[/]")

    if _confirm(con, "Override default model name?", default=False):
        model = _ask(con, "Model name", default=config.llm.model or "")
        if model:
            config.llm.model = model

    status.llm_ready = has_llm_credentials(config.llm)
    return config, status


def _stage_language(
    ui: _WizardUi,
    config: VulnClawConfig,
    status: SetupStatus,
    result: WizardResult,
) -> tuple[VulnClawConfig, SetupStatus]:
    current = str(getattr(config.session, "language", "") or "").strip().lower()
    if current in {"en", "zh", "auto"}:
        status.language = current
        result.skipped.append(f"language ({current})")
        return config, status

    ui.begin("UI language", 1)
    con = ui.console
    lang = _ask(con, "Language [en/zh/auto]", default="en").strip().lower()
    if lang not in {"en", "zh", "auto"}:
        lang = "en"
    config.session.language = lang
    status.language = lang
    try:
        from vulnclaw.i18n import init_i18n

        init_i18n(lang=lang if lang != "auto" else None, config=config)
        from vulnclaw.cli.tui import rebuild_translations

        rebuild_translations()
    except Exception:
        pass
    con.print(f"  ✓ session.language → {lang}")
    _pause(con, "Continue")
    return config, status


def _stage_chrome(
    ui: _WizardUi,
    status: SetupStatus,
    result: WizardResult,
) -> tuple[int, Optional[str], Path, SetupStatus]:
    port = status.debug_port
    chrome = status.chrome_path
    profile = CHROME_PROFILE

    # Fully ready: Chrome debug endpoint answering.
    if status.chrome_debug_live:
        result.skipped.append(f"Chrome debug (:{port})")
        status.chrome_debug_live = True
        return port, chrome, profile, status

    ui.begin("Chrome remote debugging", 3)
    con = ui.console
    con.print(
        "  Real Chrome with remote debugging lets chrome-devtools MCP share "
        "cookies after you pass Cloudflare once."
    )

    if not chrome:
        chrome = _ask(con, "Path to chrome.exe / Google Chrome", default="").strip() or None
        status.chrome_path = chrome

    profile.mkdir(parents=True, exist_ok=True)
    if chrome:
        con.print(f"  Launching Chrome on port {port}…")
        if launch_chrome_debug(chrome, port=port, user_data_dir=profile):
            # Give Chrome a moment to bind the port.
            for _ in range(10):
                if port_open("127.0.0.1", port):
                    break
                time.sleep(0.4)
        else:
            con.print("  [yellow]⚠ auto-launch failed — starting with explicit path.[/]")
            con.print(
                f'    "{chrome}" --remote-debugging-port={port} '
                f'--user-data-dir="{profile}"'
            )
            _pause(con, "Press Enter after Chrome is open with debugging")
    else:
        con.print("  [yellow]Chrome not found — install Chrome, then re-run /wizard.[/]")
        _pause(con, "Continue without Chrome")

    status.chrome_debug_live = port_open("127.0.0.1", port)
    if status.chrome_debug_live:
        con.print(f"  ✓ DevTools live on {port}")
    else:
        con.print(f"  [yellow]Port {port} not up yet — browser MCP may wait until it is.[/]")
    _pause(con, "Continue")
    return port, chrome, profile, status


def _stage_chrome_devtools(
    ui: _WizardUi,
    config: VulnClawConfig,
    status: SetupStatus,
    debug_port: int,
    result: WizardResult,
) -> tuple[VulnClawConfig, SetupStatus]:
    browser_url = f"http://127.0.0.1:{debug_port}"
    if status.chrome_devtools_enabled and (
        status.chrome_devtools_url == browser_url
        or status.chrome_devtools_url.endswith(f":{debug_port}")
    ):
        result.skipped.append("chrome-devtools MCP")
        return config, status

    ui.begin("chrome-devtools MCP", 2)
    con = ui.console
    con.print(f"  Enabling chrome-devtools → {browser_url}")
    config = enable_chrome_devtools(config, browser_url=browser_url)
    status.chrome_devtools_enabled = True
    status.chrome_devtools_url = browser_url
    con.print("  ✓ mcp.servers.chrome-devtools enabled")
    if not status.npx:
        con.print("  [yellow]npx missing — install Node.js so the MCP server can start.[/]")
    _pause(con, "Continue")
    return config, status


def _stage_burp(
    ui: _WizardUi,
    config: VulnClawConfig,
    status: SetupStatus,
    result: WizardResult,
) -> tuple[VulnClawConfig, SetupStatus]:
    # Fully ready: config enabled + SSE answering.
    if status.burp_enabled and status.burp_sse_live:
        result.skipped.append("Burp MCP")
        return config, status

    # JAR + config already ok, only SSE missing — short reminder, still skip rebuild.
    if status.burp_enabled and status.burp_jar and not status.burp_sse_live:
        result.skipped.append("Burp MCP build (JAR ready; load/enable in Burp if needed)")
        return config, status

    ui.begin("Burp Suite MCP", 4)
    con = ui.console

    if status.burp_enabled and status.burp_jar is None:
        con.print("  Burp is enabled in config but the JAR is missing — rebuilding…")
    elif not status.burp_enabled:
        if not _confirm(
            con,
            "Install Burp MCP now? (install Java if needed, clone, build, enable)",
            default=False,
        ):
            con.print("  [dim]Skipped Burp.[/]")
            _pause(con, "Continue")
            return config, status

    java, java_err = ensure_java(con, status)
    if not java:
        con.print(f"  [yellow]⚠ Cannot build Burp MCP: {java_err}[/]")
        _pause(con, "Continue")
        return config, status

    ok, jar, err = ensure_burp_mcp_jar(console=con, status=status)
    if not ok or jar is None:
        con.print(f"  [yellow]⚠ Burp MCP build incomplete: {err or 'unknown error'}[/]")
        con.print("  VulnClaw config was not force-enabled. Fix tools and re-run /wizard.")
        _pause(con, "Continue")
        return config, status

    status.burp_jar = jar
    config = enable_burp_mcp(config, sse_url=status.burp_sse_url)
    # Prefer stdio wrapper recommended in README when jar is local.
    config = enable_burp_mcp_stdio(config, jar=jar, sse_url=status.burp_sse_url)
    status.burp_enabled = True
    con.print(f"  ✓ JAR ready: {jar}")
    con.print("  ✓ mcp.servers.burp enabled in VulnClaw")

    status.burp_sse_live = port_open("127.0.0.1", BURP_SSE_PORT)
    if status.burp_sse_live:
        con.print(f"  ✓ Burp MCP SSE already answering on :{BURP_SSE_PORT}")
    else:
        con.print(
            "  [yellow]One manual Burp step remains (API cannot load extensions for you):[/]"
        )
        con.print("    Burp → Extensions → Add → Java → select the JAR above")
        con.print("    Then enable the MCP tab (SSE default http://127.0.0.1:9876)")
        if _confirm(con, "Open the JAR folder in Explorer/Finder?", default=True):
            _open_path(jar.parent)
    _pause(con, "Continue")
    return config, status


def _reload_mcp(
    ui: _WizardUi,
    config: VulnClawConfig,
    mcp_manager: Any,
    result: WizardResult,
) -> bool:
    ui.begin("Apply MCP", 1)
    con = ui.console
    if mcp_manager is None:
        con.print("  [dim]No live MCP manager — restart VulnClaw to attach new servers.[/]")
        _pause(con, "Finish")
        return False

    started = 0
    try:
        mcp_manager.config = config
        for name in ("chrome-devtools", "burp"):
            srv = config.mcp.servers.get(name)
            if not srv or not srv.enabled:
                continue
            mcp_manager.registry.register_server(name)
            try:
                if mcp_manager._start_server(name, srv):  # noqa: SLF001
                    started += 1
                    con.print(f"  ✓ attached: {name}")
                else:
                    con.print(f"  [yellow]⚠ {name} registered; attach incomplete[/]")
            except Exception as exc:
                con.print(f"  [yellow]⚠ {name}: {exc}[/]")
        con.print(f"  MCP attach attempts: {started}")
    except Exception as exc:
        con.print(f"  [yellow]⚠ MCP reload failed: {exc}[/]")
        _pause(con, "Finish")
        return False
    _pause(con, "Finish")
    return started > 0


# ── Burp automation ──────────────────────────────────────────────────────


def find_burp_jar() -> Optional[Path]:
    """Locate a built burp-mcp-all.jar under ~/.vulnclaw or known checkout paths."""
    candidates = [
        TOOLS_DIR / BURP_JAR_NAME,
        BURP_MCP_DIR / "build" / "libs" / BURP_JAR_NAME,
        BURP_MCP_DIR / BURP_JAR_NAME,
    ]
    # Windows download folders sometimes used by hand.
    home = Path.home()
    candidates.append(home / "Downloads" / BURP_JAR_NAME)
    for path in candidates:
        if path.is_file():
            return path
    # Newest match under tools/burp-mcp
    if BURP_MCP_DIR.is_dir():
        matches = sorted(BURP_MCP_DIR.rglob(BURP_JAR_NAME), key=lambda p: p.stat().st_mtime)
        if matches:
            return matches[-1]
    return None


def ensure_burp_mcp_jar(
    *,
    console: Console,
    status: SetupStatus,
) -> tuple[bool, Optional[Path], str]:
    """Clone + build PortSwigger MCP server and install the JAR under tools/.

    Fully automatic except Burp Suite GUI loading, which no API can do.
    """
    existing = find_burp_jar()
    if existing is not None and existing.is_file():
        # Prefer a stable location under TOOLS_DIR.
        stable = TOOLS_DIR / BURP_JAR_NAME
        if existing.resolve() != stable.resolve():
            try:
                TOOLS_DIR.mkdir(parents=True, exist_ok=True)
                shutil.copy2(existing, stable)
                console.print(f"  ✓ copied JAR → {stable}")
                return True, stable, ""
            except OSError:
                return True, existing, ""
        console.print(f"  ✓ existing JAR → {existing}")
        return True, existing, ""

    if not status.git and not shutil.which("git"):
        return False, None, "git not found on PATH"

    java = status.java or detect_java_path()
    if not java:
        return False, None, "java not found (need Java 11+)"
    status.java = java

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    if not (BURP_MCP_DIR / ".git").is_dir():
        if BURP_MCP_DIR.exists():
            shutil.rmtree(BURP_MCP_DIR, ignore_errors=True)
        console.print(f"  Cloning {BURP_REPO} …")
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", BURP_REPO, str(BURP_MCP_DIR)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return False, None, f"git clone failed: {(proc.stderr or proc.stdout)[:400]}"
    else:
        console.print("  ✓ burp-mcp repo already present")

    gradlew = BURP_MCP_DIR / ("gradlew.bat" if platform.system() == "Windows" else "gradlew")
    if not gradlew.is_file():
        return False, None, f"gradle wrapper missing at {gradlew}"

    # Ensure gradlew is executable on Unix.
    if platform.system() != "Windows":
        try:
            gradlew.chmod(gradlew.stat().st_mode | 0o111)
        except OSError:
            pass

    env = os.environ.copy()
    home = java_home_from_binary(java)
    if home:
        env["JAVA_HOME"] = home
        # Put this Java first so Gradle wrapper sees it.
        bin_dir = str(Path(java).parent)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    console.print(f"  Using Java: {java}")
    if home:
        console.print(f"  JAVA_HOME={home}")

    console.print("  Running Gradle embedProxyJar (first run may download deps)…")
    if platform.system() == "Windows":
        proc = subprocess.run(
            f'"{gradlew}" embedProxyJar --no-daemon',
            cwd=str(BURP_MCP_DIR),
            capture_output=True,
            text=True,
            check=False,
            shell=True,
            env=env,
        )
    else:
        proc = subprocess.run(
            [str(gradlew), "embedProxyJar", "--no-daemon"],
            cwd=str(BURP_MCP_DIR),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-600:]
        return False, None, f"gradle failed: {tail}"

    built = find_burp_jar()
    if built is None:
        # Common Gradle output location.
        libs = BURP_MCP_DIR / "build" / "libs"
        if libs.is_dir():
            jars = list(libs.glob("*.jar"))
            if jars:
                built = jars[0]
    if built is None:
        return False, None, "build finished but burp-mcp-all.jar was not found"

    stable = TOOLS_DIR / BURP_JAR_NAME
    try:
        shutil.copy2(built, stable)
        built = stable
    except OSError:
        pass
    return True, built, ""


def enable_burp_mcp_stdio(
    config: VulnClawConfig,
    *,
    jar: Path,
    sse_url: str = DEFAULT_BURP_SSE,
) -> VulnClawConfig:
    """Enable Burp MCP with the stdio java -jar form from README when possible."""
    jar_str = str(jar)
    # Expand for humans in yaml; java needs a real path.
    existing = config.mcp.servers.get("burp")
    transport = MCPTransportConfig(
        type="stdio",
        command="java",
        args=["-jar", jar_str, "--sse-url", sse_url],
        url=sse_url,
    )
    if existing is None:
        config.mcp.servers["burp"] = MCPServerConfig(
            name="burp",
            enabled=True,
            priority=0,
            description="Burp Suite proxy integration via MCP",
            transport=transport,
        )
    else:
        existing.enabled = True
        existing.transport = transport
    return config


# ── Config helpers ───────────────────────────────────────────────────────


def enable_chrome_devtools(
    config: VulnClawConfig, *, browser_url: str = "http://127.0.0.1:9222"
) -> VulnClawConfig:
    """Enable and configure chrome-devtools MCP for a debug browser URL."""
    args = ["-y", "chrome-devtools-mcp@latest", f"--browser-url={browser_url}"]
    existing = config.mcp.servers.get("chrome-devtools")
    if existing is None:
        config.mcp.servers["chrome-devtools"] = MCPServerConfig(
            name="chrome-devtools",
            enabled=True,
            priority=0,
            description="Browser automation for Web app pentest",
            transport=MCPTransportConfig(type="stdio", command="npx", args=args),
        )
    else:
        existing.enabled = True
        existing.transport.type = "stdio"
        existing.transport.command = "npx"
        existing.transport.args = args
    return config


def enable_burp_mcp(
    config: VulnClawConfig, *, sse_url: str = DEFAULT_BURP_SSE
) -> VulnClawConfig:
    """Enable Burp MCP over SSE (legacy/default shape)."""
    existing = config.mcp.servers.get("burp")
    if existing is None:
        config.mcp.servers["burp"] = MCPServerConfig(
            name="burp",
            enabled=True,
            priority=0,
            description="Burp Suite proxy integration for HTTP interception via SSE",
            transport=MCPTransportConfig(type="sse", url=sse_url),
        )
    else:
        existing.enabled = True
        if not existing.transport.url:
            existing.transport.url = sse_url
        if existing.transport.type not in {"sse", "stdio"}:
            existing.transport.type = "sse"
    return config


def detect_chrome_path() -> Optional[str]:
    """Best-effort Chrome/Chromium path detection (Windows / macOS / Linux)."""
    candidates: list[str] = []
    system = platform.system()
    if system == "Windows":
        pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        local = os.environ.get("LOCALAPPDATA", "")
        candidates.extend(
            [
                str(Path(pf) / "Google" / "Chrome" / "Application" / "chrome.exe"),
                str(Path(pf86) / "Google" / "Chrome" / "Application" / "chrome.exe"),
                str(Path(local) / "Google" / "Chrome" / "Application" / "chrome.exe")
                if local
                else "",
            ]
        )
    elif system == "Darwin":
        candidates.append(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )
    else:
        for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
            found = shutil.which(name)
            if found:
                return found

    for path in candidates:
        if path and Path(path).is_file():
            return path
    return shutil.which("chrome") or shutil.which("google-chrome")


def launch_chrome_debug(
    chrome_path: str, *, port: int, user_data_dir: Path
) -> bool:
    """Start Chrome with remote debugging. Returns True if spawn succeeded."""
    user_data_dir.mkdir(parents=True, exist_ok=True)
    args = [
        chrome_path,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
    ]
    try:
        kwargs: dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if platform.system() == "Windows":
            kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen(args, **kwargs)  # noqa: S603
        return True
    except OSError:
        return False


def port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _open_url(url: str) -> None:
    try:
        if platform.system() == "Windows":
            os.startfile(url)  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", url])  # noqa: S603
        else:
            subprocess.Popen(["xdg-open", url])  # noqa: S603
    except OSError:
        pass


def _open_path(path: Path) -> None:
    try:
        if platform.system() == "Windows":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", str(path)])  # noqa: S603
        else:
            subprocess.Popen(["xdg-open", str(path)])  # noqa: S603
    except OSError:
        pass


# ── UX helpers ───────────────────────────────────────────────────────────


def _ask(con: Console, prompt: str, *, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = con.input(f"  {prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return value if value else default


def _ask_secret(con: Console, prompt: str) -> str:
    import getpass

    try:
        con.print(f"  {prompt}: ", end="")
        return getpass.getpass(prompt="").strip()
    except (EOFError, KeyboardInterrupt):
        con.print()
        return ""


def _confirm(con: Console, question: str, *, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = _ask(con, f"{question} [{hint}]", default="")
    if not raw:
        return default
    return raw.lower() in {"y", "yes"}


def _pause(con: Console, label: str = "Continue") -> None:
    try:
        con.input(f"  [dim]{label} — press Enter[/] ")
    except EOFError:
        return


def _write_wizard_env(values: dict[str, str]) -> None:
    """Upsert non-secret paths into ~/.vulnclaw/wizard.env for re-runs."""
    existing: dict[str, str] = {}
    if WIZARD_ENV.is_file():
        for line in WIZARD_ENV.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                key, _, val = line.partition("=")
                existing[key.strip()] = val
    existing.update({k: v for k, v in values.items() if v is not None})
    lines = [f"{k}={v}\n" for k, v in sorted(existing.items())]
    WIZARD_ENV.parent.mkdir(parents=True, exist_ok=True)
    WIZARD_ENV.write_text("".join(lines), encoding="utf-8")
