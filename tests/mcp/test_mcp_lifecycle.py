"""VulnClaw MCP lifecycle robustness tests — restart, health, graceful stop."""

from __future__ import annotations

import asyncio

import pytest

from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager
from vulnclaw.mcp.registry import HealthStatus


def _manager() -> MCPLifecycleManager:
    return MCPLifecycleManager(VulnClawConfig())


class TestSessionTimeouts:
    """MCP session timeouts are enforced locally, not via the SDK's read_timeout_seconds.

    The SDK has typed ``ClientSession.read_timeout_seconds`` as both float-seconds
    and ``datetime.timedelta`` across releases, so passing either one crashes on
    the version that expects the other (issue #171). VulnClaw passes neither.
    """

    def test_no_client_session_passes_read_timeout_seconds(self):
        from pathlib import Path

        import vulnclaw.mcp as mcp_pkg

        offenders = []
        for path in Path(mcp_pkg.__file__).parent.glob("*.py"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "read_timeout_seconds=" in stripped:
                    offenders.append(f"{path.name}:{lineno}")
        assert offenders == [], (
            "ClientSession must not receive read_timeout_seconds; bound the call with "
            f"asyncio.wait_for instead. Offending sites: {offenders}"
        )

    def test_attached_server_call_times_out_without_sdk_timeout(self, monkeypatch):
        cfg = VulnClawConfig()
        cfg.mcp.servers["slow"] = MCPServerConfig(
            name="slow",
            transport={"type": "stdio", "command": "noop", "tool_timeout": 10},
        )
        m = MCPLifecycleManager(cfg)

        class _HangingSession:
            async def call_tool(self, name, arguments=None):
                await asyncio.sleep(60)

        async def _fake_get_or_create_session(server_name):
            return _HangingSession()

        monkeypatch.setattr(m, "_get_or_create_session", _fake_get_or_create_session)

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(m._call_attached_server("slow", "anything", {}))


class _FakeProc:
    """Minimal subprocess.Popen stand-in for liveness/termination tests."""

    def __init__(self, *, alive: bool = True) -> None:
        self._alive = alive
        self.terminate_called = False
        self.kill_called = False
        self.wait_calls = 0
        # If terminate should actually stop the process, set this True.
        self.dies_on_terminate = True

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self.terminate_called = True
        if self.dies_on_terminate:
            self._alive = False

    def kill(self):
        self.kill_called = True
        self._alive = False

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self._alive:
            raise TimeoutError("still running")
        return 0


# ── start / stop ─────────────────────────────────────────────────────


class TestStartStop:
    def test_start_local_server_marks_running_and_healthy(self):
        m = _manager()
        m.registry.register_server("fetch")
        assert m._start_server("fetch", MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"])) is True
        state = m.registry.get_all_servers()["fetch"]
        assert state.execution_mode == "local"
        assert state.health_status == HealthStatus.HEALTHY.value

    def test_stop_server_sets_unknown_and_clears_running(self):
        m = _manager()
        m.registry.register_server("fetch")
        m._start_server("fetch", MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"]))
        proc = _FakeProc(alive=True)
        m._processes["fetch"] = proc

        m.stop_server("fetch")

        assert proc.terminate_called is True
        assert "fetch" not in m._processes
        assert m.registry.get_all_servers()["fetch"].running is False
        assert m.registry.get_all_servers()["fetch"].health_status == HealthStatus.UNKNOWN.value

    def test_stop_all_stops_tracked_processes(self):
        m = _manager()
        m.registry.register_server("a")
        m.registry.register_server("b")
        m._processes["a"] = _FakeProc(alive=True)
        m._processes["b"] = _FakeProc(alive=True)

        m.stop_all()

        assert m._processes == {}

    @pytest.mark.asyncio
    async def test_astop_all_stops_in_parallel(self):
        m = _manager()
        m.registry.register_server("a")
        m.registry.register_server("b")
        m.registry.set_server_running("a", running=True)
        m.registry.set_server_running("b", running=True)
        m._processes["a"] = _FakeProc(alive=True)
        m._processes["b"] = _FakeProc(alive=True)

        await m.astop_all()

        assert m._processes == {}
        assert m.registry.get_running_servers() == []

    @pytest.mark.asyncio
    async def test_context_manager_starts_and_stops(self):
        config = VulnClawConfig()
        config.mcp.servers["fetch"] = MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"])
        async with MCPLifecycleManager(config) as m:
            assert "fetch" in m.registry.get_all_servers()
        # After exit, nothing should remain running.
        assert m.registry.get_running_servers() == []


# ── graceful termination (SIGTERM-then-SIGKILL semantics) ────────────


class TestGracefulTermination:
    def test_terminate_then_no_kill_when_process_exits(self):
        m = _manager()
        proc = _FakeProc(alive=True)
        proc.dies_on_terminate = True

        m._graceful_terminate(proc)

        assert proc.terminate_called is True
        assert proc.kill_called is False

    def test_kill_when_terminate_does_not_stop(self):
        m = _manager()
        proc = _FakeProc(alive=True)
        proc.dies_on_terminate = False  # survives terminate → must be killed

        m._graceful_terminate(proc)

        assert proc.terminate_called is True
        assert proc.kill_called is True

    @pytest.mark.asyncio
    async def test_async_terminate_escalates_to_kill(self):
        m = _manager()
        m.TERMINATE_GRACE_SECONDS = 0.1
        proc = _FakeProc(alive=True)
        proc.dies_on_terminate = False

        await m._terminate_process(proc)

        assert proc.terminate_called is True
        assert proc.kill_called is True

    @pytest.mark.asyncio
    async def test_async_terminate_no_kill_when_already_dead(self):
        m = _manager()
        proc = _FakeProc(alive=False)

        await m._terminate_process(proc)

        assert proc.terminate_called is False
        assert proc.kill_called is False


# ── auto-restart ─────────────────────────────────────────────────────


class TestAutoRestart:
    @pytest.mark.asyncio
    async def test_restart_succeeds_first_attempt(self):
        m = _manager()
        m.config.mcp.servers["fetch"] = MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"])
        m.registry.register_server("fetch")

        ok = await m._restart_server("fetch")

        assert ok is True
        assert m.registry.get_all_servers()["fetch"].restart_count == 1

    @pytest.mark.asyncio
    async def test_restart_retries_with_backoff_then_succeeds(self, monkeypatch):
        m = _manager()
        m.RESTART_BACKOFF_BASE = 0.0  # keep test fast
        cfg = MCPServerConfig(**BUILTIN_MCP_SERVERS["chrome-devtools"])
        m.config.mcp.servers["chrome-devtools"] = cfg
        m.registry.register_server("chrome-devtools")

        attempts = {"n": 0}

        def flaky_start(name, config):
            attempts["n"] += 1
            if attempts["n"] < 3:
                m.registry.set_server_running(name, running=False)
                return False
            m.registry.set_server_running(name, running=True)
            return True

        monkeypatch.setattr(m, "_start_server", flaky_start)

        ok = await m._restart_server("chrome-devtools")

        assert ok is True
        assert attempts["n"] == 3
        assert m.registry.get_all_servers()["chrome-devtools"].restart_count == 3

    @pytest.mark.asyncio
    async def test_restart_gives_up_after_max_attempts(self, monkeypatch):
        m = _manager()
        m.RESTART_BACKOFF_BASE = 0.0
        cfg = MCPServerConfig(**BUILTIN_MCP_SERVERS["chrome-devtools"])
        m.config.mcp.servers["chrome-devtools"] = cfg
        m.registry.register_server("chrome-devtools")

        def always_fail(name, config):
            m.registry.set_server_running(name, running=False)
            return False

        monkeypatch.setattr(m, "_start_server", always_fail)

        ok = await m._restart_server("chrome-devtools")

        assert ok is False
        state = m.registry.get_all_servers()["chrome-devtools"]
        assert state.restart_count == m.MAX_RESTART_ATTEMPTS
        assert state.health_status == HealthStatus.UNAVAILABLE.value

    @pytest.mark.asyncio
    async def test_call_tool_restarts_dead_subprocess(self, monkeypatch):
        m = _manager()
        m.registry.register_server("chrome-devtools")
        m.registry.register_tool(
            "chrome-devtools",
            {"name": "chrome_navigate", "description": "", "inputSchema": {"type": "object"}},
        )
        m.config.mcp.servers["chrome-devtools"] = MCPServerConfig(
            **BUILTIN_MCP_SERVERS["chrome-devtools"]
        )
        # A dead tracked process should trigger a restart on the next call.
        m._processes["chrome-devtools"] = _FakeProc(alive=False)

        restarted = {"called": False}

        async def fake_restart(name):
            restarted["called"] = True
            m._processes.pop(name, None)
            return True

        class DummySession:
            async def call_tool(self, tool_name, arguments=None):
                return {"ok": True, "tool": tool_name}

        async def fake_session(name):
            return DummySession()

        monkeypatch.setattr(m, "_restart_server", fake_restart)
        monkeypatch.setattr(m, "_get_or_create_persistent_stdio_session", fake_session)

        await m.call_tool("chrome_navigate", {"url": "https://example.com"})

        assert restarted["called"] is True


# ── health check ─────────────────────────────────────────────────────


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy_when_success_rate_above_90(self):
        m = _manager()
        m.registry.register_server("fetch")
        for _ in range(19):
            m.registry.record_tool_call("fetch", success=True)
        m.registry.record_tool_call("fetch", success=False)  # 19/20 = 95%

        assert await m.health_check("fetch") == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_degraded_when_success_rate_between_50_and_90(self):
        m = _manager()
        m.registry.register_server("fetch")
        for _ in range(7):
            m.registry.record_tool_call("fetch", success=True)
        for _ in range(3):
            m.registry.record_tool_call("fetch", success=False)  # 70%

        assert await m.health_check("fetch") == HealthStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_unavailable_when_success_rate_below_50(self):
        m = _manager()
        m.registry.register_server("fetch")
        for _ in range(2):
            m.registry.record_tool_call("fetch", success=True)
        for _ in range(8):
            m.registry.record_tool_call("fetch", success=False)  # 20%

        assert await m.health_check("fetch") == HealthStatus.UNAVAILABLE

    @pytest.mark.asyncio
    async def test_unavailable_when_subprocess_dead(self):
        m = _manager()
        m.registry.register_server("chrome-devtools")
        m.registry.record_tool_call("chrome-devtools", success=True)
        m._processes["chrome-devtools"] = _FakeProc(alive=False)

        assert await m.health_check("chrome-devtools") == HealthStatus.UNAVAILABLE

    @pytest.mark.asyncio
    async def test_no_calls_keeps_current_status(self):
        m = _manager()
        m.registry.register_server("fetch")
        m.registry.set_server_health("fetch", HealthStatus.STARTING.value)

        assert await m.health_check("fetch") == HealthStatus.STARTING

    @pytest.mark.asyncio
    async def test_unknown_server_returns_unknown(self):
        m = _manager()
        assert await m.health_check("does-not-exist") == HealthStatus.UNKNOWN


# ── stats tracking ───────────────────────────────────────────────────


class TestStats:
    def test_get_server_stats_reports_counts_and_latency(self):
        m = _manager()
        m.registry.register_server("fetch")
        m.registry.set_server_running("fetch", running=True)
        m.registry.record_tool_call("fetch", success=True)
        m.registry.set_last_call_latency("fetch", 120.0)
        m.registry.record_tool_call("fetch", success=False)
        m.registry.set_last_call_latency("fetch", 80.0)

        stats = m.registry.get_server_stats("fetch")
        assert stats["call_count"] == 2
        assert stats["success_count"] == 1
        assert stats["failure_count"] == 1
        assert stats["avg_latency_ms"] == 100.0
        assert stats["recent_success_rate"] == 0.5
        assert stats["uptime_seconds"] is not None

    def test_record_restart_updates_stats(self):
        m = _manager()
        m.registry.register_server("burp")
        m.registry.record_restart("burp")
        m.registry.record_restart("burp")

        stats = m.registry.get_server_stats("burp")
        assert stats["restart_count"] == 2
        assert stats["last_restart_time"] is not None

    def test_health_window_is_bounded(self):
        m = _manager()
        m.registry.register_server("fetch")
        for _ in range(50):
            m.registry.record_tool_call("fetch", success=True)
        state = m.registry.get_all_servers()["fetch"]
        assert len(state.recent_outcomes) == m.registry.HEALTH_WINDOW_SIZE

    @pytest.mark.asyncio
    async def test_call_tool_records_latency(self):
        m = _manager()
        m.registry.register_server("memory")
        m._start_server("memory", MCPServerConfig(**BUILTIN_MCP_SERVERS["memory"]))

        await m.call_tool("save", {"key": "k", "value": "v"})

        stats = m.registry.get_server_stats("memory")
        assert stats["call_count"] == 1
        assert stats["avg_latency_ms"] >= 0.0


def _http_server_config(name: str = "streamable-mcp-server") -> MCPServerConfig:
    return MCPServerConfig(
        name=name,
        enabled=True,
        transport={"type": "streamable-http", "url": "http://127.0.0.1:12306/mcp"},
    )


def _sse_server_config(name: str = "burp") -> MCPServerConfig:
    return MCPServerConfig(
        name=name,
        enabled=True,
        transport={"type": "sse", "url": "http://127.0.0.1:9876"},
    )


class TestStreamableHttp:
    def test_attach_success_registers_known_tools(self, monkeypatch):
        import vulnclaw.mcp._probe_mixin as _probe_mod
        import vulnclaw.mcp.lifecycle as _mod

        m = _manager()
        cfg = _http_server_config("chrome-devtools")
        m.config.mcp.servers["chrome-devtools"] = cfg
        m.registry.register_server("chrome-devtools")

        # Ensure SDK availability checks pass even when mcp package not installed
        monkeypatch.setattr(_mod, "ClientSession", object)
        monkeypatch.setattr(_mod, "streamablehttp_client", object)
        monkeypatch.setattr(_probe_mod, "ClientSession", object)
        monkeypatch.setattr(_probe_mod, "streamablehttp_client", object)
        monkeypatch.setattr(m, "_check_http_reachable", lambda url, timeout: True)

        assert m._start_server("chrome-devtools", cfg) is True
        state = m.registry.get_all_servers()["chrome-devtools"]
        assert state.running is True
        assert state.execution_mode == "http"
        assert state.health_status == HealthStatus.HEALTHY.value
        assert "chrome_navigate" in m.list_available_tools()

    def test_attach_failure_degrades_and_falls_back(self, monkeypatch):
        import vulnclaw.mcp.lifecycle as _mod

        m = _manager()
        cfg = _http_server_config("chrome-devtools")
        m.config.mcp.servers["chrome-devtools"] = cfg
        m.registry.register_server("chrome-devtools")

        monkeypatch.setattr(_mod, "ClientSession", object)
        monkeypatch.setattr(_mod, "streamablehttp_client", object)
        monkeypatch.setattr(m, "_check_http_reachable", lambda url, timeout: False)

        assert m._start_server("chrome-devtools", cfg) is True
        state = m.registry.get_all_servers()["chrome-devtools"]
        assert state.running is False
        assert state.health_status == HealthStatus.DEGRADED.value
        assert "chrome_navigate" in m.list_available_tools()

    async def test_get_or_create_session_dispatches_http(self, monkeypatch):
        m = _manager()
        m.config.mcp.servers["streamable-mcp-server"] = _http_server_config()
        sentinel = object()

        async def fake_http(name):
            assert name == "streamable-mcp-server"
            return sentinel

        monkeypatch.setattr(m, "_get_or_create_persistent_http_session", fake_http)
        got = await m._get_or_create_session("streamable-mcp-server")
        assert got is sentinel

    async def test_call_tool_routes_streamable_http_server(self, monkeypatch):
        import vulnclaw.mcp.lifecycle as _mod

        m = _manager()
        m.config.mcp.servers["streamable-mcp-server"] = _http_server_config()
        m.registry.register_server("streamable-mcp-server")
        m.registry.register_tool(
            "streamable-mcp-server",
            {"name": "do_thing", "description": "", "inputSchema": {"type": "object"}},
        )
        m.registry.set_server_execution_mode("streamable-mcp-server", "http")

        # Ensure SDK availability checks pass
        monkeypatch.setattr(_mod, "ClientSession", object)
        monkeypatch.setattr(_mod, "streamablehttp_client", object)

        class DummySession:
            async def call_tool(self, tool_name, arguments=None):
                return {"echo": tool_name, "args": arguments}

        async def fake_http(name):
            return DummySession()

        monkeypatch.setattr(m, "_get_or_create_persistent_http_session", fake_http)

        result = await m.call_tool("do_thing", {"x": 1})
        assert result["ok"] is True
        assert result["server"] == "streamable-mcp-server"
        assert "do_thing" in str(result["content"])

    async def test_http_session_cleanup_suppresses_cancel_scope_noise(self, monkeypatch):
        import vulnclaw.mcp.lifecycle as _mod

        m = _manager()
        m.config.mcp.servers["chrome-devtools"] = _http_server_config("chrome-devtools")

        class BadHttpClient:
            async def __aenter__(self):
                return object(), object(), lambda: None

            async def __aexit__(self, exc_type, exc, tb):
                raise asyncio.CancelledError("Cancelled via cancel scope cleanup")

        def fake_http_client(*args, **kwargs):
            return BadHttpClient()

        class BadSession:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def initialize(self):
                raise RuntimeError("init failed")

            async def __aexit__(self, exc_type, exc, tb):
                raise asyncio.CancelledError("Cancelled via cancel scope cleanup")

        monkeypatch.setattr(_mod, "streamablehttp_client", fake_http_client)
        monkeypatch.setattr(_mod, "ClientSession", BadSession)

        with pytest.raises(RuntimeError, match="init failed"):
            await m._get_or_create_persistent_http_session("chrome-devtools")


class TestSseMcp:
    def test_burp_attach_success_registers_runtime_tools(self, monkeypatch):
        import vulnclaw.mcp._probe_mixin as _probe_mod
        import vulnclaw.mcp.lifecycle as _mod

        m = _manager()
        cfg = _sse_server_config()
        m.config.mcp.servers["burp"] = cfg
        m.registry.register_server("burp")

        monkeypatch.setattr(_mod, "ClientSession", object)
        monkeypatch.setattr(_mod, "sse_client", object)
        monkeypatch.setattr(_probe_mod, "ClientSession", object)
        monkeypatch.setattr(_probe_mod, "sse_client", object)
        monkeypatch.setattr(m, "_check_http_reachable", lambda url, timeout: True)
        monkeypatch.setattr(
            m,
            "_probe_sse_server",
            lambda config: (
                True,
                "ok",
                [
                    {
                        "name": "get_proxy_http_history",
                        "description": "",
                        "inputSchema": {"type": "object"},
                    }
                ],
            ),
        )

        assert m._start_server("burp", cfg) is True
        state = m.registry.get_all_servers()["burp"]
        assert state.running is True
        assert state.execution_mode == "sse"
        assert state.health_status == HealthStatus.HEALTHY.value
        assert "get_proxy_http_history" in m.list_available_tools()

    async def test_get_or_create_session_dispatches_sse(self, monkeypatch):
        m = _manager()
        m.config.mcp.servers["burp"] = _sse_server_config()
        sentinel = object()

        async def fake_sse(name):
            assert name == "burp"
            return sentinel

        monkeypatch.setattr(m, "_get_or_create_persistent_sse_session", fake_sse)
        got = await m._get_or_create_session("burp")
        assert got is sentinel

    async def test_call_tool_routes_sse_server(self, monkeypatch):
        import vulnclaw.mcp.lifecycle as _mod

        m = _manager()
        m.config.mcp.servers["burp"] = _sse_server_config()
        m.registry.register_server("burp")
        m.registry.register_tool(
            "burp",
            {
                "name": "get_proxy_http_history",
                "description": "",
                "inputSchema": {"type": "object"},
            },
        )
        m.registry.set_server_execution_mode("burp", "sse")

        monkeypatch.setattr(_mod, "ClientSession", object)
        monkeypatch.setattr(_mod, "sse_client", object)

        class DummySession:
            async def call_tool(self, tool_name, arguments=None):
                return {"echo": tool_name, "args": arguments}

        async def fake_sse(name):
            return DummySession()

        monkeypatch.setattr(m, "_get_or_create_persistent_sse_session", fake_sse)

        result = await m.call_tool("get_proxy_http_history", {})
        assert result["ok"] is True
        assert result["server"] == "burp"
        assert "get_proxy_http_history" in str(result["content"])

    async def test_sse_shutdown_noise_is_ignored(self):
        m = _manager()
        m.registry.register_server("burp")
        m.registry.set_server_running("burp", running=True)

        class BadSession:
            async def __aexit__(self, exc_type, exc, tb):
                raise RuntimeError("Attempted to exit cancel scope in a different task")

        m._mcp_clients["burp"] = {
            "kind": "persistent-sse",
            "session": BadSession(),
            "context_manager": None,
        }

        await m.astop_server("burp")
        assert m.registry.get_all_servers()["burp"].running is False


# ── stdio cross-task shutdown noise (issue #81) ──────────────────────

# A minimal real stdio MCP server. Run via `python -c <src>` so the test needs
# no external package manager (npx/uvx) — only the `mcp` package itself.
_ECHO_STDIO_SERVER_SRC = """
import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

app = Server("echo")

@app.list_tools()
async def list_tools():
    return [types.Tool(name="echo", description="echo",
                       inputSchema={"type": "object",
                                    "properties": {"text": {"type": "string"}}})]

@app.call_tool()
async def call_tool(name, arguments):
    return [types.TextContent(type="text", text=str(arguments))]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

anyio.run(main)
"""


def test_persistent_stdio_shutdown_has_no_cross_task_error():
    """Regression for issue #81.

    A persistent stdio session opened inside a per-request ``asyncio.run`` loop
    is finalized by that loop's ``shutdown_asyncgens`` from a different task than
    the one that entered its anyio cancel scope, raising
    ``RuntimeError: Attempted to exit cancel scope in a different task``. The
    lifecycle manager must install its benign-shutdown exception handler on the
    loop so this noise never reaches the user.

    The failure surfaces through asyncio's default exception handler, which logs
    via the ``asyncio`` logger, so we capture that logger directly rather than a
    stream (pytest routes logging away from the raw stderr fd).
    """
    import logging
    import sys

    pytest.importorskip("mcp")

    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collector()
    asyncio_logger = logging.getLogger("asyncio")
    asyncio_logger.addHandler(handler)

    cfg = VulnClawConfig()
    cfg.mcp.servers["echo"] = MCPServerConfig.model_validate(
        {
            "name": "echo",
            "enabled": True,
            "priority": 0,
            "description": "echo",
            "transport": {
                "type": "stdio",
                "command": sys.executable,
                "args": ["-c", _ECHO_STDIO_SERVER_SRC],
            },
        }
    )
    m = MCPLifecycleManager(cfg)
    m.registry.register_server("echo")
    m._mcp_clients["echo"] = {"kind": "stdio-probe", "config": cfg.mcp.servers["echo"]}

    async def _one_request():
        # Mimic one REPL question: a real stdio session is created lazily.
        session = await m._get_or_create_persistent_stdio_session("echo")
        await session.call_tool("echo", arguments={"text": "hi"})

    # A fresh event loop per request is exactly what the REPL does; its teardown
    # (shutdown_asyncgens) is where the cross-task error used to surface.
    try:
        asyncio.run(_one_request())
    finally:
        asyncio_logger.removeHandler(handler)

    blob = "\n".join(
        r.getMessage() + "\n" + (r.exc_text or "")
        + ("" if r.exc_info is None else str(r.exc_info[1]))
        for r in records
    )
    assert "Attempted to exit cancel scope" not in blob, blob
    assert "asynchronous generator" not in blob, blob


def test_smoke_event_loop_isolation():
    # Each async test gets its own loop under asyncio_mode=auto; ensure the
    # manager does not capture a stale loop at construction time.
    asyncio.run(_noop())


async def _noop():
    return None
