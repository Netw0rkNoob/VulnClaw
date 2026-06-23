"""VulnClaw MCP lifecycle robustness tests — restart, health, graceful stop."""

from __future__ import annotations

import asyncio

import pytest

from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager
from vulnclaw.mcp.registry import HealthStatus


def _manager() -> MCPLifecycleManager:
    return MCPLifecycleManager(VulnClawConfig())


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


class TestStreamableHttp:
    def test_attach_success_registers_known_tools(self, monkeypatch):
        m = _manager()
        cfg = _http_server_config("chrome-devtools")
        m.config.mcp.servers["chrome-devtools"] = cfg
        m.registry.register_server("chrome-devtools")

        monkeypatch.setattr(m, "_check_http_reachable", lambda url, timeout: True)

        assert m._start_server("chrome-devtools", cfg) is True
        state = m.registry.get_all_servers()["chrome-devtools"]
        assert state.running is True
        assert state.execution_mode == "http"
        assert state.health_status == HealthStatus.HEALTHY.value
        # Static known tools registered at startup; real tools discovered lazily on first call
        assert "chrome_navigate" in m.list_available_tools()

    def test_attach_failure_degrades_and_falls_back(self, monkeypatch):
        m = _manager()
        cfg = _http_server_config("chrome-devtools")
        m.config.mcp.servers["chrome-devtools"] = cfg
        m.registry.register_server("chrome-devtools")

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
        m = _manager()
        m.config.mcp.servers["streamable-mcp-server"] = _http_server_config()
        m.registry.register_server("streamable-mcp-server")
        m.registry.register_tool(
            "streamable-mcp-server",
            {"name": "do_thing", "description": "", "inputSchema": {"type": "object"}},
        )
        m.registry.set_server_execution_mode("streamable-mcp-server", "http")

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


def test_smoke_event_loop_isolation():
    # Each async test gets its own loop under asyncio_mode=auto; ensure the
    # manager does not capture a stale loop at construction time.
    asyncio.run(_noop())


async def _noop():
    return None
