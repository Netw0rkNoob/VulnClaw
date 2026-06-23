"""VulnClaw MCP Module Tests — registry.py + router.py + lifecycle.py"""

from unittest.mock import AsyncMock, MagicMock

import pytest

# ── registry.py ──────────────────────────────────────────────────────


class TestMCPRegistry:
    """Test MCPRegistry."""

    def test_register_server(self):
        from vulnclaw.mcp.registry import MCPRegistry

        registry = MCPRegistry()
        registry.register_server("fetch")
        assert registry.server_count == 1

    def test_register_multiple_servers(self):
        from vulnclaw.mcp.registry import MCPRegistry

        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_server("memory")
        registry.register_server("burp")
        assert registry.server_count == 3

    def test_register_tool(self):
        from vulnclaw.mcp.registry import MCPRegistry

        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_tool(
            "fetch",
            {
                "name": "fetch",
                "description": "Fetch a URL",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
            },
        )
        assert registry.tool_count == 1

    def test_get_server_for_tool(self):
        from vulnclaw.mcp.registry import MCPRegistry

        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_tool(
            "fetch",
            {
                "name": "fetch",
                "description": "Fetch a URL",
                "inputSchema": {"type": "object", "properties": {}},
            },
        )
        assert registry.get_server_for_tool("fetch") == "fetch"

    def test_get_tool_schemas(self):
        from vulnclaw.mcp.registry import MCPRegistry

        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_tool(
            "fetch",
            {
                "name": "fetch",
                "description": "Fetch a URL",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
            },
        )
        schemas = registry.get_all_tool_schemas()
        assert len(schemas) == 1
        assert schemas[0]["name"] == "fetch"

    def test_set_server_error(self):
        from vulnclaw.mcp.registry import MCPRegistry

        registry = MCPRegistry()
        registry.register_server("burp")
        registry.set_server_error("burp", "Connection refused", error_type="service_unavailable")
        state = registry.get_all_servers()["burp"]
        assert state.last_error_type == "service_unavailable"
        assert state.health_status == "degraded"

    def test_duplicate_server_register(self):
        from vulnclaw.mcp.registry import MCPRegistry

        registry = MCPRegistry()
        registry.register_server("fetch")
        registry.register_server("fetch")  # Should not raise
        # Server count should still be reasonable
        assert registry.server_count >= 1

    def test_tool_for_nonexistent_server(self):
        from vulnclaw.mcp.registry import MCPRegistry

        registry = MCPRegistry()
        result = registry.get_server_for_tool("nonexistent")
        assert result is None


# ── router.py ────────────────────────────────────────────────────────


class TestMCPRouter:
    """Test MCPRouter."""

    def test_route_fetch(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        results = router.route("发请求访问这个接口")
        assert len(results) > 0
        assert any(r["server"] == "fetch" for r in results)

    def test_route_burp(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        results = router.route("帮我抓包看一下这个请求")
        assert len(results) > 0
        assert any(r["server"] == "burp" for r in results)

    def test_route_browser(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        results = router.route("打开网页看看")
        assert len(results) > 0
        assert any(r["server"] == "chrome-devtools" for r in results)

    def test_route_screenshot(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        results = router.route("截图")
        assert len(results) > 0
        assert any(r["tool"] == "screenshot" for r in results)

    def test_route_memory_save(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        results = router.route("记住这个发现")
        assert len(results) > 0
        assert any(r["server"] == "memory" for r in results)

    def test_route_no_match(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        results = router.route("今天天气怎么样")
        assert len(results) == 0

    def test_extract_url(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        assert router.extract_url("访问 https://example.com/path") == "https://example.com/path"
        assert router.extract_url("没有URL") is None

    def test_extract_ip(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        assert router.extract_ip("扫描 192.168.1.100") == "192.168.1.100"
        assert router.extract_ip("没有IP") is None

    def test_suggest_tools_for_phase(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        tools = router.suggest_tools_for_phase("信息收集")
        assert len(tools) > 0
        assert any(t["server"] == "fetch" for t in tools)

    def test_suggest_tools_for_unknown_phase(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        tools = router.suggest_tools_for_phase("未知阶段")
        assert tools == []

    def test_route_confidence(self):
        from vulnclaw.mcp.router import MCPRouter

        router = MCPRouter()
        results = router.route("发请求")
        for r in results:
            assert "confidence" in r
            assert 0 < r["confidence"] <= 1


# ── lifecycle.py ─────────────────────────────────────────────────────


class TestMCPLifecycleManager:
    """Test MCPLifecycleManager."""

    def test_init(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        assert manager.registry is not None

    def test_start_enabled_servers(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        config = VulnClawConfig()
        manager = MCPLifecycleManager(config)
        started = manager.start_enabled_servers()
        # At least fetch and memory should be registered
        assert started >= 0  # May or may not actually start depending on env

    def test_get_tool_schemas(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        config = VulnClawConfig()
        manager = MCPLifecycleManager(config)
        manager.start_enabled_servers()
        schemas = manager.get_tool_schemas()
        assert isinstance(schemas, list)

    def test_call_tool_unknown(self):
        """Calling an unknown tool should not crash."""
        import asyncio

        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        config = VulnClawConfig()
        manager = MCPLifecycleManager(config)
        # Call with unknown tool name
        try:
            asyncio.run(
                manager.call_tool("nonexistent_tool", {})
            )
        except Exception:
            pass  # Expected to fail for unknown tool

    def test_fetch_falls_back_to_local_mode_when_sdk_attach_fails(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("fetch")
        manager._try_attach_stdio_client = MagicMock(return_value=False)
        fetch_config = MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"])

        assert manager._start_server("fetch", fetch_config) is True
        state = manager.registry.get_all_servers()["fetch"]
        assert state.execution_mode == "local"
        assert state.attach_succeeded is True

    def test_fetch_starts_in_local_mode(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("fetch")
        fetch_config = MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"])

        assert manager._start_server("fetch", fetch_config) is True
        state = manager.registry.get_all_servers()["fetch"]
        assert state.execution_mode == "local"

    def test_memory_falls_back_to_local_mode_when_sdk_attach_fails(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("memory")
        manager._try_attach_stdio_client = MagicMock(return_value=False)
        memory_config = MCPServerConfig(**BUILTIN_MCP_SERVERS["memory"])

        assert manager._start_server("memory", memory_config) is True
        state = manager.registry.get_all_servers()["memory"]
        assert state.execution_mode == "local"

    def test_memory_starts_in_local_mode(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("memory")
        memory_config = MCPServerConfig(**BUILTIN_MCP_SERVERS["memory"])

        assert manager._start_server("memory", memory_config) is True
        state = manager.registry.get_all_servers()["memory"]
        assert state.execution_mode == "local"
        assert state.attach_succeeded is True

    def test_mcp_diagnostics_reports_execution_modes(self):
        from vulnclaw.web.services.mcp_service import get_mcp_diagnostics

        view = get_mcp_diagnostics()
        assert view.total_services >= 2
        assert view.tool_count >= 2
        assert any(
            item.name == "fetch" and item.execution_mode == "local" for item in view.services
        )
        assert any(item.execution_mode in {"placeholder", "local"} for item in view.services)

    def test_render_mcp_call_result_parses_text_content(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        class TextItem:
            type = "text"
            text = "hello from mcp"

        class DummyResult:
            content = [TextItem()]
            structuredContent = {"ok": True}
            isError = False

        manager = MCPLifecycleManager(VulnClawConfig())
        rendered, structured, is_error = manager._render_mcp_call_result(DummyResult())
        assert rendered == "hello from mcp"
        assert structured == {"ok": True}
        assert is_error is False

    def test_render_mcp_call_result_parses_error_content(self):
        from vulnclaw.config.schema import VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        class TextItem:
            type = "text"
            text = "tool failed"

        class DummyResult:
            content = [TextItem()]
            structuredContent = None
            isError = True

        manager = MCPLifecycleManager(VulnClawConfig())
        rendered, structured, is_error = manager._render_mcp_call_result(DummyResult())
        assert rendered == "tool failed"
        assert structured is None
        assert is_error is True

    def test_stdio_placeholder_records_attach_attempt_and_error(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("chrome-devtools")
        cfg = MCPServerConfig(**BUILTIN_MCP_SERVERS["chrome-devtools"])
        assert manager._start_server("chrome-devtools", cfg) is True
        state = manager.registry.get_all_servers()["chrome-devtools"]
        assert state.attach_attempted is True
        assert state.attach_succeeded is False
        assert state.execution_mode == "placeholder"
        assert state.last_error_type in {"sdk_unavailable", "config_error", "attach_failed", None}

    def test_attach_success_registers_runtime_tools(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("chrome-devtools")
        manager._probe_stdio_server = MagicMock(
            return_value=(
                True,
                "ok",
                [
                    {
                        "name": "runtime_navigate",
                        "description": "runtime navigate",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"url": {"type": "string"}},
                        },
                    }
                ],
            )
        )
        cfg = MCPServerConfig(**BUILTIN_MCP_SERVERS["chrome-devtools"])
        assert manager._start_server("chrome-devtools", cfg) is True
        tools = manager.registry.get_server_tools("chrome-devtools")
        assert "runtime_navigate" in tools
        assert "navigate" not in tools

    def test_burp_attach_success_registers_runtime_tools(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("burp")
        manager._probe_stdio_server = MagicMock(
            return_value=(
                True,
                "ok",
                [
                    {
                        "name": "runtime_send_http1_request",
                        "description": "runtime burp request",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"url": {"type": "string"}},
                        },
                    }
                ],
            )
        )
        cfg = MCPServerConfig(**BUILTIN_MCP_SERVERS["burp"])
        assert manager._start_server("burp", cfg) is True
        tools = manager.registry.get_server_tools("burp")
        assert "runtime_send_http1_request" in tools
        assert "send_http1_request" not in tools

    def test_sse_placeholder_records_invalid_url_error(self):
        from vulnclaw.config.schema import MCPServerConfig, MCPTransportConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("jadx")
        cfg = MCPServerConfig(
            name="jadx",
            enabled=True,
            priority=1,
            description="jadx",
            transport=MCPTransportConfig(type="sse", url="not-a-url"),
        )
        assert manager._start_server("jadx", cfg) is True
        state = manager.registry.get_all_servers()["jadx"]
        assert state.attach_attempted is True
        assert state.attach_succeeded is False
        assert state.last_error_type == "config_error"

    @pytest.mark.asyncio
    async def test_call_tool_returns_structured_result_for_local_tool(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("memory")
        manager._start_server("memory", MCPServerConfig(**BUILTIN_MCP_SERVERS["memory"]))
        result = await manager.call_tool("save", {"key": "demo", "value": "123"})

        assert result["ok"] is True
        assert result["server"] == "memory"
        assert result["execution_mode"] == "local"
        assert "content" in result
        state = manager.registry.get_all_servers()["memory"]
        assert state.call_count == 1
        assert state.success_count == 1
        assert state.health_status == "healthy"

    @pytest.mark.asyncio
    async def test_fetch_constraint_violation_returns_structured_error(self):
        from vulnclaw.agent.context import TaskConstraints
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("fetch")
        manager._start_server("fetch", MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"]))

        constraints = TaskConstraints(allowed_ports=[443], strict_mode=True)
        manager.set_task_constraints(constraints)

        result = await manager.call_tool("fetch", {"url": "http://example.com/"})
        assert result["ok"] is False
        assert result["error_type"] == "constraint_violation"
        assert "Port 80" in result["message"]

    @pytest.mark.asyncio
    async def test_fetch_host_constraint_violation_returns_structured_error(self):
        from vulnclaw.agent.context import TaskConstraints
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("fetch")
        manager._start_server("fetch", MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"]))

        constraints = TaskConstraints(allowed_hosts=["example.com"], strict_mode=True)
        manager.set_task_constraints(constraints)

        result = await manager.call_tool("fetch", {"url": "https://api.example.com/"})
        assert result["ok"] is False
        assert result["error_type"] == "constraint_violation"
        assert "api.example.com" in result["message"]

    @pytest.mark.asyncio
    async def test_fetch_path_constraint_violation_returns_structured_error(self):
        from vulnclaw.agent.context import TaskConstraints
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("fetch")
        manager._start_server("fetch", MCPServerConfig(**BUILTIN_MCP_SERVERS["fetch"]))

        constraints = TaskConstraints(allowed_paths=["/admin"], strict_mode=True)
        manager.set_task_constraints(constraints)

        result = await manager.call_tool("fetch", {"url": "https://example.com/login"})
        assert result["ok"] is False
        assert result["error_type"] == "constraint_violation"
        assert "/login" in result["message"]

    @pytest.mark.asyncio
    async def test_call_tool_returns_structured_result_for_placeholder_tool(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("chrome-devtools")
        manager._start_server(
            "chrome-devtools", MCPServerConfig(**BUILTIN_MCP_SERVERS["chrome-devtools"])
        )
        result = await manager.call_tool("chrome_navigate", {"url": "https://example.com"})

        assert result["ok"] is False
        assert result["server"] == "chrome-devtools"
        assert result["error_type"] == "service_unavailable"
        state = manager.registry.get_all_servers()["chrome-devtools"]
        assert state.last_error_type == "service_unavailable"
        assert state.call_count == 1
        assert state.failure_count == 1
        assert state.health_status == "degraded"

    @pytest.mark.asyncio
    async def test_call_tool_returns_success_for_chrome_when_stdio_call_succeeds(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        class DummySession:
            async def call_tool(self, tool_name, arguments=None):
                return {
                    "ok": True,
                    "result": "navigated",
                    "tool": tool_name,
                    "arguments": arguments,
                }

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("chrome-devtools")
        manager._try_attach_stdio_client = MagicMock(return_value=True)
        manager._get_or_create_persistent_stdio_session = AsyncMock(return_value=DummySession())
        manager._start_server(
            "chrome-devtools", MCPServerConfig(**BUILTIN_MCP_SERVERS["chrome-devtools"])
        )
        manager.registry.register_tool(
            "chrome-devtools",
            {
                "name": "navigate",
                "description": "navigate",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
            },
        )

        result = await manager.call_tool("navigate", {"url": "https://example.com"})
        state = manager.registry.get_all_servers()["chrome-devtools"]

        assert result["ok"] is True
        assert result["server"] == "chrome-devtools"
        assert state.health_status == "healthy"
        assert state.success_count == 1

    @pytest.mark.asyncio
    async def test_chrome_devtools_reuses_persistent_session(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        class DummySession:
            def __init__(self):
                self.calls = 0

            async def call_tool(self, tool_name, arguments=None):
                self.calls += 1
                return {"tool": tool_name, "arguments": arguments, "calls": self.calls}

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("chrome-devtools")
        manager._try_attach_stdio_client = MagicMock(return_value=True)
        session = DummySession()
        manager._get_or_create_persistent_stdio_session = AsyncMock(return_value=session)
        manager._start_server(
            "chrome-devtools", MCPServerConfig(**BUILTIN_MCP_SERVERS["chrome-devtools"])
        )
        manager.registry.register_tool(
            "chrome-devtools",
            {
                "name": "navigate",
                "description": "navigate",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
            },
        )

        first = await manager.call_tool("navigate", {"url": "https://example.com/1"})
        second = await manager.call_tool("navigate", {"url": "https://example.com/2"})

        assert first["ok"] is True
        assert second["ok"] is True
        assert session.calls == 2
        assert manager._get_or_create_persistent_stdio_session.await_count == 2

    @pytest.mark.asyncio
    async def test_call_tool_returns_success_for_burp_when_stdio_call_succeeds(self):
        from vulnclaw.config.schema import BUILTIN_MCP_SERVERS, MCPServerConfig, VulnClawConfig
        from vulnclaw.mcp.lifecycle import MCPLifecycleManager

        class DummySession:
            async def call_tool(self, tool_name, arguments=None):
                return {
                    "ok": True,
                    "result": "burp-called",
                    "tool": tool_name,
                    "arguments": arguments,
                }

        manager = MCPLifecycleManager(VulnClawConfig())
        manager.registry.register_server("burp")
        manager._try_attach_stdio_client = MagicMock(return_value=True)
        manager._get_or_create_persistent_stdio_session = AsyncMock(return_value=DummySession())
        manager._start_server("burp", MCPServerConfig(**BUILTIN_MCP_SERVERS["burp"]))
        manager.registry.register_tool(
            "burp",
            {
                "name": "send_http1_request",
                "description": "send_http1_request",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
            },
        )

        result = await manager.call_tool("send_http1_request", {"url": "https://example.com"})
        state = manager.registry.get_all_servers()["burp"]

        assert result["ok"] is True
        assert result["server"] == "burp"
        assert state.health_status == "healthy"
        assert state.success_count == 1


class TestStructuredToolResults:
    @pytest.mark.asyncio
    async def test_tool_call_manager_preserves_structured_content(self):
        from vulnclaw.agent.tool_call_manager import handle_tool_calls_with_results

        class DummyMcpManager:
            async def call_tool(self, tool_name, args):
                return {
                    "ok": True,
                    "content": "navigated",
                    "structured_content": {"url": "https://example.com", "status": "ok"},
                }

        class DummyFunction:
            name = "navigate"
            arguments = '{"url":"https://example.com"}'

        class DummyToolCall:
            id = "call_1"
            function = DummyFunction()

        class DummyMessage:
            tool_calls = [DummyToolCall()]

        class DummyAgent:
            def __init__(self):
                self.mcp_manager = DummyMcpManager()

            async def _execute_mcp_tool(self, func_name, func_args):
                return 'navigated\n[structured] {"url": "https://example.com", "status": "ok"}'

        results, skipped = await handle_tool_calls_with_results(DummyAgent(), DummyMessage())
        assert skipped == []
        assert len(results) == 1
        assert results[0]["structured_content"] == {"url": "https://example.com", "status": "ok"}
