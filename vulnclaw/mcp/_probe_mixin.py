"""MCP transport probing mixin — stdio/SSE/HTTP server attach and validation.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: S3 修复 — 从 mcp/lifecycle.py（1713 行）提取传输探测方法到独立 mixin，
         降低主文件复杂度。
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from vulnclaw.config.schema import MCPServerConfig

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # pragma: no cover
    ClientSession = None  # type: ignore[assignment]
    StdioServerParameters = None  # type: ignore[assignment]
    stdio_client = None  # type: ignore[assignment]

try:
    from mcp.client.sse import sse_client
except ImportError:  # pragma: no cover
    sse_client = None  # type: ignore[assignment]

try:
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:  # pragma: no cover
    streamablehttp_client = None  # type: ignore[assignment]


class ProbeMixin:
    """Transport probing methods for MCPLifecycleManager."""

    def _try_attach_stdio_client(self, name: str, config: MCPServerConfig) -> bool:
        """Attempt a real stdio MCP attach when SDK primitives are available."""
        transport = config.transport
        probe_overridden = "_probe_stdio_server" in self.__dict__
        if (
            not probe_overridden
            and (ClientSession is None or StdioServerParameters is None or stdio_client is None)
        ):
            self.registry.set_server_error(
                name, "MCP Python SDK is not installed", error_type="sdk_unavailable"
            )
            return False

        if not transport.command:
            self.registry.set_server_error(
                name, "stdio transport is missing command", error_type="config_error"
            )
            return False

        if not probe_overridden and self._is_deferred_package_command(transport):
            self.registry.set_server_error(
                name,
                "stdio probe skipped for package-manager command; install the MCP server "
                "locally or provide a running server config before attaching",
                error_type="attach_failed",
            )
            return False

        ok, details, tools = self._probe_stdio_server(config)
        if not ok:
            self.registry.set_server_error(
                name, details or "stdio attach probe failed", error_type="attach_failed"
            )
            return False

        self._mcp_clients[name] = {"kind": "stdio-probe", "config": config}
        if tools:
            self._register_runtime_tools(name, tools)
        return True

    def _is_deferred_package_command(self, transport: Any) -> bool:
        """Avoid letting health probes trigger package-manager installs/downloads."""
        command = (transport.command or "").lower()
        args = [str(arg).lower() for arg in (transport.args or [])]

        if command in {"npx", "pnpx", "bunx"}:
            return True

        if command == "yarn" and args and args[0] in {"dlx", "exec"}:
            return True

        return command == "npm" and any(arg in {"exec", "x"} for arg in args)

    def _try_attach_sse_client(self, name: str, config: MCPServerConfig) -> bool:
        """Validate an SSE MCP server and register discovered tools when possible."""
        url = config.transport.url or ""
        if not url:
            self.registry.set_server_error(
                name, "sse transport is missing url", error_type="config_error"
            )
            return False

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            self.registry.set_server_error(
                name, f"invalid SSE url: {url}", error_type="config_error"
            )
            return False
        if ClientSession is None or sse_client is None:
            self.registry.set_server_error(
                name, "MCP Python SDK is not installed", error_type="sdk_unavailable"
            )
            return False

        reachable = self._check_http_reachable(url, self._startup_timeout_seconds(config))
        if not reachable:
            self.registry.set_server_error(
                name, f"sse server unreachable at {url}", error_type="attach_failed"
            )
            return False

        ok, details, tools = self._probe_sse_server(config)
        if not ok:
            self.registry.set_server_error(
                name, details or "sse attach probe failed", error_type="attach_failed"
            )
            self._register_known_tools(name)
            return False

        self._mcp_clients[name] = {"kind": "sse-lazy", "config": config}
        if tools:
            self._register_runtime_tools(name, tools)
        else:
            self._register_known_tools(name)
        return True

    def _try_attach_http_client(self, name: str, config: MCPServerConfig) -> bool:
        """Validate a Streamable HTTP MCP server and mark it for lazy connection."""
        if ClientSession is None or streamablehttp_client is None:
            self.registry.set_server_error(
                name, "MCP Python SDK is not installed", error_type="sdk_unavailable"
            )
            return False

        url = config.transport.url or ""
        if not url:
            self.registry.set_server_error(
                name, "streamable-http transport is missing url", error_type="config_error"
            )
            return False

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            self.registry.set_server_error(
                name, f"invalid streamable-http url: {url}", error_type="config_error"
            )
            return False

        reachable = self._check_http_reachable(url, self._startup_timeout_seconds(config))
        if not reachable:
            self.registry.set_server_error(
                name, f"streamable-http server unreachable at {url}", error_type="attach_failed"
            )
            return False

        self._mcp_clients[name] = {"kind": "http-lazy", "config": config}
        self._register_known_tools(name)
        return True

    def _check_http_reachable(self, url: str, timeout_s: float) -> bool:
        """Quick HTTP GET to verify the server is up (no MCP protocol, no session)."""
        try:
            import httpx

            with httpx.stream("GET", url, timeout=min(timeout_s, 10), verify=False) as response:
                return response.status_code < 500
        except Exception:
            return False

    def _probe_http_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        """One-shot Streamable HTTP probe with a hard timeout (never hangs)."""
        timeout_s = self._startup_timeout_seconds(config)
        return self._run_probe(self._async_probe_http_server(config), timeout_s)

    async def _async_probe_http_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        url = config.transport.url or ""
        headers = config.transport.env or None
        connect_s = self._startup_timeout_seconds(config)
        read_s = self._tool_timeout_seconds(config)
        try:
            async with streamablehttp_client(
                url, headers=headers, timeout=connect_s, sse_read_timeout=read_s
            ) as (read_stream, write_stream, _get_session_id):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=self._client_session_timeout(config),
                ) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    tool_defs = self._normalize_mcp_tools(getattr(tools, "tools", []) or [])
                    return True, f"initialized with {len(tool_defs)} tools", tool_defs
        except BaseException as exc:
            detail = str(exc)
            if hasattr(exc, "exceptions"):
                subs = list(getattr(exc, "exceptions", []))
                if subs:
                    detail = "; ".join(str(s) for s in subs)
            if "already connected" in detail.lower():
                detail += " (请重启 MCP 服务或关闭旧客户端连接)"
            return False, detail, []

    def _probe_sse_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        timeout_s = self._startup_timeout_seconds(config)
        return self._run_probe(self._async_probe_sse_server(config), timeout_s)

    async def _async_probe_sse_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        url = config.transport.url or ""
        try:
            async with sse_client(url) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=self._client_session_timeout(config),
                ) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    tool_defs = self._normalize_mcp_tools(getattr(tools, "tools", []) or [])
                    return True, f"initialized with {len(tool_defs)} tools", tool_defs
        except BaseException as exc:
            detail = str(exc)
            if hasattr(exc, "exceptions"):
                subs = list(getattr(exc, "exceptions", []))
                if subs:
                    detail = "; ".join(str(s) for s in subs)
            return False, detail, []

    def _run_probe(
        self, coro: Any, timeout_s: float
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        """Run an async probe, handling both 'no loop' and 'loop already running' cases."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is None or not loop.is_running():
            try:
                return asyncio.run(asyncio.wait_for(coro, timeout=timeout_s))
            except asyncio.TimeoutError:
                return False, f"probe timed out after {timeout_s:.0f}s", []
            except Exception as exc:
                return False, str(exc), []

        def _in_thread():
            return asyncio.run(asyncio.wait_for(coro, timeout=timeout_s))

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_in_thread)
                return future.result(timeout=timeout_s + 5)
        except asyncio.TimeoutError:
            return False, f"probe timed out after {timeout_s:.0f}s", []
        except Exception as exc:
            return False, str(exc), []

    def _probe_stdio_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        """Run a one-shot stdio MCP probe to validate the server can initialize."""
        timeout_s = self._startup_timeout_seconds(config)
        return self._run_probe(self._async_probe_stdio_server(config), timeout_s)

    @staticmethod
    def _startup_timeout_seconds(config: MCPServerConfig) -> float:
        """Resolve the startup timeout (config is in ms) to seconds, defaulting to 30s."""
        raw = getattr(config.transport, "startup_timeout", None)
        if not raw or raw <= 0:
            return 30.0
        return float(raw) / 1000.0

    @staticmethod
    def _tool_timeout_seconds(config: MCPServerConfig) -> float:
        """Resolve the per-call tool timeout (config is in ms) to seconds, defaulting to 300s."""
        raw = getattr(config.transport, "tool_timeout", None)
        if not raw or raw <= 0:
            return 300.0
        return float(raw) / 1000.0

    @classmethod
    def _client_session_timeout(cls, config: MCPServerConfig) -> timedelta:
        """Adapt VulnClaw's numeric timeout to the MCP SDK's duration type."""
        return timedelta(seconds=cls._tool_timeout_seconds(config))

    async def _async_probe_stdio_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict[str, Any]]]:
        transport = config.transport
        server = StdioServerParameters(
            command=transport.command or "",
            args=transport.args or [],
            env=transport.env,
        )

        try:
            async with stdio_client(server) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    tool_defs = self._normalize_mcp_tools(getattr(tools, "tools", []) or [])
                    return True, f"initialized with {len(tool_defs)} tools", tool_defs
        except Exception as exc:
            return False, str(exc), []

    async def _preinit_chrome_devtools(self) -> None:
        """预初始化 chrome-devtools: 提前建 session + 发现工具."""
        try:
            await self._get_or_create_persistent_stdio_session("chrome-devtools")
        except BaseException:
            pass
