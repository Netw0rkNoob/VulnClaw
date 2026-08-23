"""VulnClaw MCP Lifecycle Manager — start/stop MCP servers and manage their lifetime."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from contextlib import suppress
from typing import Any
from urllib.parse import urlparse

from vulnclaw.config.schema import MCPServerConfig, VulnClawConfig
from vulnclaw.config.source_render import render_highlighted_source_block

# 修改者: Nyaecho
# 修改时间: 2026-07-08
# 修改原因: 消除 V1 违规 — mcp/ 基础设施层不应反向依赖 agent/ 领域层，
#          改为从 config/url_utils.py 导入纯 URL 工具函数。
from vulnclaw.config.url_utils import infer_port_from_url
from vulnclaw.mcp._probe_mixin import ProbeMixin
from vulnclaw.mcp.registry import HealthStatus, MCPRegistry

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # pragma: no cover - optional runtime dependency
    ClientSession = None
    StdioServerParameters = None
    stdio_client = None

try:
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:  # pragma: no cover - optional runtime dependency
    streamablehttp_client = None

try:
    from mcp.client.sse import sse_client
except ImportError:  # pragma: no cover - optional runtime dependency
    sse_client = None

# Transport type aliases that map to the MCP Streamable HTTP client.
HTTP_TRANSPORT_TYPES = frozenset(
    {"streamable-http", "streamable_http", "streamablehttp", "http"}
)
SSE_TRANSPORT_TYPES = frozenset({"sse", "sse-client", "sse_client", "sseclient"})

_BENIGN_SHUTDOWN_KEYWORDS = (
    "cancel scope",
    "generator didn't stop",
)

_FETCH_METHOD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_FETCH_DEFAULT_TIMEOUT = 30.0
_FETCH_MAX_TIMEOUT = 120.0
_FETCH_DEFAULT_BODY_CHARS_LIMIT = 0


def _suppress_cleanup_errors() -> suppress:
    """Suppress cleanup noise, including AnyIO cancel-scope cancellations."""

    return suppress(Exception, asyncio.CancelledError)


def _is_benign_shutdown_exception(exc: BaseException) -> bool:
    if hasattr(exc, "exceptions"):
        subs = list(getattr(exc, "exceptions", []))
        return bool(subs) and all(_is_benign_shutdown_exception(sub) for sub in subs)
    if isinstance(exc, RuntimeError):
        msg = str(exc).lower()
        if any(kw in msg for kw in _BENIGN_SHUTDOWN_KEYWORDS):
            return True
    return isinstance(exc, (GeneratorExit, asyncio.CancelledError))


def _is_tls_verification_error(exc: BaseException) -> bool:
    """Return true for certificate verification failures wrapped by httpx/httpcore."""

    current: BaseException | None = exc
    seen = 0
    while current is not None and seen < 8:
        message = str(current).lower()
        if (
            "certificate_verify_failed" in message
            or "certificate verify failed" in message
            or "unable to get local issuer certificate" in message
        ):
            return True
        current = current.__cause__ or current.__context__
        seen += 1
    return False


class MCPLifecycleManager(ProbeMixin):
    """Manages the lifecycle of MCP servers: start, stop, health check.

    Uses ProbeMixin for transport probing methods (stdio/SSE/HTTP).
    """

    # Auto-restart policy.
    MAX_RESTART_ATTEMPTS = 3
    RESTART_BACKOFF_BASE = 1.0  # seconds; attempt N waits BASE * 2**(N-1)

    # Graceful stop policy.
    TERMINATE_GRACE_SECONDS = 5.0

    # Health-score thresholds on the recent success-rate window.
    HEALTHY_RATE = 0.9
    DEGRADED_RATE = 0.5

    def __init__(self, config: VulnClawConfig) -> None:
        self.config = config
        self.registry = MCPRegistry()
        self._processes: dict[str, subprocess.Popen] = {}
        self._mcp_clients: dict[str, Any] = {}  # Server attach capability cache
        self._runtime_tool_aliases: dict[tuple[str, str], str] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_exception_handler_loop: asyncio.AbstractEventLoop | None = None
        self._task_constraints: Any = None
        # asyncio primitives are loop-bound once contended, so keep one gate
        # per (event loop, server). This protects shared stateful stdio sessions
        # across parent tools and every sub-agent.
        self._server_call_gates: dict[tuple[int, str], asyncio.Semaphore] = {}

    async def __aenter__(self) -> MCPLifecycleManager:
        self.start_enabled_servers()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.astop_all()

    def set_task_constraints(self, constraints: Any) -> None:
        """Attach current task constraints for tool-level enforcement."""
        self._task_constraints = constraints

    def _check_fetch_constraints(self, arguments: dict[str, Any]) -> dict[str, Any] | None:
        constraints = self._task_constraints
        if constraints is None or constraints.is_empty():
            return None

        url = str(arguments.get("url", "") or "").strip()
        if not url:
            return None

        try:
            parsed = urlparse(url)
        except Exception:
            parsed = None
        host = parsed.hostname.lower() if parsed and parsed.hostname else ""
        path = parsed.path.rstrip("/") if parsed and parsed.path else ""

        port = infer_port_from_url(url)
        if port is None:
            port = None

        if constraints.allowed_hosts and host and host not in constraints.allowed_hosts:
            allowed_hosts = ", ".join(constraints.allowed_hosts)
            return self._tool_result(
                ok=False,
                server="fetch",
                tool="fetch",
                execution_mode="local",
                error_type="constraint_violation",
                message=f"Host {host} is outside allowed scope [{allowed_hosts}] for url {url}",
                suggestion="Adjust the task scope or send the request to an allowed host.",
            )

        if host and host in constraints.blocked_hosts:
            return self._tool_result(
                ok=False,
                server="fetch",
                tool="fetch",
                execution_mode="local",
                error_type="constraint_violation",
                message=f"Host {host} is blocked by task constraints for url {url}",
                suggestion="Remove the blocked host from the request or adjust constraints.",
            )

        if constraints.allowed_paths and path and path not in constraints.allowed_paths:
            allowed_paths = ", ".join(constraints.allowed_paths)
            return self._tool_result(
                ok=False,
                server="fetch",
                tool="fetch",
                execution_mode="local",
                error_type="constraint_violation",
                message=f"Path {path} is outside allowed scope [{allowed_paths}] for url {url}",
                suggestion="Adjust the task scope or send the request to an allowed path.",
            )

        if path and path in constraints.blocked_paths:
            return self._tool_result(
                ok=False,
                server="fetch",
                tool="fetch",
                execution_mode="local",
                error_type="constraint_violation",
                message=f"Path {path} is blocked by task constraints for url {url}",
                suggestion="Remove the blocked path from the request or adjust constraints.",
            )

        if port is not None and constraints.allowed_ports and port not in constraints.allowed_ports:
            allowed = ", ".join(str(p) for p in constraints.allowed_ports)
            return self._tool_result(
                ok=False,
                server="fetch",
                tool="fetch",
                execution_mode="local",
                error_type="constraint_violation",
                message=f"Port {port} is outside allowed scope [{allowed}] for url {url}",
                suggestion="Adjust the task scope or send the request to an allowed port.",
            )

        if port is not None and port in constraints.blocked_ports:
            return self._tool_result(
                ok=False,
                server="fetch",
                tool="fetch",
                execution_mode="local",
                error_type="constraint_violation",
                message=f"Port {port} is blocked by task constraints for url {url}",
                suggestion="Remove the blocked port from the request or adjust constraints.",
            )

        return None

    def _tool_result(
        self,
        *,
        ok: bool,
        server: str,
        tool: str,
        execution_mode: str,
        content: Any = None,
        structured_content: dict[str, Any] | None = None,
        error_type: str | None = None,
        message: str = "",
        suggestion: str = "",
    ) -> dict[str, Any]:
        return {
            "ok": ok,
            "server": server,
            "tool": tool,
            "execution_mode": execution_mode,
            "content": content,
            "structured_content": structured_content,
            "error_type": error_type,
            "message": message,
            "suggestion": suggestion,
        }

    def _install_loop_exception_handler(self) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._loop_exception_handler_loop is loop:
            return

        original_handler = loop.get_exception_handler()

        def _handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
            exc = context.get("exception")
            if exc is not None and _is_benign_shutdown_exception(exc):
                return
            msg = str(context.get("message", "")).lower()
            if msg and any(kw in msg for kw in _BENIGN_SHUTDOWN_KEYWORDS):
                return
            # CPython's shutdown_asyncgens reports failed generator finalization
            # as "an error occurred during closing of asynchronous generator".
            if "closing" in msg and ("async_generator" in msg or "asynchronous generator" in msg):
                return
            if original_handler is not None:
                original_handler(loop, context)
            else:
                loop.default_exception_handler(context)

        loop.set_exception_handler(_handler)
        self._loop_exception_handler_loop = loop

    def start_enabled_servers(self) -> int:
        """Start all enabled MCP servers.

        Returns the number of servers successfully started.
        """
        with suppress(RuntimeError):
            self._loop = asyncio.get_running_loop()
        self._install_loop_exception_handler()
        started = 0
        for name, server_config in self.config.mcp.servers.items():
            if server_config.enabled:
                self.registry.register_server(name)
                try:
                    if self._start_server(name, server_config):
                        started += 1
                except Exception as e:
                    self.registry.set_server_error(name, str(e), error_type="startup_error")
        # 如果事件循环在跑，后台预初始化 chrome-devtools session（在主协程入口也会跑）
        try:
            loop = asyncio.get_running_loop()
            if "chrome-devtools" in self.config.mcp.servers and self.config.mcp.servers["chrome-devtools"].enabled:
                loop.create_task(self._preinit_chrome_devtools())
        except RuntimeError:
            pass
        return started

    def _start_server(self, name: str, config: MCPServerConfig) -> bool:
        """Start a single MCP server.

        Current execution modes:
        - fetch/memory: local implementation (usable now, no external MCP process)
        - stdio/sse others: attempt attach, then degrade to placeholder if unavailable
        """
        transport = config.transport

        if name in {"fetch", "memory"}:
            self.registry.set_server_running(name, running=False)
            self.registry.set_server_execution_mode(name, "local")
            self.registry.set_server_health(name, "healthy")
            self.registry.set_server_attach_result(name, attempted=False, succeeded=True)
            self._register_known_tools(name)
            return True

        if transport.type == "stdio":
            self.registry.set_server_health(name, HealthStatus.STARTING.value)
            attached = self._try_attach_stdio_client(name, config)
            self.registry.set_server_attach_result(name, attempted=True, succeeded=attached)
            self.registry.set_server_running(name, running=attached)
            self.registry.set_server_execution_mode(name, "sdk" if attached else "placeholder")
            self.registry.set_server_health(
                name,
                HealthStatus.HEALTHY.value if attached else HealthStatus.DEGRADED.value,
            )
            if not attached:
                self._register_known_tools(name)
            return True

        if transport.type in SSE_TRANSPORT_TYPES:
            self.registry.set_server_health(name, HealthStatus.STARTING.value)
            attached = self._try_attach_sse_client(name, config)
            self.registry.set_server_attach_result(name, attempted=True, succeeded=attached)
            self.registry.set_server_running(name, running=attached)
            self.registry.set_server_execution_mode(name, "sse" if attached else "placeholder")
            self.registry.set_server_health(
                name,
                HealthStatus.HEALTHY.value if attached else HealthStatus.DEGRADED.value,
            )
            if not attached:
                self._register_known_tools(name)
            return True

        if transport.type in HTTP_TRANSPORT_TYPES:
            self.registry.set_server_health(name, HealthStatus.STARTING.value)
            attached = self._try_attach_http_client(name, config)
            self.registry.set_server_attach_result(name, attempted=True, succeeded=attached)
            self.registry.set_server_running(name, running=attached)
            self.registry.set_server_execution_mode(name, "http" if attached else "placeholder")
            self.registry.set_server_health(
                name,
                HealthStatus.HEALTHY.value if attached else HealthStatus.DEGRADED.value,
            )
            if not attached:
                self._register_known_tools(name)
            return True

        self.registry.set_server_health(name, "unavailable")
        return False

    def _normalize_mcp_tools(self, tools: list[Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for tool in tools:
            name = getattr(tool, "name", None)
            if not name:
                continue
            normalized.append(
                {
                    "name": name,
                    "description": getattr(tool, "description", "") or "",
                    "inputSchema": getattr(tool, "inputSchema", None)
                    or getattr(tool, "input_schema", None)
                    or {"type": "object", "properties": {}},
                }
            )
        return normalized

    def _render_mcp_call_result(self, result: Any) -> tuple[str, dict[str, Any] | None, bool]:
        """Normalize an MCP CallToolResult into readable text plus structured data."""
        if result is None:
            return "", None, False

        structured = getattr(result, "structuredContent", None)
        is_error = bool(getattr(result, "isError", False))
        content_items = getattr(result, "content", None)

        if not content_items:
            return (
                str(structured or result),
                structured if isinstance(structured, dict) else None,
                is_error,
            )

        parts: list[str] = []
        for item in content_items:
            item_type = getattr(item, "type", "")
            if item_type == "text":
                text = getattr(item, "text", "")
                if text:
                    parts.append(str(text))
                continue
            if item_type == "image":
                mime = getattr(item, "mimeType", "") or getattr(item, "mime_type", "")
                parts.append(f"[image:{mime or 'unknown'}]")
                continue
            if item_type == "resource_link":
                uri = getattr(item, "uri", "")
                name = getattr(item, "name", "") or uri
                parts.append(f"[resource:{name}]")
                continue
            parts.append(str(item))

        rendered = "\n".join(part for part in parts if part).strip()
        if not rendered and structured is not None:
            rendered = str(structured)
        return rendered, structured if isinstance(structured, dict) else None, is_error

    def _register_runtime_tools(self, server_name: str, tools: list[dict[str, Any]]) -> None:
        """Replace static known tools with tools discovered from the live MCP server."""
        self.registry.clear_server_tools(server_name)
        for key in list(self._runtime_tool_aliases):
            if key[0] == server_name:
                self._runtime_tool_aliases.pop(key, None)
        for tool in tools:
            runtime_name = str(tool.get("name", ""))
            public_name = self._public_runtime_tool_name(server_name, runtime_name)
            if not public_name:
                continue
            if public_name != runtime_name:
                self._runtime_tool_aliases[(server_name, public_name)] = runtime_name
            public_tool = dict(tool)
            public_tool["name"] = public_name
            self.registry.register_tool(server_name, public_tool)

    def _public_runtime_tool_name(self, server_name: str, runtime_name: str) -> str:
        """Return the project-facing name for a discovered runtime MCP tool."""
        if server_name == "burp" and runtime_name.startswith("runtime_"):
            candidate = runtime_name.removeprefix("runtime_")
            if candidate in {"send_http1_request", "get_proxy_http_history"}:
                return candidate
        return runtime_name

    async def _call_stdio_server(
        self, server_name: str, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        """Run a one-shot stdio MCP call using the Python SDK."""
        client_meta = self._mcp_clients.get(server_name)
        config = None
        if isinstance(client_meta, dict):
            config = client_meta.get("config")
        if config is None:
            config = self.config.mcp.servers.get(server_name)
        if config is None:
            raise RuntimeError(f"missing MCP config for server {server_name}")

        transport = config.transport
        server = StdioServerParameters(
            command=transport.command or "",
            args=transport.args or [],
            env=transport.env,
        )

        timeout_s = self._tool_timeout_seconds(config)
        startup_s = self._startup_timeout_seconds(config)
        async with stdio_client(server) as (read_stream, write_stream):
            # read_timeout_seconds is deliberately unset: the SDK has typed it as
            # both float-seconds and timedelta across releases, so every await
            # below carries its own asyncio.wait_for instead.
            async with ClientSession(read_stream, write_stream) as session:
                await asyncio.wait_for(session.initialize(), timeout=startup_s)
                return await asyncio.wait_for(
                    session.call_tool(tool_name, arguments=arguments), timeout=timeout_s
                )

    async def _get_or_create_persistent_stdio_session(self, server_name: str) -> Any:
        """Create and cache a persistent stdio-backed MCP session for the current loop."""
        # stdio_client is an anyio TaskGroup-based async generator. When the
        # per-request event loop tears down (asyncio.run -> shutdown_asyncgens),
        # the still-open generator is finalized from a different task than the one
        # that entered its cancel scope, raising a benign cross-task RuntimeError.
        # Install the handler on *this* loop so that noise is suppressed (the SSE
        # path already does this; stdio must too).
        self._install_loop_exception_handler()

        client_meta = self._mcp_clients.get(server_name)
        current_loop = asyncio.get_running_loop()

        if isinstance(client_meta, dict) and client_meta.get("kind") == "persistent-stdio":
            if client_meta.get("loop") is current_loop and client_meta.get("session") is not None:
                return client_meta["session"]

        config = None
        if isinstance(client_meta, dict):
            config = client_meta.get("config")
        if config is None:
            config = self.config.mcp.servers.get(server_name)
        if config is None:
            raise RuntimeError(f"missing MCP config for server {server_name}")

        transport = config.transport
        server = StdioServerParameters(
            command=transport.command or "",
            args=transport.args or [],
            env=transport.env,
        )
        startup_s = self._startup_timeout_seconds(config)

        cm = stdio_client(server)
        read_stream, write_stream = await cm.__aenter__()
        # read_timeout_seconds is deliberately unset; per-call timeouts are applied
        # locally via asyncio.wait_for (see _call_attached_server).
        session = ClientSession(read_stream, write_stream)
        # 进入 ClientSession 上下文以启动 _receive_loop；否则后续调用读不到响应而卡死。
        try:
            await session.__aenter__()
            await asyncio.wait_for(session.initialize(), timeout=startup_s)
        except BaseException:
            with _suppress_cleanup_errors():
                await session.__aexit__(None, None, None)
            with _suppress_cleanup_errors():
                await cm.__aexit__(None, None, None)
            raise

        # 发现并注册真实工具名，替换 KNOWN_TOOLS 硬编码的假名
        try:
            result = await asyncio.wait_for(session.list_tools(), timeout=10)
            tool_defs = self._normalize_mcp_tools(getattr(result, "tools", []) or [])
            if tool_defs:
                self._register_runtime_tools(server_name, tool_defs)
        except BaseException:
            pass

        # 关闭旧 context_manager，避免 GC 回收时 cancel scope 跨 task 冲突
        old_cm = client_meta.get("context_manager") if isinstance(client_meta, dict) else None
        if old_cm is not None and old_cm is not cm:
            with _suppress_cleanup_errors():
                await old_cm.__aexit__(None, None, None)

        self._mcp_clients[server_name] = {
            "kind": "persistent-stdio",
            "config": config,
            "loop": current_loop,
            "session": session,
            "context_manager": cm,
        }
        return session

    async def _get_or_create_persistent_http_session(self, server_name: str) -> Any:
        """Create and cache a persistent Streamable HTTP MCP session for the current loop.

        First call establishes the session AND discovers real tools (replacing the
        static placeholders registered at startup).  Subsequent calls in the same
        event loop return the cached session.

        If the connect/initialize fails (e.g. "Already connected"), the error is
        raised to the caller so the tool_call_manager can handle it as a service
        error — it never crashes the entire solve loop.
        """
        if streamablehttp_client is None or ClientSession is None:
            raise RuntimeError("MCP Python SDK is not installed")
        # Suppress the benign cross-task cancel-scope error emitted when this
        # loop's shutdown_asyncgens finalizes the transport generator (see the
        # stdio path for the full rationale).
        self._install_loop_exception_handler()

        client_meta = self._mcp_clients.get(server_name)
        current_loop = asyncio.get_running_loop()

        if isinstance(client_meta, dict) and client_meta.get("kind") == "persistent-http":
            if client_meta.get("loop") is current_loop and client_meta.get("session") is not None:
                return client_meta["session"]

        config = None
        if isinstance(client_meta, dict):
            config = client_meta.get("config")
        if config is None:
            config = self.config.mcp.servers.get(server_name)
        if config is None:
            raise RuntimeError(f"missing MCP config for server {server_name}")

        url = config.transport.url or ""
        if not url:
            raise RuntimeError(f"streamable-http transport for {server_name} is missing url")
        headers = config.transport.env or None
        connect_s = self._startup_timeout_seconds(config)
        read_s = self._tool_timeout_seconds(config)

        cm = None
        session = None
        try:
            cm = streamablehttp_client(
                url, headers=headers, timeout=connect_s, sse_read_timeout=read_s
            )
            read_stream, write_stream, _get_session_id = await cm.__aenter__()
            # read_timeout_seconds is deliberately unset; per-call timeouts are applied
            # locally via asyncio.wait_for (see _call_attached_server).
            session = ClientSession(read_stream, write_stream)
            await session.__aenter__()
            await asyncio.wait_for(session.initialize(), timeout=connect_s)
        except BaseException as exc:
            # Clean up partial state
            if session is not None:
                with _suppress_cleanup_errors():
                    await session.__aexit__(None, None, None)
            if cm is not None:
                with _suppress_cleanup_errors():
                    await cm.__aexit__(None, None, None)
            # Extract root cause from ExceptionGroup
            detail = str(exc)
            if hasattr(exc, "exceptions"):
                subs = list(getattr(exc, "exceptions", []))
                if subs:
                    detail = "; ".join(str(s) for s in subs)
            raise RuntimeError(
                f"streamable-http session for {server_name} failed: {detail}"
            ) from None

        # 首次连接时发现真实工具并替换启动时注册的静态占位工具
        try:
            tools = await asyncio.wait_for(session.list_tools(), timeout=read_s)
            tool_defs = self._normalize_mcp_tools(getattr(tools, "tools", []) or [])
            if tool_defs:
                self._register_runtime_tools(server_name, tool_defs)
        except Exception:
            pass

        self._mcp_clients[server_name] = {
            "kind": "persistent-http",
            "config": config,
            "loop": current_loop,
            "session": session,
            "context_manager": cm,
        }
        self.registry.set_server_running(server_name, running=True)
        self.registry.set_server_health(server_name, HealthStatus.HEALTHY.value)
        return session

    async def _get_or_create_persistent_sse_session(self, server_name: str) -> Any:
        """Create and cache a persistent SSE MCP session for the current loop."""
        if sse_client is None or ClientSession is None:
            raise RuntimeError("MCP Python SDK is not installed")
        self._install_loop_exception_handler()

        client_meta = self._mcp_clients.get(server_name)
        current_loop = asyncio.get_running_loop()

        if isinstance(client_meta, dict) and client_meta.get("kind") == "persistent-sse":
            if client_meta.get("loop") is current_loop and client_meta.get("session") is not None:
                return client_meta["session"]

        config = None
        if isinstance(client_meta, dict):
            config = client_meta.get("config")
        if config is None:
            config = self.config.mcp.servers.get(server_name)
        if config is None:
            raise RuntimeError(f"missing MCP config for server {server_name}")

        url = config.transport.url or ""
        if not url:
            raise RuntimeError(f"sse transport for {server_name} is missing url")
        read_s = self._tool_timeout_seconds(config)
        connect_s = self._startup_timeout_seconds(config)

        cm = None
        session = None
        try:
            cm = sse_client(url)
            read_stream, write_stream = await cm.__aenter__()
            # read_timeout_seconds is deliberately unset; per-call timeouts are applied
            # locally via asyncio.wait_for (see _call_attached_server).
            session = ClientSession(read_stream, write_stream)
            await session.__aenter__()
            await asyncio.wait_for(session.initialize(), timeout=connect_s)
        except BaseException as exc:
            if session is not None:
                with _suppress_cleanup_errors():
                    await session.__aexit__(None, None, None)
            if cm is not None:
                with _suppress_cleanup_errors():
                    await cm.__aexit__(None, None, None)
            detail = str(exc)
            if hasattr(exc, "exceptions"):
                subs = list(getattr(exc, "exceptions", []))
                if subs:
                    detail = "; ".join(str(s) for s in subs)
            raise RuntimeError(f"sse session for {server_name} failed: {detail}") from None

        try:
            tools = await asyncio.wait_for(session.list_tools(), timeout=read_s)
            tool_defs = self._normalize_mcp_tools(getattr(tools, "tools", []) or [])
            if tool_defs:
                self._register_runtime_tools(server_name, tool_defs)
        except Exception:
            pass

        self._mcp_clients[server_name] = {
            "kind": "persistent-sse",
            "config": config,
            "loop": current_loop,
            "session": session,
            "context_manager": cm,
        }
        self.registry.set_server_running(server_name, running=True)
        self.registry.set_server_health(server_name, HealthStatus.HEALTHY.value)
        return session

    async def _get_or_create_session(self, server_name: str) -> Any:
        """Return a persistent MCP session, dispatching by the server's transport type."""
        config = self.config.mcp.servers.get(server_name)
        client_meta = self._mcp_clients.get(server_name)
        if config is None and isinstance(client_meta, dict):
            config = client_meta.get("config")
        transport_type = (
            config.transport.type if config and config.transport else ""
        ).lower()
        if transport_type in SSE_TRANSPORT_TYPES:
            return await self._get_or_create_persistent_sse_session(server_name)
        if transport_type in HTTP_TRANSPORT_TYPES:
            return await self._get_or_create_persistent_http_session(server_name)
        return await self._get_or_create_persistent_stdio_session(server_name)

    def _is_sdk_attachable(self, server_name: str) -> bool:
        """Whether this server can be driven over a real MCP SDK transport."""
        config = self.config.mcp.servers.get(server_name)
        client_meta = self._mcp_clients.get(server_name)
        if config is None and isinstance(client_meta, dict):
            config = client_meta.get("config")
        if config is None or config.transport is None:
            return False
        ttype = (config.transport.type or "").lower()
        if ttype in HTTP_TRANSPORT_TYPES:
            return streamablehttp_client is not None and ClientSession is not None
        if ttype in SSE_TRANSPORT_TYPES:
            return sse_client is not None and ClientSession is not None
        if ttype == "stdio":
            return stdio_client is not None and ClientSession is not None
        return False

    def _is_process_alive(self, server_name: str) -> bool:
        """Return True if the server's tracked subprocess (if any) is still running.

        Servers without a tracked OS process (local fetch/memory, persistent stdio
        sessions whose process is owned by the SDK context manager) are treated as
        alive; their failures surface through call errors instead.
        """
        proc = self._processes.get(server_name)
        if proc is None:
            return True
        return proc.poll() is None

    async def _restart_server(self, server_name: str) -> bool:
        """Restart a crashed server with exponential backoff (max 3 attempts).

        Returns True if the server was brought back to a running/attached state.
        """
        config = self.config.mcp.servers.get(server_name)
        if config is None:
            self.registry.set_server_error(
                server_name, "missing config for restart", error_type="config_error"
            )
            self.registry.set_server_health(server_name, HealthStatus.UNAVAILABLE.value)
            return False

        # Tear down any stale session/process before re-attaching.
        await self._teardown_server(server_name)

        for attempt in range(1, self.MAX_RESTART_ATTEMPTS + 1):
            if attempt > 1:
                backoff = self.RESTART_BACKOFF_BASE * (2 ** (attempt - 2))
                await asyncio.sleep(backoff)

            self.registry.record_restart(server_name)
            self.registry.set_server_health(server_name, HealthStatus.STARTING.value)
            try:
                started = self._start_server(server_name, config)
            except Exception as exc:
                self.registry.set_server_error(
                    server_name, str(exc), error_type="restart_error"
                )
                continue

            if started and self._is_server_back_up(server_name):
                return True

        self.registry.set_server_health(server_name, HealthStatus.UNAVAILABLE.value)
        return False

    def _is_server_back_up(self, server_name: str) -> bool:
        """A server is back up if it is attached/running, or runs in local mode.

        Local servers (fetch/memory) are never marked ``running`` because they
        have no backing process, so a healthy local execution mode counts as up.
        """
        state = self.registry.get_all_servers().get(server_name)
        if state is None:
            return False
        if state.running:
            return True
        return (
            state.execution_mode == "local"
            and state.health_status == HealthStatus.HEALTHY.value
        )

    @staticmethod
    def _is_persistent_session(client_meta: Any) -> bool:
        if not isinstance(client_meta, dict):
            return False
        return client_meta.get("kind") in (
            "persistent-stdio",
            "persistent-http",
            "persistent-sse",
        )

    async def _aclose_session_meta(self, client_meta: Any) -> None:
        """Exit a persistent session then its transport context manager (order matters)."""
        if not self._is_persistent_session(client_meta):
            return
        session = client_meta.get("session")
        if session is not None:
            try:
                await session.__aexit__(None, None, None)
            except BaseException as exc:
                if not _is_benign_shutdown_exception(exc):
                    raise
        cm = client_meta.get("context_manager")
        if cm is not None:
            try:
                await cm.__aexit__(None, None, None)
            except BaseException as exc:
                if not _is_benign_shutdown_exception(exc):
                    raise

    async def _teardown_server(self, server_name: str) -> None:
        """Close any cached session and kill any tracked process for a server."""
        client_meta = self._mcp_clients.pop(server_name, None)
        await self._aclose_session_meta(client_meta)

        proc = self._processes.pop(server_name, None)
        if proc is not None:
            await self._terminate_process(proc)

    async def health_check(self, server_name: str) -> HealthStatus:
        """Evaluate and update a server's health from its recent success rate.

        >90% success → healthy, 50-90% → degraded, <50% → unavailable.
        Servers with no recorded calls keep their current lifecycle status
        (starting/healthy/degraded) rather than being forced to a verdict.
        """
        state = self.registry.get_all_servers().get(server_name)
        if state is None:
            return HealthStatus.UNKNOWN

        # A dead subprocess is unavailable regardless of past success.
        if not self._is_process_alive(server_name):
            self.registry.set_server_health(server_name, HealthStatus.UNAVAILABLE.value)
            return HealthStatus.UNAVAILABLE

        rate = self.registry.recent_success_rate(server_name)
        if rate is None:
            try:
                return HealthStatus(state.health_status)
            except ValueError:
                return HealthStatus.UNKNOWN

        if rate > self.HEALTHY_RATE:
            status = HealthStatus.HEALTHY
        elif rate >= self.DEGRADED_RATE:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.UNAVAILABLE

        self.registry.set_server_health(server_name, status.value)
        return status

    def _register_known_tools(self, server_name: str) -> None:
        """Register known tools for a server based on its type.

        This is a temporary approach for MVP. In production, tools will be
        discovered dynamically via the MCP protocol.
        """
        KNOWN_TOOLS: dict[str, list[dict]] = {
            "fetch": [
                {
                    "name": "fetch",
                    "description": (
                        "Send an HTTP/HTTPS request and return status, headers and the full response body. "
                        "Defaults to GET; supports custom methods, headers, query params and request bodies."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "HTTP/HTTPS URL to request"},
                            "method": {
                                "type": "string",
                                "description": "HTTP method, e.g. GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
                                "default": "GET",
                            },
                            "headers": {"type": "object", "description": "HTTP request headers"},
                            "params": {"type": "object", "description": "Query parameters"},
                            "cookies": {"type": "object", "description": "Per-request cookies"},
                            "body": {"type": "string", "description": "Raw request body"},
                            "data": {
                                "description": "Form-like data or raw data body; use form for explicit form fields"
                            },
                            "form": {"type": "object", "description": "Form fields sent as application/x-www-form-urlencoded"},
                            "json": {"description": "JSON request body"},
                            "timeout": {
                                "type": "number",
                                "description": "Request timeout seconds, 1-120, default 30",
                            },
                            "follow_redirects": {
                                "type": "boolean",
                                "description": "Follow redirects, default true",
                            },
                            "verify_tls": {
                                "type": "boolean",
                                "description": "Verify TLS certificates, default false for CTF/lab compatibility",
                            },
                            "max_body_chars": {
                                "type": "integer",
                                "description": "Optional response body character limit; omitted or 0 returns the full body.",
                            },
                        },
                        "required": ["url"],
                    },
                },
            ],
            "memory": [
                {
                    "name": "save",
                    "description": "Save information to persistent memory",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "description": "Memory key"},
                            "value": {"type": "string", "description": "Memory value"},
                        },
                        "required": ["key", "value"],
                    },
                },
                {
                    "name": "retrieve",
                    "description": "Retrieve information from persistent memory",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "description": "Memory key to retrieve"},
                        },
                        "required": ["key"],
                    },
                },
            ],
            "chrome-devtools": [
                {
                    "name": "chrome_navigate",
                    "description": "Navigate Chrome to a URL. After navigating, use chrome_read_page or chrome_get_web_content to read the page content.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to navigate to"},
                        },
                        "required": ["url"],
                    },
                },
                {
                    "name": "chrome_read_page",
                    "description": "Read the current page content (HTML, text, links, forms). Use this AFTER chrome_navigate to get page data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "format": {"type": "string", "description": "Output format: text, html, links, forms", "default": "text"},
                        },
                    },
                },
                {
                    "name": "chrome_screenshot",
                    "description": "Take a screenshot of the current page",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chrome_javascript",
                    "description": "Execute JavaScript in the browser and return the result",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "description": "JavaScript code to execute"},
                        },
                        "required": ["code"],
                    },
                },
                {
                    "name": "chrome_get_web_content",
                    "description": "Get structured web content from the current page (headings, links, images, meta tags)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to get content from (optional, uses current page if omitted)"},
                        },
                    },
                },
                {
                    "name": "chrome_console",
                    "description": "Get browser console messages (errors, warnings, logs)",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chrome_network_request",
                    "description": "Send an HTTP request through the browser context (with cookies/session)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL"},
                            "method": {"type": "string", "description": "HTTP method"},
                            "headers": {"type": "object", "description": "Headers"},
                            "body": {"type": "string", "description": "Request body"},
                        },
                        "required": ["url"],
                    },
                },
                {
                    "name": "chrome_click_element",
                    "description": "Click an element on the page by CSS selector or text",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "selector": {"type": "string", "description": "CSS selector or text to click"},
                        },
                        "required": ["selector"],
                    },
                },
                {
                    "name": "chrome_fill_or_select",
                    "description": "Fill in a form field or select an option",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "selector": {"type": "string", "description": "CSS selector of the input"},
                            "value": {"type": "string", "description": "Value to fill"},
                        },
                        "required": ["selector", "value"],
                    },
                },
                {
                    "name": "chrome_pentest_http",
                    "description": "Analyze HTTP security: CORS, CSP, HSTS, cookie flags, security headers",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to analyze"},
                        },
                    },
                },
                {
                    "name": "chrome_pentest_js_analyze",
                    "description": "Analyze JavaScript for security issues: eval, innerHTML, postMessage, secrets",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chrome_pentest_cookies",
                    "description": "Analyze cookies for security: HttpOnly, Secure, SameSite flags",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chrome_pentest_headers",
                    "description": "Check HTTP response security headers",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to check"},
                        },
                    },
                },
            ],
            "burp": [
                {
                    "name": "send_http1_request",
                    "description": "Send an HTTP/1 request through Burp proxy",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string", "description": "HTTP method"},
                            "url": {"type": "string", "description": "Target URL"},
                            "headers": {"type": "object", "description": "Request headers"},
                            "body": {"type": "string", "description": "Request body"},
                        },
                        "required": ["method", "url"],
                    },
                },
                {
                    "name": "get_proxy_http_history",
                    "description": "Get items within the proxy HTTP history",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        }

        tools = KNOWN_TOOLS.get(server_name, [])
        for tool in tools:
            self.registry.register_tool(server_name, tool)

    def _graceful_terminate(self, proc: subprocess.Popen) -> None:
        """Synchronously stop a process: terminate, wait, then kill if still alive.

        On Windows there is no SIGTERM; subprocess.terminate() maps to
        TerminateProcess, so we use it directly rather than os.kill(SIGTERM).
        """
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=self.TERMINATE_GRACE_SECONDS)
            return
        except Exception:
            pass
        try:
            proc.kill()
            proc.wait(timeout=self.TERMINATE_GRACE_SECONDS)
        except Exception:
            pass

    async def _terminate_process(self, proc: subprocess.Popen) -> None:
        """Async wrapper: terminate, wait up to grace, then kill — without blocking the loop."""
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except Exception:
            pass

        deadline = time.monotonic() + self.TERMINATE_GRACE_SECONDS
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return
            await asyncio.sleep(0.05)

        with suppress(Exception):
            proc.kill()

    def stop_server(self, name: str) -> None:
        """Stop a single MCP server (synchronous; safe to call without a running loop)."""
        self.registry.set_server_health(name, HealthStatus.STOPPING.value)
        client_meta = self._mcp_clients.pop(name, None)
        if self._is_persistent_session(client_meta):
            loop = client_meta.get("loop")
            if loop is not None and not loop.is_closed():
                try:
                    future = asyncio.run_coroutine_threadsafe(
                        self._aclose_session_meta(client_meta), loop
                    )
                    future.result(timeout=5)
                except Exception:
                    pass

        proc = self._processes.pop(name, None)
        if proc is not None:
            self._graceful_terminate(proc)

        self.registry.set_server_running(name, running=False)
        self.registry.set_server_health(name, HealthStatus.UNKNOWN.value)

    async def astop_server(self, name: str) -> None:
        """Stop a single MCP server from within an event loop."""
        self.registry.set_server_health(name, HealthStatus.STOPPING.value)
        try:
            await self._teardown_server(name)
        except BaseException as exc:
            if not _is_benign_shutdown_exception(exc):
                raise
        self.registry.set_server_running(name, running=False)
        self.registry.set_server_health(name, HealthStatus.UNKNOWN.value)

    def stop_all(self) -> None:
        """Stop all running MCP servers (synchronous)."""
        names = set(self._processes.keys()) | set(self.registry.get_running_servers())
        for name in names:
            self.stop_server(name)

        for name in self.registry.get_running_servers():
            self.registry.set_server_running(name, running=False)

    async def astop_all(self) -> None:
        """Stop all running MCP servers from within an event loop."""
        names = set(self._processes.keys()) | set(self.registry.get_running_servers())
        for name in names:
            try:
                await self.astop_server(name)
            except BaseException as exc:
                if not _is_benign_shutdown_exception(exc):
                    raise

        for name in self.registry.get_running_servers():
            self.registry.set_server_running(name, running=False)

    def running_count(self) -> int:
        """Number of currently running servers."""
        return len(self.registry.get_running_servers())

    def list_available_tools(self) -> list[str]:
        """List all available tool names."""
        return [
            schema.name
            for schema in [
                self.registry.get_tool_schema(n)
                for n in [
                    t for server_tools in self.registry._server_tools.values() for t in server_tools
                ]
            ]
            if schema is not None
        ]

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        """Get all tool schemas for LLM function calling."""
        return self.registry.get_all_tool_schemas()

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Call an MCP tool by name.

        fetch/memory currently run via local implementations.
        Other servers expose structured unsupported/service-unavailable results.
        """

        server_name = self.registry.get_server_for_tool(tool_name)
        if not server_name:
            raise ValueError(f"Unknown tool: {tool_name}")

        async with self._server_call_gate(server_name):
            # Liveness gate: if a tracked subprocess died, attempt a bounded restart
            # before dispatching the call.
            if server_name in self._processes and not self._is_process_alive(server_name):
                await self._restart_server(server_name)

            server_state = self.registry.get_all_servers().get(server_name)
            mode = server_state.execution_mode if server_state else "unknown"

            call_started = time.monotonic()
            try:
                return await self._dispatch_call_tool(server_name, tool_name, arguments, mode)
            finally:
                latency_ms = (time.monotonic() - call_started) * 1000.0
                self.registry.set_last_call_latency(server_name, latency_ms)

    def _server_call_gate(self, server_name: str) -> asyncio.Semaphore:
        """Return the shared per-server gate for the current event loop."""

        key = (id(asyncio.get_running_loop()), server_name)
        gate = self._server_call_gates.get(key)
        if gate is not None:
            return gate

        server_cfg = self.config.mcp.servers.get(server_name)
        transport = getattr(server_cfg, "transport", None)
        if getattr(transport, "type", "") == "stdio":
            limit = 1
        else:
            limit = self.config.safety.tool_max_concurrent
        gate = asyncio.Semaphore(max(1, int(limit or 1)))
        self._server_call_gates[key] = gate
        return gate

    async def _dispatch_call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
        mode: str,
    ) -> Any:
        try:
            if server_name == "fetch" and tool_name == "fetch":
                violation = self._check_fetch_constraints(arguments)
                if violation is not None:
                    self.registry.record_tool_call(server_name, success=False)
                    return violation
                content = await self._call_fetch(arguments)
                self.registry.record_tool_call(server_name, success=True)
                self.registry.set_server_health(server_name, "healthy")
                return self._tool_result(
                    ok=True,
                    server=server_name,
                    tool=tool_name,
                    execution_mode=mode,
                    content=content,
                    structured_content=None,
                )
            if server_name == "memory":
                content = await self._call_memory(tool_name, arguments)
                self.registry.record_tool_call(server_name, success=True)
                self.registry.set_server_health(server_name, "healthy")
                return self._tool_result(
                    ok=True,
                    server=server_name,
                    tool=tool_name,
                    execution_mode=mode,
                    content=content,
                    structured_content=None,
                )
            if server_name == "chrome-devtools":
                try:
                    content, structured = await self._call_chrome(tool_name, arguments)
                    self.registry.record_tool_call(server_name, success=True)
                    self.registry.set_server_health(server_name, "healthy")
                    return self._tool_result(
                        ok=True,
                        server=server_name,
                        tool=tool_name,
                        execution_mode=mode,
                        content=content,
                        structured_content=structured,
                    )
                except Exception as exc:
                    message = str(exc)
                    self.registry.record_tool_call(server_name, success=False)
                    self.registry.set_server_error(
                        server_name, message, error_type="service_unavailable"
                    )
                    return self._tool_result(
                        ok=False,
                        server=server_name,
                        tool=tool_name,
                        execution_mode=mode,
                        error_type="service_unavailable",
                        message=message,
                        suggestion="Start the chrome-devtools MCP service or switch to a browser-capable local setup.",
                    )
            if server_name == "burp":
                try:
                    content, structured = await self._call_burp(tool_name, arguments)
                    self.registry.record_tool_call(server_name, success=True)
                    self.registry.set_server_health(server_name, "healthy")
                    return self._tool_result(
                        ok=True,
                        server=server_name,
                        tool=tool_name,
                        execution_mode=mode,
                        content=content,
                        structured_content=structured,
                    )
                except Exception as exc:
                    message = str(exc)
                    self.registry.record_tool_call(server_name, success=False)
                    self.registry.set_server_error(
                        server_name, message, error_type="service_unavailable"
                    )
                    return self._tool_result(
                        ok=False,
                        server=server_name,
                        tool=tool_name,
                        execution_mode=mode,
                        error_type="service_unavailable",
                        message=message,
                        suggestion="Start the Burp MCP service and verify the proxy integration is ready.",
                    )

            # 通用路径：任何经 SDK attach 成功的 stdio/streamable-http 服务（如自定义
            # streamable-mcp-server）都走真实会话调用，而不是回落到 unsupported。
            if self._is_sdk_attachable(server_name):
                try:
                    content, structured = await self._call_attached_server(
                        server_name, tool_name, arguments
                    )
                    self.registry.record_tool_call(server_name, success=True)
                    self.registry.set_server_health(server_name, "healthy")
                    return self._tool_result(
                        ok=True,
                        server=server_name,
                        tool=tool_name,
                        execution_mode=mode,
                        content=content,
                        structured_content=structured,
                    )
                except Exception as exc:
                    message = str(exc)
                    self.registry.record_tool_call(server_name, success=False)
                    self.registry.set_server_error(
                        server_name, message, error_type="service_unavailable"
                    )
                    return self._tool_result(
                        ok=False,
                        server=server_name,
                        tool=tool_name,
                        execution_mode=mode,
                        error_type="service_unavailable",
                        message=message,
                        suggestion="Verify the MCP server is reachable and the tool name/args are valid.",
                    )

            message = (
                f"MCP tool '{tool_name}' is registered in {mode} mode but is not executable yet."
            )
            suggestion = (
                "Use a local alternative, or enable a runnable MCP backend for this service."
            )
            self.registry.record_tool_call(server_name, success=False)
            self.registry.set_server_error(server_name, message, error_type="unsupported_mode")
            return self._tool_result(
                ok=False,
                server=server_name,
                tool=tool_name,
                execution_mode=mode,
                error_type="unsupported_mode",
                message=message,
                suggestion=suggestion,
            )
        except Exception as exc:
            self.registry.record_tool_call(server_name, success=False)
            self.registry.set_server_error(server_name, str(exc), error_type="execution_failed")
            return self._tool_result(
                ok=False,
                server=server_name,
                tool=tool_name,
                execution_mode=mode,
                error_type="execution_failed",
                message=str(exc),
                suggestion="Inspect the MCP service health and tool arguments, then retry.",
            )

    async def _call_fetch(self, args: dict) -> str:
        """Execute a fetch request using httpx.

        Reuses and updates the shared ``_fetch_cookies`` jar so that a
        session established elsewhere (e.g. ``brute_force_login``) carries
        over to subsequent fetch calls against the same target.
        """
        try:
            import httpx

            request = self._prepare_fetch_request(args)

            jar = getattr(self, "_fetch_cookies", None)
            if jar is None:
                jar = httpx.Cookies()
                self._fetch_cookies = jar

            try:
                async with httpx.AsyncClient(
                    verify=request["verify_tls"],
                    timeout=request["timeout"],
                    follow_redirects=request["follow_redirects"],
                    cookies=jar,
                ) as client:
                    response = await client.request(**request["kwargs"])
                    jar.extract_cookies(response)
            except httpx.TransportError as exc:
                if request["verify_tls"] and _is_tls_verification_error(exc):
                    request = {**request, "verify_tls": False, "tls_retry": True}
                    async with httpx.AsyncClient(
                        verify=False,
                        timeout=request["timeout"],
                        follow_redirects=request["follow_redirects"],
                        cookies=jar,
                    ) as client:
                        response = await client.request(**request["kwargs"])
                        jar.extract_cookies(response)
                else:
                    raise

            return self._format_fetch_response(response, request)

        except ImportError:
            return "[!] httpx 未安装，无法执行 fetch 请求"
        except Exception as e:
            return f"[!] fetch 请求失败: {e}"

    def _prepare_fetch_request(self, args: dict) -> dict[str, Any]:
        url = str(args.get("url", "") or "").strip()
        if not url:
            raise ValueError("fetch requires url")

        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("fetch only supports absolute http/https URLs")

        method = str(args.get("method", "GET") or "GET").strip().upper()
        if not _FETCH_METHOD_RE.fullmatch(method):
            raise ValueError(f"invalid HTTP method for fetch: {method!r}")

        request_kwargs: dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": self._coerce_fetch_string_map(args.get("headers"), "headers"),
        }

        params = args.get("params")
        if params is not None:
            request_kwargs["params"] = params

        cookies = self._coerce_fetch_string_map(args.get("cookies"), "cookies")
        if cookies:
            request_kwargs["cookies"] = cookies

        body_kwargs, body_mode = self._fetch_body_kwargs(args)
        request_kwargs.update(body_kwargs)

        return {
            "method": method,
            "url": url,
            "kwargs": request_kwargs,
            "body_mode": body_mode,
            "timeout": self._bounded_float(
                args.get("timeout"),
                lower=1.0,
                upper=_FETCH_MAX_TIMEOUT,
                default=_FETCH_DEFAULT_TIMEOUT,
            ),
            "follow_redirects": self._coerce_fetch_bool(args.get("follow_redirects"), True),
            "verify_tls": self._coerce_fetch_bool(args.get("verify_tls"), False),
            "max_body_chars": self._coerce_nonnegative_int(
                args.get("max_body_chars"),
                default=_FETCH_DEFAULT_BODY_CHARS_LIMIT,
            ),
        }

    @staticmethod
    def _coerce_fetch_string_map(value: Any, name: str) -> dict[str, str]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError(f"fetch {name} must be an object")
        return {str(key): str(item) for key, item in value.items()}

    @staticmethod
    def _fetch_body_kwargs(args: dict) -> tuple[dict[str, Any], str | None]:
        if args.get("json") is not None:
            return {"json": args["json"]}, "json"
        if args.get("form") is not None:
            return {"data": args["form"]}, "form"
        if args.get("data") is not None:
            return {"data": args["data"]}, "data"
        if args.get("body") is not None:
            return {"content": args["body"]}, "body"
        return {}, None

    @staticmethod
    def _bounded_float(value: Any, *, lower: float, upper: float, default: float) -> float:
        if value is None:
            return default
        try:
            number = float(value)
        except (TypeError, ValueError):
            return default
        return min(max(number, lower), upper)

    @staticmethod
    def _coerce_fetch_bool(value: Any, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "y", "on"}:
                return True
            if normalized in {"0", "false", "no", "n", "off"}:
                return False
        return bool(value)

    @staticmethod
    def _coerce_nonnegative_int(value: Any, *, default: int = 0) -> int:
        if value is None:
            return default
        try:
            number = int(value)
        except (TypeError, ValueError):
            return default
        return max(0, number)

    def _format_fetch_response(self, response: Any, request: dict[str, Any]) -> str:
        lines = [f"Request: {request['method']} {request['url']}"]
        if request.get("tls_retry"):
            lines.append(
                "TLS verification failed; retried once with verify_tls=false for lab/CTF compatibility."
            )
        final_url = str(response.url)
        if final_url != request["url"]:
            lines.append(f"Final URL: {final_url}")
        if response.history:
            redirect_chain = " -> ".join(
                str(item.status_code) for item in [*response.history, response]
            )
            lines.append(f"Redirects: {redirect_chain}")
        lines.append(f"Status: {response.status_code}")
        lines.append(f"Headers: {dict(response.headers)}")
        if request.get("body_mode"):
            lines.append(f"Request body mode: {request['body_mode']}")

        body_text = response.text
        max_body_chars = request["max_body_chars"]
        decoded_source = render_highlighted_source_block(body_text, max_chars=max_body_chars)
        if decoded_source:
            lines.append(decoded_source)
        if max_body_chars > 0 and len(body_text) > max_body_chars:
            lines.append(
                f"Body (first {max_body_chars} chars, truncated from {len(body_text)}): "
                f"{body_text[:max_body_chars]}"
            )
        else:
            lines.append(f"Body (length {len(body_text)} chars): {body_text}")

        content_type = response.headers.get("content-type", "").lower()
        if "json" in content_type and body_text.strip():
            try:
                parsed_body = response.json()
            except ValueError:
                pass
            else:
                rendered_json = json.dumps(parsed_body, ensure_ascii=False, indent=2)
                json_limit = max_body_chars
                if json_limit > 0 and len(rendered_json) > json_limit:
                    rendered_json = f"{rendered_json[:json_limit]}..."
                lines.append(f"JSON: {rendered_json}")
        return "\n".join(lines)

    async def _call_memory(self, tool_name: str, args: dict) -> str:
        """Execute a memory tool call (local implementation)."""
        from vulnclaw.agent.memory import MemoryStore

        store = MemoryStore()

        if tool_name == "save":
            store.save(args.get("key", ""), args.get("value", ""))
            return f"[+] 已保存: {args.get('key', '')}"
        elif tool_name == "retrieve":
            value = store.retrieve(args.get("key", ""))
            return str(value) if value else "[-] 未找到"
        return "[!] 未知 memory 工具"

    async def _call_attached_server(
        self, server_name: str, tool_name: str, args: dict
    ) -> tuple[str, dict[str, Any] | None]:
        """Call a tool on an attached SDK server (stdio or streamable-http).

        The call is bounded by the server's tool_timeout so a silent/streaming
        server can never deadlock the agent loop.
        """
        session = await self._get_or_create_session(server_name)
        config = self.config.mcp.servers.get(server_name)
        timeout_s = self._tool_timeout_seconds(config) if config else 300.0
        runtime_tool_name = self._runtime_tool_aliases.get((server_name, tool_name), tool_name)
        result = await asyncio.wait_for(
            session.call_tool(runtime_tool_name, arguments=args), timeout=timeout_s
        )
        rendered, structured, is_error = self._render_mcp_call_result(result)
        if is_error:
            raise RuntimeError(rendered or f"{server_name} call returned an error")
        return rendered, structured

    async def _call_chrome(self, tool_name: str, args: dict) -> tuple[str, dict[str, Any] | None]:
        """Execute a Chrome DevTools tool call."""
        return await self._call_attached_server("chrome-devtools", tool_name, args)

    async def _call_burp(self, tool_name: str, args: dict) -> tuple[str, dict[str, Any] | None]:
        """Execute a Burp Suite tool call."""
        return await self._call_attached_server("burp", tool_name, args)
