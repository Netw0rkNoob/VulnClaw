"""URL utility functions — shared across infrastructure and domain layers.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V1 违规 — mcp/lifecycle.py 基础设施层不应反向依赖
         agent/builtin_tools.py 领域层，将纯 URL 工具函数抽取到
         基础设施层 config/ 包中。
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse

# 修改者: security-hardening pass (SSRF gap closure)
# 修改原因: enforce_host_path_constraints / _check_fetch_constraints both
# return "allowed" unconditionally whenever no TaskConstraints scope is set
# (constraints.is_empty()) -- which is the *default* state for chat/repl mode
# by explicit design (see agent/core.py's "Chat mode is free-form" comment).
# That means fetch/python_execute/shell_command/chrome-devtools had zero
# built-in protection against being pointed at cloud metadata endpoints,
# regardless of whether any scope was ever declared. This is a small,
# always-on floor sitting *underneath* the optional scope allowlist: unlike
# RFC1918 private ranges (which are legitimate targets for an authorized
# internal pentest and must stay allowed when in-scope), these specific
# addresses have essentially no legitimate reason to ever be a pentest
# target, so they are hard-blocked unconditionally rather than only when a
# scope happens to be configured.
_HARD_BLOCKED_HOSTS = frozenset({
    "169.254.169.254",   # AWS / GCP / DigitalOcean / OpenStack metadata
    "169.254.170.2",     # AWS ECS task metadata
    "metadata.google.internal",
    "metadata.google",
    "fd00:ec2::254",     # AWS IMDSv2, IPv6
})


def is_cloud_metadata_address(host: str) -> tuple[bool, str]:
    """Return (True, reason) if `host` is a well-known cloud metadata
    endpoint -- checked by literal hostname/IP and, best-effort, by DNS
    resolution (so a domain that merely *resolves* to 169.254.169.254 is
    caught too, not just the literal IP)."""
    if not host:
        return False, ""

    candidate = host.strip().lower().rstrip(".")
    if candidate in _HARD_BLOCKED_HOSTS:
        return True, f"well-known cloud metadata endpoint ({candidate})"

    try:
        resolved = socket.gethostbyname(candidate)
    except (socket.gaierror, socket.timeout, OSError):
        return False, ""
    if resolved in _HARD_BLOCKED_HOSTS:
        return True, f"resolves to cloud metadata endpoint {resolved}"
    return False, ""


def infer_port_from_url(url: str) -> int | None:
    """Infer request port from URL.

    Returns the explicit port if present in the URL, otherwise infers
    from the scheme (443 for https, 80 for http), or None if unknown.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None
