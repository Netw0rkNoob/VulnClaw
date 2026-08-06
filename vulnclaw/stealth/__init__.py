"""Human Mimicry Engine — stdlib + curl_cffi with full stealth layering.

Ported from the AI Karmous project's `human_mimicry` package (same author's
other project) as VulnClaw's `stealth_fetch` builtin tool -- see
agent/builtin_tools.py's execute_stealth_fetch. Import paths adjusted
(ai_karmous_v1.human_mimicry -> vulnclaw.stealth); the module logic itself is
unmodified. Ghost Bridge (L3, ghost_bridge.py/StealthManager's ghost polling)
is an optional external service this port does not include -- it degrades
gracefully (silently no-ops) when unreachable, so every other layer still
works standalone.

Balanced architecture:
  L6: HumanMimicryClient  — curl_cffi TLS + headers + timing (baseline)
  L5: Proxy routing        — SOCKS5/HTTP for IP hiding
  L4: Identity rotation    — rotate UA/TLS per session
  L3: Ghost Bypass         — WAF bypass via Ghost Protocol (optional, external)
  L2: Traffic Shaper       — randomize packet timing
  L1: DPI Monitor          — detect deep packet inspection
  L0: Circuit Breaker      — auto-pause on detection

Every request through this tool still goes through VulnClaw's own scope/SSRF
gate (mcp/lifecycle.py's _check_fetch_constraints) before this module is ever
touched -- realistic evasion techniques do not exempt a call from being
in-scope for the authorized test.

~98% TLS/HTTP mimicry + WAF bypass + DPI awareness + IP hiding.
"""

from __future__ import annotations

from vulnclaw.stealth.client import HumanMimicryClient
from vulnclaw.stealth.ghost_bridge import GhostBridge, GhostBypassResult
from vulnclaw.stealth.header_canon import (
    CHROME_HEADER_ORDER,
    EDGE_HEADER_ORDER,
    FIREFOX_HEADER_ORDER,
    HEADER_ORDER_BY_BROWSER,
    OPERA_HEADER_ORDER,
    SAFARI_HEADER_ORDER,
    order_headers,
)
from vulnclaw.stealth.profiles import (
    BrowserFamily,
    IdentityProfile,
    Platform,
    UA_POOL,
    build_identity_profile,
    build_low_profile_headers,
    random_ua,
    random_accept_language,
    random_accept_encoding,
    random_dnt,
    random_referer,
    random_fetch_site,
    validate_identity_consistency,
)
from vulnclaw.stealth.stealth import (
    StealthManager,
    StealthMode,
    StealthState,
    ThreatLevel,
    balance_stealth_and_bypass,
)
from vulnclaw.stealth.timing import (
    HumanTimingModel,
    human_delay_seconds,
    jitter,
)
from vulnclaw.stealth.transport import (
    AutoTransport,
    CurlCffiTransport,
    StdlibTransport,
    TransportResponse,
    TransportResult,
)

__all__ = [
    "BrowserFamily",
    "Platform",
    "IdentityProfile",
    "HumanMimicryClient",
    "HumanTimingModel",
    "StealthManager",
    "StealthMode",
    "StealthState",
    "ThreatLevel",
    "GhostBridge",
    "GhostBypassResult",
    "balance_stealth_and_bypass",
    "UA_POOL",
    "CHROME_HEADER_ORDER",
    "FIREFOX_HEADER_ORDER",
    "SAFARI_HEADER_ORDER",
    "EDGE_HEADER_ORDER",
    "OPERA_HEADER_ORDER",
    "HEADER_ORDER_BY_BROWSER",
    "AutoTransport",
    "CurlCffiTransport",
    "StdlibTransport",
    "TransportResponse",
    "TransportResult",
    "build_identity_profile",
    "build_low_profile_headers",
    "order_headers",
    "human_delay_seconds",
    "jitter",
    "random_ua",
    "random_accept_language",
    "random_accept_encoding",
    "random_dnt",
    "random_referer",
    "random_fetch_site",
    "validate_identity_consistency",
]
