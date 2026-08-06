"""Human Mimicry HTTP Client — Multi-transport browser-like HTTP client.

Phase: HUMAN-MIMICRY-B — Unified client with transport selection,
identity profiles, timing models, and cookie persistence.

Transports:
  - "auto" (default): curl_cffi if available, stdlib fallback (~98% mimicry)
  - "curl_cffi": full TLS/HTTP2 impersonation (~98% mimicry)
  - "stdlib": pure Python urllib (~70% mimicry)
"""

from __future__ import annotations

import json
from typing import Any

from vulnclaw.stealth.header_canon import order_headers
from vulnclaw.stealth.profiles import (
    BrowserFamily,
    IdentityProfile,
    build_identity_profile,
)
from vulnclaw.stealth.timing import HumanTimingModel
from vulnclaw.stealth.transport import (
    AutoTransport,
    BaseTransport,
    CurlCffiTransport,
    StdlibTransport,
    TransportResponse,
    TransportResult,
)


class HumanMimicryClient:
    """stdlib+curl_cffi HTTP client with browser-like identity and timing."""

    def __init__(
        self,
        family: BrowserFamily = BrowserFamily.CHROME,
        transport: str = "auto",
        rotate_profile: bool = True,
        timing_enabled: bool = True,
        think_mean: float = 1.5,
        timeout: int = 30,
        proxy: str = "",
    ):
        self._family = family
        self._rotate_profile = rotate_profile
        self._timeout = timeout
        self._proxy = proxy
        self._timing = HumanTimingModel(enabled=timing_enabled, think_mean=think_mean)
        self._profile = build_identity_profile(family)
        self._transport = self._build_transport(transport)

    def _build_transport(self, transport: str) -> BaseTransport:
        curl_target = self._profile.curl_target or "chrome131"
        if transport == "curl_cffi":
            return CurlCffiTransport(impersonate=curl_target, timeout=self._timeout)
        if transport == "stdlib":
            return StdlibTransport(timeout=self._timeout)
        return AutoTransport(impersonate=curl_target, timeout=self._timeout)

    def _rotate(self) -> None:
        if self._rotate_profile:
            self._profile = build_identity_profile(self._family)
            if hasattr(self._transport, "set_impersonate"):
                self._transport.set_impersonate(self._profile.curl_target)
            elif isinstance(self._transport, CurlCffiTransport):
                pass

    def _build_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = self._profile.all_headers()
        if extra:
            h.update(extra)
        return h

    def request(
        self,
        method: str,
        url: str,
        data: bytes | dict | str | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> TransportResult:
        self._rotate()
        self._timing.wait("request")
        body = self._prepare_body(data)
        req_headers = self._build_headers(headers)
        ordered = order_headers(req_headers, self._family.value)
        ordered_dict = dict(ordered)
        t = timeout if timeout is not None else self._timeout
        return self._transport.request(method, url, body, ordered_dict, t)

    def get(
        self, url: str, headers: dict[str, str] | None = None, timeout: int | None = None
    ) -> TransportResult:
        return self.request("GET", url, headers=headers, timeout=timeout)

    def post(
        self, url: str, data: bytes | dict | str | None = None,
        headers: dict[str, str] | None = None, timeout: int | None = None,
    ) -> TransportResult:
        return self.request("POST", url, data=data, headers=headers, timeout=timeout)

    def head(
        self, url: str, headers: dict[str, str] | None = None, timeout: int | None = None
    ) -> TransportResult:
        return self.request("HEAD", url, headers=headers, timeout=timeout)

    def put(
        self, url: str, data: bytes | dict | str | None = None,
        headers: dict[str, str] | None = None, timeout: int | None = None,
    ) -> TransportResult:
        return self.request("PUT", url, data=data, headers=headers, timeout=timeout)

    def http_get_raw(
        self, url: str, headers: dict[str, str] | None = None, timeout: int = 10
    ) -> dict[str, Any]:
        """Raw dict response (backward compatible with v1 API)."""
        result = self.get(url, headers=headers, timeout=timeout)
        if result.response is None:
            return {"status": 0, "headers": {}, "body": b"", "url": url, "_error": result.error}
        return {
            "status": result.response.status,
            "headers": result.response.headers,
            "body": result.response.body,
            "url": result.response.url,
            "_error": result.response.error or result.error,
        }

    @staticmethod
    def _prepare_body(data: bytes | dict | str | None) -> bytes | None:
        if data is None:
            return None
        if isinstance(data, bytes):
            return data
        if isinstance(data, dict):
            return json.dumps(data).encode("utf-8")
        return data.encode("utf-8")

    def set_proxy(self, proxy: str):
        """Set SOCKS5/HTTP proxy for all requests.
        Examples: 'socks5://127.0.0.1:9050' (Tor), 'http://proxy:8080'"""
        self._proxy = proxy
        if hasattr(self._transport, 'set_proxy'):
            self._transport.set_proxy(proxy)

    def reset_cookies(self) -> None:
        self._transport.reset()
        if isinstance(self._transport, AutoTransport):
            self._transport.reset()

    def reset_timing(self) -> None:
        self._timing.reset()

    def page_read(self) -> None:
        self._timing.wait("page_read")

    def click(self) -> None:
        self._timing.wait("click")

    def think(self) -> None:
        self._timing.wait("think")

    @property
    def profile(self) -> dict[str, Any]:
        p = self._profile
        return {
            "family": p.family.value,
            "platform": p.platform.value,
            "user_agent": p.user_agent,
            "accept": p.accept,
            "accept_language": p.accept_language,
            "accept_encoding": p.accept_encoding,
            "dnt": p.dnt,
            "referer": p.referer or "",
            "curl_target": p.curl_target,
            "client_hints_count": len(p.client_hints),
            "viewport": list(p.viewport),
            "proxy": self._proxy or "none",
        }

    @property
    def request_count(self) -> int:
        return self._timing.request_count

    @property
    def total_requests(self) -> int:
        return self._timing.total_requests

    @property
    def transport_name(self) -> str:
        if isinstance(self._transport, CurlCffiTransport):
            return "curl_cffi"
        if isinstance(self._transport, StdlibTransport):
            return "stdlib"
        if isinstance(self._transport, AutoTransport):
            return "auto"
        return type(self._transport).__name__
