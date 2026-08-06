"""Transport Layer — Pluggable HTTP transport backends.

Phase: HUMAN-MIMICRY-B — Abstract transport with two backends:

1. StdlibTransport — pure Python stdlib (urllib + cookiejar + ordered headers)
   Covers ~70% of human fingerprint mimicry (headers, cookies, timing).

2. CurlCffiTransport — curl_cffi-based transport with full browser impersonation
   Covers ~98% (TLS fingerprint, HTTP/2, header ordering via impersonation).
   Requires: pip install curl_cffi

Auto-fallback: CurlCffiTransport is preferred when available; falls back to
StdlibTransport gracefully.
"""

from __future__ import annotations

import http.cookiejar
import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

_CURL_CFFI_AVAILABLE = False
try:
    import curl_cffi  # noqa: F401
    _CURL_CFFI_AVAILABLE = True
except ImportError:
    pass


# 修改者: security-hardening pass (VulnClaw integration self-audit)
# 修改原因: the client advertises `Accept-Encoding: gzip, deflate` as part of
# realistic browser mimicry (profiles.py) -- so a server is entitled to
# compress its response, and real ones do. StdlibTransport's urllib-based
# request() never decompressed anything at all: it handed back the exact
# wire bytes and TransportResponse.text just UTF-8-decoded them, silently
# producing garbled binary text for any compressed response while still
# reporting a normal 200 status -- a false-positive "success" that would
# badly mislead whoever (human or model) reads the "body". Reproduced
# against a real target: a `Content-Encoding: br` response came back as
# unreadable bytes through the stdlib fallback path (which is not a rare
# corner case -- it is what runs whenever curl_cffi isn't installed, or
# fails for any reason, e.g. a plain HTTP/1.1-only server not tolerating an
# HTTP/2-impersonated handshake).
#
# Fixed at the single point both transports funnel through
# (TransportResponse construction) rather than in each transport
# separately, and made resilient either way: gzip/deflate use the stdlib
# (zlib/gzip, no new dependency); brotli needs an optional `brotli` package
# (declared in pyproject.toml's `stealth` extra) and degrades to returning
# the raw bytes unchanged if it isn't installed, rather than raising --
# some evidence is better than a crash. If a transport (e.g. curl_cffi) has
# *already* decompressed the body itself, decompressing again would raise
# (the bytes are no longer valid gzip/br), which is caught and the
# already-correct bytes are kept as-is -- safe regardless of which
# transport handled it.
def _maybe_decompress(body: bytes, headers: dict[str, str]) -> bytes:
    if not body:
        return body
    encoding = ""
    for key, value in headers.items():
        if key.lower() == "content-encoding":
            encoding = (value or "").strip().lower()
            break
    if not encoding or encoding == "identity":
        return body

    try:
        if encoding == "gzip":
            import gzip

            return gzip.decompress(body)
        if encoding == "deflate":
            import zlib

            try:
                return zlib.decompress(body)
            except zlib.error:
                # Some servers send raw deflate without the zlib header.
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if encoding == "br":
            try:
                import brotli

                return brotli.decompress(body)
            except ImportError:
                try:
                    import brotlicffi as brotli  # type: ignore[no-redef]

                    return brotli.decompress(body)
                except ImportError:
                    return body  # no brotli decoder available -- return as-is
    except Exception:
        # Decompression failed -- most likely because the transport (e.g.
        # curl_cffi) already decompressed this body itself. Keep the bytes
        # as received rather than raising.
        return body
    return body


@dataclass
class TransportResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    error: str | None = None

    def __post_init__(self) -> None:
        self.body = _maybe_decompress(self.body, self.headers)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def json(self) -> Any:
        return json.loads(self.body)


@dataclass
class TransportResult:
    response: TransportResponse | None = None
    transport: str = "stdlib"
    curl_target_used: str = ""
    error: str | None = None


class BaseTransport(ABC):
    """Abstract transport interface."""

    @abstractmethod
    def request(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> TransportResult:
        ...

    @abstractmethod
    def reset(self) -> None:
        ...


class StdlibTransport(BaseTransport):
    """stdlib-only transport using urllib with ordered headers and cookiejar."""

    def __init__(self, timeout: int = 30):
        self._timeout = timeout
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar)
        )

    def request(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> TransportResult:
        t = timeout if timeout else self._timeout
        req = urllib.request.Request(url, data=data, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        elif data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(req, timeout=t) as resp:
                return TransportResult(
                    response=TransportResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=resp.read(),
                        url=resp.url,
                    ),
                    transport="stdlib",
                )
        except urllib.error.HTTPError as e:
            return TransportResult(
                response=TransportResponse(
                    status=e.code,
                    headers=dict(e.headers) if e.headers else {},
                    body=e.read() if hasattr(e, "read") else b"",
                    url=e.url or url,
                    error=str(e),
                ),
                transport="stdlib",
                error=str(e),
            )
        except urllib.error.URLError as e:
            return TransportResult(
                response=TransportResponse(
                    status=0,
                    headers={},
                    body=b"",
                    url=url,
                    error=str(e.reason),
                ),
                transport="stdlib",
                error=str(e.reason),
            )

    def reset(self) -> None:
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar)
        )

    @property
    def cookie_count(self) -> int:
        return len(self._jar)


class CurlCffiTransport(BaseTransport):
    """curl_cffi transport — full TLS/HTTP2 browser impersonation.

    Uses curl-impersonate under the hood to match Chrome/Firefox/Safari
    TLS fingerprints, cipher suite ordering, and HTTP/2 frame patterns.
    Supports SOCKS5/HTTP proxies for IP hiding.
    """

    def __init__(self, impersonate: str = "chrome131", timeout: int = 30,
                 proxy: str = ""):
        if not _CURL_CFFI_AVAILABLE:
            raise ImportError(
                "curl_cffi is required for CurlCffiTransport. "
                "Install with: pip install curl_cffi"
            )
        self._impersonate = impersonate
        self._timeout = timeout
        self._proxy = proxy

    def request(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> TransportResult:
        import curl_cffi.requests as curl_requests

        t = timeout if timeout else self._timeout
        try:
            kwargs = dict(
                method=method, url=url, data=data,
                headers=headers or {},
                impersonate=self._impersonate,
                timeout=t, allow_redirects=True,
            )
            if self._proxy:
                kwargs["proxies"] = {"http": self._proxy, "https": self._proxy}
            resp = curl_requests.request(**kwargs)
            return TransportResult(
                response=TransportResponse(
                    status=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.content,
                    url=str(resp.url),
                ),
                transport="curl_cffi",
                curl_target_used=self._impersonate,
            )
        except Exception as e:
            return TransportResult(
                response=TransportResponse(
                    status=0, headers={}, body=b"", url=url, error=str(e),
                ),
                transport="curl_cffi",
                curl_target_used=self._impersonate,
                error=str(e),
            )

    def reset(self) -> None:
        pass

    def set_impersonate(self, target: str) -> None:
        self._impersonate = target


class AutoTransport(BaseTransport):
    """Auto-selecting transport: prefers curl_cffi, falls back to stdlib."""

    def __init__(self, impersonate: str = "chrome131", timeout: int = 30):
        self._curl: CurlCffiTransport | None = None
        self._stdlib = StdlibTransport(timeout=timeout)
        self._impersonate = impersonate
        self._timeout = timeout
        if _CURL_CFFI_AVAILABLE:
            try:
                self._curl = CurlCffiTransport(
                    impersonate=impersonate, timeout=timeout
                )
            except Exception:
                self._curl = None

    def request(
        self,
        method: str,
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> TransportResult:
        if self._curl is not None:
            result = self._curl.request(
                method, url, data, headers, timeout
            )
            if result.response and result.response.status > 0:
                return result
        return self._stdlib.request(method, url, data, headers, timeout)

    def reset(self) -> None:
        self._stdlib.reset()
        if self._curl:
            self._curl.reset()

    def set_impersonate(self, target: str) -> None:
        self._impersonate = target
        if self._curl:
            self._curl.set_impersonate(target)

    @property
    def curl_available(self) -> bool:
        return self._curl is not None

    @property
    def cookie_count(self) -> int:
        return self._stdlib.cookie_count
