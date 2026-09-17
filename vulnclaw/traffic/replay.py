"""Replay a captured request with overrides.

``traffic_repeat`` reconstructs a stored request, applies caller overrides
(method / url / headers / body), issues it, and records the result back into the
same store with ``source="manual-replay"``. The HTTP transport is injectable so
the logic is unit-testable against a stub without touching a real target.
"""

from __future__ import annotations

from typing import Any

import httpx

from vulnclaw.traffic.models import (
    SOURCE_MANUAL_REPLAY,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    TrafficRecord,
)
from vulnclaw.traffic.store import TrafficStore


class ReplayError(Exception):
    """Raised when a request cannot be replayed."""


def _apply_overrides(
    request: CapturedRequest, overrides: dict[str, Any] | None
) -> CapturedRequest:
    overrides = overrides or {}
    method = str(overrides.get("method", request.method) or request.method)
    url = str(overrides.get("url", request.url) or request.url)

    headers = dict(request.headers)
    override_headers = overrides.get("headers")
    if isinstance(override_headers, dict):
        for name, value in override_headers.items():
            if value is None:
                headers.pop(str(name), None)
            else:
                headers[str(name)] = str(value)

    body = request.body
    if "body" in overrides:
        raw = overrides["body"]
        body = raw if isinstance(raw, bytes) else str(raw).encode("utf-8", "replace")
        # Captured lengths describe the old body. Keep both the HTTP request and
        # its saved replay evidence consistent with the replacement's byte size.
        for name in headers:
            if name.lower() == "content-length":
                headers[name] = str(len(body))

    return CapturedRequest(method=method, url=url, headers=headers, body=body)


def replay_request(
    store: TrafficStore,
    request_id: str,
    overrides: dict[str, Any] | None = None,
    *,
    transport: Any | None = None,
    timeout: float = 30.0,
) -> TrafficRecord:
    """Re-issue ``request_id`` with ``overrides`` and record the new exchange."""
    original = store.load_request(request_id)
    if original is None:
        raise ReplayError(f"request_id not found: {request_id!r}")

    request = _apply_overrides(original, overrides)
    if not request.url:
        raise ReplayError("cannot replay a request without a URL")

    # ``Host`` is derived from the target URL; drop any stale captured value.
    send_headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}

    client_kwargs: dict[str, Any] = {"timeout": timeout}
    if transport is not None:
        client_kwargs["transport"] = transport
    with httpx.Client(**client_kwargs) as client:
        http_response = client.request(
            request.method,
            request.url,
            headers=send_headers,
            content=request.body or None,
        )

    response = CapturedResponse(
        status=http_response.status_code,
        headers={k: v for k, v in http_response.headers.items()},
        body=http_response.content,
        reason=http_response.reason_phrase or "",
    )
    exchange = CapturedExchange(request=request, response=response)
    return store.record(
        exchange,
        source=SOURCE_MANUAL_REPLAY,
        tags=["replay", f"from:{request_id}"],
    )
