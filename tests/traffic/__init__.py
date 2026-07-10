"""Shared test fixtures and factories for the traffic test suite.

Both ``test_store.py`` and ``test_normalize_replay.py`` (which cover the
in-scope integration paths) and the supplementary unit-test files for
``store``/``replay`` (which cover edge cases and override mechanics) import
their ``CapturedExchange`` factory from here so the helper is defined
exactly once.
"""

from __future__ import annotations

from vulnclaw.traffic.models import (
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
)


def make_exchange(
    method: str = "GET",
    url: str = "https://example.com/api/test",
    headers: dict | None = None,
    body: bytes = b"",
    status: int = 200,
    response_body: bytes = b'{"ok": true}',
) -> CapturedExchange:
    """Construct a ``CapturedExchange`` for use in traffic unit tests."""
    request = CapturedRequest(
        method=method,
        url=url,
        headers=headers or {"User-Agent": "test-agent", "Host": "example.com"},
        body=body,
    )
    response = CapturedResponse(
        status=status,
        headers={"Content-Type": "application/json"},
        body=response_body,
        reason="OK",
    )
    return CapturedExchange(request=request, response=response)


# Backwards-compatible alias — older call sites use the ``_make_exchange``
# naming convention.
_make_exchange = make_exchange
