"""Tests for the traffic replay system (vulnclaw/traffic/replay.py).

Coverage for request replay with overrides: replay_request() reconstructs a
stored request, applies caller overrides (method/url/headers/body), issues it
via an injectable HTTP transport, and records the result back into the store
with source="manual-replay". Tests verify override application, header handling,
error cases, and transport injection.
"""

from pathlib import Path

import httpx
import pytest

from vulnclaw.traffic.models import (
    SOURCE_MANUAL_REPLAY,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
)
from vulnclaw.traffic.replay import ReplayError, _apply_overrides, replay_request
from vulnclaw.traffic.store import TrafficStore


def _make_exchange(
    method: str = "GET",
    url: str = "https://example.com/api/test",
    headers: dict | None = None,
    body: bytes = b"",
) -> CapturedExchange:
    """Helper to construct a CapturedExchange for testing."""
    request = CapturedRequest(
        method=method,
        url=url,
        headers=headers or {"User-Agent": "test-agent", "Host": "example.com"},
        body=body,
    )
    response = CapturedResponse(
        status=200,
        headers={"Content-Type": "application/json"},
        body=b'{"original": true}',
        reason="OK",
    )
    return CapturedExchange(request=request, response=response)


def _mock_transport(status_code=200, content=b'{"ok": true}', headers=None):
    """Create a proper httpx mock transport."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=status_code,
            headers=headers or {"Content-Type": "application/json"},
            content=content,
        )
    return httpx.MockTransport(handler)


class TestApplyOverrides:
    """Tests for _apply_overrides helper function."""

    def test_no_overrides_returns_original(self):
        """No overrides must return the original request unchanged."""
        original = CapturedRequest(
            method="GET",
            url="https://example.com/",
            headers={"X-Original": "value"},
            body=b"original-body",
        )
        result = _apply_overrides(original, None)
        assert result.method == "GET"
        assert result.url == "https://example.com/"
        assert result.headers == {"X-Original": "value"}
        assert result.body == b"original-body"

    def test_empty_overrides_returns_original(self):
        """Empty overrides dict must return the original request unchanged."""
        original = CapturedRequest(method="POST", url="https://example.com/", body=b"data")
        result = _apply_overrides(original, {})
        assert result.method == "POST"
        assert result.url == "https://example.com/"
        assert result.body == b"data"

    def test_method_override(self):
        """Method override must replace the original method."""
        original = CapturedRequest(method="GET", url="https://example.com/")
        result = _apply_overrides(original, {"method": "POST"})
        assert result.method == "POST"

    def test_url_override(self):
        """URL override must replace the original URL."""
        original = CapturedRequest(method="GET", url="https://example.com/old")
        result = _apply_overrides(original, {"url": "https://example.com/new"})
        assert result.url == "https://example.com/new"

    def test_headers_override_merges(self):
        """Header overrides must merge with original headers."""
        original = CapturedRequest(
            method="GET",
            url="https://example.com/",
            headers={"X-Original": "keep", "X-Remove": "value"},
        )
        result = _apply_overrides(
            original, {"headers": {"X-Original": "updated", "X-New": "added"}}
        )
        assert result.headers["X-Original"] == "updated"
        assert result.headers["X-New"] == "added"
        assert result.headers["X-Remove"] == "value"  # untouched

    def test_headers_override_removes_with_none(self):
        """Setting a header to None must remove it."""
        original = CapturedRequest(
            method="GET",
            url="https://example.com/",
            headers={"X-Keep": "value", "X-Remove": "value"},
        )
        result = _apply_overrides(original, {"headers": {"X-Remove": None}})
        assert "X-Remove" not in result.headers
        assert result.headers["X-Keep"] == "value"

    def test_body_override_with_bytes(self):
        """Body override with bytes must replace the original body."""
        original = CapturedRequest(method="POST", url="https://example.com/", body=b"old")
        result = _apply_overrides(original, {"body": b"new"})
        assert result.body == b"new"

    def test_body_override_with_string(self):
        """Body override with string must encode to UTF-8."""
        original = CapturedRequest(method="POST", url="https://example.com/", body=b"old")
        result = _apply_overrides(original, {"body": "new-string"})
        assert result.body == b"new-string"


class TestReplayRequest:
    """Tests for replay_request function."""

    def test_replay_records_new_exchange(self, tmp_path: Path):
        """replay_request must record a new exchange with source=manual-replay."""
        store = TrafficStore(tmp_path)
        original = store.record(_make_exchange(), source="proxy")

        transport = _mock_transport(status_code=201, content=b"replayed")

        replayed = replay_request(
            store, original.request_id, transport=transport
        )

        assert replayed.source == SOURCE_MANUAL_REPLAY
        assert replayed.request_id != original.request_id
        assert "replay" in replayed.tags
        assert f"from:{original.request_id}" in replayed.tags

        entries = store.entries()
        assert len(entries) == 2

    def test_replay_with_method_override(self, tmp_path: Path):
        """replay_request must apply method override."""
        store = TrafficStore(tmp_path)
        original = store.record(_make_exchange(method="GET"), source="proxy")

        replayed = replay_request(
            store,
            original.request_id,
            overrides={"method": "POST"},
            transport=_mock_transport(),
        )

        assert replayed.method == "POST"

    def test_replay_with_url_override(self, tmp_path: Path):
        """replay_request must apply URL override."""
        store = TrafficStore(tmp_path)
        original = store.record(_make_exchange(url="https://example.com/old"), source="proxy")

        replayed = replay_request(
            store,
            original.request_id,
            overrides={"url": "https://example.com/new"},
            transport=_mock_transport(),
        )

        assert replayed.url == "https://example.com/new"

    def test_replay_with_body_override(self, tmp_path: Path):
        """replay_request must apply body override."""
        store = TrafficStore(tmp_path)
        original = store.record(_make_exchange(body=b"original"), source="proxy")

        replayed = replay_request(
            store,
            original.request_id,
            overrides={"body": b"modified"},
            transport=_mock_transport(),
        )

        loaded = store.load_request(replayed.request_id)
        assert loaded is not None
        assert loaded.body == b"modified"

    def test_replay_strips_host_header_for_sending(self, tmp_path: Path):
        """replay_request strips the captured Host header; httpx re-derives it from URL."""
        store = TrafficStore(tmp_path)
        original = store.record(
            _make_exchange(headers={"Host": "old.example.com", "X-Keep": "value"}),
            source="proxy",
        )

        seen_headers: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen_headers.update(dict(request.headers))
            return httpx.Response(status_code=200, content=b"ok")

        transport = httpx.MockTransport(handler)
        replay_request(store, original.request_id, transport=transport)

        assert seen_headers.get("host") != "old.example.com"
        assert seen_headers.get("x-keep") == "value"

    def test_replay_raises_for_missing_request_id(self, tmp_path: Path):
        """replay_request must raise ReplayError for nonexistent request_id."""
        store = TrafficStore(tmp_path)

        with pytest.raises(ReplayError, match="request_id not found"):
            replay_request(store, "nonexistent-id")

    def test_replay_preserves_original_request(self, tmp_path: Path):
        """replay_request must not modify the original request in the store."""
        store = TrafficStore(tmp_path)
        original = store.record(
            _make_exchange(method="GET", url="https://example.com/original", body=b"original"),
            source="proxy",
        )

        replay_request(
            store,
            original.request_id,
            overrides={"method": "POST", "body": b"modified"},
            transport=_mock_transport(),
        )

        loaded_original = store.load_request(original.request_id)
        assert loaded_original is not None
        assert loaded_original.method == "GET"
        assert loaded_original.url == "https://example.com/original"
        assert loaded_original.body == b"original"

    def test_replay_with_multiple_overrides(self, tmp_path: Path):
        """replay_request must apply multiple overrides simultaneously."""
        store = TrafficStore(tmp_path)
        original = store.record(
            _make_exchange(
                method="GET",
                url="https://example.com/old",
                headers={"X-Old": "value"},
                body=b"old",
            ),
            source="proxy",
        )

        replayed = replay_request(
            store,
            original.request_id,
            overrides={
                "method": "PUT",
                "url": "https://example.com/new",
                "headers": {"X-New": "added"},
                "body": b"new",
            },
            transport=_mock_transport(),
        )

        assert replayed.method == "PUT"
        assert replayed.url == "https://example.com/new"

        loaded = store.load_request(replayed.request_id)
        assert loaded is not None
        assert loaded.method == "PUT"
        assert loaded.url == "https://example.com/new"
        assert loaded.headers.get("X-New") == "added"
        assert loaded.body == b"new"

    def test_replay_response_status_recorded(self, tmp_path: Path):
        """replay_request must record the HTTP response status."""
        store = TrafficStore(tmp_path)
        original = store.record(_make_exchange(), source="proxy")

        replayed = replay_request(
            store,
            original.request_id,
            transport=_mock_transport(status_code=404, content=b"not found"),
        )

        assert replayed.status == 404

    def test_replay_response_body_recorded(self, tmp_path: Path):
        """replay_request must record the HTTP response body."""
        store = TrafficStore(tmp_path)
        original = store.record(_make_exchange(), source="proxy")

        replayed = replay_request(
            store,
            original.request_id,
            transport=_mock_transport(content=b"response-body"),
        )

        response_blob = store.response_blob(replayed.request_id)
        assert response_blob is not None
        assert b"response-body" in response_blob
