"""Tests for the traffic evidence store (vulnclaw/traffic/store.py).

Coverage for the append-only traffic storage system: TrafficStore manages
captured HTTP exchanges in a run directory, writing one JSONL line per exchange
and storing raw request/response blobs. Tests verify deterministic request_id
generation, correct blob storage, index record structure, and query methods.
"""

import json
from pathlib import Path

import pytest

from tests.traffic import _make_exchange
from vulnclaw.traffic.models import (
    SOURCE_BROWSER,
    SOURCE_MANUAL_REPLAY,
    SOURCE_PROXY,
    CapturedRequest,
    CapturedResponse,
)
from vulnclaw.traffic.store import TrafficStore, compute_request_id

# ``_make_exchange`` is re-exported from ``tests.traffic`` so the helper is
# defined once; this file deliberately does not redefine it locally.


class TestComputeRequestId:
    """Tests for compute_request_id deterministic hashing."""

    def test_same_input_produces_same_id(self):
        """Identical seq + request must yield identical request_id."""
        request = CapturedRequest(method="GET", url="https://example.com/", body=b"")
        id1 = compute_request_id(0, request)
        id2 = compute_request_id(0, request)
        assert id1 == id2
        assert len(id1) == 16  # truncated hex digest

    def test_different_seq_produces_different_id(self):
        """Different sequence numbers must produce different request_ids."""
        request = CapturedRequest(method="GET", url="https://example.com/", body=b"")
        id1 = compute_request_id(0, request)
        id2 = compute_request_id(1, request)
        assert id1 != id2

    def test_different_body_produces_different_id(self):
        """Different request bodies must produce different request_ids."""
        req1 = CapturedRequest(method="POST", url="https://example.com/", body=b"body1")
        req2 = CapturedRequest(method="POST", url="https://example.com/", body=b"body2")
        id1 = compute_request_id(0, req1)
        id2 = compute_request_id(0, req2)
        assert id1 != id2


class TestTrafficStore:
    """Tests for TrafficStore append-only storage."""

    def test_record_creates_index_and_blobs(self, tmp_path: Path):
        """record() must create the index file and request/response blobs."""
        store = TrafficStore(tmp_path)
        exchange = _make_exchange()

        record = store.record(exchange, source=SOURCE_PROXY)

        # Index file created
        assert store.index_path.exists()
        lines = store.index_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1

        # Index record structure
        index_entry = json.loads(lines[0])
        assert index_entry["request_id"] == record.request_id
        assert index_entry["seq"] == 0
        assert index_entry["method"] == "GET"
        assert index_entry["url"] == "https://example.com/api/test"
        assert index_entry["host"] == "example.com"
        assert index_entry["path"] == "/api/test"
        assert index_entry["status"] == 200
        assert index_entry["source"] == SOURCE_PROXY

        # Blobs created
        blob_dir = tmp_path / record.request_id
        assert blob_dir.is_dir()
        assert (blob_dir / "request").exists()
        assert (blob_dir / "response").exists()

    def test_record_appends_multiple_exchanges(self, tmp_path: Path):
        """Multiple record() calls must append to the index."""
        store = TrafficStore(tmp_path)

        store.record(_make_exchange(url="https://example.com/first"), source=SOURCE_PROXY)
        store.record(_make_exchange(url="https://example.com/second"), source=SOURCE_BROWSER)
        store.record(_make_exchange(url="https://example.com/third"), source=SOURCE_MANUAL_REPLAY)

        entries = store.entries()
        assert len(entries) == 3
        assert entries[0]["url"] == "https://example.com/first"
        assert entries[1]["url"] == "https://example.com/second"
        assert entries[2]["url"] == "https://example.com/third"

    def test_record_rejects_invalid_source(self, tmp_path: Path):
        """record() must reject unrecognized source values."""
        store = TrafficStore(tmp_path)
        exchange = _make_exchange()

        with pytest.raises(ValueError, match="unknown traffic source"):
            store.record(exchange, source="invalid-source")

    def test_entries_returns_empty_for_missing_index(self, tmp_path: Path):
        """entries() must return [] when index file doesn't exist."""
        store = TrafficStore(tmp_path)
        assert store.entries() == []

    def test_entries_skips_malformed_lines(self, tmp_path: Path):
        """entries() must skip lines that aren't valid JSON."""
        store = TrafficStore(tmp_path)
        store.index_path.parent.mkdir(parents=True, exist_ok=True)

        # Write one valid, one invalid, one valid
        valid1 = json.dumps({"request_id": "abc123", "seq": 0, "url": "https://example.com/1"})
        valid2 = json.dumps({"request_id": "def456", "seq": 1, "url": "https://example.com/2"})
        store.index_path.write_text(f"{valid1}\nnot-json\n{valid2}\n", encoding="utf-8")

        entries = store.entries()
        assert len(entries) == 2
        assert entries[0]["request_id"] == "abc123"
        assert entries[1]["request_id"] == "def456"

    def test_find_returns_matching_entry(self, tmp_path: Path):
        """find() must return the entry with the given request_id."""
        store = TrafficStore(tmp_path)
        rec1 = store.record(_make_exchange(url="https://example.com/first"), source=SOURCE_PROXY)
        rec2 = store.record(_make_exchange(url="https://example.com/second"), source=SOURCE_PROXY)

        found = store.find(rec2.request_id)
        assert found is not None
        assert found["request_id"] == rec2.request_id
        assert found["url"] == "https://example.com/second"

    def test_find_returns_none_for_missing_id(self, tmp_path: Path):
        """find() must return None when request_id doesn't exist."""
        store = TrafficStore(tmp_path)
        store.record(_make_exchange(), source=SOURCE_PROXY)

        assert store.find("nonexistent-id") is None

    def test_view_returns_full_exchange(self, tmp_path: Path):
        """view() must return index record plus decoded request/response text."""
        store = TrafficStore(tmp_path)
        exchange = _make_exchange(
            method="POST",
            url="https://example.com/api",
            headers={"Content-Type": "application/json"},
            body=b'{"key": "value"}',
            status=201,
            response_body=b'{"created": true}',
        )
        record = store.record(exchange, source=SOURCE_PROXY, tags=["test-tag"])

        view = store.view(record.request_id)
        assert view is not None
        assert view["request_id"] == record.request_id
        assert view["method"] == "POST"
        assert view["status"] == 201
        assert view["tags"] == ["test-tag"]

        # Decoded text contains expected content
        assert "POST /api" in view["request_text"]
        assert "Content-Type: application/json" in view["request_text"]
        assert '{"key": "value"}' in view["request_text"]
        assert "201" in view["response_text"]
        assert '{"created": true}' in view["response_text"]

    def test_view_returns_none_for_missing_id(self, tmp_path: Path):
        """view() must return None when request_id doesn't exist."""
        store = TrafficStore(tmp_path)
        assert store.view("nonexistent-id") is None

    def test_load_request_reconstructs_original(self, tmp_path: Path):
        """load_request() must reconstruct the original CapturedRequest."""
        store = TrafficStore(tmp_path)
        original = CapturedRequest(
            method="PUT",
            url="https://example.com/resource",
            headers={"Authorization": "Bearer token123"},
            body=b"update-data",
        )
        exchange = CapturedExchange(request=original, response=CapturedResponse(status=200))
        record = store.record(exchange, source=SOURCE_PROXY)

        loaded = store.load_request(record.request_id)
        assert loaded is not None
        assert loaded.method == "PUT"
        assert loaded.url == "https://example.com/resource"
        assert loaded.headers.get("Authorization") == "Bearer token123"
        assert loaded.body == b"update-data"

    def test_load_request_returns_none_for_missing_id(self, tmp_path: Path):
        """load_request() must return None when request_id doesn't exist."""
        store = TrafficStore(tmp_path)
        assert store.load_request("nonexistent-id") is None

    def test_sitemap_aggregates_hosts_and_paths(self, tmp_path: Path):
        """sitemap() must aggregate captured hosts → paths with methods and counts."""
        store = TrafficStore(tmp_path)

        store.record(_make_exchange(method="GET", url="https://example.com/api/v1"), source=SOURCE_PROXY)
        store.record(_make_exchange(method="POST", url="https://example.com/api/v1"), source=SOURCE_PROXY)
        store.record(_make_exchange(method="GET", url="https://example.com/api/v2"), source=SOURCE_PROXY)
        store.record(_make_exchange(method="GET", url="https://other.com/page"), source=SOURCE_BROWSER)

        sitemap = store.sitemap()

        assert "example.com" in sitemap
        assert "other.com" in sitemap

        # example.com has two paths
        example_paths = {entry["path"]: entry for entry in sitemap["example.com"]}
        assert "/api/v1" in example_paths
        assert "/api/v2" in example_paths

        # /api/v1 was hit twice with GET and POST
        v1_entry = example_paths["/api/v1"]
        assert v1_entry["count"] == 2
        assert sorted(v1_entry["methods"]) == ["GET", "POST"]

        # /api/v2 was hit once with GET
        v2_entry = example_paths["/api/v2"]
        assert v2_entry["count"] == 1
        assert v2_entry["methods"] == ["GET"]

    def test_record_with_tags(self, tmp_path: Path):
        """record() must store tags in the index entry."""
        store = TrafficStore(tmp_path)
        exchange = _make_exchange()

        record = store.record(exchange, source=SOURCE_PROXY, tags=["tag1", "tag2"])

        entry = store.find(record.request_id)
        assert entry is not None
        assert entry["tags"] == ["tag1", "tag2"]

    def test_record_without_response(self, tmp_path: Path):
        """record() must handle exchanges without a response."""
        store = TrafficStore(tmp_path)
        request = CapturedRequest(method="GET", url="https://example.com/")
        exchange = CapturedExchange(request=request, response=None)

        record = store.record(exchange, source=SOURCE_PROXY)

        entry = store.find(record.request_id)
        assert entry is not None
        assert entry["status"] == 0
        assert entry["content_length"] == 0

        # Response blob should not exist
        blob_dir = tmp_path / record.request_id
        assert not (blob_dir / "response").exists()

    def test_request_id_deterministic_across_resumes(self, tmp_path: Path):
        """Request IDs must be deterministic so resumes don't create duplicates."""
        store1 = TrafficStore(tmp_path)
        rec1 = store1.record(_make_exchange(url="https://example.com/test"), source=SOURCE_PROXY)

        # Simulate a resume: create a new store instance pointing to the same directory
        store2 = TrafficStore(tmp_path)
        rec2 = store2.record(_make_exchange(url="https://example.com/other"), source=SOURCE_PROXY)

        # Different URLs should produce different IDs
        assert rec1.request_id != rec2.request_id

        # But if we replay the exact same request at the same seq, ID should match
        store3 = TrafficStore(tmp_path / "fresh")
        rec3 = store3.record(_make_exchange(url="https://example.com/test"), source=SOURCE_PROXY)
        assert rec1.request_id == rec3.request_id  # same seq=0, same request
