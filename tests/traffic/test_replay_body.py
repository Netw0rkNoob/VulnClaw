"""Body overrides must leave replayed HTTP requests correctly framed."""

import httpx
import pytest

from vulnclaw.traffic.models import CapturedExchange, CapturedRequest, CapturedResponse
from vulnclaw.traffic.replay import replay_request
from vulnclaw.traffic.store import TrafficStore


@pytest.mark.parametrize("length_header", ["Content-Length", "content-length", "CONTENT-LENGTH"])
@pytest.mark.parametrize("body", ["x", "a much longer body", "", "中文", b"\x00\xff"])
def test_replay_body_override_updates_content_length(tmp_path, length_header, body):
    store = TrafficStore(tmp_path / "traffic")
    original = store.record(
        CapturedExchange(
            request=CapturedRequest(
                method="POST",
                url="http://app.test/submit",
                headers={length_header: "3", "Content-Type": "application/octet-stream"},
                body=b"old",
            ),
            response=CapturedResponse(status=200),
        ),
        source="proxy",
    )
    expected = body if isinstance(body, bytes) else body.encode("utf-8")

    def handler(request):
        assert request.content == expected
        assert request.headers["content-length"] == str(len(expected))
        assert request.headers["content-type"] == "application/octet-stream"
        return httpx.Response(200, text="ok")

    replayed = replay_request(
        store,
        original.request_id,
        {"body": body},
        transport=httpx.MockTransport(handler),
    )
    saved = store.load_request(replayed.request_id)
    assert saved.body == expected
    assert httpx.Headers(saved.headers)["content-length"] == str(len(expected))
    # Replaying must not mutate the original evidence.
    assert store.load_request(original.request_id).body == b"old"


def test_replay_without_body_override_preserves_request(tmp_path):
    store = TrafficStore(tmp_path / "traffic")
    original = store.record(
        CapturedExchange(
            request=CapturedRequest(
                method="POST", url="http://app.test/submit",
                headers={"Content-Length": "3"}, body=b"old",
            ),
        ),
        source="proxy",
    )

    def handler(request):
        assert request.content == b"old"
        assert request.headers["content-length"] == "3"
        return httpx.Response(200)

    replay_request(store, original.request_id, transport=httpx.MockTransport(handler))
