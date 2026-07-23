"""Provider model-discovery behavior and security-boundary tests."""

from __future__ import annotations

import json

import httpx
import pytest

FAKE_KEY = "sk-openrouter-test-secret"
REQUIRED_PARAMETERS = ["tools", "max_tokens", "temperature"]
REAL_HTTPX_CLIENT = httpx.Client


def _model(
    model_id: object,
    *,
    output_modalities: object = None,
    supported_parameters: object = None,
    **extra: object,
) -> dict[str, object]:
    return {
        "id": model_id,
        "architecture": {
            "output_modalities": (
                ["text"] if output_modalities is None else output_modalities
            )
        },
        "supported_parameters": (
            REQUIRED_PARAMETERS
            if supported_parameters is None
            else supported_parameters
        ),
        **extra,
    }


def _install_transport(monkeypatch, handler) -> None:
    import vulnclaw.config.settings as settings

    transport = httpx.MockTransport(handler)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return REAL_HTTPX_CLIENT(*args, **kwargs)

    monkeypatch.setattr(settings.httpx, "Client", client_factory)


def _discover(monkeypatch, payload: object, *, headers: dict[str, str] | None = None):
    from vulnclaw.config.settings import discover_provider_models

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(
            "https://openrouter.ai/api/v1/models/user"
        )
        assert request.headers["authorization"] == f"Bearer {FAKE_KEY}"
        assert "http-referer" not in request.headers
        assert "x-openrouter-title" not in request.headers
        assert "x-title" not in request.headers
        return httpx.Response(
            200,
            content=json.dumps(payload).encode(),
            headers=headers or {"content-type": "application/json"},
        )

    _install_transport(monkeypatch, handler)
    return discover_provider_models(
        "https://openrouter.ai/api/v1/",
        FAKE_KEY,
        provider="openrouter",
    )


def test_openrouter_discovery_filters_orders_deduplicates_and_puts_default_first(
    monkeypatch,
):
    result = _discover(
        monkeypatch,
        {
            "data": [
                _model("z/model"),
                _model("openai/gpt-4o"),
                _model("A/model"),
                _model("z/model"),
                _model("image/only", output_modalities=["image"]),
                _model("missing/tools", supported_parameters=["max_tokens", "temperature"]),
                _model("expired/model", expiration_date="2000-01-01T00:00:00Z"),
                _model("control/\nmodel"),
                _model("x" * 161),
                _model(" private/model:free "),
            ]
        },
    )

    assert result.status.value == "ok"
    assert result.models == [
        "openai/gpt-4o",
        "A/model",
        "private/model:free",
        "z/model",
    ]
    assert FAKE_KEY not in result.detail


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        (None, "malformed_response"),
        ([], "malformed_response"),
        ({}, "malformed_response"),
        ({"data": {}}, "malformed_response"),
        ({"data": [None, {"id": 42}]}, "empty_catalog"),
    ],
)
def test_openrouter_discovery_rejects_malformed_shapes(monkeypatch, payload, status):
    result = _discover(monkeypatch, payload)

    assert result.status.value == status
    assert result.models == []
    assert FAKE_KEY not in result.detail


def test_openrouter_discovery_rejects_wrong_content_type(monkeypatch):
    result = _discover(
        monkeypatch,
        {"data": [_model("openai/gpt-4o")]},
        headers={"content-type": "text/html"},
    )

    assert result.status.value == "malformed_response"
    assert result.models == []


def test_openrouter_discovery_bounds_response_body(monkeypatch):
    from vulnclaw.config.settings import discover_provider_models

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"x" * (2 * 1024 * 1024 + 1),
            headers={"content-type": "application/json"},
        )

    _install_transport(monkeypatch, handler)
    result = discover_provider_models(
        "https://openrouter.ai/api/v1",
        FAKE_KEY,
        provider="openrouter",
    )

    assert result.status.value == "response_too_large"
    assert result.models == []


def test_openrouter_discovery_bounds_source_and_retained_records(monkeypatch):
    from vulnclaw.config.settings import OPENROUTER_MAX_SOURCE_MODELS

    source_result = _discover(
        monkeypatch,
        {
            "data": [
                _model(f"provider/model-{index}")
                for index in range(OPENROUTER_MAX_SOURCE_MODELS + 1)
            ]
        },
    )
    assert source_result.status.value == "response_too_large"

    retained_result = _discover(
        monkeypatch,
        {
            "data": [
                _model(f"provider/model-{index:04d}")
                for index in range(650)
            ]
        },
    )
    assert retained_result.status.value == "ok"
    assert len(retained_result.models) == 500
    assert retained_result.models[0] == "provider/model-0000"
    assert retained_result.models[-1] == "provider/model-0499"


@pytest.mark.parametrize(
    ("status_code", "expected_status"),
    [(401, "authentication_failed"), (500, "upstream_error")],
)
def test_openrouter_discovery_maps_http_failures_without_leaking_body(
    monkeypatch, status_code, expected_status
):
    from vulnclaw.config.settings import discover_provider_models

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            json={"error": f"upstream included {FAKE_KEY}"},
        )

    _install_transport(monkeypatch, handler)
    result = discover_provider_models(
        "https://openrouter.ai/api/v1",
        FAKE_KEY,
        provider="openrouter",
    )

    assert result.status.value == expected_status
    assert result.models == []
    assert FAKE_KEY not in result.detail


def test_openrouter_discovery_refuses_redirects(monkeypatch):
    from vulnclaw.config.settings import discover_provider_models

    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(
            302,
            headers={"location": "https://attacker.example/steal"},
        )

    _install_transport(monkeypatch, handler)
    result = discover_provider_models(
        "https://openrouter.ai/api/v1",
        FAKE_KEY,
        provider="openrouter",
    )

    assert result.status.value == "redirect_blocked"
    assert seen_urls == ["https://openrouter.ai/api/v1/models/user"]


def test_openrouter_discovery_distinguishes_missing_key_and_timeout(monkeypatch):
    from vulnclaw.config.settings import discover_provider_models

    missing = discover_provider_models(
        "https://openrouter.ai/api/v1",
        "",
        provider="openrouter",
    )
    assert missing.status.value == "missing_key"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    _install_transport(monkeypatch, handler)
    timed_out = discover_provider_models(
        "https://openrouter.ai/api/v1",
        FAKE_KEY,
        provider="openrouter",
    )
    assert timed_out.status.value == "timeout"
    assert FAKE_KEY not in timed_out.detail


def test_generic_discovery_wrapper_keeps_sdk_behavior(monkeypatch):
    import vulnclaw.config.settings as settings

    class Models:
        @staticmethod
        def list():
            return [
                type("Model", (), {"id": "z-model"})(),
                type("Model", (), {"id": "a-model"})(),
                type("Model", (), {"id": "a-model"})(),
            ]

    client = type("Client", (), {"models": Models()})()
    monkeypatch.setattr(settings, "make_openai_client", lambda **kwargs: client)

    assert settings.fetch_provider_models(
        "https://generic.example/v1",
        "fake-generic-key",
    ) == ["a-model", "a-model", "z-model"]


def test_provider_discovery_catalogs_have_matching_keys_and_placeholders():
    """OpenRouter/model-discovery i18n keys stay in sync across en/zh."""
    from pathlib import Path
    from string import Formatter

    def _catalog(lang: str) -> dict[str, str]:
        path = Path(__file__).resolve().parents[1] / "vulnclaw" / "i18n" / f"{lang}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def _placeholders(value: str) -> set[str]:
        return {name for _, name, _, _ in Formatter().parse(value) if name}

    prefixes = ("tui.model_discovery_", "tui.openrouter_")
    english = {
        key: value for key, value in _catalog("en").items() if key.startswith(prefixes)
    }
    chinese = {
        key: value for key, value in _catalog("zh").items() if key.startswith(prefixes)
    }

    assert english.keys() == chinese.keys()
    assert {
        key: (_placeholders(english[key]), _placeholders(chinese[key]))
        for key in english
        if _placeholders(english[key]) != _placeholders(chinese[key])
    } == {}
