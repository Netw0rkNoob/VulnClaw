"""Tests for the doctor LLM endpoint probe."""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.config.llm_probe import _classify_status_error, probe_llm_endpoint


class _Err(Exception):
    def __init__(self, status_code=None, body=None, text=""):
        super().__init__(text or (f"HTTP {status_code}" if status_code else "unknown"))
        self.status_code = status_code
        self.body = body


def test_classify_auth_and_not_found():
    category, _ = _classify_status_error(_Err(status_code=401))
    assert category == "auth"
    category, detail = _classify_status_error(
        _Err(status_code=404, body={"error": {"message": "model gpt-5.6-luna not found"}})
    )
    assert category == "not_found"
    assert "gpt-5.6-luna" in detail


def test_classify_connectivity_errors():
    category, _ = _classify_status_error(_Err(text="HTTPSConnectionPool: connection reset by peer"))
    assert category == "unreachable"
    category, _ = _classify_status_error(_Err(text="CONNECT tunnel failed, response 502"))
    assert category == "unreachable"


def _llm_config():
    return SimpleNamespace(
        provider="openai",
        model="test-model",
        base_url="http://endpoint.test/v1",
        max_tokens=None,
        temperature=None,
        reasoning_effort=None,
        auth_mode="static",
        api_key="test-key",
    )


class _ProbeMonkey:
    """Patch surface so probe_llm_endpoint runs without network or real OpenAI."""

    def __init__(self, monkeypatch, *, response=None, error=None, token_error=None):
        self.calls = {}
        monkeypatch.setattr(
            "vulnclaw.config.llm_probe.resolve_llm_token",
            self._resolve_token(token_error),
        )
        monkeypatch.setattr(
            "vulnclaw.config.llm_probe.make_openai_client",
            self._make_client(response, error),
        )

    def _resolve_token(self, token_error):
        def _resolve(llm):
            if token_error:
                raise token_error
            return "test-key"

        return _resolve

    def _make_client(self, response, error):
        def _factory(api_key, base_url, timeout=None):
            probe = self

            class _Completions:
                def create(self, **kwargs):
                    probe.calls["kwargs"] = kwargs
                    if error:
                        raise error
                    return response

            class _Client:
                chat = SimpleNamespace(completions=_Completions())

            return _Client()

        return _factory


def test_probe_ok_when_tool_call_emitted(monkeypatch):
    tool_call = SimpleNamespace(id="1", type="function")
    message = SimpleNamespace(content=None, tool_calls=[tool_call])
    response = SimpleNamespace(choices=[SimpleNamespace(message=message)])
    patch = _ProbeMonkey(monkeypatch, response=response)

    result = probe_llm_endpoint(_llm_config())

    assert result.ok is True
    assert result.category == "ok"
    assert result.tool_call_emitted is True
    kwargs = patch.calls["kwargs"]
    assert kwargs["model"] == "test-model"
    assert any(tool["function"]["name"] == "ping" for tool in kwargs["tools"])


def test_probe_omits_temperature_for_fixed_temperature_kimi(monkeypatch):
    tool_call = SimpleNamespace(id="1", type="function")
    message = SimpleNamespace(content=None, tool_calls=[tool_call])
    response = SimpleNamespace(choices=[SimpleNamespace(message=message)])
    patch = _ProbeMonkey(monkeypatch, response=response)
    config = _llm_config()
    config.provider = "moonshot"
    config.model = "kimi-k3"
    config.temperature = 0.1

    result = probe_llm_endpoint(config)

    assert result.ok is True
    assert "temperature" not in patch.calls["kwargs"]


def test_probe_flags_prose_only_endpoint(monkeypatch):
    message = SimpleNamespace(content="I would rather chat than call tools.", tool_calls=[])
    response = SimpleNamespace(choices=[SimpleNamespace(message=message)])
    _ProbeMonkey(monkeypatch, response=response)

    result = probe_llm_endpoint(_llm_config())

    assert result.ok is False
    assert result.category == "no_tool_call"
    assert "rather chat" in result.detail


def test_probe_flags_empty_completion(monkeypatch):
    message = SimpleNamespace(content="", tool_calls=[])
    response = SimpleNamespace(choices=[SimpleNamespace(message=message)])
    _ProbeMonkey(monkeypatch, response=response)

    result = probe_llm_endpoint(_llm_config())

    assert result.category == "no_tool_call"
    assert "(empty completion)" in result.detail


def test_probe_classifies_transport_error(monkeypatch):
    _ProbeMonkey(monkeypatch, error=_Err(text="connection timed out"))

    result = probe_llm_endpoint(_llm_config())

    assert result.ok is False
    assert result.category == "unreachable"


def test_probe_classifies_auth_error(monkeypatch):
    _ProbeMonkey(monkeypatch, error=_Err(status_code=401))

    result = probe_llm_endpoint(_llm_config())

    assert result.ok is False
    assert result.category == "auth"


def test_probe_reports_credential_resolution_failure(monkeypatch):
    _ProbeMonkey(monkeypatch, token_error=RuntimeError("no stored oauth tokens"))

    result = probe_llm_endpoint(_llm_config())

    assert result.ok is False
    assert result.category == "auth"
    assert "credential resolution failed" in result.detail


def test_probe_never_raises_on_malformed_response(monkeypatch):
    response = SimpleNamespace(choices=[])
    _ProbeMonkey(monkeypatch, response=response)

    result = probe_llm_endpoint(_llm_config())

    assert result.ok is False
    assert result.category == "unknown"
