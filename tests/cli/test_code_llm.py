"""Tests for the codescan L3 LLM client wiring."""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.cli import code
from vulnclaw.config.schema import VulnClawConfig


def _fake_openai(monkeypatch):
    captured: dict = {}

    class _Completions:
        def create(self, **kwargs):
            captured.update(kwargs)
            message = SimpleNamespace(content="ok")
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    class _Client:
        def __init__(self, **_kwargs):
            self.chat = SimpleNamespace(completions=_Completions())

    monkeypatch.setattr("openai.OpenAI", _Client)
    return captured


def _config(*, provider: str, model: str) -> VulnClawConfig:
    config = VulnClawConfig()
    config.llm.provider = provider
    config.llm.model = model
    config.llm.api_key = "test-key"
    return config


def test_code_l3_omits_temperature_for_kimi_k3(monkeypatch):
    config = _config(provider="moonshot", model="kimi-k3")
    monkeypatch.setattr("vulnclaw.config.settings.load_config", lambda: config)
    captured = _fake_openai(monkeypatch)

    llm = code._resolve_llm_client()

    assert llm is not None
    assert llm.complete("prompt") == "ok"
    assert captured["model"] == "kimi-k3"
    assert "temperature" not in captured


def test_code_l3_keeps_temperature_for_compatible_providers(monkeypatch):
    config = _config(provider="deepseek", model="deepseek-chat")
    monkeypatch.setattr("vulnclaw.config.settings.load_config", lambda: config)
    captured = _fake_openai(monkeypatch)

    llm = code._resolve_llm_client()

    assert llm is not None
    assert llm.complete("prompt") == "ok"
    assert captured["temperature"] == 0.2
