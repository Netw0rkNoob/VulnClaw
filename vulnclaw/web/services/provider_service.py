"""Provider preset + model-listing service for the Web UI backend.

Powers the Settings page dropdowns: the static list of provider presets
(provider / base URL) and a live "list models" call that reuses the saved
API key server-side (the key is never sent to the browser).
"""

from __future__ import annotations

from vulnclaw.config.schema import PROVIDER_PRESETS, LLMProvider
from vulnclaw.config.settings import (
    ProviderModelDiscoveryStatus,
    discover_provider_models,
    load_config,
)
from vulnclaw.web.schemas import (
    ProviderModelsRequest,
    ProviderModelsResponse,
    ProviderPresetView,
    ProvidersView,
)


def get_provider_presets() -> ProvidersView:
    """Return the built-in provider presets for the Settings dropdowns."""
    providers = [
        ProviderPresetView(
            id=provider.value,
            label=str(preset.get("label", provider.value)),
            base_url=str(preset.get("base_url", "")),
            default_model=str(preset.get("default_model", "")),
        )
        for provider, preset in PROVIDER_PRESETS.items()
    ]
    return ProvidersView(providers=providers)


def _resolve_base_url(request: ProviderModelsRequest, config_base_url: str) -> str:
    """Pick the base URL to query: request override > provider preset > config."""
    explicit = (request.base_url or "").strip()
    if explicit:
        return explicit
    if request.provider:
        try:
            preset = PROVIDER_PRESETS.get(LLMProvider(request.provider.lower()))
        except ValueError:
            preset = None
        if preset and preset.get("base_url"):
            return str(preset["base_url"])
    return config_base_url


def _normalize_base_url(value: str) -> str:
    return value.strip().rstrip("/").lower()


def _is_trusted_base_url(base_url: str, config_base_url: str) -> bool:
    """Only send the saved API key to a base_url we already trust.

    The saved key must never be sent to an arbitrary client-supplied host: that
    would let a malicious page (CSRF against this local API) exfiltrate the key
    by pointing base_url at a server it controls. Restrict to the currently
    saved base_url or one of the built-in provider presets.
    """
    normalized = _normalize_base_url(base_url)
    if not normalized:
        return False
    if normalized == _normalize_base_url(config_base_url):
        return True
    trusted_urls = {
        _normalize_base_url(str(preset.get("base_url", "")))
        for preset in PROVIDER_PRESETS.values()
        if preset.get("base_url")
    }
    return normalized in trusted_urls


def fetch_models(request: ProviderModelsRequest) -> ProviderModelsResponse:
    """List models for a provider/base URL using the saved API key.

    The key is read from the saved config (never accepted from the browser),
    and is only ever sent to the saved base_url or a known provider preset —
    never to an arbitrary client-supplied host — to avoid SSRF-style key
    exfiltration via a spoofed base_url.
    Returns an empty list with a hint when no key is configured.
    """
    config = load_config()
    base_url = _resolve_base_url(request, config.llm.base_url)
    provider = str(request.provider or config.llm.provider or "").strip().lower()
    api_key = config.llm.primary_key()

    if not api_key:
        return ProviderModelsResponse(
            base_url=base_url,
            models=[],
            has_api_key=False,
            status=ProviderModelDiscoveryStatus.MISSING_KEY.value,
            detail="No API key configured. Save your API key first, then refresh.",
        )

    if not _is_trusted_base_url(base_url, config.llm.base_url):
        return ProviderModelsResponse(
            base_url=base_url,
            models=[],
            has_api_key=True,
            status=ProviderModelDiscoveryStatus.UNTRUSTED_URL.value,
            detail=(
                "This base URL isn't saved or a known provider preset, so the saved "
                "API key won't be sent to it. Save it first, then refresh."
            ),
        )

    result = discover_provider_models(
        base_url,
        api_key,
        provider=provider,
    )
    return ProviderModelsResponse(
        base_url=base_url,
        models=result.models,
        has_api_key=True,
        status=result.status.value,
        detail=result.detail,
    )
