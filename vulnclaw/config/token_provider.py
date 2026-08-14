"""LLM credential resolution.

VulnClaw uses a static API key (``llm.api_key``) for the OpenAI-compatible client
by default. In addition it supports a browser sign-in via OAuth so the agent can
run on a ChatGPT subscription instead of a static key.

Supported ``llm.auth_mode`` values:

* ``static`` — (default) use ``llm.api_key`` verbatim.
* ``oauth``  — use tokens obtained by ``vulnclaw login`` (OAuth 2.0 Authorization
               Code + PKCE). The "Sign in with ChatGPT" flow stores a refreshable
               access token; at call time it is used and silently refreshed via
               the refresh token when it expires (no browser, no static key).

The resolved string is handed to the OpenAI client as ``api_key`` — the SDK sends
it as ``Authorization: Bearer <token>`` either way, so a static key and an OAuth
access token are wire-compatible.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

# Skew subtracted from a token's lifetime so we refresh slightly early.
_EXPIRY_SKEW_SECONDS = 60.0


class TokenResolutionError(RuntimeError):
    """Raised when a credential cannot be obtained."""


class OAuthError(TokenResolutionError):
    """Raised when the OAuth sign-in / refresh flow fails."""


def _get(llm: Any, name: str, default: Any = "") -> Any:
    return getattr(llm, name, default)


# ─────────────────────────────────────────────────────────────────────
# OAuth token store
# ─────────────────────────────────────────────────────────────────────

_OAUTH_LOCK = threading.Lock()
_CALLBACK_TIMEOUT_SECONDS = 300


def _oauth_store_path() -> Path:
    """Where the OAuth token bundle is persisted (per VulnClaw config dir)."""
    config_dir = Path(os.environ.get("VULNCLAW_CONFIG_DIR", str(Path.home() / ".vulnclaw")))
    return config_dir / "oauth_tokens.json"


def load_oauth_tokens() -> dict[str, Any]:
    path = _oauth_store_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_oauth_tokens(bundle: dict[str, Any]) -> None:
    path = _oauth_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    # Best-effort tighten permissions on POSIX (no-op on Windows).
    with suppress(OSError):
        os.chmod(path, 0o600)


def logout_oauth() -> bool:
    """Delete the stored OAuth token bundle. Returns True if a file was removed."""
    try:
        _oauth_store_path().unlink()
        return True
    except OSError:
        return False


# ─────────────────────────────────────────────────────────────────────
# OAuth 2.0 Authorization Code + PKCE primitives
# ─────────────────────────────────────────────────────────────────────


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class _CallbackHandler(BaseHTTPRequestHandler):
    expected_path = "/callback"
    result: dict[str, str] = {}
    done = threading.Event()

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != type(self).expected_path:
            self.send_response(404)
            self.end_headers()
            return
        params = urllib.parse.parse_qs(parsed.query)
        type(self).result = {k: v[0] for k, v in params.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        ok = "code" in type(self).result and "error" not in type(self).result
        msg = (
            "VulnClaw 登录成功，可以关闭此页面。 / Sign-in complete, you may close this tab."
            if ok
            else f"登录失败 / Sign-in failed: {type(self).result.get('error', 'unknown')}"
        )
        self.wfile.write(
            f"<html><body style='font-family:sans-serif'><h3>{msg}</h3></body></html>".encode()
        )
        type(self).done.set()

    def log_message(self, *args):  # silence access logging
        pass


def _oauth_token_request(token_url: str, form: dict[str, str], *, attempts: int = 4) -> dict[str, Any]:
    """POST a token request, retrying transient network/TLS/5xx failures.

    The OAuth endpoints can be reached over flaky TLS (e.g. intermittent
    ``SSL: UNEXPECTED_EOF_WHILE_READING``). 4xx responses (other than 429) are
    permanent and fail fast; network errors and 5xx/429 are retried with backoff.
    The authorization code is single-use but valid for minutes, so a few quick
    retries within one login call are safe.
    """
    data = urllib.parse.urlencode(form).encode("utf-8")
    body: str | None = None
    last_exc: Exception | None = None
    for i in range(attempts):
        req = urllib.request.Request(
            token_url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                body = resp.read().decode("utf-8")
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 429 and 400 <= exc.code < 500:
                detail = exc.read().decode("utf-8", "replace")[:300] if hasattr(exc, "read") else str(exc)
                raise OAuthError(
                    f"OAuth token 请求失败 / request failed, HTTP {exc.code}: {detail}"
                ) from exc
            last_exc = exc  # 5xx / 429 → retry
        except urllib.error.URLError as exc:
            last_exc = exc  # network / TLS → retry
        if i < attempts - 1:
            time.sleep(1.5 * (i + 1))

    if body is None:
        raise OAuthError(
            f"OAuth token 端点无法访问（重试 {attempts} 次后失败 / failed after {attempts} retries）: {last_exc}"
        )
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise OAuthError(
            f"OAuth token 端点返回非 JSON / endpoint returned non-JSON: {body[:200]!r}"
        ) from exc
    if "access_token" not in payload:
        raise OAuthError(
            f"OAuth 响应缺少 / response missing access_token: {body[:200]!r}"
        )
    return payload


def _bundle_from_payload(payload: dict[str, Any], fallback_refresh: str = "") -> dict[str, Any]:
    expires_in = payload.get("expires_in")
    expires_at = (
        time.time() + float(expires_in)
        if isinstance(expires_in, (int, float)) and expires_in > 0
        else 0.0
    )
    return {
        "access_token": str(payload["access_token"]),
        "refresh_token": str(payload.get("refresh_token") or fallback_refresh or ""),
        "token_type": str(payload.get("token_type") or "Bearer"),
        "expires_at": expires_at,
        "scope": str(payload.get("scope") or ""),
    }


# ─────────────────────────────────────────────────────────────────────
# "Sign in with ChatGPT" (reuses the official Codex CLI OAuth client)
# ─────────────────────────────────────────────────────────────────────
# WARNING: This authenticates against OpenAI's first-party Codex OAuth client.
# Using a ChatGPT subscription programmatically through a non-official client may
# violate OpenAI's Terms of Service and can get the account restricted. The user
# opts into this explicitly. The client_id below is public (the Codex CLI is open
# source); no secret is involved.
CHATGPT_ISSUER = "https://auth.openai.com"
CHATGPT_AUTHORIZE_URL = CHATGPT_ISSUER + "/oauth/authorize"
CHATGPT_TOKEN_URL = CHATGPT_ISSUER + "/oauth/token"
CHATGPT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CHATGPT_REDIRECT_PORT = 1455
CHATGPT_REDIRECT_PATH = "/auth/callback"
CHATGPT_SCOPE = "openid profile email offline_access"


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    """Best-effort decode of a JWT payload (no signature verification)."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # pad
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except (IndexError, ValueError, json.JSONDecodeError):
        return {}


def _extract_account_id(claims: dict[str, Any]) -> str:
    """Pull the ChatGPT account id from id_token claims, if present."""
    auth = claims.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        for key in ("chatgpt_account_id", "account_id", "organization_id"):
            if auth.get(key):
                return str(auth[key])
    return ""


def perform_chatgpt_login(*, open_browser: bool = True) -> dict[str, Any]:
    """Run the Codex "Sign in with ChatGPT" OAuth flow and persist tokens.

    Obtains a refreshable ChatGPT access token tied to the user's subscription.
    The token works against the ChatGPT backend (Responses API); VulnClaw's
    built-in proxy bridges chat.completions to it.
    """
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)

    _CallbackHandler.expected_path = CHATGPT_REDIRECT_PATH
    _CallbackHandler.result = {}
    _CallbackHandler.done = threading.Event()
    try:
        server = HTTPServer(("127.0.0.1", CHATGPT_REDIRECT_PORT), _CallbackHandler)
    except OSError as exc:
        raise OAuthError(
            f"无法绑定本地端口 {CHATGPT_REDIRECT_PORT}（Codex 重定向要求固定端口）: {exc}"
        ) from exc
    redirect_uri = f"http://localhost:{CHATGPT_REDIRECT_PORT}{CHATGPT_REDIRECT_PATH}"

    auth_params = {
        "response_type": "code",
        "client_id": CHATGPT_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": CHATGPT_SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    full_authorize_url = CHATGPT_AUTHORIZE_URL + "?" + urllib.parse.urlencode(auth_params)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        opened = False
        if open_browser:
            with suppress(Exception):
                opened = webbrowser.open(full_authorize_url)
        if not opened:
            print(f"[i] 在浏览器中打开以登录 ChatGPT / Open to sign in:\n{full_authorize_url}")
        else:
            print("[i] 已打开 ChatGPT 登录页，等待授权... / Browser opened, waiting for consent...")
        if not _CallbackHandler.done.wait(timeout=_CALLBACK_TIMEOUT_SECONDS):
            raise OAuthError("等待授权回调超时 / Timed out waiting for the OAuth callback")
    finally:
        server.shutdown()
        server.server_close()

    result = _CallbackHandler.result
    if "error" in result:
        raise OAuthError(f"授权被拒绝 / Authorization error: {result.get('error')}")
    if result.get("state") != state:
        raise OAuthError("OAuth state 不匹配（可能的 CSRF），已中止 / state mismatch, aborted")
    code = result.get("code")
    if not code:
        raise OAuthError("回调未返回授权码 / No authorization code in callback")

    payload = _oauth_token_request(
        CHATGPT_TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": CHATGPT_CLIENT_ID,
            "code_verifier": verifier,
        },
    )
    bundle = _bundle_from_payload(payload)
    id_token = str(payload.get("id_token") or "")
    if id_token:
        bundle["account_id"] = _extract_account_id(_decode_jwt_claims(id_token))
    bundle["flow"] = "chatgpt"
    save_oauth_tokens(bundle)
    return bundle


# ─────────────────────────────────────────────────────────────────────
# OAuth token refresh + resolution
# ─────────────────────────────────────────────────────────────────────


def _refresh_oauth(llm: Any, refresh_token: str) -> dict[str, Any]:
    token_url = str(_get(llm, "oauth_token_url") or "").strip()
    client_id = str(_get(llm, "oauth_client_id") or "").strip()
    if not (token_url and client_id):
        raise OAuthError(
            "OAuth 刷新需要 / refresh requires llm.oauth_token_url and llm.oauth_client_id"
        )
    payload = _oauth_token_request(
        token_url,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        },
    )
    bundle = _bundle_from_payload(payload, fallback_refresh=refresh_token)
    # Preserve flow-specific metadata across refreshes (e.g. ChatGPT account id).
    prior = load_oauth_tokens()
    for key in ("account_id", "flow"):
        if prior.get(key) and not bundle.get(key):
            bundle[key] = prior[key]
    save_oauth_tokens(bundle)
    return bundle


def _resolve_oauth_token(llm: Any) -> str:
    """Return a valid OAuth access token, refreshing silently if needed."""
    with _OAUTH_LOCK:
        bundle = load_oauth_tokens()
        access = str(bundle.get("access_token") or "")
        expires_at = float(bundle.get("expires_at") or 0.0)
        refresh = str(bundle.get("refresh_token") or "")

        valid = access and (expires_at == 0.0 or time.time() < expires_at - _EXPIRY_SKEW_SECONDS)
        if valid:
            return access
        if refresh:
            return str(_refresh_oauth(llm, refresh)["access_token"])
        if access:
            # No refresh token and (possibly) expired — return what we have and
            # let the API surface a 401 rather than failing pre-emptively.
            return access
        raise OAuthError(
            "尚未登录或令牌已失效，请运行 `vulnclaw login` / Not signed in — run `vulnclaw login`"
        )


def resolve_llm_token(llm: Any) -> str:
    """Return the effective bearer token / API key for the configured auth mode.

    ``static`` returns the primary key from ``llm.api_keys``/``llm.api_key``
    (possibly empty, preserving legacy behaviour); ``oauth`` returns a valid
    access token, refreshing if needed.
    """
    mode = str(_get(llm, "auth_mode") or "static").strip().lower()
    if mode in ("", "static"):
        primary_key = getattr(llm, "primary_key", None)
        if callable(primary_key):
            return str(primary_key() or "")
        return str(_get(llm, "api_key") or "")
    if mode == "oauth":
        return _resolve_oauth_token(llm)
    raise TokenResolutionError(
        f"未知的 / unknown llm.auth_mode={mode!r} (supported / 支持: static/oauth)"
    )


def has_llm_credentials(llm: Any) -> bool:
    """Whether usable credentials are configured, without minting a token.

    ``static`` requires a non-empty ``api_key``/``api_keys``; ``oauth``
    requires stored tokens. This is a cheap pre-flight check — it does NOT
    validate that the credential actually works.
    """
    mode = str(_get(llm, "auth_mode") or "static").strip().lower()
    if mode in ("", "static"):
        primary_key = getattr(llm, "primary_key", None)
        if callable(primary_key):
            return bool(primary_key())
        return bool(_get(llm, "api_key"))
    if mode == "oauth":
        bundle = load_oauth_tokens()
        return bool(bundle.get("access_token") or bundle.get("refresh_token"))
    return False
