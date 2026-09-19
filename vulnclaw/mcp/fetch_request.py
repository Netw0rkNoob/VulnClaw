"""Shared fetch argument normalization for execution and report reconstruction."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

_METHOD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")


def _string_map(value: Any, name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"fetch {name} must be an object")
    return {str(key): str(item) for key, item in value.items()}


def prepare_fetch_request_kwargs(args: dict) -> tuple[dict[str, Any], str | None]:
    """Return HTTPX request kwargs and the selected body mode, without sending."""
    url = str(args.get("url", "") or "").strip()
    if not url:
        raise ValueError("fetch requires url")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("fetch only supports absolute http/https URLs")
    method = str(args.get("method", "GET") or "GET").strip().upper()
    if not _METHOD_RE.fullmatch(method):
        raise ValueError(f"invalid HTTP method for fetch: {method!r}")
    kwargs: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": _string_map(args.get("headers"), "headers"),
    }
    if args.get("params") is not None:
        kwargs["params"] = args["params"]
    cookies = _string_map(args.get("cookies"), "cookies")
    if cookies:
        kwargs["cookies"] = cookies
    for mode, keyword in (("json", "json"), ("form", "data"), ("data", "data"), ("body", "content")):
        if args.get(mode) is not None:
            kwargs[keyword] = args[mode]
            return kwargs, mode
    return kwargs, None
