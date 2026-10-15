"""Canonical identities for structured submissions, independent of their prose."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit, urlunsplit


def canonical_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return endpoint
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
        host += f":{port}"
    # Query values/order and path case may affect the request; fragments do not.
    return urlunsplit((parsed.scheme, host, parsed.path or "/", parsed.query, ""))


def structured_finding_id(kind: str, target: str, location: str, method: str | None) -> str:
    return hashlib.sha256(
        json.dumps([kind, target, location, method], ensure_ascii=False).encode()
    ).hexdigest()[:32]
