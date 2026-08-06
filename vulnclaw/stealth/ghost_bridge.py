"""Ghost Protocol Bridge — Routes Human Mimicry traffic through Ghost bypass.

Phase: STEALTH-A — Bridge between HumanMimicryClient and Ghost Protocol.
When active, all requests go through Ghost Protocol's WAF bypass proxy.
The Ghost Protocol handles: mutation, encoding, fragmentation, smuggling.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

_GHOST_DEFAULT = "http://127.0.0.1:4700"


@dataclass
class GhostBypassResult:
    status: int
    body: bytes
    headers: dict[str, str]
    waf_detected: str
    bypass_used: str
    dpi_detected: bool
    error: str | None = None


class GhostBridge:
    """Routes HTTP requests through Ghost Protocol's WAF bypass layer."""

    def __init__(self, ghost_url: str = _GHOST_DEFAULT):
        self.ghost_url = ghost_url.rstrip("/")
        self._enabled = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False

    def probe(self, target_url: str, timeout: int = 15) -> GhostBypassResult:
        """Send probe request through Ghost Protocol bypass."""
        try:
            url = f"{self.ghost_url}/api/probe?url={target_url}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            return GhostBypassResult(
                status=data.get("status", 0),
                body=json.dumps(data).encode(),
                headers=data.get("headers", {}),
                waf_detected=data.get("waf_type", "none"),
                bypass_used=data.get("bypass_used", "direct"),
                dpi_detected=False,
            )
        except Exception as e:
            return GhostBypassResult(
                status=0, body=b"", headers={},
                waf_detected="unknown", bypass_used="none",
                dpi_detected=False, error=str(e)[:200],
            )

    def get_status(self, timeout: int = 5) -> dict:
        try:
            req = urllib.request.Request(
                f"{self.ghost_url}/bypass/status",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except Exception:
            return {"breaker": {"state": "UNKNOWN"}, "waf": {"waf_type": "unknown"}}

    def get_dpi_status(self, timeout: int = 5) -> dict:
        try:
            req = urllib.request.Request(
                f"{self.ghost_url}/dpi/status",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except Exception:
            return {"dpi_detected": False, "dpi_type": "unknown"}

    def rotate_identity(self, timeout: int = 3):
        try:
            req = urllib.request.Request(
                f"{self.ghost_url}/identity/rotate", method="POST"
            )
            urllib.request.urlopen(req, timeout=timeout)
        except Exception:
            pass

    def get_alerts(self, timeout: int = 5) -> list:
        try:
            req = urllib.request.Request(
                f"{self.ghost_url}/deception/alerts",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
                return data.get("alerts", [])
        except Exception:
            return []

    def authorize(self, target: str, timeout: int = 10) -> dict:
        try:
            data = json.dumps({"target": target}).encode()
            req = urllib.request.Request(
                f"{self.ghost_url}/gateway/authorize",
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except Exception as e:
            return {"authorization": "ERROR", "error": str(e)[:200]}
