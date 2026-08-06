"""Stealth Manager — Coordinates all stealth layers with bypass capability.

Phase: STEALTH-A — Multi-layer stealth coordinator.

Layers (bottom to top):
  L0: Circuit Breaker    — auto-pause on detection, avoid burning identity
  L1: DPI Monitor        — detect deep packet inspection, adjust strategy
  L2: Traffic Shaper     — randomize timing, add decoy, hide patterns
  L3: Ghost Bypass       — WAF bypass techniques (mutation, encoding, fragmentation)
  L4: Identity Rotation  — rotate UA, headers, TLS fingerprint per session
  L5: Proxy Routing      — SOCKS5/HTTP proxy for IP hiding
  L6: Application Mimicry — curl_cffi TLS impersonation + Client Hints

Balance principle:
  - When WAF detected → enable bypass layers (L3)
  - When DPI detected → enable traffic shaping (L2)
  - When circuit breaker open → PAUSE all, wait, rotate identity (L4+L5)
  - Always maintain application mimicry (L6) — baseline stealth
"""

from __future__ import annotations

import json
import time
import random
import urllib.request
from dataclasses import dataclass, field
from enum import Enum


class StealthMode(str, Enum):
    MAXIMUM = "maximum"       # All layers active — slowest, safest
    BALANCED = "balanced"     # Most layers — good balance
    BYPASS_FOCUSED = "bypass"  # Prioritize WAF bypass over IP hiding
    MINIMAL = "minimal"       # Just app mimicry — fastest, least stealth


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"           # Basic WAF detected
    MEDIUM = "medium"     # Cloudflare/advanced WAF
    HIGH = "high"         # DPI + WAF + challenge
    CRITICAL = "critical" # JS challenge + rate limit + ban risk


@dataclass
class StealthState:
    mode: StealthMode = StealthMode.BALANCED
    threat_level: ThreatLevel = ThreatLevel.LOW
    circuit_open: bool = False
    dpi_detected: bool = False
    waf_type: str = "none"
    identity_rotations: int = 0
    proxy_active: bool = False
    traffic_shaping_active: bool = False
    bypass_active: bool = False
    requests_since_rotation: int = 0
    consecutive_failures: int = 0
    last_alert_at: float = 0.0
    ghost_status: dict = field(default_factory=dict)


class StealthManager:
    """Orchestrates all stealth layers. Call before every request."""

    def __init__(
        self,
        mode: StealthMode = StealthMode.BALANCED,
        ghost_url: str = "http://127.0.0.1:4700",
        rotate_every: int = 20,
        max_failures: int = 5,
    ):
        self.mode = mode
        self.ghost_url = ghost_url
        self.rotate_every = rotate_every
        self.max_failures = max_failures
        self._state = StealthState(mode=mode)
        self._rotation_callbacks: list = []

    def on_rotation(self, callback):
        self._rotation_callbacks.append(callback)

    def pre_request(self) -> dict[str, bool]:
        """Called before each request. Returns active layers."""
        self._state.requests_since_rotation += 1
        self._poll_ghost_status()
        self._evaluate_threat()
        self._decide_layers()

        if self._state.circuit_open:
            cooldown = self._get_cooldown()
            time.sleep(cooldown)

        if self._should_rotate():
            self._rotate_identity()

        return {
            "circuit_breaker": self._state.circuit_open,
            "dpi_detected": self._state.dpi_detected,
            "traffic_shaping": self._state.traffic_shaping_active,
            "bypass_active": self._state.bypass_active,
            "proxy_active": self._state.proxy_active,
            "threat_level": self._state.threat_level.value,
        }

    def post_request(self, success: bool, status_code: int = 0):
        if not success or status_code in (403, 429, 503):
            self._state.consecutive_failures += 1
            if self._state.consecutive_failures >= self.max_failures:
                self._state.circuit_open = True
        else:
            self._state.consecutive_failures = 0

    def _poll_ghost_status(self):
        try:
            req = urllib.request.Request(
                f"{self.ghost_url}/bypass/status",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
                self._state.ghost_status = data
                breaker = data.get("breaker", {})
                waf = data.get("waf", {})
                self._state.circuit_open = (
                    breaker.get("state") == "OPEN"
                )
                self._state.waf_type = waf.get("waf_type", "none")
        except Exception:
            pass

        try:
            req = urllib.request.Request(
                f"{self.ghost_url}/dpi/status",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
                self._state.dpi_detected = data.get("dpi_detected", False)
        except Exception:
            pass

    def _evaluate_threat(self):
        waf = self._state.waf_type
        dpi = self._state.dpi_detected
        failures = self._state.consecutive_failures

        if failures >= 3:
            self._state.threat_level = ThreatLevel.CRITICAL
        elif dpi and waf not in ("none", ""):
            self._state.threat_level = ThreatLevel.HIGH
        elif dpi:
            self._state.threat_level = ThreatLevel.MEDIUM
        elif waf not in ("none", ""):
            self._state.threat_level = ThreatLevel.MEDIUM
        else:
            self._state.threat_level = ThreatLevel.LOW

    def _decide_layers(self):
        mode = self.mode
        threat = self._state.threat_level

        self._state.traffic_shaping_active = (
            mode == StealthMode.MAXIMUM
            or (mode == StealthMode.BALANCED and threat in (ThreatLevel.MEDIUM, ThreatLevel.HIGH))
        )
        self._state.bypass_active = (
            mode != StealthMode.MINIMAL
            and self._state.waf_type not in ("none", "")
        )

    def _should_rotate(self) -> bool:
        return self._state.requests_since_rotation >= self.rotate_every

    def _rotate_identity(self):
        self._state.identity_rotations += 1
        self._state.requests_since_rotation = 0
        for cb in self._rotation_callbacks:
            try:
                cb()
            except Exception:
                pass

    def _get_cooldown(self) -> float:
        opens = self._state.consecutive_failures
        return min(2.0 ** opens, 300.0) + random.uniform(0, 5)

    @property
    def state(self) -> dict:
        return {
            "mode": self._state.mode.value,
            "threat_level": self._state.threat_level.value,
            "waf_type": self._state.waf_type,
            "dpi_detected": self._state.dpi_detected,
            "circuit_open": self._state.circuit_open,
            "identity_rotations": self._state.identity_rotations,
            "proxy_active": self._state.proxy_active,
            "traffic_shaping": self._state.traffic_shaping_active,
            "bypass_active": self._state.bypass_active,
            "consecutive_failures": self._state.consecutive_failures,
        }


def balance_stealth_and_bypass(
    waf_detected: bool,
    dpi_detected: bool,
    target_sensitivity: str = "medium",
) -> dict:
    """Decision matrix for balancing stealth vs bypass."""
    if waf_detected and dpi_detected:
        strategy = "FULL_STEALTH_WITH_BYPASS"
        layers = ["mimicry", "proxy", "traffic_shaping", "ghost_bypass"]
    elif waf_detected:
        strategy = "BYPASS_FOCUSED"
        layers = ["mimicry", "ghost_bypass"]
    elif dpi_detected:
        strategy = "STEALTH_FOCUSED"
        layers = ["mimicry", "proxy", "traffic_shaping"]
    else:
        strategy = "FAST_MIMICRY"
        layers = ["mimicry"]

    return {
        "strategy": strategy,
        "active_layers": layers,
        "recommended_delay_mean": 2.0 if dpi_detected else 1.0,
        "rotate_identity_every": 10 if dpi_detected else 30,
    }
