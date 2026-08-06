"""Human Mimicry Timing — Sophisticated human-like request timing models.

Phase: HUMAN-MIMICRY-B — Models human interaction rhythms:
- Think time (exponential distribution, ~1.5s mean)
- Burst mode (rapid requests followed by reading pauses)
- Page reading time (log-normal, ~5-30s)
- Jitter (random micro-delays)
- Click delay (uniform ~0.5-3s between clicks)

These models are based on measured human browsing patterns.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field


@dataclass
class TimingState:
    last_request_at: float = 0.0
    request_count: int = 0
    burst_count: int = 0
    burst_remaining: int = 0
    total_requests: int = 0


class HumanTimingModel:
    """Models realistic human interaction timing."""

    def __init__(
        self,
        enabled: bool = True,
        think_mean: float = 1.5,
        burst_size: int = 3,
        reading_mean: float = 8.0,
        reading_sigma: float = 0.6,
        click_range: tuple[float, float] = (0.5, 3.0),
    ):
        self.enabled = enabled
        self.think_mean = think_mean
        self.burst_size = burst_size
        self.reading_mean = reading_mean
        self.reading_sigma = reading_sigma
        self.click_min, self.click_max = click_range
        self._state = TimingState()

    def reset(self) -> None:
        self._state = TimingState()

    def wait(self, action: str = "request") -> None:
        if self.enabled and self._state.request_count > 0:
            delay = self._delay_for(action)
            if delay > 0:
                self._sleep(delay)
        now = time.time()
        self._state.last_request_at = now
        self._state.request_count += 1
        self._state.total_requests += 1

    def _delay_for(self, action: str) -> float:
        if self._state.request_count == 0:
            return 0.0
        if action == "page_read":
            return self._page_read_delay()
        if action == "click":
            return self._click_delay()
        if action == "think":
            return self._think_delay()
        return self._think_delay()

    def _think_delay(self) -> float:
        return random.expovariate(1.0 / self.think_mean)

    def _page_read_delay(self) -> float:
        return random.lognormvariate(
            math.log(self.reading_mean), self.reading_sigma
        )

    def _click_delay(self) -> float:
        return random.uniform(self.click_min, self.click_max)

    def _sleep(self, seconds: float) -> None:
        elapsed = time.time() - self._state.last_request_at
        remaining = seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def burst_wait(self) -> None:
        if not self.enabled:
            return
        if self._state.burst_remaining <= 0:
            self._state.burst_remaining = random.randint(
                1, self.burst_size
            )
            self._state.burst_count += 1
            self._page_read_delay()
            self._sleep(self._page_read_delay())
        self._state.burst_remaining -= 1
        self.wait("click")

    @property
    def request_count(self) -> int:
        return self._state.request_count

    @property
    def total_requests(self) -> int:
        return self._state.total_requests

    @property
    def in_burst(self) -> bool:
        return self._state.burst_remaining > 0


def human_delay_seconds(
    action: str = "think",
    think_mean: float = 1.5,
    reading_mean: float = 8.0,
) -> float:
    if action == "think":
        return random.expovariate(1.0 / think_mean)
    if action == "click":
        return random.uniform(0.5, 3.0)
    if action == "page_read":
        return random.lognormvariate(math.log(reading_mean), 0.6)
    return 0.0


def jitter(value: float, fraction: float = 0.1) -> float:
    return value * (1.0 + random.uniform(-fraction, fraction))
