"""Real dollar-cost budget for LLM usage, independent of solve_max_steps.

Why this exists: `session.solve_max_steps` (default 240) bounds how many
autonomous tool-calling rounds a solve loop may run, but says nothing about
what those rounds actually cost. 240 rounds of short, cheap completions and
240 rounds of `reasoning_effort: high` on an expensive model are very
different dollar amounts, and nothing before this stopped the latter. This
module tracks an approximate running cost in USD, independent of step count,
and lets a session hard-stop when a configured ceiling is hit.

Deliberately approximate, not a billing reconciliation tool: pricing changes,
providers differ, and this only needs to be close enough to catch a runaway
loop before it burns real money -- not to the cent.
"""

from __future__ import annotations

from typing import Any

# Approximate USD price per 1M tokens: (input, output). Matched by substring
# against the configured model name (case-insensitive), so "gpt-4o-mini-2024"
# still matches "gpt-4o-mini". Unlisted models fall back to
# _DEFAULT_PRICE_PER_MILLION_USD, a deliberately mid/high estimate so the cap
# still means something for a model we don't recognize, rather than silently
# under-counting it as free.
_PRICING_PER_MILLION_USD: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-5.5": (3.00, 15.00),
    "gpt-5": (2.50, 10.00),
    "o4-mini": (1.10, 4.40),
    "o3": (2.00, 8.00),
    "claude-opus": (15.00, 75.00),
    "claude-sonnet": (3.00, 15.00),
    "claude-haiku": (0.80, 4.00),
    "deepseek-reasoner": (0.55, 2.19),
    "deepseek-chat": (0.27, 1.10),
    "deepseek": (0.27, 1.10),
    "glm-4": (0.50, 0.50),
    "qwen": (0.50, 2.00),
    "kimi": (0.60, 2.50),
}
_DEFAULT_PRICE_PER_MILLION_USD = (3.00, 15.00)


class SessionCostExceeded(RuntimeError):
    """Raised when a new LLM call would run (or already has run) past the
    configured session cost ceiling."""

    def __init__(self, spent_usd: float, limit_usd: float):
        self.spent_usd = spent_usd
        self.limit_usd = limit_usd
        super().__init__(
            f"Session cost budget exceeded: ${spent_usd:.4f} spent > ${limit_usd:.2f} limit"
        )


def _lookup_price_per_million(model: str) -> tuple[float, float]:
    model_lower = (model or "").strip().lower()
    for key, price in _PRICING_PER_MILLION_USD.items():
        if key in model_lower:
            return price
    return _DEFAULT_PRICE_PER_MILLION_USD


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    """Approximate USD cost for one LLM call given its token usage."""
    in_price, out_price = _lookup_price_per_million(model)
    return (max(0, input_tokens) * in_price + max(0, output_tokens) * out_price) / 1_000_000.0


def extract_usage_tokens(response: Any) -> tuple[int, int]:
    """Best-effort (input_tokens, output_tokens) extraction from an
    OpenAI-compatible completion response. Returns (0, 0) if usage is
    unavailable (some providers omit it) -- callers should treat that as
    "unknown", not "free"."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return 0, 0
    input_tokens = int(
        getattr(usage, "prompt_tokens", None) or getattr(usage, "input_tokens", None) or 0
    )
    output_tokens = int(
        getattr(usage, "completion_tokens", None) or getattr(usage, "output_tokens", None) or 0
    )
    return input_tokens, output_tokens


def check_and_accumulate_cost(agent: Any, response: Any) -> None:
    """Add this call's estimated cost to the agent's running session total,
    then raise SessionCostExceeded if the *new* total is past the configured
    ceiling. Checked after accumulating (not before) so the ceiling reflects
    real spend up to and including the call that just completed -- the next
    call is what actually gets stopped, matching how solve_max_steps already
    behaves (checked once per round, not a mid-call kill)."""
    safety = getattr(getattr(agent, "config", None), "safety", None)
    limit_usd = float(getattr(safety, "max_session_cost_usd", 0.0) or 0.0)
    if limit_usd <= 0:
        return  # 0 = disabled, matches this codebase's existing "0 = unlimited" convention

    model = str(getattr(getattr(agent, "config", None), "llm", None) and agent.config.llm.model or "")
    input_tokens, output_tokens = extract_usage_tokens(response)
    cost = estimate_cost_usd(model, input_tokens, output_tokens)

    spent_so_far = float(getattr(agent, "session_cost_usd", 0.0) or 0.0) + cost
    try:
        agent.session_cost_usd = spent_so_far
    except AttributeError:
        pass

    if spent_so_far > limit_usd:
        raise SessionCostExceeded(spent_so_far, limit_usd)
