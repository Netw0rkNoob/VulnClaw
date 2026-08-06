"""Redact obvious secrets from persisted session/target-state text.

Why this exists: SessionState.save() (agent/context.py) and target_state/
persist the full session -- including raw tool call arguments and results --
to plaintext JSON on disk with zero redaction. A session that exercises an
authenticated target (a successful brute_force_login, a fetch/stealth_fetch
call carrying a real Authorization header, a captured Set-Cookie) writes that
literal credential to `~/.vulnclaw/sessions/*.json`. Sharing that file for
debugging, or accidentally committing it, leaks a real credential for
whatever target was being tested.

Deliberately a structural, string-level pass applied once to the final
serialized JSON text, not a per-field allowlist: the session model is deeply
nested and varied (tool args, tool results, findings, evidence), and a field
-by-field approach would need updating every time a new tool or finding
shape is added. A regex pass over the fully-serialized text catches a secret
wherever it ended up, at the cost of being pattern-based rather than
semantic -- it will not catch a credential in a shape none of these patterns
anticipate, so this is a floor, not a guarantee.
"""

from __future__ import annotations

import re

_REDACTED = "[REDACTED]"

# Each pattern captures the sensitive value in group 2, with groups 1/3
# preserving the surrounding quotes/key/prefix so the output stays valid
# JSON / readable text. `\\?"` (an optional single backslash before each
# quote) matches both a bare JSON key/value ("Authorization": "...") AND the
# same thing one level deep inside a JSON string -- e.g. a tool result string
# that itself contains a rendered header dict as text
# (`"result": "...{\"Set-Cookie\": \"...\"}..."`), which is exactly the shape
# _format_fetch_response's `f"Headers: {dict(response.headers)}"` produces
# once that whole string becomes a session-JSON value. Only handles one level
# of escaping; a secret nested two JSON layers deep would need its own
# backslash-count, which this deliberately does not chase further -- see the
# module docstring on this being a floor, not a guarantee.
_JSON_KEY_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r'(\\?"(?:authorization|set-cookie|cookie)\\?"\s*:\s*\\?")([^"]*?)(\\?")',
        r'(\\?"(?:password|passwd|pwd|api_key|apikey|secret|access_token|'
        r'refresh_token|client_secret|bearer_token|session_token)\\?"\s*:\s*\\?")([^"]*?)(\\?")',
    )
)

_HEADER_TEXT_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(Authorization:\s*(?:Bearer|Basic|Digest)\s+)(\S+)",
        r"(Set-Cookie:\s*[^=;\s]+=)([^;\s\"']+)",
        r"(Cookie:\s*[^=;\s]+=)([^;\s\"']+)",
    )
)

# Provider-specific credential shapes worth catching even outside a
# recognizable key/header context (e.g. embedded in free-text evidence).
_BARE_SECRET_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),  # GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_)
)


def redact_secrets(text: str) -> str:
    """Best-effort redaction of credentials/tokens from serialized session
    text. Preserves JSON/text structure around the redacted value."""
    if not text:
        return text

    for pattern in _JSON_KEY_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}{_REDACTED}{m.group(3)}", text)
    for pattern in _HEADER_TEXT_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}{_REDACTED}", text)
    for pattern in _BARE_SECRET_PATTERNS:
        text = pattern.sub(_REDACTED, text)

    return text
