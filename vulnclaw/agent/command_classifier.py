"""Shell-command safety classifier for the auto_review permission mode.

A faithful lightweight port of Codex CLI's exec-policy layer
(``codex-rs/core/src/exec_policy.rs``), minus the OS sandbox:

- compound commands are split into plain segments (quote-aware);
- every segment is matched against a three-way decision:
  * **allow**    — a curated read-only table (with per-tool argument rules),
                   or an operator-configured trusted prefix;
  * **prompt**   — everything else, including interpreters, dangerous
                   patterns and leading environment assignments (degraded to
                   the interactive approval flow);
  * reasons are surfaced to the approval UI.

Honest boundary: without an OS sandbox this classifier *is* the router that
decides what runs unattended. It trusts command names plus explicit argument
rules, so the tables below stay conservative: interpreters and Git are never
built-in auto-approved, ``find`` carries argument rules, and operator
extensions are validated against the banned-name list at load time.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Callable

# Characters that make a command impossible to decompose safely at this
# layer: redirections, substitutions, grouping. Found outside quotes ⇒ the
# whole command goes to interactive approval.
_UNSUPPORTED_METACHARS = set("><$()`")

# Segment separators we DO understand (split like Codex's
# parse_shell_lc_plain_commands).
_SEPARATORS = (";", "|", "&", "\n")


@dataclass(frozen=True)
class Classification:
    decision: str  # "allow" | "prompt"
    reason: str = ""


def _prompt(reason: str) -> Classification:
    return Classification("prompt", reason)


def _allow() -> Classification:
    return Classification("allow", "")


# ── Argument rules for individually risky tools ──────────────────────────


def _find_args_rule(tokens: list[str]) -> str | None:
    """find(1) can execute arbitrary programs or delete files."""
    bad_flags = {
        "-exec", "-execdir", "-ok", "-okdir",
        "-delete", "-fls", "-fprint", "-fprint0", "-fprintf",
    }
    for tok in tokens[1:]:
        if tok.lower() in bad_flags or tok.startswith("-fprint"):
            return f"find flag {tok} can execute or destroy"
    return None


def _grep_args_rule(tokens: list[str]) -> str | None:
    # grep itself is read-only; nothing to forbid today.
    return None


def _diff_args_rule(tokens: list[str]) -> str | None:
    """diff is read-only unless its output-file option is used."""
    for tok in tokens[1:]:
        lowered = tok.lower()
        if lowered == "--output" or lowered.startswith("--output="):
            return f"diff flag {tok} writes to a file"
    return None


SAFE_COMMANDS: dict[str, Callable[[list[str]], str | None] | None] = {
    "ls": None, "pwd": None, "cd": None, "echo": None, "printf": None,
    "cat": None, "head": None, "tail": None, "wc": None,
    "grep": _grep_args_rule, "egrep": None, "fgrep": None,
    "find": _find_args_rule,
    "file": None, "stat": None, "du": None, "df": None,
    "which": None, "type": None,
    "id": None, "whoami": None, "uname": None, "date": None,
    "diff": _diff_args_rule, "cmp": None,
    "cut": None, "tr": None, "tac": None, "rev": None,
    "basename": None, "dirname": None, "readlink": None,
    "md5sum": None, "sha1sum": None, "sha256sum": None, "sha512sum": None,
    "jq": None, "tree": None, "who": None, "w": None,
    "uptime": None, "free": None, "lscpu": None, "ss": None,
}

# Basenames that must never be auto-approved, mirroring Codex's
# BANNED_PREFIX_SUGGESTIONS: shells, interpreters, privilege/file-destroying
# utilities and multipliers. Operator extensions are validated against this
# list and refused at load time.
BANNED_NAMES = frozenset({
    "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
    "python", "python3", "pythonw", "py", "pypy", "pypy3",
    "node", "nodejs", "deno", "bun", "ruby", "perl", "lua",
    "julia", "rscript", "php",
    "rm", "sudo", "doas", "su",
    "env", "xargs", "awk", "gawk", "setsid", "nohup", "stdbuf",
    "nc", "ncat", "socat", "eval", "source", ".",
})

_INTERPRETER_REASON = (
    "interpreters and shells cannot run in auto-review "
    "(use per-request approval or full_access)"
)


def _basename(token: str) -> str:
    name = token.rsplit("/", 1)[-1] if "/" in token else token
    name = name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _scan_unsupported(text: str) -> str | None:
    """Return a reason when unsupported metachars appear outside quotes."""
    quote: str | None = None
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and quote == "'":
            continue  # backslash is literal inside single quotes
        if ch == "\\":
            escaped = True
            continue
        if quote:
            # POSIX shells still expand variables and execute command
            # substitutions inside double quotes. Treat every unescaped '$'
            # or backtick there as unsupported; single quotes remain literal.
            if quote == '"' and ch in {"$", "`"}:
                return f"unsupported shell construct {ch!r} (quoted substitution)"
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch in _UNSUPPORTED_METACHARS:
            return f"unsupported shell construct {ch!r} (redirection/substitution)"
    if quote:
        return "unterminated quote"
    return None


def _split_segments(text: str) -> list[str]:
    """Split on ; | & and newlines outside quotes; drop empty segments."""
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for ch in text:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\" and quote != "'":
            current.append(ch)
            escaped = True
            continue
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            current.append(ch)
            continue
        if ch in _SEPARATORS:
            segments.append("".join(current))
            current = []
            continue
        current.append(ch)
    segments.append("".join(current))
    return [seg.strip() for seg in segments if seg.strip()]


_ENV_ASSIGN_PREFIX_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _starts_with_env_assignment(tokens: list[str]) -> bool:
    """True when the segment opens with FOO=bar assignment prefixes.

    ``sh -c`` applies these to the command's environment *before* lookup:
    a leading ``PATH=`` redirects the binary search and ``LD_PRELOAD`` /
    ``DYLD_*`` / ``GIT_EXEC_PATH`` inject code into whatever runs. Stripping
    the prefix and matching the remainder against the allow table (the
    previous behavior) therefore let ``PATH=/tmp/evil ls`` auto-approve.
    Assignments are always routed to interactive approval; operators who
    need them should wrap the invocation in their own trusted script.
    """
    return bool(tokens) and _ENV_ASSIGN_PREFIX_RE.match(tokens[0]) is not None


def classify_segment(tokens: list[str], trusted: tuple[tuple[str, ...], ...]) -> Classification:
    if _starts_with_env_assignment(tokens):
        return _prompt(
            "leading environment assignment cannot be verified safely "
            "(can hijack PATH lookup or inject LD_PRELOAD/GIT_EXEC_PATH)"
        )
    if not tokens:
        return _allow()
    name = _basename(tokens[0])

    if name in BANNED_NAMES:
        return _prompt(_INTERPRETER_REASON if name in {
            "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
            "cmd", "powershell", "pwsh", "python", "python3", "pythonw",
            "py", "pypy", "pypy3", "node", "nodejs", "deno", "bun",
            "ruby", "perl", "lua", "julia", "rscript", "php",
        } else f"{name!r} is never auto-approved")

    for entry in trusted:
        if len(tokens) >= len(entry) and tokens[0].lower() == entry[0] and all(
            tokens[i] == entry[i] for i in range(1, len(entry))
        ):
            return _allow()

    if name in SAFE_COMMANDS:
        rule = SAFE_COMMANDS[name]
        violation = rule(tokens) if rule is not None else None
        if violation:
            return _prompt(f"{name}: {violation}")
        return _allow()

    return _prompt(f"'{tokens[0]}' is not in the trusted command table")


def parse_trusted_commands(
    entries: list[str],
) -> tuple[tuple[tuple[str, ...], ...], list[str]]:
    """Normalize operator config entries into token-prefix tuples.

    Returns (prefixes, warnings). Entries whose first token is banned are
    refused with a warning instead of being loaded silently.
    """
    prefixes: list[tuple[str, ...]] = []
    warnings: list[str] = []
    for raw in entries or []:
        text = str(raw).strip()
        if not text:
            continue
        try:
            tokens = shlex.split(text)
        except ValueError:
            warnings.append(f"trusted_commands: unparseable entry {raw!r}")
            continue
        if not tokens:
            continue
        if _basename(tokens[0]) in BANNED_NAMES:
            warnings.append(
                f"trusted_commands: {_basename(tokens[0])!r} is on the banned "
                "list and cannot be auto-approved"
            )
            continue
        prefixes.append((tokens[0].lower(), *tokens[1:]))
    return tuple(prefixes), warnings


def classify_shell_command(
    command: str, trusted: tuple[tuple[str, ...], ...] = ()
) -> Classification:
    """Classify one shell_command invocation for the auto_review mode.

    Returns allow only when *every* segment is allowed; anything else yields
    prompt with the most specific reason found.
    """
    unsupported = _scan_unsupported(command)
    if unsupported:
        return _prompt(unsupported)

    reasons: list[str] = []
    for segment in _split_segments(command):
        try:
            tokens = shlex.split(segment)
        except ValueError as exc:
            return _prompt(f"unparseable segment: {exc}")
        verdict = classify_segment(tokens, trusted)
        if verdict.decision != "allow":
            reasons.append(verdict.reason or segment[:80])
    if reasons:
        return _prompt("; ".join(dict.fromkeys(reasons)))
    return _allow()
