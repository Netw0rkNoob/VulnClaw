"""Heuristics for REPL routing of conversational vs. operational user turns."""

from __future__ import annotations

import re

_AFFIRMATIVE = frozenset(
    {
        "y",
        "yes",
        "yeah",
        "yep",
        "yup",
        "ok",
        "okay",
        "sure",
        "go",
        "go ahead",
        "proceed",
        "continue",
        "start",
        "begin",
        "do it",
        "let's go",
        "lets go",
        "ship it",
        "好",
        "好的",
        "行",
        "可以",
        "是",
        "是的",
        "继续",
        "开始",
        "干",
        "搞起",
    }
)

_READINESS_RE = re.compile(
    r"(ready\s+to|are\s+(we|you)\s+ready|shall\s+we|should\s+we|"
    r"can\s+we\s+(begin|start)|want\s+to\s+(begin|start)|good\s+to\s+go|"
    r"all\s+set\??|"
    r"准备好|可以开始|开始吗|开始么|开始了吗|要开始|开不开)",
    re.IGNORECASE,
)

_URL_OR_IP_RE = re.compile(r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE)

_IMPERATIVE_START_RE = re.compile(
    r"^(?:please\s+)?(?:"
    r"go|start|continue|resume|scan|recon(?:naissance)?|test|pentest|"
    r"exploit|enumerate|probe|fetch|check|run|do|"
    r"扫描|测试|渗透|侦察|继续|开始"
    r")\b",
    re.IGNORECASE,
)

# An operational directive names a testing action, even when it is politely
# phrased as a question and carries no URL ("can you test the login for SQLi?").
# Readiness/meta questions are filtered out before this runs, so matching an
# action verb anywhere in the turn is a signal to keep it on the work path.
_OPERATIONAL_ACTION_RE = re.compile(
    r"\b(?:scan|test|pentest|exploit|enumerate|probe|fuzz|attack|inject|"
    r"brute(?:force|-force)?|recon(?:naissance)?)\b|"
    # A named vulnerability class is itself a testing directive, so it keeps
    # the turn operational even when the verb is a soft one like "check".
    r"\b(?:sql\s*injection|sqli|xss|idor|ssrf|rce|csrf|lfi|rfi|xxe|ssti|"
    r"open\s*redirect|path\s*traversal|command\s*injection)\b|"
    r"扫描|测试|渗透|侦察|利用|爆破|枚举|注入",
    re.IGNORECASE,
)


def is_affirmative_continue(user_input: str) -> bool:
    """True when the user is green-lighting the next autonomous step."""
    text = " ".join((user_input or "").strip().lower().split())
    return text in _AFFIRMATIVE


def is_conversational_checkin(user_input: str) -> bool:
    """True when the user is asking a readiness/meta question, not issuing work.

    Example: ``ready to begin bug hunting?`` should get a spoken status first,
    not an immediate ``agent_run`` recon wave.
    """
    text = (user_input or "").strip()
    if not text or is_affirmative_continue(text):
        return False

    if _READINESS_RE.search(text):
        return True

    is_question = "?" in text or text.endswith("？") or text.endswith("吗") or text.endswith("么")
    if not is_question:
        return False

    # Operational questions with a concrete host stay on the work path.
    if _URL_OR_IP_RE.search(text):
        return False

    # Short "scan it?"-style commands are not check-ins.
    if _IMPERATIVE_START_RE.match(text) and len(text) <= 40:
        return False

    # A concrete testing directive stays on the work path even without a host
    # and even when phrased as a question ("can you test X for SQLi?").
    if _OPERATIONAL_ACTION_RE.search(text):
        return False

    # Short open questions → answer first (status, plan, clarification).
    return len(text) <= 120


def continue_task_prompt(last_auto_input: str, current_target: str | None = None) -> str:
    """Rewrite a terse affirmative into a full continue-task goal."""
    prior = (last_auto_input or "").strip()
    target = (current_target or "").strip()
    if prior and not is_affirmative_continue(prior) and not is_conversational_checkin(prior):
        return (
            f"User confirmed: continue the prior autonomous engagement.\n"
            f"Prior task: {prior}"
            + (f"\nTarget: {target}" if target else "")
        )
    if target:
        return (
            f"User confirmed: begin or continue authorized recon and bug hunting "
            f"on in-scope target {target}."
        )
    return "User confirmed: continue the current authorized engagement."
