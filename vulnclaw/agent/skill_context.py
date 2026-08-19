"""Skill selection helpers for AgentCore.

Keyword-selected skills remain optional reference indexes (body not injected);
``load_skill_reference`` is still model-chosen for supporting docs.

Explicit launches (``/skill`` or ``Use VulnClaw skill X``) inject the primary
skill body so workflow skills such as ``hackerone`` actually execute.

Resolving once per turn is deliberate: the recorded provenance attached to
findings names the same reference bundle that was offered to the model.
"""

from __future__ import annotations

from typing import Any, Optional

from vulnclaw.config.domain_models import phase_canonical_id
from vulnclaw.skills.loader import load_skill_by_name
from vulnclaw.skills.resolver import SkillQuery, SkillResolver, SkillSelection
from vulnclaw.skills.routing import keyword_present, normalize_token

# Free-text vulnerability keywords (bilingual) -> canonical routing token.
_VULN_HINT_KEYWORDS: dict[str, str] = {
    "sql注入": "sqli",
    "sqli": "sqli",
    "xss": "xss",
    "rce": "rce",
    "命令注入": "rce",
    "远程代码执行": "rce",
    "ssrf": "ssrf",
    "ssti": "ssti",
    "xxe": "xxe",
    "csrf": "csrf",
    "反序列化": "deserialization",
    "越权": "idor",
    "idor": "idor",
    "文件上传": "file_upload",
    "路径遍历": "path_traversal",
    "目录穿越": "path_traversal",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "jwt": "jwt",
    "oauth": "oauth",
    "认证绕过": "auth_bypass",
    "prompt注入": "prompt_injection",
    "prompt injection": "prompt_injection",
    "提权": "privilege_escalation",
    "横向": "lateral_movement",
}

# Technology keywords worth passing as routing signals.
_TECH_KEYWORDS = ("php", "java", "python", "nodejs", "node.js", "wordpress", "django", "spring")


def _infer_target_type(target: Optional[str], text: str) -> Optional[str]:
    """Conservatively infer a target type from the target string/request text."""

    blob = f"{target or ''} {text}".lower()
    if target:
        low = target.lower()
        if low.startswith(("http://", "https://")):
            return "web"
        if _looks_like_ip(low):
            return "network"
    if any(keyword in blob for keyword in ("apk", "安卓", "android")):
        return "android"
    if "http://" in blob or "https://" in blob:
        return "web"
    return None


def _looks_like_ip(value: str) -> bool:
    parts = value.split(":")[0].split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _extract_vuln_hints(text: str) -> list[str]:
    low = text.lower()
    hints: list[str] = []
    for keyword, token in _VULN_HINT_KEYWORDS.items():
        if token not in hints and keyword_present(keyword, low):
            hints.append(token)
    return hints


def _extract_technologies(text: str, recon_data: Optional[dict[str, Any]]) -> list[str]:
    low = text.lower()
    techs: list[str] = []
    for keyword in _TECH_KEYWORDS:
        if keyword_present(keyword, low):
            token = normalize_token(keyword)
            if token not in techs:
                techs.append(token)
    if isinstance(recon_data, dict):
        raw = recon_data.get("technologies")
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    token = normalize_token(item)
                    if token and token not in techs:
                        techs.append(token)
    return techs


def _build_query(
    user_input: Optional[str],
    *,
    phase_label: Optional[str] = None,
    target: Optional[str] = None,
    recon_data: Optional[dict[str, Any]] = None,
    task_summary: Optional[str] = None,
) -> SkillQuery:
    text = f"{user_input or ''} {task_summary or ''}"
    canonical_phase = phase_canonical_id(phase_label)
    return SkillQuery.from_input(
        user_input,
        phase=None if canonical_phase == "idle" else canonical_phase,
        target_type=_infer_target_type(target, text),
        vuln_hints=_extract_vuln_hints(text),
        technologies=_extract_technologies(text, recon_data),
        task_summary=task_summary,
    )


def resolve_active_skill_selection(
    user_input: Optional[str] = None,
    **kwargs: Any,
) -> Optional[SkillSelection]:
    """Resolve the optional reference bundle for a turn, or None."""

    task_summary = kwargs.get("task_summary")
    if not (user_input or task_summary):
        return None
    try:
        selection = SkillResolver().resolve(_build_query(user_input, **kwargs))
        return selection if not selection.is_empty() else None
    except Exception:
        return None


def apply_skill_selection(state: Any, user_input: Optional[str] = None) -> Optional[str]:
    """Resolve, record provenance on ``state``, and return skill prompt context.

    Keyword-selected skills stay optional indexes (body not injected). Explicit
    slash / "Use VulnClaw skill" launches inject the primary skill body so
    workflow skills such as ``hackerone`` are actually executable.
    """

    phase_label = getattr(getattr(state, "phase", None), "value", None)
    selection = resolve_active_skill_selection(
        user_input,
        phase_label=phase_label,
        target=getattr(state, "target", None),
        recon_data=getattr(state, "recon_data", None),
    )
    try:
        state.set_active_skill_selection(selection.to_provenance() if selection else None)
    except Exception:
        pass

    if selection and selection.primary:
        return format_selection_context(selection)
    return None


def get_active_skill_context(user_input: Optional[str] = None, **kwargs: Any) -> Optional[str]:
    """Get skill prompt context without recording provenance."""

    if user_input or kwargs.get("task_summary"):
        selection = resolve_active_skill_selection(user_input, **kwargs)
        if selection and selection.primary:
            return format_selection_context(selection)
    return None


def _is_explicit_selection(selection: SkillSelection) -> bool:
    """True when the user explicitly launched this skill (slash or Use-skill)."""
    if "explicit" in (selection.signals or []):
        return True
    reason = (selection.reason or "").lower()
    return reason.startswith("explicit")


# Soft cap so a huge SKILL.md cannot monopolize the system prompt.
_EXPLICIT_SKILL_BODY_MAX_CHARS = 48_000


def format_selection_context(selection: SkillSelection) -> str:
    """Render a resolved skill bundle for the system prompt.

    Explicit launches inject the primary skill body as the active workflow.
    Keyword / fallback selection still injects only an optional reference index
    so the model remains free to ignore suggested methodology.
    """

    primary = load_skill_by_name(selection.primary) if selection.primary else None
    if _is_explicit_selection(selection) and primary:
        return _format_explicit_skill_context(selection, primary)
    return _format_optional_skill_index(selection, primary)


def _format_explicit_skill_context(
    selection: SkillSelection, primary: dict[str, Any]
) -> str:
    body = str(primary.get("content") or "").strip()
    if len(body) > _EXPLICIT_SKILL_BODY_MAX_CHARS:
        body = (
            body[:_EXPLICIT_SKILL_BODY_MAX_CHARS]
            + "\n\n[skill body truncated for prompt budget]"
        )

    parts: list[str] = [
        f"## Active skill (explicit invocation) — `{selection.primary}`",
        (
            "The operator launched this skill deliberately via a slash command or "
            '"Use VulnClaw skill ...". Follow its workflow as the primary plan unless '
            "the user overrides it. Do not reverse-engineer scope hosts (for example "
            "do not run js_recon against hackerone.com)."
        ),
    ]
    if body:
        parts.append(body)
    else:
        desc = primary.get("description", "").strip()
        parts.append(desc or f"(skill {selection.primary} has an empty body)")

    support_lines: list[str] = []
    for name in selection.supporting:
        skill = load_skill_by_name(name)
        if not skill:
            continue
        desc = skill.get("description", "").strip()
        summary = desc.splitlines()[0] if desc else "(no description)"
        support_lines.append(f"- optional supporting reference: {name} — {summary}")
    if support_lines:
        parts.append(
            "Optional supporting skills (not mandatory):\n" + "\n".join(support_lines)
        )

    refs = primary.get("references", []) or []
    if refs:
        ref_list = ", ".join(refs[:10])
        if len(refs) > 10:
            ref_list += f", ... ({len(refs)} total)"
        parts.append(
            "Optional reference files for this skill — load only when needed with "
            f"`load_skill_reference`: {ref_list}"
        )

    if selection.reason:
        parts.append(
            f"<!-- skill routing: {selection.reason}; confidence={selection.confidence:.2f} -->"
        )
    return "\n\n".join(part for part in parts if part)


def _format_optional_skill_index(
    selection: SkillSelection, primary: Optional[dict[str, Any]]
) -> str:
    parts: list[str] = [
        "These skills are optional reference material only. They are not mandatory "
        "workflows, phases, checklists, or tool schedules. Use or ignore them based "
        "on the current evidence and your own reasoning."
    ]

    if primary:
        desc = primary.get("description", "").strip()
        summary = desc.splitlines()[0] if desc else "(no description)"
        parts.append(f"- primary reference: {selection.primary} — {summary}")

    for name in selection.supporting:
        skill = load_skill_by_name(name)
        if not skill:
            continue
        desc = skill.get("description", "").strip()
        summary = desc.splitlines()[0] if desc else "(no description)"
        parts.append(f"- supporting reference: {name} — {summary}")

    refs = primary.get("references", []) if primary else []
    if refs:
        ref_list = ", ".join(refs[:10])
        if len(refs) > 10:
            ref_list += f", ... ({len(refs)} total)"
        parts.append(
            "Available reference files, load only if useful with "
            f"`load_skill_reference`: {ref_list}"
        )

    if selection.reason:
        parts.append(
            f"<!-- reference routing: {selection.reason}; confidence={selection.confidence:.2f} -->"
        )

    return "\n\n".join(part for part in parts if part)
