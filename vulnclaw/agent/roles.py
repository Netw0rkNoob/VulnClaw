"""Role registry and hard tool allow-list helpers for team runs."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class AgentRole:
    """One code-enforced role definition for team and sub-agent runs."""

    name: str
    persona: str
    allowed_tool_globs: tuple[str, ...]
    goal_template: str
    session_kind: str = "team"
    persistent: bool = False
    allowed_child_types: tuple[str, ...] = ()
    task_kinds: tuple[str, ...] = ()


ROLE_REGISTRY: dict[str, AgentRole] = {
    "researcher": AgentRole(
        name="researcher",
        persona=(
            "You are the Researcher specialist. Focus on reconnaissance, OSINT, "
            "asset discovery, safe bodyless GET/HEAD/OPTIONS fetching, and evidence "
            "summaries. Do not send query payloads, credentials, custom active "
            "headers, request bodies, exploitation, or payload execution."
        ),
        allowed_tool_globs=(
            "load_skill_reference",
            "memory_search",
            "evidence_*",
            "submit_finding",
            "vault_*",
            "source_extract",
            "space_search",
            "subdomain_enum",
            "js_recon",
            "dir_enum",
            "unauth_test",
            "osint_recon",
            "cve_lookup",
            "topology_build",
            "fetch",
            "http_probe_batch",
            "search*",
            "*search*",
        ),
        goal_template=(
            "Research objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return verified facts, sources, and follow-up surfaces only."
        ),
        session_kind="leaf",
        task_kinds=("research",),
    ),
    "developer": AgentRole(
        name="developer",
        persona=(
            "You are the Developer specialist. Build payload candidates, parsers, "
            "decoders, and offline analysis helpers. Do not touch the target directly."
        ),
        allowed_tool_globs=(
            "load_skill_reference",
            "memory_search",
            "evidence_*",
            "submit_finding",
            "vault_*",
            "source_extract",
            "runtime_diff_probe",
            "shell_command",
            "python_execute",
            "crypto_decode",
            "cve_lookup",
            "topology_build",
            "findings_*",
            "remediation_advice",
            "attack_map",
        ),
        goal_template=(
            "Development objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return reusable payloads, parsers, and assumptions to verify."
        ),
    ),
    "executor": AgentRole(
        name="executor",
        persona=(
            "You are the Executor specialist. Run authorized checks against the "
            "target, capture concrete tool output, and avoid claims without evidence."
        ),
        allowed_tool_globs=(
            "load_skill_reference",
            "memory_search",
            "evidence_*",
            "submit_finding",
            "vault_*",
            "source_extract",
            "runtime_diff_probe",
            "shell_command",
            "python_execute",
            "crypto_decode",
            "nmap_scan",
            "brute_force_login",
            "space_search",
            "subdomain_enum",
            "js_recon",
            "dir_enum",
            "unauth_test",
            "osint_recon",
            "fetch",
            "http*",
            "request*",
            "curl*",
            "browser*",
            "navigate",
            "click",
            "submit*",
            "*scan*",
            "*recon*",
        ),
        goal_template=(
            "Execution objective: {objective}\n"
            "Done when: {done_when}\n"
            "Use real tool output as evidence and record what was verified."
        ),
        session_kind="leaf",
        task_kinds=("execute",),
    ),
    "adviser": AgentRole(
        name="adviser",
        persona=(
            "You are the Adviser specialist. Plan, critique, and decide whether to "
            "continue, re-plan, or stop. You have no execution tools."
        ),
        allowed_tool_globs=("memory_search", "vault_*"),
        goal_template=(
            "Advisory objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return a decision and rationale without executing tools."
        ),
    ),
}

SUBAGENT_ROLE_REGISTRY: dict[str, AgentRole] = {
    "researcher": ROLE_REGISTRY["researcher"],
    "executor": ROLE_REGISTRY["executor"],
    "group-leader": AgentRole(
        name="group-leader",
        persona=(
            "You are a Group Leader. Plan bounded waves, delegate execution to "
            "fresh leaf agents, compare their returned evidence, and synthesize. "
            "Do not execute target-facing tools yourself."
        ),
        allowed_tool_globs=("agent_run", "evidence_*", "submit_finding"),
        goal_template=(
            "Coordination objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return a bounded evidence-backed synthesis."
        ),
        session_kind="group_leader",
        persistent=True,
        allowed_child_types=("researcher", "executor", "verifier"),
        task_kinds=("coordinate",),
    ),
    "verifier": AgentRole(
        name="verifier",
        persona=(
            "You are an independent Verifier. Recheck the assigned claim using "
            "a different method, input, control, or evidence class. Do not trust "
            "the original executor's conclusion."
        ),
        allowed_tool_globs=(
            "load_skill_reference",
            "evidence_*",
            "submit_finding",
            "vault_*",
            "source_extract",
            "runtime_diff_probe",
            "shell_command",
            "python_execute",
            "fetch",
            "http*",
            "request*",
            "browser*",
            "*scan*",
            "*recon*",
        ),
        goal_template=(
            "Verification objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return independent evidence and a verdict."
        ),
        session_kind="leaf",
        task_kinds=("verify",),
    ),
    "general": AgentRole(
        name="general",
        persona=(
            "You are a general isolated worker. Follow the assignment without "
            "delegating and use no specialist-only assumptions."
        ),
        allowed_tool_globs=("shell_command",),
        goal_template=(
            "Objective: {objective}\n"
            "Done when: {done_when}\n"
            "Return a concise result."
        ),
        session_kind="leaf",
        task_kinds=("general",),
    ),
}

def normalize_role_name(role: str | None) -> str | None:
    """Return a canonical role name, or ``None`` when no role is active."""
    normalized = str(role or "").strip().lower()
    return normalized or None


def get_role(role: str | None) -> AgentRole | None:
    """Look up a role definition by name."""
    normalized = normalize_role_name(role)
    if normalized is None:
        return None
    return ROLE_REGISTRY.get(normalized) or SUBAGENT_ROLE_REGISTRY.get(
        normalized
    )


def subagent_roles() -> tuple[AgentRole, ...]:
    """Return only roles registered for the compact task runtime."""

    return tuple(SUBAGENT_ROLE_REGISTRY.values())


def roles_for_task_kind(task_kind: str) -> tuple[str, ...]:
    normalized = str(task_kind or "").strip().lower()
    return tuple(
        role.name
        for role in subagent_roles()
        if normalized in role.task_kinds
    )


def require_role(role: str) -> AgentRole:
    """Return a role or raise a stable ValueError."""
    definition = get_role(role)
    if definition is None:
        raise ValueError(f"Unknown team role: {role}")
    return definition


def tool_allowed_for_role(tool_name: str, role: str | None) -> bool:
    """Return whether ``tool_name`` is allowed for ``role``.

    A missing role preserves today's behavior: all tools are available.
    """
    normalized = normalize_role_name(role)
    if normalized is None:
        return True
    definition = get_role(normalized)
    if definition is None:
        return False
    return any(fnmatchcase(tool_name, pattern) for pattern in definition.allowed_tool_globs)


def filter_tools_for_role(
    tools: list[dict[str, Any]],
    role: str | None,
) -> list[dict[str, Any]]:
    """Filter OpenAI tool schemas to the active role's allow-list."""
    if normalize_role_name(role) is None:
        return tools

    filtered: list[dict[str, Any]] = []
    for tool in tools:
        function = tool.get("function", {}) if isinstance(tool, dict) else {}
        tool_name = str(function.get("name", "") or "")
        if tool_name and tool_allowed_for_role(tool_name, role):
            filtered.append(tool)
    return filtered


_SAFE_RESEARCH_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}
_SAFE_RESEARCH_HTTP_HEADERS = {
    "accept",
    "accept-language",
    "if-modified-since",
    "if-none-match",
    "range",
    "user-agent",
}


def _research_http_is_active(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name == "fetch":
        requests = [args]
    elif tool_name == "http_probe_batch":
        requests = args.get("requests")
        if not isinstance(requests, list):
            return True
    else:
        return False

    for request in requests:
        if not isinstance(request, dict):
            return True
        method = str(request.get("method") or "GET").strip().upper()
        if method not in _SAFE_RESEARCH_HTTP_METHODS:
            return True
        if any(request.get(key) not in (None, "", {}, []) for key in ("data", "json", "cookies", "params")):
            return True
        headers = request.get("headers") or {}
        if not isinstance(headers, dict) or any(
            str(name).strip().lower() not in _SAFE_RESEARCH_HTTP_HEADERS
            for name in headers
        ):
            return True
        url = str(
            request.get("raw_url")
            or request.get("url")
            or args.get("base_url")
            or ""
        )
        if not url or urlsplit(url).query:
            return True
    return False


def role_tool_violation(
    role: str | None,
    tool_name: str,
    args: dict[str, Any] | None = None,
) -> str | None:
    """Return a structured rejection message for out-of-role calls."""
    normalized = normalize_role_name(role)
    if (
        normalized == "researcher"
        and tool_name in {"fetch", "http_probe_batch"}
        and _research_http_is_active(tool_name, args or {})
    ):
        return (
            "[role_tool_violation] role 'researcher' may use HTTP only for safe "
            "reconnaissance; active requests require role 'executor' with "
            "task_kind 'execute'"
        )
    if normalized is None or tool_allowed_for_role(tool_name, normalized):
        return None
    if get_role(normalized) is None:
        return f"[role_tool_violation] unknown active role {normalized!r}; blocked tool {tool_name!r}"
    return (
        f"[role_tool_violation] role {normalized!r} is not allowed to call tool "
        f"{tool_name!r}; the call was blocked before execution"
    )


def role_prompt_block(role: str | None) -> str:
    """Render the role persona block for an active worker."""
    definition = get_role(role)
    if definition is None:
        return ""
    allowed = ", ".join(definition.allowed_tool_globs) or "none"
    return (
        "## Active Specialist Role\n"
        f"Role: {definition.name}\n"
        f"{definition.persona}\n"
        f"Allowed tool patterns: {allowed}\n"
        "Stay inside this role. If a task needs a different role, report that need."
    )
