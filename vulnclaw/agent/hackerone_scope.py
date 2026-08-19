"""Fetch and normalize HackerOne program structured scope via public GraphQL.

HackerOne program pages are SPAs: HTML fetches return an empty app shell. Scope
rows load from ``https://hackerone.com/graphql`` (or authenticated
``api.hackerone.com``). This module is the deterministic path for the
``hackerone`` skill so agents do not reverse-engineer HackerOne's frontend.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

GRAPHQL_URL = "https://hackerone.com/graphql"
DEFAULT_PAGE_SIZE = 100
MAX_PAGES = 20
REQUEST_TIMEOUT_S = 30.0

_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

_GRAPHQL_QUERY = """
query VulnClawStructuredScopes($handle: String!, $first: Int!, $after: String) {
  team(handle: $handle) {
    id
    handle
    name
    structured_scopes(first: $first, after: $after, archived: false) {
      total_count
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        id
        asset_type
        asset_identifier
        instruction
        eligible_for_bounty
        eligible_for_submission
        max_severity
      }
    }
  }
}
""".strip()

# Asset types pentest-flow can drive without a specialized workflow.
_DIRECT_TYPES = frozenset({"URL", "WILDCARD", "DOMAIN"})


@dataclass
class ScopeAsset:
    identifier: str
    asset_type: str
    eligible_for_submission: bool
    eligible_for_bounty: bool
    max_severity: str = ""
    instruction: str = ""

    @property
    def direct_testable(self) -> bool:
        return self.asset_type.upper() in _DIRECT_TYPES and self.eligible_for_submission


@dataclass
class ScopeBundle:
    handle: str
    program_name: str = ""
    program_id: str = ""
    source: str = "hackerone_graphql"
    in_scope: list[ScopeAsset] = field(default_factory=list)
    out_of_scope: list[ScopeAsset] = field(default_factory=list)
    total_count: int = 0
    errors: list[str] = field(default_factory=list)

    def first_direct_asset(self) -> ScopeAsset | None:
        for asset in self.in_scope:
            if asset.direct_testable:
                return asset
        return None


def extract_program_handle(seed: str) -> str:
    """Extract a HackerOne program handle from a URL, path, or bare handle."""
    raw = (seed or "").strip().strip("\"'")
    if not raw:
        raise ValueError("empty HackerOne program seed")

    candidate = raw
    if "://" in raw or raw.startswith("//") or "hackerone.com" in raw.lower():
        parsed = urlparse(raw if "://" in raw else f"https://{raw.lstrip('/')}")
        path = (parsed.path or "").strip("/")
        if not path:
            raise ValueError(f"no program handle in URL path: {seed!r}")
        candidate = path.split("/")[0]

    candidate = candidate.strip().strip("/")
    if candidate.lower() in {"opportunities", "directory", "hacktivity", "users"}:
        raise ValueError(f"not a program handle: {candidate!r}")
    if not _HANDLE_RE.match(candidate):
        raise ValueError(f"invalid HackerOne program handle: {candidate!r}")
    return candidate


def fetch_program_scope(
    seed: str,
    *,
    page_size: int = DEFAULT_PAGE_SIZE,
    timeout_s: float = REQUEST_TIMEOUT_S,
    opener: Any | None = None,
) -> ScopeBundle:
    """Fetch structured scope for a program seed (URL or handle)."""
    handle = extract_program_handle(seed)
    page_size = max(1, min(int(page_size or DEFAULT_PAGE_SIZE), 200))
    nodes: list[dict[str, Any]] = []
    program_name = ""
    program_id = ""
    total_count = 0
    after: str | None = None
    open_url = opener or urllib.request.urlopen

    for _ in range(MAX_PAGES):
        payload = {
            "operationName": "VulnClawStructuredScopes",
            "variables": {
                "handle": handle,
                "first": page_size,
                "after": after,
            },
            "query": _GRAPHQL_QUERY,
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            GRAPHQL_URL,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "VulnClaw/hackerone_scope",
            },
        )
        try:
            with open_url(request, timeout=timeout_s) as response:
                raw = response.read().decode("utf-8", errors="replace")
                status = getattr(response, "status", None) or response.getcode()
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"HackerOne GraphQL HTTP {exc.code}: {err_body[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"HackerOne GraphQL network error: {exc}") from exc

        if status and int(status) >= 400:
            raise RuntimeError(f"HackerOne GraphQL HTTP {status}: {raw[:500]}")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("HackerOne GraphQL returned non-JSON") from exc

        if data.get("errors"):
            messages = [
                str(item.get("message") or item)
                for item in data["errors"]
                if isinstance(item, dict) or item
            ]
            raise RuntimeError(
                "HackerOne GraphQL errors: " + "; ".join(messages[:5])
            )

        team = (data.get("data") or {}).get("team")
        if not team:
            raise RuntimeError(
                f"HackerOne program not found or not publicly visible: {handle!r}"
            )

        program_name = str(team.get("name") or program_name or handle)
        program_id = str(team.get("id") or program_id or "")
        scopes = team.get("structured_scopes") or {}
        total_count = int(scopes.get("total_count") or total_count or 0)
        batch = scopes.get("nodes") or []
        if not isinstance(batch, list):
            raise RuntimeError("unexpected structured_scopes.nodes shape")
        nodes.extend(item for item in batch if isinstance(item, dict))

        page_info = scopes.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")
        if not after:
            break

    return _bundle_from_nodes(
        handle=handle,
        program_name=program_name,
        program_id=program_id,
        total_count=total_count or len(nodes),
        nodes=nodes,
    )


def format_scope_report(bundle: ScopeBundle) -> str:
    """Render a skill-friendly markdown report for tool results."""
    first = bundle.first_direct_asset()
    lines = [
        f"# HackerOne scope: {bundle.program_name or bundle.handle}",
        "",
        f"- handle: `{bundle.handle}`",
        f"- source: {bundle.source}",
        f"- totals: {len(bundle.in_scope)} in-scope, {len(bundle.out_of_scope)} out-of-scope"
        f" (API total_count={bundle.total_count})",
    ]
    if first:
        lines.append(
            f"- first direct URL/WILDCARD asset: `{first.identifier}` "
            f"({first.asset_type})"
        )
    else:
        lines.append(
            "- first direct URL/WILDCARD asset: none "
            "(confirm mobile/source/other types with the user)"
        )
    lines.extend(["", "## In scope"])
    if not bundle.in_scope:
        lines.append("(none)")
    else:
        for asset in bundle.in_scope:
            bounty = "bounty" if asset.eligible_for_bounty else "no-bounty"
            lines.append(
                f"- {asset.identifier} | {asset.asset_type} | submission |"
                f" {bounty}"
                + (f" | max={asset.max_severity}" if asset.max_severity else "")
            )
            if asset.instruction:
                instr = asset.instruction.strip().replace("\n", " ")
                if len(instr) > 240:
                    instr = instr[:237] + "..."
                lines.append(f"  instruction: {instr}")

    lines.extend(["", "## Out of scope (never test)"])
    if not bundle.out_of_scope:
        lines.append("(none listed)")
    else:
        for asset in bundle.out_of_scope:
            lines.append(f"- {asset.identifier} | {asset.asset_type}")

    if first:
        lines.extend(
            [
                "",
                "## Next step",
                (
                    f"Scope defined: {len(bundle.in_scope)} in-scope, "
                    f"{len(bundle.out_of_scope)} out-of-scope. "
                    f"Starting recon on {first.identifier}."
                ),
                "Load `pentest-flow` methodology only as needed; do not recon "
                "hackerone.com itself.",
            ]
        )
    return "\n".join(lines)


def execute_hackerone_scope(args: dict[str, Any]) -> str:
    """Builtin tool entrypoint."""
    seed = str(args.get("program") or args.get("url") or args.get("handle") or "").strip()
    if not seed:
        return (
            "[!] hackerone_scope requires program= "
            "(handle, program URL, or .../policy_scopes link)"
        )
    try:
        page_size = int(args.get("page_size") or DEFAULT_PAGE_SIZE)
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    try:
        bundle = fetch_program_scope(seed, page_size=page_size)
    except ValueError as exc:
        return f"[!] invalid HackerOne program seed: {exc}"
    except RuntimeError as exc:
        return (
            f"[!] failed to load HackerOne scope: {exc}\n"
            "[suggestion] Ask the user to paste the Scope tab tables "
            "(in-scope / out-of-scope) and stop before recon."
        )
    except Exception as exc:  # noqa: BLE001 — surface unexpected transport errors
        return f"[!] hackerone_scope error: {exc}"

    # Compact machine-readable appendix for the agent; humans read the report.
    payload = {
        "handle": bundle.handle,
        "program_name": bundle.program_name,
        "in_scope": [asdict(a) for a in bundle.in_scope],
        "out_of_scope": [asdict(a) for a in bundle.out_of_scope],
        "first_direct_asset": (
            asdict(bundle.first_direct_asset())
            if bundle.first_direct_asset()
            else None
        ),
    }
    return (
        f"[tool:hackerone_scope]\n{format_scope_report(bundle)}\n\n"
        f"```json\n{json.dumps(payload, ensure_ascii=False, indent=2)}\n```"
    )


def _bundle_from_nodes(
    *,
    handle: str,
    program_name: str,
    program_id: str,
    total_count: int,
    nodes: list[dict[str, Any]],
) -> ScopeBundle:
    in_scope: list[ScopeAsset] = []
    out_of_scope: list[ScopeAsset] = []
    seen: set[tuple[str, str, bool]] = set()

    for node in nodes:
        identifier = str(
            node.get("asset_identifier")
            or node.get("identifier")
            or ""
        ).strip()
        if not identifier:
            continue
        asset_type = str(
            node.get("asset_type") or node.get("display_name") or "OTHER"
        ).strip()
        submission = _as_bool(node.get("eligible_for_submission"), default=False)
        bounty = _as_bool(node.get("eligible_for_bounty"), default=False)
        key = (identifier, asset_type.upper(), submission)
        if key in seen:
            continue
        seen.add(key)
        asset = ScopeAsset(
            identifier=identifier,
            asset_type=asset_type.upper(),
            eligible_for_submission=submission,
            eligible_for_bounty=bounty,
            max_severity=str(node.get("max_severity") or node.get("cvss_score") or ""),
            instruction=str(node.get("instruction") or "").strip(),
        )
        if submission:
            in_scope.append(asset)
        else:
            out_of_scope.append(asset)

    return ScopeBundle(
        handle=handle,
        program_name=program_name,
        program_id=program_id,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        total_count=total_count,
    )


def _as_bool(value: Any, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return default
