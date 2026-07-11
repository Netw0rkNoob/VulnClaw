"""Bounded multi-agent coordination for parallel attack-surface work."""

from __future__ import annotations

import asyncio
import copy
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from vulnclaw.agent.agent_graph import AgentGraph, AgentOutcome
from vulnclaw.agent.context import SessionState, VulnerabilityFinding


@dataclass(frozen=True)
class AttackSurface:
    """A concrete surface a child agent can investigate."""

    target: str
    kind: str = "surface"
    reason: str = ""


@dataclass
class ParallelAgentRunResult:
    """Summary of a parallel multi-agent run."""

    root_results: list[Any] = field(default_factory=list)
    worker_results: list[Any] = field(default_factory=list)
    surfaces: list[AttackSurface] = field(default_factory=list)
    waves_completed: int = 0


AgentFactory = Callable[[], Any]


def extract_attack_surfaces(session: SessionState, *, limit: int = 20) -> list[AttackSurface]:
    """Extract high-value concrete surfaces from the current session state."""
    surfaces: list[AttackSurface] = []

    for service in session.recon_data.get("network_services", []) or []:
        if not isinstance(service, dict):
            continue
        host = str(service.get("host", "") or "").strip()
        port = service.get("port")
        proto = str(service.get("protocol", "tcp") or "tcp").strip()
        service_name = str(service.get("service", "") or "").strip()
        if not host or not port:
            continue
        surfaces.append(
            AttackSurface(
                target=f"{host}:{port}",
                kind="service",
                reason=f"{proto}/{service_name or 'unknown'} discovered during network scan",
            )
        )

    for scan in session.recon_data.get("network_scans", []) or []:
        if not isinstance(scan, dict):
            continue
        for weak_link in scan.get("weak_links", []) or []:
            if not isinstance(weak_link, dict):
                continue
            target = str(weak_link.get("target", "") or "").strip()
            if target:
                surfaces.append(
                    AttackSurface(
                        target=target,
                        kind="weak_link",
                        reason=str(weak_link.get("reason", "") or "weak-link candidate"),
                    )
                )

    for key, kind in (("subdomains", "host"), ("paths", "path")):
        for value in session.recon_data.get(key, []) or []:
            target = str(value).strip()
            if target:
                surfaces.append(AttackSurface(target=target, kind=kind, reason=f"recon {key}"))

    for finding in session.findings:
        location = _extract_location(finding)
        if location:
            surfaces.append(
                AttackSurface(
                    target=location,
                    kind="finding",
                    reason=f"{finding.title} ({finding.verification_status})",
                )
            )

    return _dedupe_surfaces(surfaces)[:limit]


async def run_parallel_pentest(
    root_agent: Any,
    *,
    agent_factory: AgentFactory,
    user_input: str,
    target: str,
    discovery_rounds: int = 1,
    worker_rounds: int = 3,
    max_agents: int = 3,
    max_depth: int = 1,
    surface_limit: int = 20,
    stream_sink: Any = None,
    graph: Optional[AgentGraph] = None,
) -> ParallelAgentRunResult:
    """Run a root discovery pass, then fan out bounded child agents by surface.

    This is the **surface-wave scheduler strategy**: ``extract_attack_surfaces``
    plus the bounded semaphore wave. When ``graph`` is supplied it becomes the
    durable source of truth — the strategy only drives it. Each surface becomes
    an ``AgentNode`` via ``create_agent``; ``merge_session_state`` runs as the
    ``child_finish`` reconciliation hook; the root is finished (fail-loud) only
    once every child is ``done``. Callers that pass no ``graph`` keep the
    original fire-and-forget behavior unchanged.
    """
    discovery_rounds = max(1, discovery_rounds)
    worker_rounds = max(1, worker_rounds)
    max_agents = max(1, max_agents)
    max_depth = max(1, max_depth)

    summary = ParallelAgentRunResult()
    if graph is not None and graph.root_id is None:
        graph.create_root(role="root", task_summary=user_input)

    summary.root_results = await root_agent.auto_pentest(
        user_input,
        target=target,
        max_rounds=discovery_rounds,
        stream_sink=stream_sink,
    )

    seen: set[str] = set()
    for depth in range(1, max_depth + 1):
        surfaces = [
            surface
            for surface in extract_attack_surfaces(root_agent.session_state, limit=surface_limit)
            if surface.target not in seen
        ][:max_agents]
        if not surfaces:
            break

        for surface in surfaces:
            seen.add(surface.target)
        summary.surfaces.extend(surfaces)

        worker_results = await _run_surface_wave(
            root_agent,
            agent_factory=agent_factory,
            surfaces=surfaces,
            worker_rounds=worker_rounds,
            graph=graph,
        )
        summary.worker_results.extend(worker_results)
        summary.waves_completed = depth

    if graph is not None:
        graph.root_finish()

    return summary


async def _run_surface_wave(
    root_agent: Any,
    *,
    agent_factory: AgentFactory,
    surfaces: list[AttackSurface],
    worker_rounds: int,
    graph: Optional[AgentGraph] = None,
) -> list[Any]:
    # When a graph drives the wave its concurrency cap is the real gate, so the
    # semaphore mirrors max_concurrent — the graph is the source of truth, not
    # cosmetic bookkeeping. Without a graph, keep the original per-wave sizing.
    slots = graph.caps.max_concurrent if graph is not None else len(surfaces)
    semaphore = asyncio.Semaphore(max(1, slots))

    async def _run_one(surface: AttackSurface) -> Any:
        async with semaphore:
            node_id: Optional[str] = None
            if graph is not None and graph.root_id is not None:
                created = graph.create_agent(
                    graph.root_id,
                    role="worker",
                    task_summary=f"{surface.kind}:{surface.target}",
                )
                if not created.accepted:
                    # A cap (max_total / max_depth) rejected this surface — the
                    # graph already logged it; don't run an untracked child.
                    return {"surface": surface, "results": None, "rejected": created.reason}
                node_id = created.node.id

            child = agent_factory()
            _seed_child_session(child.session_state, root_agent.session_state, surface)
            prompt = _surface_prompt(surface, root_agent.session_state)

            def _merge() -> None:
                merge_session_state(root_agent.session_state, child.session_state)

            try:
                result = await child.auto_pentest(
                    prompt,
                    target=root_agent.session_state.target,
                    max_rounds=worker_rounds,
                )
            except Exception as exc:  # noqa: BLE001 - a crashed child must fail loud in the graph
                if graph is not None and node_id is not None:
                    graph.child_finish(node_id, outcome=AgentOutcome.FAILED, error=str(exc))
                raise

            if graph is not None and node_id is not None:
                # merge_session_state is the child-finish reconciliation hook.
                graph.child_finish(node_id, hook=_merge)
            else:
                _merge()
            return {"surface": surface, "results": result}

    raw = await asyncio.gather(
        *(_run_one(surface) for surface in surfaces),
        return_exceptions=True,
    )
    results: list[dict] = []
    for idx, r in enumerate(raw):
        if isinstance(r, BaseException):
            results.append({"surface": surfaces[idx], "error": str(r)})
        else:
            results.append(r)
    return results


def merge_session_state(parent: SessionState, child: SessionState) -> None:
    """Merge child findings, recon data, notes, and steps into a parent session."""
    for finding in child.findings:
        parent.add_finding(finding)

    for key, value in child.recon_data.items():
        existing = parent.recon_data.get(key)
        if isinstance(value, list):
            if not isinstance(existing, list):
                parent.recon_data[key] = list(value)
            else:
                parent.recon_data[key] = existing + [item for item in value if item not in existing]
        elif isinstance(value, dict):
            merged = dict(existing) if isinstance(existing, dict) else {}
            merged.update(value)
            parent.recon_data[key] = merged
        elif key not in parent.recon_data or not parent.recon_data[key]:
            parent.recon_data[key] = value

    for note in child.notes:
        if note not in parent.notes:
            parent.notes.append(note)
    # [P18 修改] 只合并 step_records，不再合并 executed_steps
    # executed_steps 现为 @property，从 step_records 动态生成
    for record in child.step_records:
        if record not in parent.step_records:
            parent.step_records.append(record)

    parent._notify_checkpoint("child_agent_finish")


def _seed_child_session(child: SessionState, parent: SessionState, surface: AttackSurface) -> None:
    child.target = parent.target
    child.phase = parent.phase
    child.task_constraints = parent.task_constraints.model_copy(deep=True)
    child.recon_data = copy.deepcopy(parent.recon_data)
    child.resume_summary = (
        f"Parallel worker assigned to {surface.kind} {surface.target}. "
        f"Reason: {surface.reason}. Preserve scope constraints."
    )


def _surface_prompt(surface: AttackSurface, session: SessionState) -> str:
    constraints = session.task_constraints.to_prompt_block()
    constraints_suffix = f"\n\n{constraints}" if constraints else ""
    return (
        f"Parallel worker task for authorized testing of attack surface {surface.target}. "
        f"Surface type: {surface.kind}. Reason: {surface.reason}. "
        "Investigate this surface only. Record concrete evidence, candidate findings, "
        "safe verification results, and new surfaces discovered. "
        "Do not brute force credentials, run destructive payloads, or perform post-exploitation "
        "unless the inherited task constraints explicitly allow exploit actions."
        f"{constraints_suffix}"
    )


def _dedupe_surfaces(surfaces: list[AttackSurface]) -> list[AttackSurface]:
    seen: set[str] = set()
    deduped: list[AttackSurface] = []
    for surface in surfaces:
        key = surface.target.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(surface)
    return deduped


def _extract_location(finding: VulnerabilityFinding) -> str:
    text = f"{finding.evidence or ''}\n{finding.description or ''}"
    url_match = re.search(r"https?://[^\s<>'\")\]]+", text)
    if url_match:
        return url_match.group(0)
    host_port_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b", text)
    if host_port_match:
        return host_port_match.group(0)
    return ""
