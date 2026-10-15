"""Tests for bounded parallel agent coordination."""

from __future__ import annotations

import pytest

from vulnclaw.agent.agent_graph import AgentGraph, AgentOutcome, AgentStatus, FanOutCaps
from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.agent.parallel_agents import extract_attack_surfaces, run_parallel_pentest


class FakeAgent:
    def __init__(self) -> None:
        self.session_state = SessionState(target="192.168.1.0/24")
        self.calls: list[str] = []

    async def auto_pentest(self, prompt, target=None, max_rounds=0, stream_sink=None):
        self.calls.append(prompt)
        if "authorized fast network scan" in prompt:
            self.session_state.recon_data["network_services"] = [
                {
                    "host": "192.168.1.10",
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                },
                {
                    "host": "192.168.1.20",
                    "port": 445,
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                },
            ]
            return ["root-discovery"]

        self.session_state.add_finding(
            VulnerabilityFinding(
                title=f"Surface reviewed {len(self.calls)}",
                severity="Info",
                vuln_type="surface-review",
                evidence=prompt,
            )
        )
        self.session_state.notes.append("worker note")
        return ["worker-result"]


def test_merging_a_repeated_finding_keeps_both_sides_evidence():
    from vulnclaw.agent.parallel_agents import merge_session_state
    from vulnclaw.findings.types import EvidenceSnapshotRef

    def snapshot(evidence_id, sha256):
        return EvidenceSnapshotRef(
            evidence_id=evidence_id, source_id=evidence_id, target="https://lab.test",
            root="/evidence", path=f"findings/x/{sha256}.json", sha256=sha256,
            fingerprint=f"fp-{sha256}",
        )

    def finding(description, sha256):
        record = VulnerabilityFinding(
            title="Command injection candidate", vuln_type="RCE", severity="High",
            target="https://lab.test", endpoint="https://lab.test/cmd", method="GET",
            finding_id="shared-identity", description=description,
            evidence=f"[e001] saved tool evidence: findings/x/{sha256}.json",
        )
        record.evidence_snapshots = [snapshot("e001", sha256)]
        return record

    parent = SessionState(target="https://lab.test")
    parent.add_finding(finding("first weak observation", "aa"))
    child = SessionState(target="https://lab.test")
    child.add_finding(finding("supplementary reproduction evidence", "bb"))

    merge_session_state(parent, child)

    # One finding, but the child's novel evidence must survive the merge.
    assert len(parent.findings) == 1
    merged = parent.findings[0]
    assert [ref.sha256 for ref in merged.evidence_snapshots] == ["aa", "bb"]
    assert merged.description == "first weak observation"
    assert "findings/x/bb.json" in merged.evidence

    # Re-merging the same child evidence is idempotent.
    merge_session_state(parent, child)
    assert [ref.sha256 for ref in parent.findings[0].evidence_snapshots] == ["aa", "bb"]


def test_merging_distinct_snapshots_preserves_shared_fingerprint():
    from vulnclaw.agent.parallel_agents import merge_session_state
    from vulnclaw.findings.types import EvidenceSnapshotRef

    parent = SessionState(target="https://lab.test")
    shared = parent.agent_state.remember_tool_result(
        tool="fetch", arguments={"url": "https://lab.test/cmd"},
        output="shared output", target="https://lab.test",
    )
    first = VulnerabilityFinding(
        title="Command injection candidate", vuln_type="RCE", severity="High",
        target="https://lab.test", endpoint="https://lab.test/cmd", method="GET",
        finding_id="shared-identity", description="parent side",
    )
    # Parent-side snapshot of a tool result the child also snapshotted.
    first.evidence_snapshots = [EvidenceSnapshotRef(
        evidence_id=shared.id, source_id=shared.id, target="https://lab.test",
        root="/evidence", path="findings/x/aa.json", sha256="aa",
        fingerprint=shared.fingerprint,
    )]
    parent.add_finding(first)
    child = SessionState(target="https://lab.test")
    second = VulnerabilityFinding(
        title="Command injection candidate", vuln_type="RCE", severity="High",
        target="https://lab.test", endpoint="https://lab.test/cmd", method="GET",
        finding_id="shared-identity", description="child side",
    )
    # A matching fingerprint does not establish that two saved snapshots are
    # identical. Keep both source references even after the parent ID mapping.
    second.evidence_snapshots = [EvidenceSnapshotRef(
        evidence_id="c001", source_id="c001", target="https://lab.test",
        root="/evidence", path="findings/x/bb.json", sha256="bb",
        fingerprint=shared.fingerprint,
    )]
    child.add_finding(second)

    merge_session_state(parent, child)

    merged = parent.findings[0]
    assert [ref.sha256 for ref in merged.evidence_snapshots] == ["aa", "bb"]
    assert len({ref.evidence_id for ref in merged.evidence_snapshots}) == 2
    assert [ref.source_id for ref in merged.evidence_snapshots] == [shared.id, "c001"]


@pytest.mark.parametrize("legacy_fingerprint", [False, True])
@pytest.mark.parametrize("commit_evidence", [False, True])
def test_merging_long_request_arguments_keeps_distinct_evidence(
    tmp_path, legacy_fingerprint, commit_evidence,
):
    import hashlib
    from types import SimpleNamespace

    from vulnclaw.agent.parallel_agents import merge_session_state
    from vulnclaw.agent.subagent.merge import EvidenceCommitter
    from vulnclaw.config.schema import VulnClawConfig
    from vulnclaw.findings.evidence import load_snapshots
    from vulnclaw.findings.intake import submit_finding

    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    sessions = []
    records = []
    for task, argument in (("parent", "baseline"), ("child", "id")):
        state = SessionState(target="https://lab.test", task_id=task)
        record = state.agent_state.remember_tool_result(
            tool="fetch", target=state.target, output="same response",
            arguments={"url": "https://lab.test/cmd", "headers": {"Cookie": "x" * 700},
                       "params": {"arg": argument}},
        )
        if legacy_fingerprint:
            record.fingerprint = hashlib.sha256(
                f"fetch\0{record.key_args}\0{record.content}".encode()
            ).hexdigest()[:24]
        agent = SimpleNamespace(config=config, session_state=state,
                                context=SimpleNamespace(state=state))
        submit_finding(agent, {
            "title": "Candidate", "description": "Recorded observation", "vuln_type": "RCE",
            "severity": "High", "endpoint": "https://lab.test/cmd", "evidence_ids": [record.id],
        })
        sessions.append(state)
        records.append(record)
    assert records[0].key_args == records[1].key_args
    assert (records[0].fingerprint == records[1].fingerprint) == legacy_fingerprint

    def merge():
        if commit_evidence:
            EvidenceCommitter().commit(
                SimpleNamespace(context=SimpleNamespace(state=sessions[0])), sessions[1],
                task_id="child", agent_type="test", baseline_fingerprints=set(),
                include_session_state=True,
            )
        else:
            merge_session_state(*sessions)

    merge()
    merged = sessions[0].findings[0]
    snapshots = load_snapshots(merged)
    assert {snapshot.arguments["params"]["arg"] for snapshot in snapshots.values()} == {"baseline", "id"}
    assert len({ref.evidence_id for ref in merged.evidence_snapshots}) == 2
    merge()
    assert len(merged.evidence_snapshots) == 2


def test_extract_attack_surfaces_from_network_state_and_findings():
    state = SessionState(target="192.168.1.0/24")
    state.recon_data["network_services"] = [
        {"host": "192.168.1.10", "port": 22, "protocol": "tcp", "service": "ssh"},
        {"host": "192.168.1.10", "port": 22, "protocol": "tcp", "service": "ssh"},
    ]
    state.recon_data["network_scans"] = [
        {
            "weak_links": [
                {"target": "192.168.1.20:445", "reason": "SMB exposed"},
            ]
        }
    ]
    state.add_finding(
        VulnerabilityFinding(
            title="Web finding",
            vuln_type="web",
            evidence="Observed at http://192.168.1.30/admin",
        )
    )

    surfaces = extract_attack_surfaces(state)

    assert [surface.target for surface in surfaces] == [
        "192.168.1.10:22",
        "192.168.1.20:445",
        "http://192.168.1.30/admin",
    ]


@pytest.mark.asyncio
async def test_run_parallel_pentest_fans_out_and_merges_worker_state():
    root = FakeAgent()
    children: list[FakeAgent] = []

    def factory():
        child = FakeAgent()
        children.append(child)
        return child

    result = await run_parallel_pentest(
        root,
        agent_factory=factory,
        user_input="Perform an authorized fast network scan against 192.168.1.0/24.",
        target="192.168.1.0/24",
        discovery_rounds=1,
        worker_rounds=2,
        max_agents=2,
        max_depth=1,
    )

    assert result.root_results == ["root-discovery"]
    assert result.waves_completed == 1
    assert [surface.target for surface in result.surfaces] == [
        "192.168.1.10:22",
        "192.168.1.20:445",
    ]
    assert len(children) == 2
    assert len(root.session_state.findings) == 2
    assert root.session_state.notes == ["worker note"]
    assert all("Investigate this surface only" in child.calls[0] for child in children)


@pytest.mark.asyncio
async def test_surface_wave_strategy_drives_agent_graph(tmp_path):
    root = FakeAgent()

    def factory():
        return FakeAgent()

    graph = AgentGraph(
        tmp_path / "agents",
        caps=FanOutCaps(max_concurrent=2, max_total=10, max_depth=1),
    )

    result = await run_parallel_pentest(
        root,
        agent_factory=factory,
        user_input="Perform an authorized fast network scan against 192.168.1.0/24.",
        target="192.168.1.0/24",
        discovery_rounds=1,
        worker_rounds=2,
        max_agents=2,
        max_depth=1,
        graph=graph,
    )

    # Existing callers still get the same fan-out result.
    assert result.waves_completed == 1
    assert len(root.session_state.findings) == 2

    # The graph is now the durable source of truth: root + one node per surface.
    snapshot = graph.view_graph()
    assert snapshot.root_id == graph.root_id
    worker_nodes = [n for n in snapshot.nodes if n.parent_id == graph.root_id]
    assert len(worker_nodes) == 2

    # merge_session_state ran as the child-finish hook → children finished.
    assert all(n.status == AgentStatus.DONE for n in worker_nodes)
    assert all(n.outcome == AgentOutcome.FINISHED for n in worker_nodes)

    # Every child done → root_finish accepted (fail-loud rule satisfied).
    root_node = graph.get_node(graph.root_id)
    assert root_node.status == AgentStatus.DONE
    assert root_node.outcome == AgentOutcome.FINISHED


@pytest.mark.asyncio
async def test_surface_wave_strategy_honors_max_total_cap(tmp_path):
    root = FakeAgent()

    def factory():
        return FakeAgent()

    # max_total=2 leaves room for the root + exactly one worker; the second
    # surface's create_agent is rejected and that child must not run.
    graph = AgentGraph(
        tmp_path / "agents",
        caps=FanOutCaps(max_concurrent=2, max_total=2, max_depth=1),
    )

    await run_parallel_pentest(
        root,
        agent_factory=factory,
        user_input="Perform an authorized fast network scan against 192.168.1.0/24.",
        target="192.168.1.0/24",
        discovery_rounds=1,
        worker_rounds=2,
        max_agents=2,
        max_depth=1,
        graph=graph,
    )

    snapshot = graph.view_graph()
    worker_nodes = [n for n in snapshot.nodes if n.parent_id == graph.root_id]
    assert len(worker_nodes) == 1  # second surface rejected by max_total
    assert len(root.session_state.findings) == 1  # rejected child never merged
    assert graph.get_node(graph.root_id).outcome == AgentOutcome.FINISHED
