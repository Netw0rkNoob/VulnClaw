from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from vulnclaw.agent.builtin_tools import build_openai_tools
from vulnclaw.agent.context import ContextManager
from vulnclaw.agent.roles import roles_for_task_kind, tool_allowed_for_role
from vulnclaw.agent.subagent.budget import BudgetExceeded, UsageBudget
from vulnclaw.agent.subagent.integration import sanitize_checkpoint
from vulnclaw.agent.subagent.merge import EvidenceCommitter, merge_agent_state
from vulnclaw.agent.subagent.models import (
    AgentResult,
    AgentSpec,
    SubagentContext,
    TaskStatus,
)
from vulnclaw.agent.subagent.service import (
    AgentRunner,
    DelegationDenied,
    TaskService,
)
from vulnclaw.agent.subagent.solve import inject_messages, owner_ids
from vulnclaw.config.schema import VulnClawConfig


async def _wait_for_background(service: TaskService, task_id: str) -> None:
    task = service.records[task_id].asyncio_task
    assert task is not None
    await asyncio.wait_for(asyncio.shield(task), timeout=2)


def test_usage_budget_tracks_only_model_usage() -> None:
    budget = UsageBudget(solve_limit=100, group_limit=60)

    first = budget.try_begin("c1", "g1", 30)
    assert first.estimated_tokens == 30
    assert budget.snapshot()["pressure_total"] == 30

    budget.settle("c1", 18)
    assert budget.snapshot()["used_total"] == 18
    assert budget.snapshot()["used_by_group"] == {"g1": 18}

    budget.try_begin("c2", "g1", 40)
    with pytest.raises(BudgetExceeded):
        budget.try_begin("c3", "g1", 3)


def test_usage_budget_records_actual_overshoot_and_blocks_later_calls() -> None:
    budget = UsageBudget(solve_limit=100, group_limit=100)
    budget.try_begin("c1", "g1", 70)

    budget.settle("c1", 110)

    assert budget.snapshot()["used_total"] == 110
    with pytest.raises(BudgetExceeded, match="solve"):
        budget.try_begin("c2", "g1", 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_type", ["group-leader", "general"])
async def test_background_agent_runs_asynchronously_and_notifies_once(agent_type) -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    events = []

    async def execute(_definition, _spec, _session, _context):
        started.set()
        await release.wait()
        return AgentResult(summary="group done")

    service = TaskService(
        runner=AgentRunner(execute),
        event_sink=lambda kind, payload: events.append((kind, payload)),
    )
    main = service.main_context()
    handle = await service.spawn_background(
        AgentSpec(
            description="auth group",
            prompt="investigate authentication",
            agent_type=agent_type,
            name="auth",
        ),
        main,
    )

    await asyncio.wait_for(started.wait(), timeout=1)
    assert (await service.collect(handle.task_id)).status is TaskStatus.RUNNING
    lifecycle = [payload for kind, payload in events if kind == "subagent"]
    assert [event["status"] for event in lifecycle] == ["pending", "running"]
    assert all(event["parent_id"] == main.task_id for event in lifecycle)
    assert all(event["agent_type"] == agent_type for event in lifecycle)
    expected_group = handle.task_id if agent_type == "group-leader" else ""
    assert all(event["group_id"] == expected_group for event in lifecycle)

    release.set()
    await _wait_for_background(service, handle.task_id)
    [notification] = service.drain_notifications()
    assert notification.task_id == handle.task_id
    assert notification.status is TaskStatus.COMPLETED
    assert (await service.collect(handle.task_id)).result.summary == "group done"
    assert service.drain_notifications() == []
    lifecycle = [payload for kind, payload in events if kind == "subagent"]
    assert [event["status"] for event in lifecycle] == ["pending", "running", "completed"]

    await service.shutdown()


@pytest.mark.asyncio
async def test_task_service_emits_thin_group_projection() -> None:
    events: list[tuple[str, dict[str, object]]] = []

    async def execute(definition, _spec, _session, context):
        if definition.name == "group-leader":
            await service.run_foreground(
                AgentSpec(
                    "independent verification",
                    "verify the claim",
                    "verifier",
                    metadata={"wave_id": "wave-1"},
                ),
                context,
            )
            return AgentResult(summary="group synthesis", evidence=["e002"])
        return AgentResult(summary="verified")

    service = TaskService(
        runner=AgentRunner(execute),
        event_sink=lambda kind, payload: events.append((kind, payload)),
    )
    handle = await service.spawn_background(
        AgentSpec(
            "auth group",
            "coordinate auth verification",
            "group-leader",
        ),
        service.main_context(),
    )
    await _wait_for_background(service, handle.task_id)

    kinds = [kind for kind, _payload in events]
    assert kinds[0] == "group_created"
    assert "group_started" in kinds
    assert "group_progress" in kinds
    assert kinds[-1] == "group_notified"
    terminal = next(
        payload for kind, payload in events if kind == "group_finished"
    )
    assert terminal["group_id"] == handle.task_id
    assert terminal["member_total"] == 1
    assert terminal["member_done"] == 1
    assert terminal["wave_count"] == 1
    assert terminal["evidence_count"] == 1
    assert terminal["budget"] is None
    member_events = [
        payload["member_event"]
        for kind, payload in events
        if kind == "group_progress" and payload.get("member_event")
    ]
    assert member_events == ["created", "started", "terminal"]
    assert "cursor" not in terminal
    assert "events" not in terminal
    await service.shutdown()


@pytest.mark.asyncio
async def test_leaf_stays_pending_until_concurrency_slot_is_acquired() -> None:
    group_started = asyncio.Event()
    release_group = asyncio.Event()
    first_leaf_started = asyncio.Event()
    release_leaf = asyncio.Event()

    async def execute(definition, _spec, _session, _context):
        if definition.name == "group-leader":
            group_started.set()
            await release_group.wait()
        else:
            first_leaf_started.set()
            await release_leaf.wait()
        return AgentResult(summary="done")

    service = TaskService(
        runner=AgentRunner(execute),
        max_concurrent_leaf_total=1,
        max_concurrent_leaf_per_group=1,
    )
    handle = await service.spawn_background(
        AgentSpec("group", "coordinate", "group-leader"),
        service.main_context(),
    )
    await asyncio.wait_for(group_started.wait(), timeout=1)
    leader = service.records[handle.task_id]
    assert leader.context is not None

    first = asyncio.create_task(
        service.run_foreground(
            AgentSpec("first", "probe", "executor"),
            leader.context,
        )
    )
    await asyncio.wait_for(first_leaf_started.wait(), timeout=1)
    second = asyncio.create_task(
        service.run_foreground(
            AgentSpec("second", "research", "researcher"),
            leader.context,
        )
    )
    await asyncio.sleep(0)

    leaves = [
        record
        for record in service.records.values()
        if record.parent_id == handle.task_id
    ]
    assert [record.status for record in leaves] == [
        TaskStatus.RUNNING,
        TaskStatus.PENDING,
    ]
    assert leaves[1].started_at is None

    release_leaf.set()
    await asyncio.gather(first, second)
    assert leaves[1].started_at is not None
    release_group.set()
    await _wait_for_background(service, handle.task_id)
    await service.shutdown()


@pytest.mark.asyncio
async def test_task_kind_is_checked_against_hard_coded_role_registry() -> None:
    from vulnclaw.agent.subagent.integration import group_leader_prompt

    service = TaskService(
        runner=AgentRunner(
            lambda *_args: AgentResult(summary="done")
        )
    )

    with pytest.raises(
        DelegationDenied,
        match="role researcher cannot handle task_kind execute",
    ):
        await service.run_foreground(
            AgentSpec(
                "nmap",
                "scan services",
                "researcher",
                task_kind="execute",
            ),
            service.main_context(),
        )

    result = await service.run_foreground(
        AgentSpec(
            "nmap",
            "scan services",
            "executor",
            task_kind="execute",
        ),
        service.main_context(),
    )
    assert result.status == "completed"
    assert roles_for_task_kind("execute") == ("executor",)
    assert tool_allowed_for_role("nmap_scan", "executor")
    assert not tool_allowed_for_role("nmap_scan", "researcher")
    assert not tool_allowed_for_role("shell_command", "researcher")
    leader_prompt = group_leader_prompt(target="target", assignment="scan")
    assert "task_kind=execute" in leader_prompt
    assert "nmap_scan" in leader_prompt
    assert "exactly one foreground researcher" in leader_prompt
    assert "non-overlapping scopes" in leader_prompt
    await service.shutdown()


@pytest.mark.asyncio
async def test_leaf_cannot_delegate_and_leader_cannot_spawn_leader() -> None:
    leaf_context = None

    async def execute(definition, _spec, _session, context):
        nonlocal leaf_context
        if definition.name == "group-leader":
            await service.run_foreground(
                AgentSpec("leaf", "work", "executor"),
                context,
            )
        else:
            leaf_context = context
        return AgentResult(summary="done")

    service = TaskService(runner=AgentRunner(execute))
    group_result = await service.run_foreground(
        AgentSpec("group", "coordinate", "group-leader"),
        service.main_context(),
    )
    assert group_result.summary == "done"
    assert leaf_context is not None

    with pytest.raises(DelegationDenied):
        await service.run_foreground(
            AgentSpec("nested", "invalid", "group-leader"),
            leaf_context,
        )

    leader_record = next(
        record
        for record in service.records.values()
        if record.definition.name == "group-leader"
    )
    with pytest.raises(DelegationDenied):
        await service.run_foreground(
            AgentSpec("nested group", "invalid", "group-leader"),
            leader_record.context,
        )

    await service.shutdown()


@pytest.mark.asyncio
async def test_named_leader_receives_pending_message() -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def execute(_definition, _spec, session, _context):
        started.set()
        await release.wait()
        messages = session.drain_pending_messages()
        return AgentResult(summary=messages[0])

    service = TaskService(runner=AgentRunner(execute))
    handle = await service.spawn_background(
        AgentSpec(
            "auth",
            "wait for changed premise",
            "group-leader",
            name="auth",
        ),
        service.main_context(),
    )
    await asyncio.wait_for(started.wait(), timeout=1)
    await service.message(handle.task_id, "cookie boundary changed")
    release.set()

    await _wait_for_background(service, handle.task_id)
    [notification] = service.drain_notifications()
    assert notification.result.summary == "cookie boundary changed"
    await service.shutdown()


def test_pending_leader_message_is_injected_at_turn_boundary() -> None:
    from vulnclaw.agent.subagent.models import AgentSession

    session = AgentSession(prompt="coordinate")
    session.queue_message("scope premise changed")
    agent = SimpleNamespace(
        context=ContextManager(),
        _subagent_ctx=SubagentContext(
            task_context=SimpleNamespace(session=session)
        ),
    )

    inject_messages(agent)

    assert "scope premise changed" in agent.context.messages[-1]["content"]
    assert not session.pending_messages


def test_leader_session_compacts_at_turn_boundary_and_preserves_goal() -> None:
    from vulnclaw.agent.subagent.models import AgentSession

    session = AgentSession(prompt="coordinate auth verification")
    session.messages.extend(
        {"role": "assistant", "content": f"plan/result {index}"}
        for index in range(90)
    )
    agent = SimpleNamespace(
        context=SimpleNamespace(),
        _subagent_ctx=SubagentContext(
            task_context=SimpleNamespace(session=session)
        ),
    )

    inject_messages(agent)

    assert len(session.messages) == 41
    assert session.messages[0]["role"] == "system"
    assert "coordinate auth verification" in session.messages[0]["content"]
    assert "plan/result 49" in session.messages[0]["content"]
    assert session.messages[-1]["content"] == "plan/result 89"


@pytest.mark.asyncio
async def test_terminal_notification_is_injected_into_main_input_queue() -> None:
    async def execute(_definition, _spec, _session, _context):
        return AgentResult(summary="verified auth boundary", evidence=["e101"])

    service = TaskService(runner=AgentRunner(execute))
    handle = await service.spawn_background(
        AgentSpec("auth", "coordinate", "group-leader"),
        service.main_context(),
    )
    for _ in range(20):
        if (await service.collect(handle.task_id)).status.terminal:
            break
        await asyncio.sleep(0)

    agent = SimpleNamespace(
        context=ContextManager(),
        _subagent_ctx=SubagentContext(service=service),
    )
    inject_messages(agent)
    content = agent.context.messages[-1]["content"]
    assert "<task-notification>" in content
    assert "verified auth boundary" in content
    payload = json.loads(
        content.removeprefix("<task-notification>\n").removesuffix(
            "\n</task-notification>"
        )
    )
    assert payload["parent_evidence_ids"] == ["e101"]
    assert payload["evidence_namespace"] == "main"
    assert "evidence" not in payload
    assert service.drain_notifications() == []
    await service.shutdown()


@pytest.mark.asyncio
async def test_group_cancel_cascades_to_running_leaf() -> None:
    events: list[tuple[str, dict[str, object]]] = []
    leaf_started = asyncio.Event()
    leaf_cancelling = asyncio.Event()
    release_cancellation = asyncio.Event()
    never = asyncio.Event()

    async def execute(definition, _spec, _session, context):
        if definition.name == "group-leader":
            await service.run_foreground(
                AgentSpec("leaf", "long probe", "executor"),
                context,
            )
        else:
            leaf_started.set()
            try:
                await never.wait()
            except asyncio.CancelledError:
                leaf_cancelling.set()
                await release_cancellation.wait()
                return AgentResult(
                    status="cancelled",
                    summary="leaf cancelled",
                    usage={
                        "requests": 2,
                        "input_tokens": 120,
                        "output_tokens": 30,
                    },
                )
        return AgentResult(summary="unexpected")

    service = TaskService(
        runner=AgentRunner(execute),
        event_sink=lambda kind, payload: events.append((kind, payload)),
    )
    handle = await service.spawn_background(
        AgentSpec("group", "coordinate", "group-leader"),
        service.main_context(),
    )
    await asyncio.wait_for(leaf_started.wait(), timeout=1)
    cancelling = asyncio.create_task(service.cancel(handle.task_id, reason="stop"))
    await asyncio.wait_for(leaf_cancelling.wait(), timeout=1)
    group_context = service.records[handle.task_id].context
    assert group_context is not None
    with pytest.raises(DelegationDenied, match="parent agent is not active"):
        service._register(
            AgentSpec("late", "late probe", "verifier"),
            group_context,
            background=False,
        )
    release_cancellation.set()
    group_snapshot = await cancelling

    assert group_snapshot.status is TaskStatus.KILLED
    assert group_snapshot.child_ids
    assert all(
        service.records[task_id].status is TaskStatus.KILLED
        for task_id in group_snapshot.child_ids
    )
    leaf = service.records[group_snapshot.child_ids[0]]
    assert leaf.result is not None
    assert leaf.result.usage["input_tokens"] == 120
    terminal_member = next(
        payload
        for kind, payload in events
        if kind == "group_progress"
        and payload.get("member_event") == "terminal"
    )
    assert terminal_member["member_usage"] == {
        "requests": 2,
        "input_tokens": 120,
        "output_tokens": 30,
    }
    leaf_terminal_index = next(
        index
        for index, (kind, payload) in enumerate(events)
        if kind == "group_progress"
        and payload.get("member_event") == "terminal"
    )
    group_terminal_index = next(
        index
        for index, (kind, _payload) in enumerate(events)
        if kind == "group_cancelled"
    )
    notified_index = next(
        index
        for index, (kind, _payload) in enumerate(events)
        if kind == "group_notified"
    )
    assert leaf_terminal_index < group_terminal_index < notified_index
    await service.shutdown()


@pytest.mark.asyncio
async def test_agent_job_never_exposes_uncommitted_leaf_evidence_ids() -> None:
    from vulnclaw.agent.subagent.integration import (
        execute_agent_job,
        get_task_runtime,
    )

    root = SimpleNamespace(
        config=VulnClawConfig(),
        context=ContextManager(),
        _subagent_ctx=SubagentContext(),
    )
    runtime = get_task_runtime(root)
    service = runtime.service
    group = service._register(
        AgentSpec("group", "coordinate", "group-leader"),
        service.main_context(),
        background=True,
    )
    assert group.context is not None
    leaf = service._register(
        AgentSpec("leaf", "distinct probe", "executor"),
        group.context,
        background=False,
    )
    leaf.status = TaskStatus.COMPLETED
    leaf.result = AgentResult(
        summary="verified by e006; dropped local evidence e007",
        content="FINAL: cite e006, not e007",
        evidence=["e006"],
    )

    pending = await execute_agent_job(root, {"action": "list"})
    assert "e006" not in pending
    assert "e007" not in pending
    pending_payload = json.loads(pending)["tasks"][1]
    assert pending_payload["result_pending_parent_commit"] is True
    assert pending_payload["result"]["parent_evidence_ids"] == []

    runtime.evidence_maps[(group.task_id, "main")] = {"e006": "e011"}
    committed = await execute_agent_job(root, {"action": "list"})
    assert "e006" not in committed
    assert "e007" not in committed
    committed_result = json.loads(committed)["tasks"][1]["result"]
    assert "evidence" not in committed_result
    assert committed_result["parent_evidence_ids"] == ["e011"]
    assert committed_result["summary"] == (
        "verified by e011; dropped local evidence [uncommitted evidence]"
    )
    assert committed_result["content"] == (
        "FINAL: cite e011, not [uncommitted evidence]"
    )


def test_child_state_seed_copies_knowledge_without_execution_history() -> None:
    from vulnclaw.agent.subagent.integration import _seed_child_agent_state

    parent = ContextManager().state.agent_state
    evidence = parent.remember_tool_result(
        tool="fetch",
        arguments={"url": "http://target.local"},
        output="baseline",
    )
    parent.record_tool_call(tool="fetch", arguments={}, evidence_id=evidence.id)
    parent.record_step(reason="probe")

    child = _seed_child_agent_state(parent)

    assert child.evidence[0] is not evidence
    assert child.evidence[0].content is evidence.content
    assert child.tool_calls == []
    assert child.steps == []


def test_running_child_checkpoint_hides_inherited_conclusions(tmp_path) -> None:
    state = ContextManager().state
    state.session_kind = "leaf"
    state.lifecycle_status = "running"
    state._checkpoint_transform = sanitize_checkpoint
    evidence = state.agent_state.remember_tool_result(
        tool="fetch",
        arguments={"url": "http://target.local"},
        output="baseline",
    )
    state.agent_state.record_verified_claim("inherited claim", [evidence.id])
    state.agent_state.final_answer = "must not be published while running"
    path = tmp_path / "child.json"
    state.set_save_path(path)

    state.save()
    running = json.loads(path.read_text(encoding="utf-8"))
    assert running["agent_state"]["verified_claims"] == []
    assert running["agent_state"]["final_answer"] == ""

    state.lifecycle_status = "completed"
    state.save()
    completed = json.loads(path.read_text(encoding="utf-8"))
    assert completed["agent_state"]["verified_claims"][0]["id"] == "c001"
    assert completed["agent_state"]["final_answer"] == (
        "must not be published while running"
    )


def test_claim_ids_are_renumbered_in_parent_namespace() -> None:
    parent = ContextManager().state.agent_state
    for label in ("left", "right"):
        child = ContextManager().state.agent_state
        evidence = child.remember_tool_result(
            tool=label,
            arguments={},
            output=f"{label} evidence",
        )
        child.record_verified_claim(f"{label} claim", [evidence.id])
        merge_agent_state(
            parent,
            child,
            max_records=8,
            baseline_fingerprints=set(),
        )

    assert [claim.id for claim in parent.verified_claims] == ["c001", "c002"]


def test_nested_provenance_keeps_leaf_identity_and_parent_ids_do_not_collide() -> None:
    import copy

    committer = EvidenceCommitter(max_records=8)
    main = SimpleNamespace(context=ContextManager())
    main_evidence = main.context.state.agent_state.remember_tool_result(
        tool="main",
        arguments={},
        output="main evidence",
    )
    leader = SimpleNamespace(
        context=ContextManager(),
        _subagent_ctx=SubagentContext(
            task_context=SimpleNamespace(task_id="a-0001")
        ),
    )
    leader.context.state.agent_state = copy.deepcopy(
        main.context.state.agent_state
    )
    leaf_session = copy.deepcopy(leader.context.state)
    leaf_evidence = leaf_session.agent_state.remember_tool_result(
        tool="nmap_scan",
        arguments={},
        output="leaf evidence",
    )

    baseline = {main_evidence.fingerprint}
    committer.commit(
        leader,
        leaf_session,
        task_id="a-0004",
        agent_type="executor",
        baseline_fingerprints=baseline,
        include_session_state=True,
    )
    report = committer.commit(
        main,
        leader.context.state,
        task_id="a-0001",
        agent_type="group-leader",
        baseline_fingerprints=baseline,
        include_session_state=True,
    )

    assert report.evidence_ids == ("e002",)
    provenance = main.context.state.subagent_evidence_provenance["e002"]
    assert provenance["contributors"] == [
        {
            "task_id": "a-0004",
            "agent_type": "executor",
            "source_evidence_ids": [leaf_evidence.id],
            "path": ["a-0001", "a-0004"],
        }
    ]
    assert owner_ids(main.context.state, ["e001"]) == set()
    assert owner_ids(main.context.state, ["e002"]) == {"a-0004"}


@pytest.mark.asyncio
async def test_wall_timeout_cancels_inner_agent_execution() -> None:
    inner_cancelled = asyncio.Event()

    async def execute(_definition, _spec, _session, _context):
        try:
            await asyncio.Event().wait()
        finally:
            inner_cancelled.set()

    service = TaskService(
        runner=AgentRunner(execute),
        leaf_timeout_seconds=0.01,
    )
    with pytest.raises(RuntimeError, match="wall timeout"):
        await service.run_foreground(
            AgentSpec("leaf", "never finishes", "general"),
            service.main_context(),
        )
    assert inner_cancelled.is_set()
    assert next(iter(service.records.values())).status is TaskStatus.FAILED
    await service.shutdown()


@pytest.mark.asyncio
async def test_group_leaf_and_wave_limits_are_enforced() -> None:
    release = asyncio.Event()

    async def execute(definition, _spec, _session, _context):
        if definition.name == "group-leader":
            await release.wait()
        return AgentResult(summary="done")

    service = TaskService(
        runner=AgentRunner(execute),
        max_leaf_per_group=3,
        max_waves_per_group=1,
    )
    await service.spawn_background(
        AgentSpec("group", "coordinate", "group-leader"),
        service.main_context(),
    )
    await asyncio.sleep(0)
    leader = next(iter(service.records.values()))
    context = leader.context
    assert context is not None

    await service.run_foreground(
        AgentSpec(
            "leaf one",
            "one",
            "executor",
            metadata={"wave_id": "wave-1"},
        ),
        context,
    )
    await service.run_foreground(
        AgentSpec(
            "leaf two",
            "two",
            "verifier",
            metadata={"wave_id": "wave-1"},
        ),
        context,
    )
    assert leader.leaf_count == 2
    assert leader.wave_count == 1

    with pytest.raises(DelegationDenied, match="wave limit"):
        await service.run_foreground(
            AgentSpec(
                "leaf three",
                "three",
                "researcher",
                metadata={"wave_id": "wave-2"},
            ),
            context,
        )
    await service.run_foreground(
        AgentSpec(
            "leaf three",
            "three",
            "researcher",
            metadata={"wave_id": "wave-1"},
        ),
        context,
    )
    with pytest.raises(DelegationDenied, match="leaf limit"):
        await service.run_foreground(
            AgentSpec(
                "leaf four",
                "four",
                "executor",
                metadata={"wave_id": "wave-1"},
            ),
            context,
        )
    release.set()
    await _wait_for_background(service, leader.task_id)
    await service.shutdown()


def test_compact_model_catalog_exposes_only_two_subagent_tools() -> None:
    tools = build_openai_tools(
        None,
        include_subagent_tool=True,
    )
    names = {item["function"]["name"] for item in tools}
    compact_names = names.intersection(
        {
            "agent_run",
            "agent_job",
            "spawn_subagents",
            "subagent_status",
            "subagent_collect",
            "subagent_cancel",
            "subagent_takeover",
        }
    )
    assert compact_names == {"agent_run", "agent_job"}

    leader_tools = build_openai_tools(
        None,
        active_role="group-leader",
        include_subagent_tool=True,
    )
    assert {item["function"]["name"] for item in leader_tools} == {
        "submit_finding",
        "agent_run",
        "evidence_list",
        "evidence_view",
        "evidence_search",
    }


def test_terminal_commit_uses_latest_parent_state_and_keeps_provenance() -> None:
    import copy

    parent = SimpleNamespace(context=ContextManager())
    parent_state = parent.context.state.agent_state
    baseline = parent_state.remember_tool_result(
        tool="main",
        arguments={"path": "/before"},
        output="baseline",
    )
    child_session = copy.deepcopy(parent.context.state)
    child_record = child_session.agent_state.remember_tool_result(
        tool="leaf",
        arguments={"path": "/leaf"},
        output="independent result",
    )
    child_session.agent_state.record_verified_claim(
        "leaf claim",
        [child_record.id],
    )

    concurrent = parent_state.remember_tool_result(
        tool="main",
        arguments={"path": "/concurrent"},
        output="main progressed while group ran",
    )
    report = EvidenceCommitter(max_records=8).commit(
        parent,
        child_session,
        task_id="group-1",
        agent_type="group-leader",
        baseline_fingerprints={baseline.fingerprint},
        include_session_state=True,
    )

    assert concurrent.id in parent_state.evidence_ids()
    assert report.evidence_ids == ("e003",)
    claim = next(
        item
        for item in parent_state.verified_claims
        if item.claim == "leaf claim"
    )
    assert claim.evidence_ids == ["e003"]
    provenance = parent.context.state.subagent_evidence_provenance["e003"]
    assert provenance == {
        "origin_kind": "subagent",
        "contributors": [
            {
                "task_id": "group-1",
                "agent_type": "group-leader",
                "source_evidence_ids": ["e002"],
                "path": ["group-1"],
            }
        ],
    }


@pytest.mark.asyncio
async def test_real_agent_adapter_runs_leader_with_parallel_leaf_wave(monkeypatch) -> None:
    from vulnclaw.agent.solver import SolveResult
    from vulnclaw.agent.subagent.integration import (
        execute_agent_job,
        execute_agent_run,
        get_task_runtime,
    )

    class FakeAgent:
        def __init__(self, config=None, mcp_manager=None):
            self.config = config or VulnClawConfig()
            self.mcp_manager = mcp_manager
            self.context = ContextManager()
            self.context.state.target = "http://target.local"
            self.context.state.agent_state.origin = "http://target.local"
            self.context.state.agent_state.goal = "test auth"
            self.active_role = None
            self.agent_id = "main"
            self._subagent_ctx = SubagentContext()
            self._key_pool = ["k"]
            self._key_index = 0
            self._client = None

        def _child_factory(self):
            return FakeAgent(self.config, self.mcp_manager)

    leaf_active = 0
    leaf_peak = 0
    leaf_wave_started = asyncio.Event()
    release_leaf_wave = asyncio.Event()

    async def fake_solve(child, **_kwargs):
        nonlocal leaf_active, leaf_peak
        sink = _kwargs["stream_sink"]
        sink.on_thinking_token("inspect ")
        sink.on_thinking_token(child.active_role)
        sink.on_tool_call("probe", "{}")
        sink.on_tool_result("live tool result")
        sink.on_content_token("working")
        sink.on_stream_end()
        kind = child.context.state.session_kind
        if kind == "group_leader":
            results = await asyncio.gather(
                execute_agent_run(
                    child,
                    {
                        "description": "probe",
                        "prompt": "probe auth boundary",
                        "agent_type": "executor",
                        "_wave_id": "wave-1",
                    },
                ),
                execute_agent_run(
                    child,
                    {
                        "description": "review",
                        "prompt": "independently review auth state",
                        "agent_type": "verifier",
                        "_wave_id": "wave-1",
                    },
                ),
            )
            payloads = [json.loads(item) for item in results]
            assert all(item["ok"] for item in payloads)
            parent_ids = [
                evidence_id
                for item in payloads
                for evidence_id in item["parent_evidence_ids"]
            ]
            child.context.state.agent_state.final_answer = (
                f"FINAL: cite {' and '.join(parent_ids)}"
            )
        else:
            child.context.state.agent_state.remember_tool_result(
                tool=child.active_role,
                arguments={"task": child.context.state.task_id},
                output=f"distinct evidence from {child.active_role}",
            )
            leaf_active += 1
            leaf_peak = max(leaf_peak, leaf_active)
            if leaf_active == 2:
                leaf_wave_started.set()
            await release_leaf_wave.wait()
            leaf_active -= 1
            child.context.state.agent_state.final_answer = "FINAL: cite e006"
        return SolveResult(
            completed=True,
            reason="done",
            steps=1,
            evidence=len(child.context.state.agent_state.evidence),
            agent_state=child.context.state.agent_state,
        )

    monkeypatch.setattr("vulnclaw.agent.solver.solve", fake_solve)
    root = FakeAgent()
    live_events = []
    root._subagent_ctx.event_sink = lambda kind, payload: live_events.append((kind, payload))
    for index in range(5):
        root.context.state.agent_state.remember_tool_result(
            tool="main",
            arguments={"baseline": index},
            output=f"baseline {index}",
        )
    raw = await execute_agent_run(
        root,
        {
            "description": "auth group",
            "prompt": "coordinate auth verification",
            "agent_type": "group-leader",
            "name": "auth",
            "background": True,
        },
    )
    handle = json.loads(raw)
    assert handle["background"] is True

    await asyncio.wait_for(leaf_wave_started.wait(), timeout=1)
    assert leaf_peak == 2
    # Observe all three agents while the two leaf solves are still blocked.
    streams = [payload for kind, payload in live_events if kind == "subagent_stream"]
    assert len({event["agent_id"] for event in streams}) == 3
    for agent_id in {event["agent_id"] for event in streams}:
        agent_stream = [event for event in streams if event["agent_id"] == agent_id]
        assert [event["type"] for event in agent_stream] == [
            "reasoning", "reasoning", "tool_call", "tool_result", "log",
        ]
        assert agent_stream[0]["append"] is False
        assert agent_stream[1]["append"] is True
    lifecycle = [payload for kind, payload in live_events if kind == "subagent"]
    assert {event["agent_id"] for event in lifecycle} == {event["agent_id"] for event in streams}
    assert all(event["status"] in {"pending", "running"} for event in lifecycle)
    assert not any(event["event"] == "subagent_stream" for event in root.context.state.subagent_events)
    for index in range(14):
        root.context.state.agent_state.remember_tool_result(
            tool="main",
            arguments={"concurrent": index},
            output=f"concurrent main evidence {index}",
        )
    release_leaf_wave.set()

    runtime = get_task_runtime(root)
    await _wait_for_background(runtime.service, handle["task_id"])
    collected = json.loads(
        await execute_agent_job(
            root,
            {"action": "collect", "job_id": handle["task_id"]},
        )
    )
    assert collected["result"]["parent_evidence_ids"] == ["e020", "e021"]
    assert collected["result"]["summary"] in {
        "FINAL: cite e020 and e021",
        "FINAL: cite e021 and e020",
    }
    assert "e006" not in json.dumps(collected)
    assert "e007" not in json.dumps(collected)
    [notification] = runtime.service.drain_notifications()
    assert notification.task_id == handle["task_id"]
    assert notification.status is TaskStatus.COMPLETED
    assert notification.result is not None
    assert notification.result.evidence == ["e020", "e021"]
    assert notification.result.summary == collected["result"]["summary"]
    assert len(runtime.service.records) == 3
    assert {
        record.definition.name for record in runtime.service.records.values()
    } == {"group-leader", "executor", "verifier"}
    durable_events = root.context.state.subagent_events
    assert durable_events[-1]["event"] == "group_notified"
    assert any(
        event.get("member_event") == "terminal"
        for event in durable_events
        if event["event"] == "group_progress"
    )
    terminal = next(
        event
        for event in durable_events
        if event["event"] == "group_finished"
    )
    assert terminal["budget"]["inflight_calls"] == 0
    for index in range(300):
        runtime._record_event("group_progress", {"index": index})
    assert len(root.context.state.subagent_events) == 256
    assert root.context.state.subagent_events[0]["index"] == 44
    await runtime.service.shutdown()


@pytest.mark.asyncio
async def test_cancelled_group_commits_leaf_before_terminal_notification(
    monkeypatch,
) -> None:
    from vulnclaw.agent.solver import SolveResult
    from vulnclaw.agent.subagent.integration import (
        execute_agent_run,
        get_task_runtime,
    )
    from vulnclaw.agent.subagent.models import get_subagent_context

    class FakeAgent:
        def __init__(self, config=None):
            self.config = config or VulnClawConfig()
            self.context = ContextManager()
            self.context.state.target = "http://target.local"
            self.active_role = None
            self._subagent_ctx = SubagentContext()
            self._key_pool = ["k"]
            self._client = None

        def _child_factory(self):
            return FakeAgent(self.config)

    leaf_started = asyncio.Event()
    never = asyncio.Event()

    async def fake_solve(child, **_kwargs):
        if child.context.state.session_kind == "group_leader":
            await execute_agent_run(
                child,
                {
                    "description": "leaf",
                    "prompt": "distinct active probe",
                    "agent_type": "executor",
                    "task_kind": "execute",
                },
            )
        else:
            child.context.state.agent_state.remember_tool_result(
                tool="nmap_scan",
                arguments={"target": "target.local"},
                output="leaf evidence committed during cancellation",
            )
            context = get_subagent_context(child)
            assert context is not None
            context.input_tokens_used = 321
            admission = context.usage_budget.try_begin(
                f"{child.context.state.task_id}.test",
                context.task_context.group_id,
                100,
            )
            leaf_started.set()
            try:
                await never.wait()
            finally:
                context.usage_budget.settle(admission.call_id, 42)
        return SolveResult(
            completed=True,
            reason="done",
            steps=1,
            evidence=len(child.context.state.agent_state.evidence),
            agent_state=child.context.state.agent_state,
        )

    monkeypatch.setattr("vulnclaw.agent.solver.solve", fake_solve)
    root = FakeAgent()
    handle = json.loads(
        await execute_agent_run(
            root,
            {
                "description": "group",
                "prompt": "coordinate one probe",
                "agent_type": "group-leader",
                "background": True,
            },
        )
    )
    runtime = get_task_runtime(root)
    await asyncio.wait_for(leaf_started.wait(), timeout=1)
    snapshot = await runtime.service.cancel(
        handle["task_id"],
        reason="stop",
    )

    assert snapshot.status is TaskStatus.KILLED
    leaf = runtime.service.records[snapshot.child_ids[0]]
    assert leaf.result is not None
    assert leaf.result.usage["input_tokens"] == 321
    assert root.context.state.agent_state.evidence_ids() == ["e001"]
    provenance = root.context.state.subagent_evidence_provenance["e001"]
    assert provenance["contributors"][0]["task_id"] == leaf.task_id
    [notification] = runtime.service.drain_notifications()
    assert notification.result is not None
    assert notification.result.evidence == ["e001"]
    events = root.context.state.subagent_events
    leaf_terminal = next(
        index
        for index, event in enumerate(events)
        if event["event"] == "group_progress"
        and event.get("member_event") == "terminal"
    )
    group_terminal = next(
        index
        for index, event in enumerate(events)
        if event["event"] == "group_cancelled"
    )
    assert events[group_terminal]["budget"]["inflight_calls"] == 0
    assert events[group_terminal]["budget"]["used_total"] == 42
    notified = next(
        index
        for index, event in enumerate(events)
        if event["event"] == "group_notified"
    )
    assert leaf_terminal < group_terminal < notified
    await runtime.service.shutdown()


@pytest.mark.asyncio
async def test_runtime_writes_one_checkpoint_per_group_member(
    monkeypatch,
    tmp_path,
) -> None:
    from vulnclaw.agent.solver import SolveResult
    from vulnclaw.agent.subagent.integration import (
        execute_agent_run,
        get_task_runtime,
    )

    class FakeAgent:
        def __init__(self, config=None, mcp_manager=None):
            self.config = config or VulnClawConfig()
            self.mcp_manager = mcp_manager
            self.context = ContextManager()
            self.context.state.target = "http://target.local"
            self.active_role = None
            self._subagent_ctx = SubagentContext()
            self._key_pool = ["k"]
            self._client = None

        def _child_factory(self):
            return FakeAgent(self.config, self.mcp_manager)

    inherited_counts: list[int] = []

    async def fake_solve(child, **_kwargs):
        if child.context.state.session_kind == "group_leader":
            baseline = await execute_agent_run(
                child,
                {
                    "description": "shared baseline",
                    "prompt": "one safe shared reconnaissance pass",
                    "agent_type": "researcher",
                    "task_kind": "research",
                    "_wave_id": "baseline",
                },
            )
            assert json.loads(baseline)["ok"]
            results = await asyncio.gather(
                *[
                    execute_agent_run(
                        child,
                        {
                            "description": f"leaf {index}",
                            "prompt": f"probe surface {index}",
                            "agent_type": (
                                "researcher" if index == 0 else "executor"
                            ),
                            "task_kind": (
                                "research" if index == 0 else "execute"
                            ),
                            "_wave_id": "wave-1",
                        },
                    )
                    for index in range(5)
                ]
            )
            assert all(json.loads(item)["ok"] for item in results)
        else:
            inherited_counts.append(
                len(child.context.state.agent_state.evidence)
            )
            child.context.state.agent_state.remember_tool_result(
                tool=child.active_role,
                arguments={},
                output=f"evidence from {child.context.state.task_id}",
            )
        child.context.state.agent_state.final_answer = "FINAL: done"
        return SolveResult(
            completed=True,
            reason="done",
            steps=1,
            evidence=len(child.context.state.agent_state.evidence),
            agent_state=child.context.state.agent_state,
        )

    monkeypatch.setattr("vulnclaw.config.settings.SESSIONS_DIR", tmp_path)
    monkeypatch.setattr("vulnclaw.agent.solver.solve", fake_solve)
    root = FakeAgent()
    handle = json.loads(
        await execute_agent_run(
            root,
            {
                "description": "group",
                "prompt": "coordinate five probes",
                "agent_type": "group-leader",
                "background": True,
            },
        )
    )
    runtime = get_task_runtime(root)
    await _wait_for_background(runtime.service, handle["task_id"])
    [notification] = runtime.service.drain_notifications()
    assert notification.task_id == handle["task_id"]
    assert inherited_counts[0] == 0
    assert inherited_counts[1:] == [1, 1, 1, 1, 1]

    checkpoints = sorted(tmp_path.glob(f"subagent_{runtime.run_id}_*.json"))
    assert len(checkpoints) == 7
    persisted_ids = {
        json.loads(path.read_text(encoding="utf-8"))["task_id"]
        for path in checkpoints
    }
    assert persisted_ids == set(runtime.service.records)
    assert all(
        json.loads(path.read_text(encoding="utf-8"))["lifecycle_status"]
        == "completed"
        for path in checkpoints
    )
    await runtime.service.shutdown()
