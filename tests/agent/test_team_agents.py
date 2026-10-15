from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent.context import SessionState
from vulnclaw.findings.intake import submit_finding


@pytest.fixture(autouse=True)
def isolate_team_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(FakeAgent, 'output_dir', tmp_path, raising=False)


class FakeAgent:
    active_solves = 0
    max_active_solves = 0
    solve_order: list[str | None] = []

    def __init__(self, *, delay: float = 0) -> None:
        self.session_state = SessionState(target="https://example.com")
        self.context = SimpleNamespace(state=self.session_state)
        self.config = SimpleNamespace(
            llm=SimpleNamespace(
                provider="openai",
                model="gpt-4o",
                max_tokens=4096,
                temperature=0.1,
                reasoning_effort="high",
            ),
            session=SimpleNamespace(solve_max_steps=40, output_dir=self.output_dir),
        )
        self.active_role: str | None = None
        self.calls: list[tuple[str | None, str, int]] = []
        self.delay = delay

    def _get_client(self):
        raise AssertionError("default team run should not call an LLM planner/adviser")

    async def solve(
        self,
        prompt,
        *,
        target=None,
        goal=None,
        max_steps=0,
        max_directions=0,
        max_tool_rounds=0,
        stream_sink=None,
        on_event=None,
    ):
        import asyncio

        FakeAgent.active_solves += 1
        FakeAgent.max_active_solves = max(FakeAgent.max_active_solves, FakeAgent.active_solves)
        FakeAgent.solve_order.append(self.active_role)
        if self.delay:
            await asyncio.sleep(self.delay)
        self.calls.append((self.active_role, goal or prompt, max_steps))
        record = self.session_state.agent_state.remember_tool_result(
            tool='fetch', arguments={'url': f'https://example.com/{self.active_role}'},
            output=goal or prompt, target=self.session_state.target,
        )
        submit_finding(self, {
            'title': f'{self.active_role} finding', 'severity': 'Info', 'vuln_type': 'team-test',
            'description': goal or prompt, 'endpoint': f'https://example.com/{self.active_role}',
            'evidence_ids': [record.id],
        })
        self.session_state.notes.append(f"{self.active_role} note")
        self.session_state.agent_state.record_verified_claim(
            f"{self.active_role} research fact",
            evidence_ids=[record.id],
        )
        FakeAgent.active_solves -= 1
        return SimpleNamespace(completed=False, reason="worker done", steps=1)


def test_role_registry_defines_seed_roles_as_data():
    from vulnclaw.agent.roles import ROLE_REGISTRY

    assert set(ROLE_REGISTRY) == {"researcher", "developer", "executor", "adviser"}
    for name, role in ROLE_REGISTRY.items():
        assert role.name == name
        assert role.persona
        assert isinstance(role.allowed_tool_globs, tuple)
        assert role.goal_template


def test_planner_validates_plan_and_falls_back_on_malformed_output():
    from vulnclaw.agent.team import validate_plan

    valid = validate_plan(
        {
            "steps": [
                {
                    "role": "researcher",
                    "objective": "Map login endpoints",
                    "done_when": "Endpoints are listed",
                },
                {
                    "role": "developer",
                    "objective": "Build payload candidates",
                    "done_when": "Payloads are ready",
                },
                {
                    "role": "executor",
                    "objective": "Verify the best payload",
                    "done_when": "Tool output proves impact",
                },
            ]
        },
        fallback_goal="Capture the flag",
    )

    assert [step.role for step in valid.steps] == ["researcher", "developer", "executor"]
    assert valid.fallback_used is False

    fallback = validate_plan({"steps": []}, fallback_goal="Capture the flag")

    assert fallback.fallback_used is True
    assert [(step.role, step.objective) for step in fallback.steps] == [
        ("executor", "Capture the flag")
    ]


@pytest.mark.asyncio
async def test_make_team_plan_uses_adviser_role_and_json_extraction(monkeypatch):
    from vulnclaw.agent import solver
    from vulnclaw.agent.team import make_team_plan

    seen_roles = []

    async def fake_structured_call(agent, prompt, *, max_tokens):
        seen_roles.append(agent.active_role)
        return """
        Planner notes:
        {"steps":[
          {"role":"researcher","objective":"Map login endpoints","done_when":"Endpoints listed"},
          {"role":"developer","objective":"Build payload candidates","done_when":"Payloads ready"},
          {"role":"executor","objective":"Verify payload","done_when":"Tool evidence captured"}
        ]}
        """

    monkeypatch.setattr(solver, "structured_call", fake_structured_call)

    class PlannerAgent(FakeAgent):
        def _get_client(self):
            raise AssertionError("structured call is patched")

    agent = PlannerAgent()
    plan = await make_team_plan(agent, "https://example.com", "Capture flag", ["seed fact"])

    assert [step.role for step in plan.steps] == ["researcher", "developer", "executor"]
    assert plan.fallback_used is False
    assert seen_roles == ["adviser"]
    assert agent.active_role is None


@pytest.mark.asyncio
async def test_run_team_pentest_defaults_to_single_executor_step_and_seeds_agent_state():
    from vulnclaw.agent.team import run_team_pentest

    root = FakeAgent()
    children: list[FakeAgent] = []

    def factory():
        child = FakeAgent()
        children.append(child)
        return child

    result = await run_team_pentest(
        root,
        user_input="Capture the flag",
        target="https://example.com",
        planner=lambda agent, origin, goal, facts: {"steps": []},
        adviser=lambda agent, origin, goal, step, step_result: {"action": "continue"},
        agent_factory=factory,
        max_steps=4,
    )

    assert result.plan.fallback_used is True
    assert [(step.role, step.objective) for step in result.plan.steps] == [
        ("executor", "Capture the flag")
    ]
    assert [call[0] for child in children for call in child.calls] == ["executor"]
    assert [call[2] for child in children for call in child.calls] == [4]
    assert root.session_state.agent_state.origin == "https://example.com"
    assert root.session_state.agent_state.goal == "Capture the flag"
    assert "Team run origin=https://example.com" in root.session_state.agent_state.compact_summary
    assert len(root.session_state.findings) == 1
    assert root.session_state.notes[-1:] == ["executor note"]
    assert root.active_role is None


@pytest.mark.asyncio
async def test_run_team_pentest_runs_roles_and_merges_worker_state():
    from vulnclaw.agent.team import TeamPlan, TeamStep, run_team_pentest

    root = FakeAgent()
    children: list[FakeAgent] = []

    def factory():
        child = FakeAgent()
        children.append(child)
        return child

    plan = TeamPlan(
        steps=[
            TeamStep(
                role="researcher",
                objective="Collect login facts",
                done_when="Facts are in shared research state",
            ),
            TeamStep(
                role="developer",
                objective="Build candidate payloads",
                done_when="Payloads are ready",
            ),
            TeamStep(
                role="executor",
                objective="Run authorized verification",
                done_when="Tool output verifies the finding",
            ),
        ]
    )

    result = await run_team_pentest(
        root,
        user_input="Capture the flag",
        target="https://example.com",
        planner=lambda agent, origin, goal, facts: plan,
        adviser=lambda agent, origin, goal, step, step_result: {"action": "continue"},
        agent_factory=factory,
        max_steps=4,
    )

    assert [call[0] for child in children for call in child.calls] == [
        "researcher",
        "developer",
        "executor",
    ]
    assert [call[2] for child in children for call in child.calls] == [4, 3, 2]
    assert result.plan.steps == plan.steps
    assert len(root.session_state.findings) == 3
    assert root.last_team_plan == (
        "[team-plan]\n"
        "1. researcher: Collect login facts (done when: Facts are in shared research state)\n"
        "2. developer: Build candidate payloads (done when: Payloads are ready)\n"
        "3. executor: Run authorized verification (done when: Tool output verifies the finding)"
    )
    assert root.session_state.notes[-3:] == ["researcher note", "developer note", "executor note"]
    assert any(
        claim.claim == "executor research fact"
        for claim in root.session_state.agent_state.verified_claims
    )
    assert root.active_role is None


@pytest.mark.asyncio
async def test_adviser_replans_are_bounded():
    from vulnclaw.agent.team import TeamDecision, TeamPlan, TeamStep, run_team_pentest

    root = FakeAgent()
    planner_calls = 0

    def planner(agent, origin, goal, facts):
        nonlocal planner_calls
        planner_calls += 1
        return TeamPlan(
            steps=[
                TeamStep(role="researcher", objective=f"research {planner_calls}", done_when="facts"),
                TeamStep(role="developer", objective=f"develop {planner_calls}", done_when="payload"),
                TeamStep(role="executor", objective=f"execute {planner_calls}", done_when="evidence"),
            ]
        )

    def adviser(agent, origin, goal, step, step_result):
        return TeamDecision(action="replan")

    result = await run_team_pentest(
        root,
        user_input="Capture the flag",
        target="https://example.com",
        planner=planner,
        adviser=adviser,
        agent_factory=FakeAgent,
        max_replans=2,
    )

    assert result.replans_used == 2
    assert planner_calls == 3
    assert len(result.adviser_decisions) >= 3


@pytest.mark.asyncio
async def test_adviser_stop_does_not_override_evidence_gate():
    from vulnclaw.agent.team import TeamDecision, TeamPlan, TeamStep, run_team_pentest

    root = FakeAgent()
    plan = TeamPlan(
        steps=[
            TeamStep(role="researcher", objective="Map facts", done_when="facts"),
            TeamStep(role="developer", objective="Build candidates", done_when="payloads"),
            TeamStep(role="executor", objective="Verify evidence", done_when="evidence"),
        ]
    )

    result = await run_team_pentest(
        root,
        user_input="Capture the flag",
        target="https://example.com",
        planner=lambda agent, origin, goal, facts: plan,
        adviser=lambda agent, origin, goal, step, step_result: TeamDecision(action="stop"),
        agent_factory=FakeAgent,
    )

    assert result.stopped_by_adviser is True
    assert [call[0] for child in result.worker_results for call in []] == []
    assert len(result.worker_results) == 3
    assert root.session_state.agent_state.completed is False


@pytest.mark.asyncio
async def test_independent_steps_run_in_parallel_before_dependent_step():
    from vulnclaw.agent.team import TeamDecision, TeamPlan, TeamStep, run_team_pentest

    FakeAgent.active_solves = 0
    FakeAgent.max_active_solves = 0
    FakeAgent.solve_order = []
    root = FakeAgent()
    children: list[FakeAgent] = []

    def factory():
        child = FakeAgent(delay=0.01)
        children.append(child)
        return child

    plan = TeamPlan(
        steps=[
            TeamStep(
                role="researcher",
                objective="Collect endpoint facts",
                done_when="facts ready",
                depends_on=(),
            ),
            TeamStep(
                role="developer",
                objective="Build payload candidates",
                done_when="payloads ready",
                depends_on=(),
            ),
            TeamStep(
                role="executor",
                objective="Verify the candidate",
                done_when="evidence ready",
                depends_on=(0, 1),
            ),
        ]
    )

    await run_team_pentest(
        root,
        user_input="Capture the flag",
        target="https://example.com",
        planner=lambda agent, origin, goal, facts: plan,
        adviser=lambda agent, origin, goal, step, step_result: TeamDecision(action="continue"),
        agent_factory=factory,
        max_parallel=2,
    )

    assert FakeAgent.max_active_solves == 2
    assert FakeAgent.solve_order[:2] == ["researcher", "developer"]
    assert FakeAgent.solve_order[2] == "executor"


@pytest.mark.asyncio
async def test_team_run_does_not_start_more_workers_than_remaining_step_budget():
    from vulnclaw.agent.team import TeamDecision, TeamPlan, TeamStep, run_team_pentest

    FakeAgent.active_solves = 0
    FakeAgent.max_active_solves = 0
    FakeAgent.solve_order = []
    root = FakeAgent()
    plan = TeamPlan(
        steps=[
            TeamStep(role="researcher", objective="Collect facts", done_when="facts", depends_on=()),
            TeamStep(role="developer", objective="Build payload", done_when="payload", depends_on=()),
            TeamStep(role="executor", objective="Verify payload", done_when="evidence", depends_on=()),
        ]
    )

    await run_team_pentest(
        root,
        user_input="Capture the flag",
        target="https://example.com",
        planner=lambda agent, origin, goal, facts: plan,
        adviser=lambda agent, origin, goal, step, step_result: TeamDecision(action="continue"),
        agent_factory=FakeAgent,
        max_steps=1,
        max_parallel=3,
    )

    assert FakeAgent.solve_order == ["researcher"]


@pytest.mark.asyncio
async def test_each_dispatched_step_is_recorded_under_the_leader_node():
    from vulnclaw.agent.team import LEADER_ROLE, TeamPlan, TeamStep, run_team_pentest

    root = FakeAgent()
    roles = ["researcher", "executor", "developer"]
    plan = TeamPlan(
        steps=[
            TeamStep(role=role, objective=f"{role} work", done_when=f"{role} done")
            for role in roles
        ]
    )
    result = await run_team_pentest(
        root,
        user_input="Capture the flag",
        target="https://example.com",
        planner=lambda agent, origin, goal, facts: plan,
        adviser=lambda agent, origin, goal, step, step_result: {"action": "continue"},
        agent_factory=lambda: FakeAgent(),
        max_steps=8,
    )

    graph = root.agent_graph
    snapshot = graph.view_graph()
    assert snapshot.root_id is not None

    nodes = {node.id: node for node in snapshot.nodes}
    leader = nodes[snapshot.root_id]
    assert leader.role == LEADER_ROLE
    assert leader.parent_id is None
    assert leader.status.value == "done"
    assert leader.outcome.value == "finished"

    # Every planned step became a finished child of the leader.
    assert [step.role for step in result.plan.steps] == roles
    children = [node for node in snapshot.nodes if node.parent_id == snapshot.root_id]
    assert sorted(child.role for child in children) == sorted(roles)
    assert all(child.status.value == "done" for child in children)
    assert len(snapshot.nodes) == len(roles) + 1, "leader plus one node per step"


@pytest.mark.asyncio
async def test_a_failing_step_is_recorded_as_failed_rather_than_dropped():
    from vulnclaw.agent.team import run_team_pentest

    class ExplodingAgent(FakeAgent):
        async def solve(self, prompt, **kwargs):
            raise RuntimeError("worker exploded")

    root = FakeAgent()

    await run_team_pentest(
        root,
        user_input="Capture the flag",
        target="https://example.com",
        # An empty plan takes the documented single-executor fallback.
        planner=lambda agent, origin, goal, facts: {"steps": []},
        adviser=lambda agent, origin, goal, step, step_result: {"action": "continue"},
        agent_factory=ExplodingAgent,
        max_steps=4,
    )

    children = [
        node
        for node in root.agent_graph.view_graph().nodes
        if node.parent_id == root.agent_graph.root_id
    ]
    assert len(children) == 1
    assert children[0].status.value == "done"
    assert children[0].outcome.value == "failed"
    assert "worker exploded" in (children[0].error or "")
