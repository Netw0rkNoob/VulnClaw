"""Discovery records evidence; structured intake owns candidate registration."""

import asyncio
import json
from types import SimpleNamespace

from typer.testing import CliRunner

from vulnclaw.agent.context import SessionState
from vulnclaw.agent.network_scan import attach_network_scan_to_session
from vulnclaw.agent.team import TeamStep, _run_team_step
from vulnclaw.cli.main import app
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.findings.evidence import load_snapshots
from vulnclaw.findings.intake import submit_finding
from vulnclaw.findings.types import EvidenceReview
from vulnclaw.findings.verification import verify_findings


async def test_plugin_session_records_evidence_for_explicit_submission(tmp_path, monkeypatch):
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    config.session.auto_save = False
    monkeypatch.setattr('vulnclaw.cli.main.load_config', lambda: config)
    path = tmp_path / 'plugin-session.json'
    result = await asyncio.to_thread(CliRunner().invoke, app, [
        'plugins', 'run', 'builtin.web.headers', '--target', 'https://lab.test',
        '--option', 'headers={"server":"nginx"}', '--session', str(path),
    ])
    assert result.exit_code == 0, result.output
    state = SessionState.load(path)
    assert state.target == 'https://lab.test'
    assert state.findings == []
    assert len(state.agent_state.evidence) == 1
    record = state.agent_state.evidence[0]
    assert record.tool == 'plugin:builtin.web.headers'
    assert json.loads(record.content)['findings']
    agent = SimpleNamespace(config=config, context=SimpleNamespace(state=state), session_state=state)
    submit_finding(agent, {
        'title': 'Missing security headers', 'description': 'Review the recorded plugin result',
        'vuln_type': 'security_headers', 'severity': 'Low', 'evidence_ids': [record.id],
    })
    finding = state.findings[0]
    assert finding.submission_id
    assert load_snapshots(finding)[record.id].content == record.content
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *_: EvidenceReview(
        confidence='low', reason='Provided headers still require target reproduction',
        observations=[{'evidence_id': record.id, 'quote': 'missing_headers'}],
    ))
    view = await verify_findings(state, config=config, poc_verify=False)
    assert view.findings[0].assessment.complete
    assert view.findings[0].assessment.outcome == 'suspected_low'


def test_network_recon_does_not_implicitly_register_candidates():
    state = SessionState(target='lab.test')
    weak_link = {'host': 'lab.test', 'port': 23, 'target': 'lab.test:23',
                 'service': 'telnet', 'risk': 'unencrypted_protocol', 'severity': 'High'}
    attach_network_scan_to_session(state, {
        'target': state.target, 'open_services': [weak_link], 'weak_links': [weak_link],
    }, profile='fast')
    assert state.findings == []
    assert state.recon_data['network_scans'][0]['weak_links'] == [weak_link]
    assert state.step_records[-1].action == 'network scan'


async def test_team_uses_canonical_finding_and_parent_evidence_ids(tmp_path):
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    config.session.auto_save = False

    class Agent:
        def __init__(self):
            self.config = config
            self.session_state = SessionState(target='https://lab.test')
            self.context = SimpleNamespace(state=self.session_state)
            self.active_role = None

        async def solve(self, *_args, **_kwargs):
            state = self.session_state
            record = state.agent_state.remember_tool_result(
                tool='fetch', arguments={'url': state.target + '/cmd', 'role': self.active_role},
                output=f'{self.active_role} response', target=state.target,
            )
            state.agent_state.record_verified_claim(self.active_role, [record.id])
            submit_finding(self, {
                'title': f'{self.active_role} candidate', 'description': 'Recorded observation',
                'vuln_type': 'SQLi', 'severity': 'High', 'endpoint': state.target + '/cmd',
                'evidence_ids': [record.id],
            })
            return SimpleNamespace(completed=False, steps=1)

    root = Agent()
    root.session_state.agent_state.goal = 'root goal'
    for role in ['researcher', 'developer']:
        await _run_team_step(
            root, TeamStep(role=role, objective='probe', done_when='evidence'),
            target=root.session_state.target, agent_factory=Agent, max_steps=1, max_tool_rounds=1,
        )
    state = root.session_state
    assert len(state.findings) == 1
    assert len(load_snapshots(state.findings[0])) == 2
    assert len({record.id for record in state.agent_state.evidence}) == 2
    assert state.agent_state.evidence_seq == 2
    for claim in state.agent_state.verified_claims:
        assert len(claim.evidence_ids) == 1
        assert state.agent_state.get_evidence(claim.evidence_ids[0]).content == claim.claim + ' response'
    assert state.agent_state.goal == 'root goal'
    assert not state.agent_state.completed
    assert all(':team:' not in ref.evidence_id for ref in state.findings[0].evidence_snapshots)
