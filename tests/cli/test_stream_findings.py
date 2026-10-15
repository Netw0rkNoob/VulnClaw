"""Streamed findings must come from registered candidates, not task completion claims."""

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import vulnclaw.cli.main as cli
from vulnclaw.agent.context import SessionState
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.findings.intake import submit_finding


@pytest.mark.parametrize('command', ['run', 'solve'])
@pytest.mark.parametrize('submit_candidate', [False, True])
def test_stream_completion_uses_registered_candidates(
    tmp_path, monkeypatch, command, submit_candidate,
):
    config = VulnClawConfig()
    config.llm.api_key = 'test-key'
    config.session.output_dir = tmp_path
    config.session.auto_save = False
    state = SessionState(target='https://lab.test')
    record = state.agent_state.remember_tool_result(
        tool='fetch', arguments={'url': state.target}, output='normal page', target=state.target,
    )
    state.agent_state.mark_complete('Normal page loaded', evidence_ids=[record.id])

    class Agent:
        def __init__(self):
            self.config = config
            self.session_state = state
            self.context = SimpleNamespace(state=state)

        async def solve(self, *_args, **_kwargs):
            return SimpleNamespace(completed=True, steps=1)

    agent = Agent()
    if submit_candidate:
        submit_finding(agent, {
            'title': 'Headers require review', 'description': 'Recorded request needs analysis',
            'vuln_type': 'security_headers', 'severity': 'Low', 'endpoint': state.target,
            'evidence_ids': [record.id],
        })

    async def orchestrated(*, runner, **_kwargs):
        await runner(agent, config)
        return SimpleNamespace(summary={'findings_count': len(state.findings)})

    monkeypatch.setattr(cli, 'load_config', lambda: config)
    monkeypatch.setattr(cli, '_run_cli_orchestrated_task', orchestrated)
    result = CliRunner().invoke(cli.app, [command, state.target, '--stream'])
    assert result.exit_code == 0, result.exception
    events = [json.loads(line) for line in result.output.splitlines() if line.startswith('{')]
    findings = next(event for event in events if event['type'] == 'complete')['result']['findings']
    assert len(findings) == int(submit_candidate)
    if submit_candidate:
        assert findings[0]['id'] == state.findings[0].finding_id
        assert findings[0]['title'] == state.findings[0].title
        assert findings[0]['severity'] == 'Low'
        assert findings[0]['verification_status'] == 'pending'
        assert not findings[0]['verified']
        assert 'submission_id' not in findings[0]
        assert 'evidence_snapshots' not in findings[0]
        from io import StringIO

        from vulnclaw.tui_protocol import JsonlWriter

        JsonlWriter(StringIO()).event('finding', task_id='stream-task', finding=findings[0])
