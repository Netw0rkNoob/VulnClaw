import json
from unittest.mock import AsyncMock

import pytest

from vulnclaw.agent.core import AgentCore
from vulnclaw.agent.tool_call_manager import _record_tool_result_with_record
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.findings.evidence import load_snapshots
from vulnclaw.findings.intake import submit_finding


@pytest.fixture
def agent(tmp_path, monkeypatch):
    cfg = VulnClawConfig()
    cfg.session.output_dir = tmp_path
    cfg.session.auto_save = False
    monkeypatch.setattr(AgentCore, '_report_kb_status', lambda self: None)
    obj = AgentCore(cfg)
    obj.session_state.target = 'https://lab.test'
    return obj


def record(agent, path='/login', *, method='GET', content='SQL error under review'):
    return agent.session_state.agent_state.remember_tool_result(
        tool='fetch', arguments={'url': 'https://lab.test' + path, 'method': method},
        output=content, target=agent.session_state.target,
    ).id


def payload(evidence_id='e001', **overrides):
    return {'title': 'Login injection candidate', 'vuln_type': 'SQLi', 'severity': 'High',
            'description': 'An actual request produced an error that needs verification.',
            'endpoint': 'https://lab.test/login', 'evidence_ids': [evidence_id], **overrides}


def test_explicit_submission_snapshots_and_deduplicates(agent):
    key = record(agent)
    first = json.loads(submit_finding(agent, payload(key)))
    second = json.loads(submit_finding(agent, payload(key)))
    assert first['action'] == 'created' and second['action'] == 'duplicate'
    assert first['finding_id'] == second['finding_id']
    finding = agent.session_state.findings[0]
    assert not finding.verified and finding.verification_status == 'pending'
    agent.session_state.agent_state.evidence.clear()
    assert load_snapshots(finding)[key].content == 'SQL error under review'


@pytest.mark.parametrize('threshold', [0.75, 0.6])
def test_different_structured_types_never_merge_via_prose(agent, threshold):
    agent.session_state.semantic_dedup_threshold = threshold
    key = record(agent)
    submit_finding(agent, payload(key))
    submit_finding(agent, payload(key, vuln_type='XSS'))
    assert {f.vuln_type for f in agent.session_state.findings} == {
        'sql_injection', 'cross_site_scripting',
    }


@pytest.mark.parametrize(('first', 'equivalent'), [
    ('https://lab.test/login', 'https://LAB.test:443/login'),
    ('https://lab.test', 'https://lab.test:443/'),
    ('https://lab.test/login?q=1', 'https://lab.test:443/login?q=1#fragment'),
])
def test_equivalent_endpoints_have_one_structured_identity(agent, first, equivalent):
    record = agent.session_state.agent_state.remember_tool_result(
        tool='fetch', arguments={'url': first}, output='observed', target=agent.session_state.target,
    )
    one = json.loads(submit_finding(agent, payload(record.id, endpoint=first)))
    two = json.loads(submit_finding(agent, payload(record.id, endpoint=equivalent)))
    assert one['finding_id'] == two['finding_id']
    assert two['action'] == 'duplicate'
    assert len(agent.session_state.findings) == 1


@pytest.mark.parametrize('other', [
    'https://lab.test/login?q=2', 'https://lab.test:8443/login?q=1',
    'http://lab.test/login?q=1', 'https://lab.test/Login?q=1',
])
def test_endpoint_normalization_preserves_request_semantics(agent, other):
    for endpoint in ['https://lab.test/login?q=1', other]:
        record = agent.session_state.agent_state.remember_tool_result(
            tool='fetch', arguments={'url': endpoint}, output='observed',
            target=agent.session_state.target,
        )
        submit_finding(agent, payload(record.id, endpoint=endpoint))
    assert len(agent.session_state.findings) == 2


@pytest.mark.parametrize('override', [
    {'verified': True}, {'evidence_level': 'L4'}, {'evidence': 'invented'},
    {'evidence_ids': []}, {'evidence_ids': ['e999']}, {'title': '   '},
    {'endpoint': 'https://outside.test/login'}, {'endpoint': 'https://lab.test/other'},
    {'method': 'POST'}, {'severity': 'certain'},
])
def test_invalid_submissions_do_not_mutate_findings(agent, override):
    record(agent)
    with pytest.raises(ValueError):
        submit_finding(agent, payload(**override))
    assert agent.session_state.findings == []


def test_evidence_collected_for_another_target_cannot_be_relabelled(agent):
    record(agent)
    agent.session_state.target = 'https://another.test'
    with pytest.raises(ValueError, match='another target'):
        submit_finding(agent, payload(endpoint=None))


def test_snapshot_write_failure_does_not_leave_a_finding(agent, monkeypatch):
    record(agent)
    def fail(*args):
        raise OSError('disk is full')
    monkeypatch.setattr('vulnclaw.findings.evidence.atomic_write_json', fail)
    with pytest.raises(OSError):
        submit_finding(agent, payload())
    assert agent.session_state.findings == []


def test_locations_and_methods_are_distinct_and_new_evidence_preserves_terminal_status(agent):
    one = record(agent)
    two = record(agent, '/other')
    three = record(agent, method='POST')
    submit_finding(agent, payload(one))
    submit_finding(agent, payload(two, endpoint='https://lab.test/other'))
    submit_finding(agent, payload(three, method='POST'))
    assert len(agent.session_state.findings) == 3
    original = agent.session_state.findings[0]
    original.mark_rejected('Controlled test disproved this specific assertion')
    extra = record(agent, content='Additional observation')
    result = json.loads(submit_finding(agent, payload(extra)))
    assert result['action'] == 'updated' and original.verification_status == 'rejected'
    assert len(original.evidence_snapshots) == 2


def record_batch(agent, requests, base_url='https://lab.test'):
    return agent.session_state.agent_state.remember_tool_result(
        tool='http_probe_batch', arguments={'base_url': base_url, 'requests': requests},
        output='batch probe results', target=agent.session_state.target,
    ).id


def test_batch_probe_evidence_concerns_the_submitted_endpoint(agent):
    key = record_batch(agent, [
        {'url': '/cmd', 'method': 'GET', 'params': {'arg': 'id'}},
        {'url': 'https://lab.test/other'},
        {'method': 'POST', 'url': '/submit'},
    ])
    result = json.loads(submit_finding(agent, payload(key, endpoint='https://lab.test/cmd')))
    assert result['action'] == 'created'
    assert agent.session_state.findings[0].method == 'GET'


def test_batch_probe_post_spec_supports_a_post_candidate(agent):
    key = record_batch(agent, [{'url': '/submit', 'method': 'POST'}])
    with pytest.raises(ValueError, match='HTTP method'):
        submit_finding(agent, payload(key, endpoint='https://lab.test/submit', method='GET'))
    assert agent.session_state.findings == []
    result = json.loads(submit_finding(
        agent, payload(key, endpoint='https://lab.test/submit', method='POST')))
    assert result['action'] == 'created'
    assert agent.session_state.findings[0].method == 'POST'


@pytest.mark.parametrize('spec', [
    {'params': {'arg': 'id'}},
    {'method': 'POST', 'json': {'arg': 'id'}},
])
def test_batch_probe_can_submit_evidence_using_only_base_url(agent, spec):
    from vulnclaw.agent.builtin_tools import _prepare_http_probe_request

    endpoint = 'https://lab.test/cmd'
    prepared = _prepare_http_probe_request(agent, endpoint, 1, spec)
    assert 'error' not in prepared
    key = record_batch(agent, [spec], base_url=endpoint)
    result = json.loads(submit_finding(
        agent, payload(key, endpoint=prepared['url'], method=prepared['method']),
    ))
    assert result['action'] == 'created'
    assert agent.session_state.findings[0].method == prepared['method']


def test_unresolvable_relative_batch_urls_do_not_match(agent):
    key = record_batch(agent, [{'url': '/cmd'}], base_url='')
    with pytest.raises(ValueError, match='concerns the submitted endpoint'):
        submit_finding(agent, payload(key, endpoint='https://lab.test/cmd'))
    assert agent.session_state.findings == []


def test_evidence_from_another_port_or_scheme_cannot_concern_the_endpoint(agent):
    key = record(agent, path='/cmd')
    with pytest.raises(ValueError, match='concerns the submitted endpoint'):
        submit_finding(agent, payload(key, endpoint='https://lab.test:8443/cmd'))
    with pytest.raises(ValueError, match='concerns the submitted endpoint'):
        submit_finding(agent, payload(key, endpoint='http://lab.test/cmd'))
    assert agent.session_state.findings == []


def test_default_ports_are_equivalent_for_endpoint_matching(agent):
    key = record(agent, path='/cmd')
    result = json.loads(submit_finding(agent, payload(key, endpoint='https://lab.test:443/cmd')))
    assert result['action'] == 'created'
    assert len(agent.session_state.findings) == 1


def test_receipts_are_not_new_evidence(agent):
    record(agent)
    content, evidence, raw = _record_tool_result_with_record(
        agent, 'submit_finding', payload(), '{"finding_id":"x"}',
    )
    assert evidence is None and len(agent.session_state.agent_state.evidence) == 1
    assert raw == content


@pytest.mark.parametrize('response', [
    '[Critical] Example RCE\n确认：命令执行成功\nflag{example}',
    'SQL injection may cause SQL errors and HTTP 500. For example, /login?id=1.',
    'FINAL: SQL injection confirmed, evidence=e001',
])
async def test_conversation_cannot_submit_or_verify_a_finding(agent, monkeypatch, response):
    monkeypatch.setattr('vulnclaw.agent.core.call_llm', AsyncMock(return_value=response))
    monkeypatch.setattr(agent, '_build_system_prompt', lambda *args, **kwargs: 'system')
    await agent.chat('Explain vulnerability categories', target='https://lab.test')
    agent._observation_parser.parse(response)
    assert agent.session_state.findings == []


def test_tool_registration_respects_roles(agent):
    from vulnclaw.agent.builtin_tools import build_openai_tools
    for role in (None, 'researcher', 'executor', 'developer', 'verifier', 'group-leader'):
        names = {item['function']['name'] for item in build_openai_tools(None, active_role=role)}
        assert 'submit_finding' in names
    names = {item['function']['name'] for item in build_openai_tools(None, active_role='adviser')}
    assert 'submit_finding' not in names


def test_child_evidence_id_collision_keeps_immutable_evidence(agent):
    from vulnclaw.agent.context import SessionState
    from vulnclaw.agent.parallel_agents import merge_session_state
    record(agent, content='parent output')
    child = AgentCore(agent.config)
    child.context.state = SessionState(target=agent.session_state.target, task_id='leaf')
    key = record(child, content='child output')
    submit_finding(child, payload(key))
    merge_session_state(agent.session_state, child.session_state)
    finding = agent.session_state.findings[0]
    snapshots = load_snapshots(finding)
    assert list(snapshots.values())[0].content == 'child output'
    assert list(snapshots) != ['e001']


async def test_tool_executes_through_existing_dispatch(agent):
    record(agent)
    result = await agent._execute_mcp_tool('submit_finding', payload())
    assert json.loads(result)['action'] == 'created'
    assert len(agent.session_state.findings) == 1
