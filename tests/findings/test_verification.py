import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.findings.intake import submit_finding
from vulnclaw.findings.types import EvidenceReview, FindingAssessment
from vulnclaw.findings.verification import verify_findings
from vulnclaw.report.findings_output import build_findings_document, to_sarif
from vulnclaw.report.generator import generate_report


@pytest.fixture
def candidate(tmp_path):
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    config.session.auto_save = False
    state = SessionState(target='https://lab.test')
    state.agent_state.remember_tool_result(
        tool='fetch', arguments={'url': 'https://lab.test/login'}, target=state.target,
        output='Observed a SQL error on the actual login request',
    )
    agent = SimpleNamespace(config=config, context=SimpleNamespace(state=state), session_state=state)
    submit_finding(agent, {'title': 'Injection candidate', 'description': 'Observed request error',
                          'vuln_type': 'SQLi', 'severity': 'High', 'endpoint': 'https://lab.test/login',
                          'evidence_ids': ['e001']})
    return config, state


def review(confidence='high'):
    return EvidenceReview(confidence=confidence, reason='A direct observation remains unverified',
                          observations=[{'evidence_id': 'e001', 'quote': 'Observed a SQL error'}],
                          missing_checks=['Independent reproduction'])


async def test_default_disabled_poc_still_reviews_and_cannot_promote(candidate, monkeypatch):
    config, state = candidate
    calls = []
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *args: calls.append(args) or review())
    poc = AsyncMock()
    monkeypatch.setattr('vulnclaw.findings.verification.execute_plan', poc)
    state.findings[0].mark_verified('Previous conclusion')
    view = await verify_findings(state, config=config)
    assert len(calls) == 1 and poc.await_count == 0
    assert not state.findings[0].verified
    assert not view.findings[0].verified
    assert view.findings[0].assessment.outcome == 'suspected_high'
    assert view.findings[0].previous_verification['verification_status'] == 'verified'
    assert to_sarif(view.findings)['runs'][0]['results'] == []


@pytest.mark.parametrize('invalid', [
    EvidenceReview(confidence='high', reason='unsupported', observations=[]),
    EvidenceReview(confidence='high', reason='wrong id', observations=[{'evidence_id': 'e999', 'quote': 'SQL error'}]),
    EvidenceReview(confidence='high', reason='invented quote', observations=[{'evidence_id': 'e001', 'quote': 'RCE confirmed'}]),
])
async def test_review_invalid_references_are_incomplete_low(candidate, monkeypatch, invalid, i18n_language):
    config, state = candidate
    i18n_language("zh")  # pin the incomplete marker regardless of auto-detection
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *args: invalid)
    view = await verify_findings(state, config=config)
    result = view.findings[0].assessment
    assert result.outcome == 'suspected_low' and not result.complete
    assert '校验未完成' in result.reason


async def test_snapshot_tampering_never_reaches_review(candidate, monkeypatch):
    config, state = candidate
    ref = state.findings[0].evidence_snapshots[0]
    (Path(ref.root) / ref.path).write_text('{}')
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *args: pytest.fail('Tampered snapshots'))
    view = await verify_findings(state, config=config)
    assert not view.findings[0].assessment.complete
    assert 'integrity' in view.findings[0].assessment.reason


async def test_poc_unavailable_falls_back_to_review(candidate, monkeypatch):
    config, state = candidate
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *args: review('low'))
    view = await verify_findings(state, config=config, poc_verify=True)
    result = view.findings[0].assessment
    assert result.method == 'evidence_review' and result.outcome == 'suspected_low'
    assert 'No supported' in result.failure_reason


@pytest.mark.parametrize('outcome', ['verified', 'rejected'])
async def test_conclusive_poc_updates_new_session_and_audits(candidate, monkeypatch, outcome):
    config, state = candidate
    monkeypatch.setattr('vulnclaw.findings.verification.build_plan', lambda *args: object())
    assessment = FindingAssessment(outcome=outcome, method='poc', reason='A controlled test gave a conclusive result', evidence_ids=['e001'])
    monkeypatch.setattr('vulnclaw.findings.verification.execute_plan', AsyncMock(return_value=assessment))
    path = state.save(config.session.output_dir / 'new-session.json')
    view = await verify_findings(state, config=config, poc_verify=True)
    restored = SessionState.load(path)
    assert restored.findings[0].verification_status == outcome
    assert restored.findings[0].verification_history[-1].reason == assessment.reason
    document = build_findings_document(view)
    assert document['schema_version'] == '1.2'
    assert document['summary'][outcome] == 1
    assert len(to_sarif(view.findings)['runs'][0]['results']) == (1 if outcome == 'verified' else 0)


async def test_changed_input_does_not_receive_stale_verdict(candidate, monkeypatch):
    config, state = candidate
    async def changed(*args, **kwargs):
        state.findings[0].description = 'Updated by the running task'
        return FindingAssessment(outcome='verified', method='poc', reason='Old result')
    monkeypatch.setattr('vulnclaw.findings.verification.assess_finding', changed)
    view = await verify_findings(state, config=config)
    assert not state.findings[0].verified and state.findings[0].verification_history == []
    assert not view.findings[0].assessment.complete


async def test_cancel_stops_generation_without_fallback(candidate, monkeypatch):
    config, state = candidate
    monkeypatch.setattr('vulnclaw.findings.verification.build_plan', lambda *args: object())
    monkeypatch.setattr('vulnclaw.findings.verification.execute_plan', AsyncMock(side_effect=asyncio.CancelledError()))
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *args: pytest.fail('cancelled'))
    with pytest.raises(asyncio.CancelledError):
        await verify_findings(state, config=config, poc_verify=True)
    assert state.findings[0].verification_history == []


async def test_legacy_state_is_only_read_and_never_rewritten(tmp_path):
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    path = tmp_path / 'old.json'
    path.write_text(json.dumps({'target': 'lab.test', 'findings': [{'title': 'Old claim', 'verified': True}]}))
    original = path.read_bytes()
    state = SessionState.load(path)
    from vulnclaw.finding_service import verify_session_file

    view, audited_path = await verify_session_file(str(path), config=config)
    assert audited_path != path and audited_path.exists()
    assert path.read_bytes() == original
    assert state.findings[0].verified and not view.findings[0].verified
    assert not view.findings[0].assessment.complete


async def test_report_and_machine_outputs_use_current_review(candidate, monkeypatch):
    config, state = candidate
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *args: review())
    view = await verify_findings(state, config=config)
    path = await generate_report(view, str(config.session.output_dir / 'report.md'), llm_attack_summary='A suspected finding requires reproduction')
    text = path.read_text(encoding='utf-8')
    assert 'suspected' in text or '疑似' in text
    artifact_dir = path.parent / 'report.artifacts' / 'findings'
    document = json.loads((artifact_dir / 'findings.json').read_text(encoding='utf-8'))
    assert document['summary']['suspected_high'] == 1
    assert document['verified'] == []
    assert json.loads(
        (artifact_dir / 'findings.sarif').read_text(encoding='utf-8')
    )['runs'][0]['results'] == []


def test_export_cannot_bypass_assessment():
    state = SessionState()
    state.add_finding(VulnerabilityFinding(title='Self-certified', verified=True))
    with pytest.raises(ValueError, match='assessment'):
        to_sarif(state.findings)


async def test_unchanged_results_reuse_but_explicit_audits_repeat(candidate, monkeypatch):
    config, state = candidate
    calls = []
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm',
                        lambda *_: calls.append(1) or review())
    first = await verify_findings(state, config=config)
    await verify_findings(state, config=config)
    assert len(calls) == 1 and len(state.findings[0].verification_history) == 1
    first.findings[0].assessment.reason = 'Changed by snapshot consumer'
    assert state.findings[0].assessment.reason != first.findings[0].assessment.reason
    await verify_findings(state, config=config, reuse=False)
    assert len(calls) == 2 and len(state.findings[0].verification_history) == 2


async def test_changed_inputs_and_poc_upgrade_trigger_audit(candidate, monkeypatch):
    config, state = candidate
    calls = []
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm',
                        lambda *_: calls.append(1) or review())
    await verify_findings(state, config=config)
    state.findings[0].description = 'A new observation needs assessment'
    await verify_findings(state, config=config)
    assert len(calls) == 2
    config.session.poc_verify_enabled = True
    await verify_findings(state, config=config)
    assert len(calls) == 3 and state.findings[0].assessment.poc_attempted
    await verify_findings(state, config=config)
    assert len(calls) == 3


async def test_cached_assessment_rechecks_evidence_integrity(candidate, monkeypatch):
    config, state = candidate
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *_: review())
    await verify_findings(state, config=config)
    ref = state.findings[0].evidence_snapshots[0]
    (Path(ref.root) / ref.path).write_text('{}')
    view = await verify_findings(state, config=config)
    assert not view.findings[0].assessment.complete
    assert not state.findings[0].assessment.complete
    assert len(state.findings[0].verification_history) == 2


async def test_incomplete_audit_retries_and_save_failure_rolls_back(candidate, monkeypatch):
    config, state = candidate
    assess = AsyncMock(return_value=FindingAssessment(
        outcome='suspected_low', method='evidence_review', reason='Unavailable', complete=False,
    ))
    monkeypatch.setattr('vulnclaw.findings.verification.assess_finding', assess)
    await verify_findings(state, config=config)
    await verify_findings(state, config=config)
    assert assess.await_count == 2
    prior = state.findings[0].model_dump(mode='json')

    def cannot_save(*_args):
        raise OSError('Disk full')

    state.set_checkpoint_callback(cannot_save)
    assess.return_value = FindingAssessment(outcome='verified', method='poc', reason='Controlled')
    with pytest.raises(OSError, match='Disk full'):
        await verify_findings(state, config=config)
    assert state.findings[0].model_dump(mode='json') == prior


async def test_renderers_consume_snapshot_without_auditing_or_mutating(candidate, monkeypatch):
    from vulnclaw.report.generator import generate_persistent_cycle_report

    config, state = candidate
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *_: review())
    view = await verify_findings(state, config=config)
    prior = view.model_dump(mode='json')
    monkeypatch.setattr('vulnclaw.findings.verification.assess_finding',
                        AsyncMock(side_effect=AssertionError('Renderer called verification')))
    for fmt in ('markdown', 'html'):
        path = await generate_report(
            view, str(config.session.output_dir / f'render-{fmt}.md'),
            report_format=fmt, llm_attack_summary='Saved conclusions',
        )
        document = json.loads(
            (path.parent / (path.stem + '.artifacts') / 'findings' / 'findings.json')
            .read_text(encoding='utf-8')
        )
        assert document['summary']['suspected_high'] == 1
        assert document['verified'] == []
    await generate_persistent_cycle_report(
        view, 1, str(config.session.output_dir / 'cycle.md'),
        llm_attack_summary='Saved conclusions',
    )
    assert view.model_dump(mode='json') == prior
    view.findings[0].description = 'Changed after handoff'
    with pytest.raises(ValueError, match='assessment'):
        await generate_report(view, str(config.session.output_dir / 'stale.md'))


async def test_file_audit_caches_without_rewriting_source(candidate, monkeypatch):
    from vulnclaw.finding_service import verify_session_file

    config, state = candidate
    source = state.save(config.session.output_dir / 'historical.json')
    original = source.read_bytes()
    calls = []
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm',
                        lambda *_: calls.append(1) or review())
    _view, path = await verify_session_file(str(source), config=config, reuse=True)
    await verify_session_file(str(source), config=config, reuse=True)
    assert len(calls) == 1 and source.read_bytes() == original
    assert path != source and SessionState.load(path).findings[0].assessment.complete
    await verify_session_file(str(source), config=config)
    assert len(calls) == 2


async def test_task_completion_audits_and_persists_before_summary(candidate, monkeypatch):
    import vulnclaw.target_state.store as store
    from vulnclaw.orchestrator import run_agent_task

    config, state = candidate
    monkeypatch.setattr(store, 'TARGETS_DIR', config.session.output_dir / 'targets')
    config.session.runs_dir = config.session.output_dir / 'runs'
    agent = SimpleNamespace(config=config, context=SimpleNamespace(state=state),
                            session_state=state, runtime=None)
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *_: review())
    result = await run_agent_task(agent=agent, command='run', target=state.target,
                                  resume=False, runner=AsyncMock())
    raw = json.loads(
        result.run_context.state_path(result.run_context.targets[0]).read_text(encoding='utf-8')
    )
    assert raw['findings'][0]['assessment']['outcome'] == 'suspected_high'
    assert raw['resume_meta']['checkpoint_reason'] == 'run_complete'
    assert result.audited_session.findings[0].assessment.complete
    assert result.status == 'completed'


@pytest.mark.parametrize('auto_report', [False, True])
async def test_persistent_cycle_audits_before_summary_and_callback(candidate, monkeypatch, auto_report):
    from vulnclaw.agent.core import AgentCore
    from vulnclaw.agent.loop_controller import persistent_pentest
    from vulnclaw.agent.runtime_state import AgentResult

    config, state = candidate
    agent = AgentCore(config)
    agent.context.state = state
    order = []
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm',
                        lambda *_: order.append('audit') or review())
    monkeypatch.setattr(agent, 'auto_pentest', AsyncMock(return_value=[AgentResult(should_continue=True)]))

    async def summary():
        assert state.findings[0].assessment.complete
        order.append('summary')
        return 'Saved conclusions'

    async def report(**kwargs):
        assert kwargs['session'].findings[0].assessment.complete
        assert 'config' not in kwargs
        order.append('report')
        return config.session.output_dir / 'cycle.md'

    monkeypatch.setattr(agent, '_generate_attack_summary', summary)
    monkeypatch.setattr('vulnclaw.report.generator.generate_persistent_cycle_report', report)
    await persistent_pentest(
        agent, 'Review the target', target=state.target, max_cycles=1, auto_report=auto_report,
        on_cycle_complete=lambda *_: order.append('complete'),
    )
    assert order == ['audit', 'summary', *(['report'] if auto_report else []), 'complete']
    assert SessionState.load(state._save_path).findings[0].assessment.complete


async def test_verify_cli_and_web_endpoint_delegate_to_independent_audits(candidate, monkeypatch):
    from typer.testing import CliRunner

    import vulnclaw.cli.main as cli
    import vulnclaw.finding_service as service
    import vulnclaw.web.auth as auth
    from vulnclaw.web.app import create_app

    config, state = candidate
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *_: review())
    view = await verify_findings(state, config=config)
    calls = []

    async def target_audit(target, *, config, poc_verify):
        calls.append((target, poc_verify))
        return view, config.session.output_dir / 'audited.json', {}

    monkeypatch.setattr(service, 'verify_target', target_audit)
    monkeypatch.setattr(cli, 'load_config', lambda: config)
    monkeypatch.setattr('vulnclaw.config.settings.load_config', lambda: config)
    result = await asyncio.to_thread(CliRunner().invoke, cli.app,
                                    ['verify', state.target, '--target', '--poc-verify'])
    assert result.exit_code == 0, result.output
    # Rich can wrap a long Windows path inside the filename.
    assert 'audited.json' in ''.join(result.output.splitlines())
    monkeypatch.setattr(auth, 'verify_token', lambda _: True)
    client = pytest.importorskip('fastapi.testclient').TestClient(create_app())
    response = await asyncio.to_thread(
        client.post, '/api/findings/verify', headers={'Authorization': 'Bearer test'},
        json={'target': state.target, 'poc_verify': False},
    )
    assert response.status_code == 200
    assert response.json()['summary']['suspected_high'] == 1
    assert calls == [(state.target, True), (state.target, False)]
    report_help = CliRunner().invoke(cli.app, ['report', '--help'])
    assert '--poc-verify' not in report_help.output


def test_legacy_fields_migrate_without_dual_serialization():
    from vulnclaw.config.settings import _merge_config

    config = _merge_config(VulnClawConfig(), {'session': {'report_poc_verify_enabled': True}})
    assert config.session.poc_verify_enabled
    assert 'report_poc_verify_enabled' not in config.session.model_dump()
    config = _merge_config(config, {'session': {'report_poc_verify_enabled': True,
                                               'poc_verify_enabled': False}})
    assert not config.session.poc_verify_enabled
    finding = VulnerabilityFinding.model_validate({
        'title': 'Historical candidate', 'vuln_type': 'SQLi', 'evidence': 'Old observation',
        'report_assessment': {'outcome': 'suspected_low', 'method': 'evidence_review', 'reason': 'Old'},
    })
    assert finding.assessment.reason == 'Old'
    assert 'report_assessment' not in finding.model_dump()
    assert not finding.assessment.input_digest


async def test_target_export_reuses_audit_without_new_checkpoint(candidate, monkeypatch):
    import vulnclaw.target_state.store as store
    from vulnclaw.finding_service import verify_target

    config, state = candidate
    monkeypatch.setattr(store, 'TARGETS_DIR', config.session.output_dir / 'targets')
    source = store.save_target_state(state.target, state, command='initial')
    calls = []
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm',
                        lambda *_: calls.append(1) or review())
    await verify_target(state.target, config=config, reuse=True)
    current = source.read_bytes()
    _view, path, _raw = await verify_target(state.target, config=config, reuse=True)
    assert len(calls) == 1
    assert path == source and source.read_bytes() == current


async def test_target_audit_does_not_overwrite_concurrent_task_updates(candidate, monkeypatch):
    import vulnclaw.target_state.store as store
    from vulnclaw.finding_service import FindingStateChangedError, verify_target

    config, state = candidate
    monkeypatch.setattr(store, 'TARGETS_DIR', config.session.output_dir / 'targets')
    store.save_target_state(state.target, state, command='initial')

    async def concurrent_update(*_args, **_kwargs):
        current = SessionState(**store.load_target_state(state.target))
        current.findings[0].description = 'New evidence from the running task'
        store.save_target_state(state.target, current, command='concurrent', merge_existing=False)
        return FindingAssessment(outcome='verified', method='poc', reason='Old input result')

    monkeypatch.setattr('vulnclaw.findings.verification.assess_finding', concurrent_update)
    with pytest.raises(FindingStateChangedError, match='changed during audit'):
        await verify_target(state.target, config=config)
    current = store.load_target_state(state.target)
    assert current['findings'][0]['description'] == 'New evidence from the running task'
    assert current['findings'][0]['assessment'] is None


async def test_failed_poc_is_incomplete_and_retried(candidate, monkeypatch):
    config, state = candidate
    execute = AsyncMock(side_effect=TimeoutError('controlled timeout'))
    monkeypatch.setattr('vulnclaw.findings.verification.build_plan', lambda *_: object())
    monkeypatch.setattr('vulnclaw.findings.verification.execute_plan', execute)
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *_: review())
    first = await verify_findings(state, config=config, poc_verify=True)
    await verify_findings(state, config=config, poc_verify=True)
    result = first.findings[0].assessment
    assert (result.outcome, result.complete, execute.await_count) == ('suspected_low', False, 2)


@pytest.mark.parametrize('removed', [False, True])
async def test_replaced_candidate_does_not_return_unsaved_success(candidate, monkeypatch, removed):
    config, state = candidate

    async def replace(*_args, **_kwargs):
        if removed:
            state.findings.clear()
        else:
            replacement = state.findings[0].model_copy(deep=True)
            replacement.description = 'New input on replacement object'
            state.findings[0] = replacement
        return FindingAssessment(outcome='verified', method='poc', reason='Old input')

    monkeypatch.setattr('vulnclaw.findings.verification.assess_finding', replace)
    view = await verify_findings(state, config=config)
    assert not view.findings[0].assessment.complete
    assert not view.findings[0].verified


@pytest.mark.parametrize('structured', [False, True])
async def test_legacy_target_queries_use_current_assessment(candidate, monkeypatch, structured):
    import vulnclaw.target_state.store as store
    import vulnclaw.web.services.target_service as targets

    config, state = candidate
    monkeypatch.setattr(store, 'TARGETS_DIR', config.session.output_dir / 'targets')
    monkeypatch.setattr(targets, 'TARGETS_DIR', store.TARGETS_DIR)
    monkeypatch.setattr('vulnclaw.findings.verification._review_with_llm', lambda *_: review())
    if not structured:
        state.findings[0].submission_id = ''
    await verify_findings(state, config=config)
    path = store.save_target_state(state.target, state, command='test')
    raw = json.loads(path.read_text(encoding='utf-8'))
    # Old persisted flags conflict with the current fingerprinted assessment.
    raw['findings'][0]['verified'] = True
    raw['findings'][0]['verification_status'] = 'verified'
    raw['findings'][0]['report_assessment'] = raw['findings'][0].pop('assessment')
    path.write_text(json.dumps(raw))
    original = path.read_bytes()
    restored = SessionState(**store.load_target_state(state.target))
    view = targets.get_target(state.target)
    preview = store.get_target_state_preview(state.target)
    assert not restored.findings[0].verified
    assert (view.verified_count, view.raw['findings'][0]['verified'], preview['verified_count']) == (0, False, 0)
    listed = targets.list_targets()[0]
    assert listed.verified_count == 0 and not listed.raw['findings'][0]['verified']
    assert 'report_assessment' not in view.raw['findings'][0]
    assert 'report_assessment' not in listed.raw['findings'][0]
    assert path.read_bytes() == original


@pytest.mark.parametrize('failure', ['cancel', 'save'])
async def test_audit_failure_preserves_previously_saved_progress(candidate, monkeypatch, failure):
    from vulnclaw.run_context import atomic_write_json

    config, state = candidate
    second = state.findings[0].model_copy(deep=True)
    second.finding_id = 'second'
    second.title = 'Second candidate'
    second.endpoint = 'https://lab.test/second'
    state.findings.append(second)
    path = config.session.output_dir / 'progress.json'

    def checkpoint(session, _reason):
        if failure == 'save' and session.findings[1].assessment:
            raise OSError('Disk full')
        atomic_write_json(path, session.model_dump(mode='json'))

    state.set_checkpoint_callback(checkpoint)

    async def assess(_session, finding, *_args, **_kwargs):
        if failure == 'cancel' and finding.title == 'Second candidate':
            raise asyncio.CancelledError()
        return FindingAssessment(outcome='verified', method='poc', reason='Controlled result')

    monkeypatch.setattr('vulnclaw.findings.verification.assess_finding', assess)
    with pytest.raises(asyncio.CancelledError if failure == 'cancel' else OSError):
        await verify_findings(state, config=config)
    restored = SessionState.load(path)
    assert restored.findings[0].assessment.outcome == 'verified'
    assert state.findings[0].assessment.outcome == 'verified'
    assert restored.findings[1].assessment is None and state.findings[1].assessment is None
    assert not restored.findings[1].verification_history
