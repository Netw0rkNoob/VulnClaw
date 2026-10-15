"""Evidence aliases must preserve the meaning of saved assessment citations."""

import json
from types import SimpleNamespace

import pytest

from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.agent.parallel_agents import merge_session_state
from vulnclaw.agent.subagent.merge import EvidenceCommitter
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.findings.evidence import load_snapshots, merge_finding_evidence
from vulnclaw.findings.intake import submit_finding
from vulnclaw.findings.types import EvidenceSnapshotRef, FindingAssessment, merge_snapshot_refs


def test_reserved_aliases_and_reload_do_not_change_evidence_identity():
    def ref(key, digest):
        return EvidenceSnapshotRef(evidence_id=key, source_id='e001', sha256=digest,
                                   target='lab', root='/evidence', path=digest, fingerprint=digest)

    refs = [ref('e001', 'a'), ref('e001', 'b'), ref('e001:b', 'c'), ref('e001:b:2', 'd')]
    normalized = merge_snapshot_refs(refs)
    assert [r.evidence_id for r in normalized] == ['e001', 'e001:b:3', 'e001:b', 'e001:b:2']
    finding = VulnerabilityFinding(title='Candidate', vuln_type='SQLi', evidence_snapshots=refs)
    for _ in range(3):
        finding = VulnerabilityFinding.model_validate_json(finding.model_dump_json())
        assert finding.evidence_snapshots == normalized
    assert [r.evidence_id for r in refs] == ['e001', 'e001', 'e001:b', 'e001:b:2']


@pytest.fixture
def sessions(tmp_path):
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    config.session.auto_save = False
    states = []
    for task, text in [('parent', 'parent response'), ('child', 'child response')]:
        state = SessionState(target='https://lab.test', task_id=task)
        record = state.agent_state.remember_tool_result(
            tool='fetch', arguments={'url': state.target + '/cmd'},
            output=text, target=state.target,
        )
        agent = SimpleNamespace(config=config, context=SimpleNamespace(state=state), session_state=state)
        submit_finding(agent, {'title': 'Candidate', 'description': 'Recorded observation',
                              'vuln_type': 'SQLi', 'severity': 'High',
                              'endpoint': state.target + '/cmd', 'evidence_ids': [record.id]})
        assessment = FindingAssessment(
            outcome='suspected_high', method='evidence_review', reason=task,
            evidence_ids=[record.id], observations=[{'evidence_id': record.id, 'quote': text}],
        )
        state.findings[0].verification_history.append(assessment)
        state.findings[0].assessment = assessment.model_copy(deep=True)
        states.append(state)
    return states


def assert_citations(finding):
    snapshots = load_snapshots(finding)
    assessments = [*finding.verification_history]
    if finding.assessment:
        assessments.append(finding.assessment)
    for assessment in assessments:
        assert assessment.evidence_ids == [o['evidence_id'] for o in assessment.observations]
        for observation in assessment.observations:
            assert snapshots[observation['evidence_id']].content == observation['quote']
        assert not getattr(assessment, 'unresolved_evidence_ids', [])


@pytest.mark.parametrize('path', ['memory', 'parallel', 'committer', 'persistence'])
def test_merge_preserves_historical_citations(sessions, tmp_path, monkeypatch, path):
    import vulnclaw.target_state.store as store

    parent, child = sessions
    original_child = child.model_dump(mode='json')
    if path == 'persistence':
        monkeypatch.setattr(store, 'TARGETS_DIR', tmp_path / 'targets')
        store.save_target_state(parent.target, parent, command='test')

    def merge():
        if path == 'memory':
            merge_finding_evidence(parent.findings[0], child.findings[0])
        elif path == 'parallel':
            merge_session_state(parent, child)
        elif path == 'committer':
            EvidenceCommitter().commit(
                SimpleNamespace(context=SimpleNamespace(state=parent)), child,
                task_id='child', agent_type='test', baseline_fingerprints=set(),
                include_session_state=True,
            )
        else:
            store.save_target_state(child.target, child, command='test')

    merge()
    result = store.hydrate_session_from_target_state(parent.target) if path == 'persistence' else parent
    assert_citations(result.findings[0])
    assert len(result.findings[0].verification_history) == 2
    merge()
    result = store.hydrate_session_from_target_state(parent.target) if path == 'persistence' else parent
    assert len(result.findings[0].verification_history) == 2
    restored = SessionState.model_validate_json(result.model_dump_json())
    assert_citations(restored.findings[0])
    assert child.findings[0].verification_history[0].model_dump(mode='json') == (
        original_child['findings'][0]['verification_history'][0]
    )


def test_old_ambiguous_citations_are_flagged_instead_of_guessed(sessions):
    parent, child = sessions
    raw = parent.findings[0].model_dump(mode='json')
    raw['evidence_snapshots'] += child.findings[0].model_dump(mode='json')['evidence_snapshots']
    raw['verification_history'] += child.findings[0].model_dump(mode='json')['verification_history']
    finding = VulnerabilityFinding.model_validate(raw)
    assert len(load_snapshots(finding)) == 2
    assert all(a.unresolved_evidence_ids == ['e001'] for a in finding.verification_history)
    assert finding.assessment.unresolved_evidence_ids == ['e001']
    assert [a.observations for a in finding.verification_history] == [
        a['observations'] for a in raw['verification_history']
    ]
    assert VulnerabilityFinding.model_validate_json(finding.model_dump_json()) == finding


def test_new_child_finding_remaps_assessment_even_without_collision(sessions):
    parent, child = sessions
    parent = SessionState(target=parent.target, agent_state=parent.agent_state)
    merge_session_state(parent, child)
    assert_citations(parent.findings[0])


def test_appending_evidence_after_restore_preserves_existing_citations(sessions, tmp_path):
    parent, _ = sessions
    state = SessionState(target=parent.target, findings=[parent.findings[0].model_copy(deep=True)])
    config = VulnClawConfig()
    config.session.output_dir = tmp_path
    record = state.agent_state.remember_tool_result(
        tool='fetch', arguments={'url': state.target + '/cmd'},
        output='new session response', target=state.target,
    )
    assert record.id == state.findings[0].evidence_snapshots[0].evidence_id
    agent = SimpleNamespace(config=config, context=SimpleNamespace(state=state), session_state=state)
    submit_finding(agent, {'title': 'Candidate', 'description': 'Recorded observation',
                          'vuln_type': 'SQLi', 'severity': 'High',
                          'endpoint': state.target + '/cmd', 'evidence_ids': [record.id]})
    assert len({ref.evidence_id for ref in state.findings[0].evidence_snapshots}) == 2
    assert_citations(state.findings[0])


def test_duplicate_snapshot_aliases_rebind_to_the_retained_snapshot(sessions):
    parent, _ = sessions
    raw = parent.findings[0].model_dump(mode='json')
    raw['evidence_snapshots'].append({**raw['evidence_snapshots'][0], 'evidence_id': 'alias'})
    assessment = raw['verification_history'][0]
    assessment['evidence_ids'] = ['alias']
    assessment['observations'][0]['evidence_id'] = 'alias'
    finding = VulnerabilityFinding.model_validate(raw)
    assert len(finding.evidence_snapshots) == 1
    assert_citations(finding)


def test_target_state_moves_metadata_to_canonical_identity(sessions, tmp_path, monkeypatch):
    import vulnclaw.target_state.store as store

    parent, child = sessions
    monkeypatch.setattr(store, 'TARGETS_DIR', tmp_path / 'targets')
    path = store.save_target_state(parent.target, parent, command='test')
    raw = json.loads(path.read_text(encoding='utf-8'))
    first = raw['findings'][0]
    first['finding_id'] = 'old-first'
    second = child.findings[0].model_dump(mode='json')
    second.update(endpoint='https://LAB.test:443/cmd', finding_id='old-second')
    raw['findings'].append(second)
    raw['finding_meta'] = {
        'old-first': {'first_seen_at': '2026-01-01T00:00:00', 'last_seen_at': '2026-01-02T00:00:00', 'observation_count': 2},
        'old-second': {'first_seen_at': '2026-01-03T00:00:00', 'last_seen_at': '2026-01-04T00:00:00', 'observation_count': 3},
    }
    path.write_text(json.dumps(raw))
    original = path.read_bytes()
    loaded = store.load_target_state(parent.target)
    assert len(loaded['findings']) == 1
    identity = loaded['findings'][0]['finding_id']
    assert set(loaded['finding_meta']) == {identity}
    metadata = loaded['finding_meta'][identity]
    assert metadata['observation_count'] == 5
    assert metadata['first_seen_at'] == '2026-01-01T00:00:00'
    assert metadata['last_seen_at'] == '2026-01-04T00:00:00'
    assert path.read_bytes() == original
    assert store.load_target_state(parent.target) == loaded


def test_legacy_url_identities_merge_on_session_reload(sessions, tmp_path, monkeypatch):
    import hashlib

    import vulnclaw.target_state.store as store

    parent, child = sessions
    raw = parent.model_dump(mode='json')
    old_child = child.findings[0].model_dump(mode='json')
    old_child['endpoint'] = 'https://LAB.test:443/cmd#old'
    old_child['finding_id'] = hashlib.sha256(json.dumps([
        old_child['vuln_type'], old_child['target'], old_child['endpoint'], old_child['method'],
    ], ensure_ascii=False).encode()).hexdigest()[:32]
    raw['findings'].append(old_child)
    source = tmp_path / 'legacy.json'
    source.write_text(json.dumps(raw))
    original = source.read_bytes()
    restored = SessionState.load(source)
    assert len(restored.findings) == 1
    assert len(restored.findings[0].evidence_snapshots) == 2
    assert_citations(restored.findings[0])
    assert restored._vulnerabilities.findings == restored.findings
    assert restored._finding_ids_cache == {restored.findings[0].finding_id}
    assert source.read_bytes() == original
    monkeypatch.setattr(store, 'TARGETS_DIR', tmp_path / 'targets')
    store.save_target_state(parent.target, parent, command='test')
    # Also exercise raw persistence merging against a pre-normalization ID.
    child.findings[0].endpoint = old_child['endpoint']
    child.findings[0].finding_id = old_child['finding_id']
    store.save_target_state(child.target, child, command='test')
    saved = store.hydrate_session_from_target_state(parent.target)
    assert len(saved.findings) == 1
    assert_citations(saved.findings[0])
