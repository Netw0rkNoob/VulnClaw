from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnclaw.agent.context import ContextManager, PentestPhase, SessionState
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.run_context import (
    RunCollisionError,
    RunCorruptError,
    atomic_write_text,
    create_run_context,
    load_run_context,
)
from vulnclaw.targets import legacy_target_state_key, parse_target


def test_target_model_infers_and_canonicalizes_equivalent_paths(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(tmp_path)

    relative = parse_target("./repo")
    absolute = parse_target(str(repo))
    repo_url = parse_target("https://github.com/JMAN730/VulnClaw/")
    web_url = parse_target("https://example.com/app/")
    domain = parse_target("Example.COM.")
    ip = parse_target("192.168.0.1")

    assert relative.kind == "local_repo"
    assert relative.canonical == str(repo.resolve())
    assert relative.state_key == absolute.state_key
    assert repo_url.kind == "repo_url"
    assert web_url.kind == "web_url"
    assert web_url.canonical == "https://example.com/app"
    assert domain.kind == "domain"
    assert domain.canonical == "example.com"
    assert ip.kind == "ip"


def test_run_context_creates_manifest_and_rejects_explicit_collision(tmp_path):
    target = parse_target("https://example.com")
    ctx = create_run_context(
        command="run",
        targets=[target],
        runs_dir=tmp_path / "runs",
        run_name="demo-run",
    )

    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["run_name"] == "demo-run"
    assert manifest["targets"][0]["state_path"] == (
        f"targets/{target.target_id}/state/current.json"
    )
    assert (ctx.run_dir / "events" / "events.jsonl").exists()
    assert (ctx.run_dir / "targets" / target.target_id / "target.json").exists()

    with pytest.raises(RunCollisionError):
        create_run_context(
            command="run",
            targets=[target],
            runs_dir=tmp_path / "runs",
            run_name="demo-run",
        )


def test_run_context_fails_loudly_for_partial_run(tmp_path):
    target = parse_target("https://example.com")
    create_run_context(
        command="run",
        targets=[target],
        runs_dir=tmp_path / "runs",
        run_name="partial-run",
    )

    with pytest.raises(RunCorruptError, match="target state is missing"):
        load_run_context("partial-run", runs_dir=tmp_path / "runs")


def test_atomic_write_text_skips_directory_fsync_when_unsupported(tmp_path, monkeypatch):
    import vulnclaw.run_context as run_context

    monkeypatch.setattr(run_context.os, "O_DIRECTORY", None, raising=False)
    path = tmp_path / "state" / "current.json"

    atomic_write_text(path, '{"ok": true}')

    assert path.read_text(encoding="utf-8") == '{"ok": true}'


def test_run_aware_save_writes_current_snapshot_and_index(tmp_path, monkeypatch):
    import vulnclaw.target_state.store as store

    monkeypatch.setattr(store, "TARGETS_DIR", tmp_path / "targets")
    target = parse_target("https://example.com/")
    ctx = create_run_context(
        command="run",
        targets=[target],
        runs_dir=tmp_path / "runs",
        run_name="indexed-run",
    )
    state = SessionState(target=target.raw)
    state.add_step("checked headers", action="probe", target=target.raw, result="ok")

    current_path = store.save_target_state(
        target.raw,
        state,
        command="run",
        run_context=ctx,
        target_model=target,
        checkpoint_reason="test",
    )

    assert current_path == ctx.run_dir / "targets" / target.target_id / "state" / "current.json"
    assert current_path.exists()
    snapshots = list((current_path.parent / "snapshots").glob("*.json"))
    assert len(snapshots) == 1
    assert not (tmp_path / "targets" / target.state_key / "state.json").exists()

    loaded = store.load_target_state(target.raw)
    assert loaded is not None
    assert loaded["resume_meta"]["run_name"] == "indexed-run"
    assert loaded["resume_meta"]["target_id"] == target.target_id


def test_indexed_snapshot_path_rejects_traversal_ids(tmp_path, monkeypatch):
    import vulnclaw.target_state.store as store

    monkeypatch.setattr(store, "TARGETS_DIR", tmp_path / "targets")
    target = parse_target("https://example.com/")
    ctx = create_run_context(
        command="run",
        targets=[target],
        runs_dir=tmp_path / "runs",
        run_name="indexed-guard-run",
    )
    # A run-backed save writes the index.json mirror the guarded branch reads.
    store.save_target_state(
        target.raw,
        SessionState(target=target.raw),
        command="run",
        run_context=ctx,
        target_model=target,
        checkpoint_reason="test",
    )
    assert store._index_path(target).exists()

    # Plant a JSON file outside the state dir that a traversal id could reach.
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"stolen": True}), encoding="utf-8")

    for bad_id in ["../../../../outside", "/tmp/other", "../outside"]:
        assert store._indexed_state_path(target, snapshot_id=bad_id) is None
        assert store.load_target_state(target.raw, snapshot_id=bad_id) is None


@pytest.mark.asyncio
async def test_multi_target_run_seeds_secondary_state_and_resumes(tmp_path, monkeypatch):
    import vulnclaw.target_state.store as store
    from vulnclaw.orchestrator import run_agent_task

    monkeypatch.setattr(store, "TARGETS_DIR", tmp_path / "targets")
    secondary = parse_target("https://secondary.example")

    # The secondary target already has real, run-backed state from a prior run.
    prior_ctx = create_run_context(
        command="recon",
        targets=[secondary],
        runs_dir=tmp_path / "runs",
        run_name="prior-secondary-run",
    )
    prior_state = SessionState(target=secondary.raw)
    prior_state.add_step(
        "prior secondary work", action="probe", target=secondary.raw, result="ok"
    )
    store.save_target_state(
        secondary.raw,
        prior_state,
        command="recon",
        run_context=prior_ctx,
        target_model=secondary,
        checkpoint_reason="prior",
    )
    index_before = store._index_path(secondary).read_text(encoding="utf-8")

    agent = DummyAgent(tmp_path / "runs")

    async def runner(shared_agent):
        shared_agent.session_state.add_step(
            "checked primary",
            action="probe",
            target="https://primary.example",
            result="ok",
        )

    result = await run_agent_task(
        agent=agent,
        command="recon",
        target="https://primary.example",
        additional_targets=[secondary.raw],
        resume=False,
        runner=runner,
    )

    run_name = result.summary["run_name"]
    run_dir = Path(result.summary["run_dir"])
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert len(manifest["targets"]) == 2

    # Every manifest target must have a state file, or resume rejects the run.
    for entry in manifest["targets"]:
        assert (run_dir / entry["state_path"]).exists()

    # Resuming the multi-target run must not raise "target state is missing".
    load_run_context(run_name, runs_dir=tmp_path / "runs")

    # Seeding a never-driven secondary must not clobber its global index/state:
    # a default load still resolves to the prior run's real work, not the seed.
    assert store._index_path(secondary).read_text(encoding="utf-8") == index_before
    preserved = store.load_target_state(secondary.raw)
    assert preserved is not None
    step_records = preserved.get("step_records", [])
    assert len(step_records) > 0
    assert step_records[0].get("action") == "probe"


def test_legacy_import_copies_once_and_leaves_legacy_read_only(tmp_path, monkeypatch):
    import vulnclaw.target_state.store as store

    monkeypatch.setattr(store, "TARGETS_DIR", tmp_path / "targets")
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    raw_target = "./repo"
    target = parse_target(raw_target)

    legacy_dir = tmp_path / "targets" / legacy_target_state_key(raw_target)
    legacy_dir.mkdir(parents=True)
    legacy_state = SessionState(target=raw_target)
    legacy_state.advance_phase(PentestPhase.RECON)
    (legacy_dir / "state.json").write_text(
        json.dumps(legacy_state.model_dump(mode="json"), ensure_ascii=False),
        encoding="utf-8",
    )

    ctx = create_run_context(
        command="run",
        targets=[target],
        runs_dir=tmp_path / "runs",
        run_name="legacy-import",
    )
    result = store.import_legacy_target_state(
        raw_target,
        run_context=ctx,
        target_model=target,
        command="run",
    )

    assert result.restored is True
    loaded = store.load_target_state(raw_target)
    assert loaded is not None
    assert loaded["resume_meta"]["run_name"] == "legacy-import"
    assert (legacy_dir / "state.json").stat().st_mode & 0o222 == 0


class DummyAgent:
    def __init__(self, runs_dir: Path) -> None:
        self.config = VulnClawConfig()
        self.config.session.runs_dir = runs_dir
        self.context = ContextManager()
        self.runtime = None

    @property
    def session_state(self) -> SessionState:
        return self.context.state


@pytest.mark.asyncio
async def test_orchestrator_checkpoints_and_resumes_exact_run(tmp_path, monkeypatch):
    import vulnclaw.target_state.store as store
    from vulnclaw.orchestrator import run_agent_task

    monkeypatch.setattr(store, "TARGETS_DIR", tmp_path / "targets")
    agent = DummyAgent(tmp_path / "runs")

    async def runner(shared_agent):
        shared_agent.session_state.add_step(
            "checked login",
            action="probe",
            target="https://example.com/login",
            result="ok",
        )
        shared_agent.session_state.advance_phase(PentestPhase.RECON)

    result = await run_agent_task(
        agent=agent,
        command="recon",
        target="https://example.com",
        resume=False,
        runner=runner,
    )

    run_name = result.summary["run_name"]
    run_dir = Path(result.summary["run_dir"])
    assert result.status == "completed"
    assert result.summary["resume_command"] == f"vulnclaw --resume {run_name}"
    assert json.loads((run_dir / "run.json").read_text(encoding="utf-8"))["status"] == (
        "completed"
    )
    state_dir = run_dir / "targets" / result.run_context.targets[0].target_id / "state"
    snapshots = list((state_dir / "snapshots").glob("*.json"))
    assert len(snapshots) >= 3

    resumed_agent = DummyAgent(tmp_path / "runs")

    async def noop(_shared_agent):
        return None

    resumed = await run_agent_task(
        agent=resumed_agent,
        command="recon",
        target="ignored.example",
        resume=True,
        resume_run_name=run_name,
        runner=noop,
    )

    assert resumed.restore_result.restored is True
    assert any("probe" in s and "checked login" not in s for s in resumed_agent.session_state.executed_steps)
    assert len(resumed_agent.session_state.step_records) >= 2

    (state_dir / "current.json").unlink()
    with pytest.raises(RunCorruptError, match="target state is missing"):
        load_run_context(run_name, runs_dir=tmp_path / "runs")


@pytest.mark.asyncio
async def test_completed_run_starts_distillation_after_status_is_durable(tmp_path, monkeypatch):
    import vulnclaw.orchestrator as orchestrator
    import vulnclaw.target_state.store as store

    monkeypatch.setattr(store, "TARGETS_DIR", tmp_path / "targets")
    agent = DummyAgent(tmp_path / "runs")
    scheduled: list[str] = []

    def fake_schedule(shared_agent, context, target):
        assert context.manifest["status"] == "completed"
        assert target.raw == "https://example.com"
        scheduled.append(context.run_name)

    monkeypatch.setattr(orchestrator, "_schedule_completed_run_distillation", fake_schedule)

    async def noop(_shared_agent):
        return None

    result = await orchestrator.run_agent_task(
        agent=agent,
        command="recon",
        target="https://example.com",
        resume=False,
        runner=noop,
    )

    assert result.status == "completed"
    assert scheduled == [result.run_context.run_name]


def test_distillation_setup_failure_is_logged_without_affecting_completed_run(tmp_path, monkeypatch):
    import vulnclaw.agent.distiller as distiller
    import vulnclaw.orchestrator as orchestrator

    target = parse_target("https://example.com")
    context = create_run_context(
        command="recon", targets=[target], runs_dir=tmp_path / "runs", run_name="done-run"
    )
    context.update_manifest(status="completed")
    agent = DummyAgent(tmp_path / "runs")
    agent.config.llm.api_key = "test-key"
    monkeypatch.setattr(
        distiller, "configured_distiller", lambda _config: (_ for _ in ()).throw(RuntimeError())
    )

    orchestrator._schedule_completed_run_distillation(agent, context, target)

    assert context.manifest["status"] == "completed"
    events = (context.run_dir / "events" / "events.jsonl").read_text(encoding="utf-8")
    assert '"kind": "distillation_failed"' in events


@pytest.mark.asyncio
async def test_no_import_legacy_resume_does_not_create_run_copy(tmp_path, monkeypatch):
    import vulnclaw.target_state.store as store
    from vulnclaw.orchestrator import run_agent_task

    monkeypatch.setattr(store, "TARGETS_DIR", tmp_path / "targets")
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    raw_target = "./repo"

    legacy_dir = tmp_path / "targets" / legacy_target_state_key(raw_target)
    legacy_dir.mkdir(parents=True)
    legacy_state = SessionState(target=raw_target)
    legacy_state.add_step("legacy step", action="probe", target=raw_target, result="ok")
    (legacy_dir / "state.json").write_text(
        json.dumps(legacy_state.model_dump(mode="json"), ensure_ascii=False),
        encoding="utf-8",
    )

    agent = DummyAgent(tmp_path / "runs")

    async def noop(_shared_agent):
        return None

    result = await run_agent_task(
        agent=agent,
        command="run",
        target=raw_target,
        resume=True,
        no_import=True,
        runner=noop,
    )

    assert result.run_context is None
    assert result.restore_result.restored is True
    assert len(agent.session_state.step_records) >= 1
    assert agent.session_state.step_records[0].action == "probe"
    assert not (tmp_path / "runs").exists()
    assert not (tmp_path / "targets" / parse_target(raw_target).state_key / "index.json").exists()
