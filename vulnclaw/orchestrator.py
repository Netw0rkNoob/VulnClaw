"""Shared task orchestration helpers for CLI and Web flows."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from vulnclaw.agent.context import SessionState
from vulnclaw.agent.core import AgentCore
from vulnclaw.run_context import (
    RunContext,
    RunCorruptError,
    build_completion_summary,
    create_run_context,
    load_run_context,
    mark_run_status,
)
from vulnclaw.target_state.store import (
    SessionRestoreResult,
    apply_target_state_to_agent,
    build_task_session_summary,
    import_legacy_target_state,
    legacy_target_state_exists,
    save_target_state,
)
from vulnclaw.targets import Target, build_targets


@dataclass
class OrchestratorRunResult:
    restore_result: SessionRestoreResult
    summary: dict[str, Any]
    run_context: RunContext | None = None
    status: str = "completed"
    exit_code: int = 0


async def run_agent_task(
    *,
    agent: AgentCore,
    command: str,
    target: str,
    resume: bool = True,
    snapshot_id: Optional[str] = None,
    run_name: Optional[str] = None,
    resume_run_name: Optional[str] = None,
    runs_dir: Optional[str] = None,
    additional_targets: Optional[list[str]] = None,
    target_type: Optional[str] = None,
    mount: bool = False,
    repair: bool = False,
    force_fresh: bool = False,
    no_import: bool = False,
    before_restore: Optional[Callable[[SessionRestoreResult | None], None]] = None,
    on_restored: Optional[Callable[[SessionRestoreResult], None]] = None,
    on_legacy_import: Optional[Callable[[SessionRestoreResult], None]] = None,
    runner: Callable[[AgentCore], Awaitable[Any]],
) -> OrchestratorRunResult:
    """Run a shared task flow with optional restore and summary generation."""
    targets = build_targets(
        target,
        additional_targets,
        target_type=target_type,
        mount=mount,
    )
    legacy_read_only = bool(
        no_import
        and resume
        and not resume_run_name
        and legacy_target_state_exists(targets[0].raw, targets[0])
    )
    run_context = (
        None
        if legacy_read_only
        else _resolve_run_context(
            command=command,
            targets=targets,
            run_name=run_name,
            resume_run_name=resume_run_name,
            runs_dir=runs_dir,
            config=getattr(agent, "config", None),
            repair=repair,
            force_fresh=force_fresh,
        )
    )
    if resume_run_name:
        if run_context is None:
            raise RunCorruptError(Path("."), "resume run context was not loaded")
        targets = _targets_from_run_context(run_context)
        target = targets[0].raw

    restore_result = None
    if before_restore is not None:
        before_restore(None)

    primary_target = targets[0]
    if resume_run_name:
        if run_context is None:
            raise RunCorruptError(Path("."), "resume run context was not loaded")
        restore_result = apply_target_state_to_agent(
            agent,
            primary_target.raw,
            snapshot_id=snapshot_id,
            run_context=run_context,
            target_model=primary_target,
        )
        if restore_result.restored and on_restored is not None:
            on_restored(restore_result)
    elif resume:
        if legacy_target_state_exists(primary_target.raw, primary_target):
            if no_import:
                restore_result = apply_target_state_to_agent(
                    agent,
                    primary_target.raw,
                    snapshot_id=snapshot_id,
                )
            else:
                if run_context is None:
                    raise RunCorruptError(Path("."), "run context was not created")
                import_result = import_legacy_target_state(
                    primary_target.raw,
                    run_context=run_context,
                    target_model=primary_target,
                    command=command,
                    runtime=agent.runtime,
                )
                if import_result.restored and on_legacy_import is not None:
                    on_legacy_import(import_result)
                restore_result = apply_target_state_to_agent(
                    agent,
                    primary_target.raw,
                    snapshot_id=snapshot_id,
                    run_context=run_context,
                    target_model=primary_target,
                )
        else:
            restore_result = apply_target_state_to_agent(
                agent, primary_target.raw, snapshot_id=snapshot_id
            )
        if restore_result.restored and on_restored is not None:
            on_restored(restore_result)
    else:
        agent.context.state.target = primary_target.raw
        restore_result = SessionRestoreResult(
            restored=False,
            target=primary_target.raw,
            phase=getattr(agent.context.state.phase, "value", str(agent.context.state.phase)),
            snapshot_id=snapshot_id or "",
            preview={"target": primary_target.raw},
        )

    checkpoint = (
        _install_checkpoint_hook(agent, command, run_context, targets)
        if run_context is not None
        else lambda _reason: None
    )
    checkpoint("run_start")

    status = "completed"
    exit_code = 0
    try:
        await runner(agent)
        checkpoint("run_complete")
        if run_context is not None:
            mark_run_status(run_context, "completed", exit_code=0)
            _schedule_completed_run_distillation(agent, run_context, primary_target)
    except KeyboardInterrupt:
        status = "interrupted"
        exit_code = 130
        checkpoint("interrupt")
        if run_context is not None:
            mark_run_status(run_context, "interrupted", exit_code=130)
    except asyncio.CancelledError:
        status = "interrupted"
        exit_code = 130
        checkpoint("cancelled")
        if run_context is not None:
            mark_run_status(run_context, "interrupted", exit_code=130)
        raise
    except Exception as exc:
        status = "failed"
        exit_code = 1
        checkpoint("failed")
        if run_context is not None:
            mark_run_status(run_context, "failed", exit_code=1, message=str(exc))
        raise

    summary = _build_summary(
        agent=agent,
        command=command,
        restore_result=restore_result,
        run_context=run_context,
        status=status,
        exit_code=exit_code,
    )
    return OrchestratorRunResult(
        restore_result=restore_result or SessionRestoreResult(target=target),
        summary=summary,
        run_context=run_context,
        status=status,
        exit_code=exit_code,
    )


def _schedule_completed_run_distillation(
    agent: AgentCore,
    run_context: RunContext,
    target: Target,
) -> None:
    """Launch lesson distillation after persistence; never affect run completion."""

    try:
        from vulnclaw.agent.distiller import (
            RunArtifacts,
            configured_distiller,
            schedule_run_distillation,
        )
        from vulnclaw.config.token_provider import has_llm_credentials
        from vulnclaw.feedback import feedback_for_distillation
        from vulnclaw.kb.experience import ExperienceStore

        if not has_llm_credentials(agent.config.llm):
            run_context.append_event("distillation_skipped", {"reason": "missing_llm_credentials"})
            return
        artifacts = RunArtifacts.from_session(
            run_context.run_name,
            agent.session_state,
            target_key=target.target_id,
            feedback=feedback_for_distillation(run_context.run_dir),
        )
        schedule_run_distillation(
            artifacts=artifacts,
            llm=configured_distiller(agent.config),
            store=ExperienceStore(),
            run_context=run_context,
        )
    except Exception as exc:
        # Completion is already durable. Any learning failure is diagnostic-only.
        try:
            run_context.append_event("distillation_failed", {"error": type(exc).__name__})
        except Exception:
            pass


def _resolve_run_context(
    *,
    command: str,
    targets: list[Target],
    run_name: str | None,
    resume_run_name: str | None,
    runs_dir: str | None,
    config: Any,
    repair: bool,
    force_fresh: bool,
) -> RunContext:
    if resume_run_name:
        try:
            return load_run_context(
                resume_run_name,
                runs_dir=runs_dir,
                config=config,
                repair=repair,
            )
        except RunCorruptError:
            if not force_fresh:
                raise
    return create_run_context(
        command=command,
        targets=targets,
        runs_dir=runs_dir,
        config=config,
        run_name=run_name,
        replace=False,
    )


def _targets_from_run_context(run_context: RunContext) -> list[Target]:
    targets: list[Target] = []
    for item in run_context.manifest.get("targets", []):
        if not isinstance(item, dict):
            continue
        raw = str(item.get("input") or item.get("canonical") or "")
        canonical = str(item.get("canonical") or raw)
        kind = str(item.get("type") or "domain")
        targets.append(
            Target(
                kind=kind,  # type: ignore[arg-type]
                raw=raw,
                canonical=canonical,
                label=item.get("label") if isinstance(item.get("label"), str) else None,
                ingress_mode=str(item.get("ingress_mode") or "copy"),  # type: ignore[arg-type]
                scope_mode=str(item.get("scope_mode") or "auto"),  # type: ignore[arg-type]
                diff_base=item.get("diff_base") if isinstance(item.get("diff_base"), str) else None,
            )
        )
    if not targets:
        raise RunCorruptError(run_context.run_dir, "run.json targets[] is empty")
    return targets


def _install_checkpoint_hook(
    agent: AgentCore,
    command: str,
    run_context: RunContext,
    targets: list[Target],
) -> Callable[[str], None]:
    primary_target = targets[0]
    secondary_targets = targets[1:]
    checkpointing = False
    secondaries_seeded = False

    def _seed_secondary_targets() -> None:
        """Initialize a state file for every non-primary manifest target.

        The agent loop only drives the primary target, but a multi-target run
        lists every target in ``run.json`` and ``validate_run_context`` requires
        a ``current.json`` per entry. Without this, ``--resume-run`` rejects the
        run as corrupt. Seed a fresh session for any secondary target that has
        no state yet so the whole manifest stays resumable.

        The agent loop never drives these targets in this run, so the seed
        writes only the run-local ``current.json`` and does not touch the global
        per-target index mirror. That keeps a plain ``load_target_state()`` /
        default resume for the target pointed at whatever real state it already
        had, instead of shadowing it with this empty placeholder snapshot.
        """
        for target in secondary_targets:
            if run_context.state_path(target).exists():
                continue
            save_target_state(
                target.raw,
                SessionState(target=target.raw),
                command=command,
                runtime=agent.runtime,
                run_context=run_context,
                target_model=target,
                checkpoint_reason="seed",
                merge_existing=False,
                update_index=False,
            )

    def checkpoint(reason: str) -> None:
        nonlocal checkpointing, secondaries_seeded
        if checkpointing:
            return
        checkpointing = True
        try:
            if not secondaries_seeded:
                secondaries_seeded = True
                _seed_secondary_targets()
            state = agent.session_state
            state.target = state.target or primary_target.raw
            save_target_state(
                primary_target.raw,
                state,
                command=command,
                runtime=agent.runtime,
                run_context=run_context,
                target_model=primary_target,
                checkpoint_reason=reason,
                merge_existing=False,
            )
        finally:
            checkpointing = False

    agent.session_state.set_checkpoint_callback(lambda _state, reason: checkpoint(reason))
    return checkpoint


def _build_summary(
    *,
    agent: AgentCore,
    command: str,
    restore_result: SessionRestoreResult | None,
    run_context: RunContext | None,
    status: str,
    exit_code: int,
) -> dict[str, Any]:
    base = build_task_session_summary(
        agent.session_state,
        command=command,
        restored=bool(restore_result and restore_result.restored),
        snapshot_id=restore_result.snapshot_id if restore_result else "",
    )
    completion = build_completion_summary(
        context=run_context,
        session=agent.session_state,
        command=command,
        restored=bool(restore_result and restore_result.restored),
        snapshot_id=restore_result.snapshot_id if restore_result else "",
        status=status,
        exit_code=exit_code,
    )
    return {**base, **completion}
