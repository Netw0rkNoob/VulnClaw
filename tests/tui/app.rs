use std::sync::mpsc;
use vulnclaw_tui::workbench::ViewId;

use crate::support::AppHarness;
use vulnclaw_tui::app::{
    parse_scope_payload, parse_task_payload, strip_prompt_prefix, App, ExecutionMode,
    PermissionMode, TranscriptItem, TranscriptKind,
};

fn push_log(app: &mut App, text: impl Into<String>) {
    app.transcript.push(TranscriptItem {
        kind: TranscriptKind::Log,
        text: text.into(),
    });
}

fn extract_rect_text(buffer: &ratatui::buffer::Buffer, rect: ratatui::layout::Rect) -> String {
    let area = buffer.area;
    let mut output = String::new();
    for y in rect.y..rect.bottom() {
        if y >= area.height {
            break;
        }
        let mut line = String::new();
        for x in rect.x..rect.right() {
            if x >= area.width {
                break;
            }
            let index = (y * area.width + x) as usize;
            if let Some(cell) = buffer.content.get(index) {
                line.push_str(cell.symbol());
            }
        }
        output.push_str(line.trim_end());
        output.push('\n');
    }
    output
}

fn start_task(harness: &mut AppHarness, target: &str) -> (String, String) {
    harness.app.insert_text(&format!("/run {target}"));
    harness.app.submit();
    harness.app.confirm_task();
    match harness.apply_next() {
        vulnclaw_tui::protocol::BackendEvent::TaskStarted {
            request_id,
            task_id,
            ..
        } => (request_id, task_id),
        event => panic!("expected task_started, got {event:?}"),
    }
}

#[test]
fn strip_prompt_prefix_tolerates_pasted_transcript_prefix() {
    assert_eq!(
        strip_prompt_prefix("You  > /run https://example.com"),
        "/run https://example.com"
    );
    // Doubled prefix (composer prompt + pasted prefix) also resolves.
    assert_eq!(
        strip_prompt_prefix("You  > You  > /run https://example.com"),
        "/run https://example.com"
    );
    // Bare "> " prefix from the transcript echo.
    assert_eq!(strip_prompt_prefix("> /shield scan ."), "/shield scan .");
    // Clean command without a prompt artifact is left untouched.
    assert_eq!(strip_prompt_prefix("/help"), "/help");
}

#[test]
fn composer_suggests_and_completes_slash_commands() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.backend_commands = vec!["run".into()];
    app.insert_text("/ru");

    assert!(app.palette_visible());
    assert!(app.accept_selected_command());
    assert_eq!(app.input, "/run ");
}

#[test]
fn task_dispatch_uses_frontend_known_task_verbs() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.mode = ExecutionMode::Agent;
    app.backend_ready = true;
    app.backend_commands = vec!["recon".into()];
    app.insert_text("/recon https://lab.example");
    app.submit();

    assert_eq!(
        app.pending_task.as_deref(),
        Some("/recon https://lab.example")
    );

    // /run is a known task verb even if the backend has not advertised it,
    // so it is accepted and armed (execution is still gated on backend_ready).
    app.dismiss_task();
    app.backend_ready = true;
    app.backend_commands = Vec::new();
    app.insert_text("/run https://lab.example");
    app.submit();
    assert!(app.pending_task.is_some());
    assert!(app
        .transcript
        .iter()
        .any(|item| item.text.contains("armed for")));
}

#[test]
fn codescan_dispatches_as_known_task_verb() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.mode = ExecutionMode::Agent;
    app.backend_ready = true;
    app.backend_commands = vec!["codescan".into()];
    app.insert_text("/codescan demo/unsafe-ai-sample.ts");
    app.submit();

    assert_eq!(
        app.pending_task.as_deref(),
        Some("/codescan demo/unsafe-ai-sample.ts")
    );

    // /codescan is part of the frontend's canonical task verbs, so it is still
    // armed when the backend has not advertised it yet.
    app.dismiss_task();
    app.backend_ready = true;
    app.backend_commands = Vec::new();
    app.insert_text("/codescan src/main.rs");
    app.submit();
    assert!(app.pending_task.is_some());
}

#[test]
fn scope_command_routes_to_capability_gated_control() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);

    app.insert_text("/scope");
    app.submit();
    assert!(app
        .transcript
        .iter()
        .any(|item| item.text.contains("Usage: /scope")));

    app.insert_text("/scope --only-port 443");
    app.submit();
    assert!(app
        .transcript
        .iter()
        .any(|item| { item.text.contains("The Python backend is not ready") }));
    assert!(!app
        .transcript
        .iter()
        .any(|item| item.text.contains("Unknown command: /scope")));
}

#[test]
fn ready_event_hydrates_backend_capabilities() {
    let harness = AppHarness::connected();

    assert_eq!(harness.app.backend_commands, vec!["recon", "run", "scan"]);
    assert_eq!(
        harness.app.backend_control_operations,
        vec![
            "config.models",
            "config.preset",
            "config.read",
            "config.write",
            "example.inspect",
            "session.permission.set",
            "session.scope.reset",
            "session.scope.update"
        ]
    );
    assert!(harness.app.backend_supports_cancellation);
    assert!(harness.app.backend_ready);
}

#[test]
fn ready_event_captures_the_provider_and_model() {
    let harness = AppHarness::connected();

    assert_eq!(harness.app.provider.as_deref(), Some("test"));
    assert_eq!(harness.app.model.as_deref(), Some("test"));
}

#[test]
fn provider_and_model_are_unknown_until_the_backend_reports() {
    let (sender, _) = mpsc::channel();
    let app = App::new_disconnected(sender);

    assert!(app.provider.is_none());
    assert!(app.model.is_none());
}
#[test]
fn authoritative_state_replaces_and_clears_every_business_field() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.target = "stale.test".into();
    app.phase = "stale".into();
    app.worker_active = true;
    app.active_task_id = Some("stale-task".into());
    app.task_constraints = serde_json::json!({"allowed_hosts": ["stale.test"]});
    app.last_run = Some(serde_json::json!({"status": "stale"}));
    app.evidence = vec![serde_json::json!({"path": "stale"})];
    app.constraint_violations = vec!["stale violation".into()];

    app.apply_event(vulnclaw_tui::protocol::AppEvent::backend(
        vulnclaw_tui::protocol::BackendEvent::State {
            request_id: None,
            state: vulnclaw_tui::protocol::StateSnapshot {
                target: String::new(),
                phase: String::new(),
                task_constraints: serde_json::json!({"allowed_ports": [443]}),
                findings: Vec::new(),
                task: vulnclaw_tui::protocol::BackendTaskState {
                    active: false,
                    task_id: None,
                },
                last_run: Some(serde_json::json!({"status": "completed"})),
                evidence: vec![serde_json::json!({"path": "fresh"})],
                constraint_violations: vec!["fresh violation".into()],
            },
        },
    ));

    assert!(app.target.is_empty());
    assert!(app.phase.is_empty());
    assert!(!app.worker_active);
    assert!(app.active_task_id.is_none());
    assert_eq!(app.task_constraints["allowed_ports"][0], 443);
    assert_eq!(app.last_run.as_ref().unwrap()["status"], "completed");
    assert_eq!(app.evidence[0]["path"], "fresh");
    assert_eq!(app.constraint_violations, vec!["fresh violation"]);
}

#[test]
fn response_ids_are_correlated_with_request_kind_and_task() {
    let mut harness = AppHarness::connected();
    let (request_id, task_id) = start_task(&mut harness, "correlation.test");

    harness
        .app
        .apply_event(vulnclaw_tui::protocol::AppEvent::backend(
            vulnclaw_tui::protocol::BackendEvent::Error {
                request_id: Some(request_id),
                task_id: Some("different-task".into()),
                code: "task_busy".into(),
                message: "mismatched task response".into(),
            },
        ));

    assert!(harness.app.worker_active);
    assert_eq!(
        harness.app.active_task_id.as_deref(),
        Some(task_id.as_str())
    );
    assert!(harness
        .app
        .transcript
        .iter()
        .any(|item| item.text.contains("Mismatched task error response")));
}
#[test]
fn task_event_summaries_never_override_authoritative_state() {
    let mut harness = AppHarness::connected();
    let (request_id, task_id) = start_task(&mut harness, "summary.test");

    harness
        .app
        .apply_event(vulnclaw_tui::protocol::AppEvent::backend(
            vulnclaw_tui::protocol::BackendEvent::TaskStarted {
                request_id: request_id.clone(),
                task_id: task_id.clone(),
                task: serde_json::json!({
                    "command": "run",
                    "target": "summary.test"
                }),
                state: vulnclaw_tui::protocol::StateSnapshot {
                    target: "authoritative.test".into(),
                    phase: "recon".into(),
                    task_constraints: serde_json::json!({
                        "allowed_hosts": ["authoritative.test"]
                    }),
                    task: vulnclaw_tui::protocol::BackendTaskState {
                        active: true,
                        task_id: Some(task_id.clone()),
                    },
                    ..Default::default()
                },
            },
        ));

    assert_eq!(harness.app.target, "authoritative.test");
    assert_eq!(
        harness.app.task_constraints["allowed_hosts"][0],
        "authoritative.test"
    );

    let authoritative_finding = vulnclaw_tui::protocol::Finding {
        id: "state-finding".into(),
        severity: "high".into(),
        title: "Authoritative".into(),
        target: "authoritative.test".into(),
        ..Default::default()
    };
    let summary_finding = vulnclaw_tui::protocol::Finding {
        id: "summary-finding".into(),
        ..Default::default()
    };
    harness
        .app
        .apply_event(vulnclaw_tui::protocol::AppEvent::backend(
            vulnclaw_tui::protocol::BackendEvent::TaskCompleted {
                request_id,
                task_id,
                result: serde_json::json!({}),
                findings: vec![summary_finding],
                state: vulnclaw_tui::protocol::StateSnapshot {
                    target: "authoritative.test".into(),
                    phase: "reporting".into(),
                    task_constraints: harness.app.task_constraints.clone(),
                    findings: vec![authoritative_finding],
                    task: vulnclaw_tui::protocol::BackendTaskState {
                        active: false,
                        task_id: None,
                    },
                    last_run: Some(serde_json::json!({"status": "completed"})),
                    ..Default::default()
                },
            },
        ));

    assert_eq!(harness.app.findings.len(), 1);
    assert_eq!(harness.app.findings[0].id, "state-finding");
}
#[test]
fn mode_and_permission_cycles_are_independent() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.cycle_mode();
    app.cycle_permission();

    // Default posture is Agent; one Tab cycles to the read-only Plan.
    // Permission now requires a connected backend (the server owns the
    // authoritative policy), so offline cycling must keep the posture.
    assert_eq!(app.mode, ExecutionMode::Plan);
    assert_eq!(app.permission, PermissionMode::Ask);
}

#[test]
fn active_task_permission_change_waits_for_backend_confirmation() {
    let mut harness = AppHarness::connected();
    let (_, _) = start_task(&mut harness, "permission.test");
    assert!(harness.app.worker_active);
    assert_eq!(harness.app.permission, PermissionMode::Ask);

    harness.app.cycle_permission();
    assert_eq!(
        harness.app.permission,
        PermissionMode::Ask,
        "the client must not update permission optimistically"
    );
    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::ControlResult { .. }
    ));
    assert_eq!(harness.app.permission, PermissionMode::AutoReview);
    assert!(harness.app.worker_active);
}

#[test]
fn composer_supports_cursor_editing_and_history() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.insert_text("/hep");
    app.move_input_cursor(false);
    app.insert_text("l");
    app.submit();
    app.insert_text("draft");
    app.recall_history(true);

    assert_eq!(app.input, "/help");
    app.recall_history(false);
    assert_eq!(app.input, "draft");
}

#[test]
fn plan_mode_blocks_task_before_a_confirmation_can_be_armed() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.mode = ExecutionMode::Plan;
    app.backend_commands = vec!["run".into()];
    app.insert_text("/run https://lab.example");
    app.submit();

    assert!(app.pending_task.is_none());
    assert!(!app.worker_active);
    assert!(app
        .transcript
        .iter()
        .any(|item| item.text.contains("Plan mode is read-only")));
}

#[test]
fn agent_mode_arms_a_task_and_waits_for_confirmation() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.mode = ExecutionMode::Agent;
    app.permission = PermissionMode::FullAccess;
    app.backend_ready = true;
    app.backend_commands = vec!["run".into()];

    app.insert_text("/run https://lab.example");
    app.submit();

    assert!(app.pending_task.is_some());
    assert!(!app.worker_active);
}

#[test]
fn paste_in_main_input_still_works() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.insert_text("hello world");
    assert_eq!(app.input, "hello world");
}

#[test]
fn task_requires_a_target() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.mode = ExecutionMode::Agent;
    app.backend_ready = true;
    app.backend_commands = vec!["run".into()];

    app.insert_text("/run");
    app.submit();

    assert!(app.pending_task.is_none());
    assert!(app
        .transcript
        .iter()
        .any(|item| item.text.contains("requires a target")));
}

#[test]
fn task_command_is_only_a_presentation_adapter_for_the_structured_dto() {
    let task = parse_task_payload(
        "/scan https://app.test/admin --ports 80,443 --only-port 443 --no-resume",
    )
    .unwrap();

    assert_eq!(task["command"], "scan");
    assert_eq!(task["target"], "https://app.test/admin");
    assert_eq!(task["resume"], false);
    assert_eq!(task["options"]["ports"], "80,443");
    assert_eq!(task["options"]["only_port"], 443);
}

#[test]
fn scope_adapter_rejects_non_scope_fields() {
    let error = parse_scope_payload("--engine solve").unwrap_err();
    assert!(error.contains("unsupported scope option"));
}

#[test]
fn streamed_events_update_and_finalize_the_work_receipt() {
    let mut harness = AppHarness::connected();
    let (_, task_id) = start_task(&mut harness, "complete.test");
    let finding = vulnclaw_tui::protocol::Finding {
        severity: "high".into(),
        title: "Test finding".into(),
        ..Default::default()
    };

    harness
        .app
        .apply_event(vulnclaw_tui::protocol::AppEvent::backend(
            vulnclaw_tui::protocol::BackendEvent::Finding { task_id, finding },
        ));
    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::TaskCompleted { .. }
    ));

    assert!(harness.app.active_receipt.is_none());
    assert_eq!(harness.app.last_receipt.as_ref().unwrap().findings, 1);
    assert_eq!(
        harness.app.last_receipt.as_ref().unwrap().phase,
        "Completed"
    );
}
#[test]
fn active_view_rect_partitions_the_workbench_without_overlap() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 28);

    app.layout.focus = ViewId::Status;
    let workspace = app.active_view_rect(app.terminal_size);
    app.layout.focus = ViewId::Output;
    let transcript = app.active_view_rect(app.terminal_size);
    app.layout.focus = ViewId::Findings;
    let findings = app.active_view_rect(app.terminal_size);

    // Independent view regions must not overlap.
    assert_eq!(workspace.x, 0);
    assert!(
        workspace.right() <= transcript.x,
        "workspace right of transcript start"
    );
    assert!(
        transcript.right() <= findings.x,
        "transcript right of findings start"
    );
    assert!(findings.right() <= 120);
    // None of them spans the full screen — each is an independent region.
    assert!(workspace.width < 120);
    assert!(transcript.width < 120);
    assert!(findings.width < 120);
}

/// The composer is chrome, not a view: focus must never park on something that
/// draws no focus marker and cannot be scrolled.
#[test]
fn focus_cycling_visits_every_rendered_view_and_nothing_else() {
    use std::collections::HashSet;

    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 28);
    let views = app.layout.primary.len() + app.layout.secondary.len() + 1;
    let start = app.layout.focus;

    let mut visited = Vec::new();
    for _ in 0..views {
        app.cycle_active_view(false);
        assert!(
            app.geometry(app.terminal_size)
                .view(app.layout.focus)
                .is_some(),
            "{:?} is not rendered, so focusing it is invisible",
            app.layout.focus
        );
        visited.push(app.layout.focus);
    }

    assert_eq!(app.layout.focus, start, "the cycle closes over every view");
    assert_eq!(
        visited.iter().collect::<HashSet<_>>().len(),
        views,
        "each view is visited exactly once: {visited:?}"
    );
}

#[test]
fn copy_active_view_renders_only_the_focused_region() {
    use vulnclaw_tui::workbench::{resize, ContainerId, SashId};
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 28);
    let geometry = app.geometry(app.terminal_size);
    let primary = geometry.container(ContainerId::Primary);
    let target = geometry
        .drop_target(ratatui::layout::Position::new(primary.x, primary.y))
        .unwrap();
    app.layout.move_view(ViewId::Findings, target, &geometry);
    let geometry = app.geometry(app.terminal_size);
    resize(&mut app.layout, &geometry, SashId::Primary, 5, 0);

    let backend = ratatui::backend::TestBackend::new(120, 28);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| vulnclaw_tui::ui::draw(f, &app)).unwrap();
    for (id, included, excluded) in [
        (ViewId::Output, "Session transcript", "Findings inspector"),
        (ViewId::Findings, "Findings inspector", "Workspace"),
    ] {
        app.layout.focus = id;
        let rect = app.active_view_rect(app.terminal_size);
        let text = extract_rect_text(term.backend().buffer(), rect);
        assert!(text.contains(included));
        assert!(
            !text.contains(excluded),
            "copied view includes neighboring content"
        );
    }
}

#[test]
fn transcript_autoscroll_pins_to_bottom_and_tracks_growth() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 30);
    app.layout.focus = ViewId::Output;

    // Short lines never wrap at the ~50-col inner width, so the pin point is
    // purely a function of content length.
    for i in 0..5 {
        push_log(&mut app, format!("line {i}"));
    }
    app.refresh_view_scrolls();
    let small = app.layout.output.scroll as usize;
    assert!(app.layout.output.follow);

    for i in 5..45 {
        push_log(&mut app, format!("line {i}"));
    }
    app.refresh_view_scrolls();
    let large = app.layout.output.scroll as usize;
    assert!(app.layout.output.follow);
    // More content => larger bottom offset => the view followed the growth.
    assert!(large > small);
}

#[test]
fn transcript_short_content_has_zero_scroll() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 30);
    app.layout.focus = ViewId::Output;
    app.refresh_view_scrolls();
    // Only the two welcome lines — they fit, so no scrolling is needed.
    assert_eq!(app.layout.output.scroll, 0);
    assert!(app.layout.output.follow);
}

#[test]
fn scrolling_up_pauses_follow_and_bottom_resumes_it() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 30);
    app.layout.focus = ViewId::Output;
    for i in 0..45 {
        push_log(&mut app, format!("line {i}"));
    }
    app.refresh_view_scrolls();
    let max = app.layout.output.scroll;
    assert!(max > 0);
    assert_eq!(app.layout.output.scroll, max);
    assert!(app.layout.output.follow);

    // Scroll up once to read history: follow must switch off.
    app.scroll_active_view(false);
    assert!(!app.layout.output.follow);
    assert_eq!(app.layout.output.scroll, max - 1);

    // Scroll back down to the bottom: follow must switch back on.
    for _ in 0..(max as usize + 2) {
        app.scroll_active_view(true);
    }
    assert!(app.layout.output.follow);
    assert_eq!(app.layout.output.scroll, max);
}

#[test]
fn rejected_cancellation_keeps_the_active_task_running() {
    let mut harness = AppHarness::connected();
    let (_, task_id) = start_task(&mut harness, "cancel-reject.test");

    harness.app.stop_worker();
    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::Error { .. }
    ));

    assert!(harness.app.worker_active);
    assert_eq!(
        harness.app.active_task_id.as_deref(),
        Some(task_id.as_str())
    );
    assert!(harness.app.active_receipt.is_some());
    assert!(harness
        .app
        .transcript
        .iter()
        .any(|item| item.text.contains("cancellation_rejected")));
}
#[test]
fn control_result_is_correlated_and_applies_authoritative_state() {
    let mut harness = AppHarness::connected();
    harness.app.insert_text("/scope --only-port 443");
    harness.app.submit();

    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::ControlResult { .. }
    ));
    assert_eq!(harness.app.target, "scope.test");
    assert_eq!(
        harness.app.task_constraints["allowed_ports"],
        serde_json::json!([443])
    );
    assert!(harness
        .app
        .transcript
        .iter()
        .any(|item| item.text == "scope updated"));
}
#[test]
fn terminal_task_events_finalize_receipts_from_authoritative_state() {
    let mut cancelled = AppHarness::connected();
    start_task(&mut cancelled, "cancel.test");
    cancelled.app.stop_worker();
    assert!(matches!(
        cancelled.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::TaskCancelled { .. }
    ));
    assert!(!cancelled.app.worker_active);
    assert!(cancelled.app.active_task_id.is_none());
    assert_eq!(cancelled.app.phase, "cancelled");
    assert_eq!(
        cancelled.app.last_receipt.as_ref().unwrap().phase,
        "Cancelled"
    );

    let mut failed = AppHarness::connected();
    start_task(&mut failed, "fail.test");
    assert!(matches!(
        failed.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::TaskFailed { .. }
    ));
    assert!(!failed.app.worker_active);
    assert!(failed.app.active_task_id.is_none());
    assert_eq!(failed.app.phase, "failed");
    assert_eq!(failed.app.last_receipt.as_ref().unwrap().phase, "Failed");
    assert!(failed
        .app
        .transcript
        .iter()
        .any(|item| item.text.contains("scanner unavailable")));
}
#[test]
fn backend_exit_clears_transport_state_and_closes_the_active_receipt() {
    let mut harness = AppHarness::connected();
    start_task(&mut harness, "disconnect.test");

    harness
        .app
        .apply_event(vulnclaw_tui::protocol::AppEvent::BackendExited(false));

    assert!(!harness.app.backend_ready);
    assert!(harness.app.backend_pid.is_none());
    assert!(harness.app.backend_commands.is_empty());
    assert!(harness.app.backend_control_operations.is_empty());
    assert!(!harness.app.backend_supports_cancellation);
    assert!(!harness.app.worker_active);
    assert!(harness.app.worker_started_at.is_none());
    assert!(harness.app.active_task_id.is_none());
    assert_eq!(
        harness.app.last_receipt.as_ref().unwrap().phase,
        "Backend disconnected"
    );
}

#[test]
fn the_palette_lists_each_backend_verb_once() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.backend_commands = vec!["run".into(), "recon".into(), "scan".into()];
    app.insert_text("/r");

    let commands: Vec<_> = app
        .suggested_commands()
        .into_iter()
        .map(|item| item.command)
        .collect();

    let mut unique = commands.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        commands.len(),
        unique.len(),
        "the local fallback must not repeat a verb the backend advertises: {commands:?}"
    );
    // The backend's verbs still lead, followed by local-only helpers. `/run`
    // and `/recon` live in both lists and must appear once each.
    assert_eq!(
        commands,
        ["/run ", "/recon ", "/report"],
        "got {commands:?}"
    );
}

#[test]
fn the_palette_falls_back_to_local_verbs_before_the_handshake() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.insert_text("/run");

    let commands: Vec<_> = app
        .suggested_commands()
        .into_iter()
        .map(|item| item.command)
        .collect();

    assert_eq!(
        commands,
        ["/run "],
        "the local list keeps task verbs discoverable while the backend is silent"
    );
}

fn open_settings(harness: &mut AppHarness) {
    harness.app.insert_text("/config");
    harness.app.submit();
    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::ControlResult { .. }
    ));
}

#[test]
fn config_command_opens_the_settings_screen_seeded_from_the_backend() {
    let mut harness = AppHarness::connected();

    harness.app.insert_text("/config");
    harness.app.submit();
    // The screen opens immediately and awaits the backend rather than blocking.
    assert!(harness.app.llm_settings.is_some());
    assert!(harness.app.llm_settings.as_ref().unwrap().loading);

    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::ControlResult { .. }
    ));
    let settings = harness.app.llm_settings.as_ref().unwrap();
    assert!(!settings.loading);
    assert_eq!(settings.provider, "deepseek");
    assert_eq!(settings.website_url, "https://www.deepseek.com/");
    assert_eq!(settings.base_url, "https://api.deepseek.com");
    assert_eq!(settings.model, "deepseek-v4-pro");
    assert!(settings.api_key_set);
    // The credential itself never crosses the protocol.
    assert!(settings.api_key.is_empty());
    assert_eq!(settings.providers.len(), 2);
    assert_eq!(
        settings.display_value(vulnclaw_tui::app::LlmField::ApiKey),
        "•••••••• (saved)"
    );
}

#[test]
fn choosing_the_custom_template_blanks_the_preset_fields() {
    let mut harness = AppHarness::connected();
    open_settings(&mut harness);

    harness.app.select_llm_template("custom");
    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::ControlResult { .. }
    ));

    let settings = harness.app.llm_settings.as_ref().unwrap();
    assert_eq!(settings.provider, "custom");
    assert!(settings.website_url.is_empty());
    assert!(settings.base_url.is_empty());
    assert!(settings.model.is_empty());
}

#[test]
fn saving_the_settings_refreshes_the_header_and_closes_the_screen() {
    let mut harness = AppHarness::connected();
    open_settings(&mut harness);

    harness.app.llm_settings.as_mut().unwrap().model = "deepseek-v4-pro".into();
    harness.app.save_llm_settings();
    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::ControlResult { .. }
    ));

    // The badge is otherwise only seeded from `ready`, so a save must refresh it.
    assert_eq!(harness.app.provider.as_deref(), Some("deepseek"));
    assert_eq!(harness.app.model.as_deref(), Some("deepseek-v4-pro"));
    assert!(harness.app.llm_settings.is_none());
    assert!(harness
        .app
        .transcript
        .iter()
        .any(|item| item.text == "Saved deepseek/deepseek-v4-pro"));
}

#[test]
fn a_rejected_save_keeps_the_screen_open_with_the_reason() {
    let mut harness = AppHarness::connected();
    open_settings(&mut harness);

    // The fake backend rejects this sentinel provider.
    harness.app.llm_settings.as_mut().unwrap().provider = "reject".into();
    harness.app.save_llm_settings();
    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::Error { .. }
    ));

    let settings = harness.app.llm_settings.as_ref().unwrap();
    assert!(!settings.loading);
    assert!(settings.error.contains("config.write failed"));
}

#[test]
fn opening_the_model_row_fetches_the_suggestions() {
    use vulnclaw_tui::app::LlmField;

    let mut harness = AppHarness::connected();
    open_settings(&mut harness);

    // Enter on the model row opens it for typing and pulls the list — there is
    // no separate fetch command.
    harness.app.llm_settings.as_mut().unwrap().focus = LlmField::Model;
    harness.app.begin_llm_edit();
    assert!(harness.app.llm_settings.as_ref().unwrap().editing);
    assert!(matches!(
        harness.apply_next(),
        vulnclaw_tui::protocol::BackendEvent::ControlResult { .. }
    ));

    let settings = harness.app.llm_settings.as_ref().unwrap();
    assert_eq!(settings.models, vec!["deepseek-chat", "deepseek-v4-pro"]);
    assert!(!settings.loading);
    // Nothing is adopted just by opening the row.
    assert_eq!(settings.model, "deepseek-v4-pro");
    assert!(settings.suggestion.is_none());
}

#[test]
fn an_open_row_still_offers_suggestions_matching_what_was_typed() {
    use vulnclaw_tui::app::LlmField;

    let mut harness = AppHarness::connected();
    open_settings(&mut harness);
    harness.app.llm_settings.as_mut().unwrap().focus = LlmField::Model;
    harness.app.begin_llm_edit();
    harness.apply_next();

    // Retype a prefix; suggestions narrow to the matching models.
    let settings = harness.app.llm_settings.as_mut().unwrap();
    settings.model = "deepseek-c".into();
    settings.move_cursor_to_edge(true);
    assert_eq!(
        harness.app.llm_settings.as_ref().unwrap().suggestions(),
        vec!["deepseek-chat"]
    );

    // ↓ picks it, and the confirming Enter adopts it.
    harness.app.move_llm_suggestion(true);
    harness.app.commit_llm_edit();

    let settings = harness.app.llm_settings.as_ref().unwrap();
    assert_eq!(settings.model, "deepseek-chat");
    assert!(!settings.editing);
}

#[test]
fn an_open_row_cannot_be_left_without_a_second_enter() {
    use vulnclaw_tui::app::LlmField;

    let mut harness = AppHarness::connected();
    open_settings(&mut harness);
    harness.app.llm_settings.as_mut().unwrap().focus = LlmField::Model;
    harness.app.begin_llm_edit();

    // ↑/↓ inside an open row walk its suggestions, never the rows.
    harness.app.move_llm_focus(true);
    harness.app.move_llm_focus(true);
    assert_eq!(
        harness.app.llm_settings.as_ref().unwrap().focus,
        LlmField::Model
    );

    // Esc reverts the text and closes the row, leaving the screen up.
    harness.app.llm_settings.as_mut().unwrap().model = "half-typed".into();
    harness.app.cancel_llm_edit();
    let settings = harness.app.llm_settings.as_ref().unwrap();
    assert_eq!(settings.model, "deepseek-v4-pro");
    assert!(!settings.editing);

    // Only now do the rows move again (Model is last, so forward wraps).
    harness.app.move_llm_focus(true);
    assert_eq!(
        harness.app.llm_settings.as_ref().unwrap().focus,
        LlmField::Provider
    );
}

#[test]
fn the_settings_screen_refuses_to_open_while_a_task_runs() {
    let mut harness = AppHarness::connected();
    start_task(&mut harness, "complete.test");

    harness.app.open_llm_settings();

    assert!(harness.app.llm_settings.is_none());
    assert!(harness
        .app
        .transcript
        .iter()
        .any(|item| item.text.contains("cannot change while a task is running")));
}

#[test]
fn a_long_model_list_stays_fully_navigable() {
    use vulnclaw_tui::app::LlmField;

    let mut harness = AppHarness::connected();
    open_settings(&mut harness);
    // Far more models than the six rows the screen can show — OpenRouter
    // advertises several hundred.
    let models: Vec<String> = (0..40).map(|i| format!("model-{i:02}")).collect();
    {
        let settings = harness.app.llm_settings.as_mut().unwrap();
        settings.focus = LlmField::Model;
        settings.models = models;
        settings.model = String::new();
        settings.begin_edit();
        settings.move_cursor_to_edge(true);
    }

    // Every match is offered, not only the ones that fit on screen.
    assert_eq!(
        harness
            .app
            .llm_settings
            .as_ref()
            .unwrap()
            .suggestions()
            .len(),
        40
    );

    // ↓ walks past the first window instead of wrapping inside it: the first
    // press selects entry 0, so ten presses land on entry 9 — well beyond the
    // six rows the screen shows.
    for _ in 0..10 {
        harness.app.move_llm_suggestion(true);
    }
    assert_eq!(
        harness.app.llm_settings.as_ref().unwrap().suggestion,
        Some(9)
    );

    // The tail of the list is reachable, and only the end wraps.
    for _ in 0..30 {
        harness.app.move_llm_suggestion(true);
    }
    assert_eq!(
        harness.app.llm_settings.as_ref().unwrap().suggestion,
        Some(39)
    );
    harness.app.move_llm_suggestion(true);
    assert_eq!(
        harness.app.llm_settings.as_ref().unwrap().suggestion,
        Some(0)
    );

    // ↑ from the top wraps to the last entry, not the last visible one.
    harness.app.move_llm_suggestion(false);
    assert_eq!(
        harness.app.llm_settings.as_ref().unwrap().suggestion,
        Some(39)
    );

    // The confirming Enter adopts whatever the window scrolled to.
    for _ in 0..8 {
        harness.app.move_llm_suggestion(false);
    }
    harness.app.commit_llm_edit();
    assert_eq!(harness.app.llm_settings.as_ref().unwrap().model, "model-31");
}

#[test]
fn typing_narrows_a_long_model_list_without_capping_it() {
    use vulnclaw_tui::app::LlmField;

    let mut harness = AppHarness::connected();
    open_settings(&mut harness);
    let settings = harness.app.llm_settings.as_mut().unwrap();
    settings.focus = LlmField::Model;
    settings.models = (0..40).map(|i| format!("model-{i:02}")).collect();
    settings.begin_edit();

    // A prefix that matches more than the window can hold stays fully listed.
    settings.model = "model-1".into();
    settings.move_cursor_to_edge(true);
    let matches = harness.app.llm_settings.as_ref().unwrap().suggestions();
    assert_eq!(matches.len(), 10);
    assert_eq!(matches[0], "model-10");
    assert_eq!(matches[9], "model-19");
}
