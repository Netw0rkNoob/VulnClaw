use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use vulnclaw_tui::{
    app::{ActivePane, App, ExecutionMode, PermissionMode},
    events::handle_key,
};

#[test]
fn tab_cycles_execution_mode_and_shift_tab_cycles_permission() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);

    handle_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
    );

    // Default posture is Agent; one Tab cycles to the read-only Plan.
    // Offline permission cycling is rejected (backend-owned policy).
    assert_eq!(app.mode, ExecutionMode::Plan);
    assert_eq!(app.permission, PermissionMode::Ask);
}

#[test]
fn arrows_scroll_the_selected_inspector() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.active_pane = ActivePane::Findings;

    handle_key(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));

    assert_eq!(app.findings_scroll, 1);
    assert_eq!(app.transcript_scroll, 0);
}

#[test]
fn task_confirmation_captures_shortcuts() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.pending_task = Some("/run target.test".into());

    handle_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));

    // While a task confirmation is pending, Tab is swallowed by the
    // confirmation prompt and must not change the execution mode.
    assert_eq!(app.mode, ExecutionMode::Agent);
    assert!(app.pending_task.is_some());
}

#[test]
fn enter_executes_an_exact_command_instead_of_refilling_it() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.input = "/plan".into();

    handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

    assert!(app.input.is_empty());
    assert!(app.transcript.iter().any(|item| item.text == "> /plan"));
}

#[test]
fn cursor_and_history_shortcuts_edit_the_composer() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.input = "/helpx".into();
    app.input_cursor = app.input.len();

    handle_key(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    handle_key(&mut app, KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL),
    );

    assert_eq!(app.input, "/help");
}

#[test]
fn ctrl_c_requests_task_cancel_without_quitting_or_killing_backend() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.worker_active = true;
    app.active_task_id = Some("t1".into());

    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(
        app.worker_active,
        "task remains active until Python acknowledges cancellation"
    );
    assert!(
        app.running,
        "TUI should stay open after requesting cancellation"
    );
}

#[test]
fn ctrl_c_quits_when_no_worker_is_running() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.worker_active = false;

    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );

    assert!(!app.running);
}

// ── Execution approval modal (C-1/C-2) ─────────────────────────────────

use vulnclaw_tui::app::PendingExecution;

fn approval_event(task_id: &str, command: &str) -> vulnclaw_tui::protocol::AppEvent {
    vulnclaw_tui::protocol::AppEvent::backend(
        vulnclaw_tui::protocol::BackendEvent::ApprovalRequired {
            task_id: task_id.to_string(),
            question: command.to_string(),
            request_hash: "a".repeat(64),
            kind: "shell".to_string(),
            cwd: "/tmp/target".to_string(),
            detail: "auto-review: unknown command".to_string(),
            expires_at: "2026-08-23T07:00:00+00:00".to_string(),
            expires_in_seconds: 300,
            risk: "not sandboxed".to_string(),
        },
    )
}

#[test]
fn structured_approval_opens_modal_and_swallows_typing() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.active_task_id = Some("task-1".into());
    app.apply_event(approval_event("task-1", "whoami"));

    assert!(app.pending_execution.is_some(), "modal must open");

    // While the modal is open, ordinary typing must NOT reach the composer.
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
    );
    assert_eq!(app.input, "");
}

#[test]
fn y_approves_and_clears_modal() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.active_task_id = Some("task-1".into());
    app.apply_event(approval_event("task-1", "id"));

    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
    );

    assert!(app.pending_execution.is_none());
    assert!(
        app.transcript.iter().any(|i| i.text.contains("已提交批准")),
        "approval submission must be visible"
    );
}

#[test]
fn esc_denies_by_default() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.active_task_id = Some("task-1".into());
    app.apply_event(approval_event("task-1", "sudo rm -rf /"));

    handle_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.pending_execution.is_none());
    assert!(
        app.transcript.iter().any(|i| i.text.contains("已提交拒绝")),
        "deny must be the default decision"
    );
}

#[test]
fn legacy_question_only_event_does_not_open_modal() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.active_task_id = Some("task-1".into());
    app.apply_event(vulnclaw_tui::protocol::AppEvent::backend(
        vulnclaw_tui::protocol::BackendEvent::ApprovalRequired {
            task_id: "task-1".into(),
            question: "old style ask_user".into(),
            request_hash: String::new(),
            expires_in_seconds: 0,
            kind: String::new(),
            cwd: String::new(),
            detail: String::new(),
            expires_at: String::new(),
            risk: String::new(),
        },
    ));
    assert!(app.pending_execution.is_none());

    // Typing still reaches the composer for legacy questions.
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
    );
    assert_eq!(app.input, "x");
}

#[test]
fn task_completion_clears_pending_modal() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.active_task_id = Some("task-1".into());
    app.apply_event(approval_event("task-1", "id"));
    assert!(app.pending_execution.is_some());

    app.clear_task_requests("task-1");
    assert!(app.pending_execution.is_none());
}

#[test]
fn pending_execution_struct_roundtrip() {
    let p = PendingExecution {
        request_hash: "h".into(),
        kind: "shell".into(),
        command: "ls".into(),
        cwd: "/".into(),
        detail: String::new(),
        expires_at: String::new(),
        expires_in_secs: 300,
        received_at: std::time::Instant::now(),
        risk: String::new(),
    };
    assert_eq!(p.kind, "shell");
    assert_eq!(p.remaining_secs(), 300);
}

#[test]
fn approval_closed_event_clears_modal() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.active_task_id = Some("task-1".into());
    app.apply_event(approval_event("task-1", "whoami"));

    assert!(app.pending_execution.is_some());
    app.apply_event(vulnclaw_tui::protocol::AppEvent::backend(
        vulnclaw_tui::protocol::BackendEvent::ApprovalClosed {
            task_id: "task-1".into(),
            request_hash: "a".repeat(64),
            status: "expired".into(),
        },
    ));
    // 超时关闭:弹窗消失,并留下原因
    assert!(app.pending_execution.is_none());
    assert!(app
        .transcript
        .iter()
        .any(|i| i.text.contains("审批超时,已自动拒绝")));
}

#[test]
fn approval_closed_ignores_non_matching_hash() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.active_task_id = Some("task-1".into());
    app.apply_event(approval_event("task-1", "whoami"));

    app.apply_event(vulnclaw_tui::protocol::AppEvent::backend(
        vulnclaw_tui::protocol::BackendEvent::ApprovalClosed {
            task_id: "task-1".into(),
            request_hash: "b".repeat(64),
            status: "approved".into(),
        },
    ));
    assert!(app.pending_execution.is_some(), "hash 不匹配不得误关");
}
