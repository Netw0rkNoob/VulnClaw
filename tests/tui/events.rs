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
    assert_eq!(app.mode, ExecutionMode::Plan);
    assert_eq!(app.permission, PermissionMode::FullAccess);
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
