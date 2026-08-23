use std::sync::mpsc;
use std::time::Instant;

use ratatui::{backend::TestBackend, Terminal};

use vulnclaw_tui::{
    app::{App, OperationReceipt},
    ui::layout::render,
};

#[test]
fn renders_a_composer_centered_security_workbench() {
    let (sender, _) = mpsc::channel();
    let app = App::new_disconnected(sender);
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Session transcript"));
    assert!(rendered.contains("Findings inspector (0)"));
    assert!(rendered.contains("Type / for commands"));
    assert!(rendered.contains("Tab mode"));
    assert!(rendered.contains("ready"));
    assert!(!rendered.contains("[Skills] [Findings] [Output]"));
}

#[test]
fn header_shows_live_timer_and_running_state_while_a_worker_is_active() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.worker_active = true;
    app.worker_started_at = Some(Instant::now());
    app.active_receipt = Some(OperationReceipt {
        command: "task run https://example.com".into(),
        phase: "Running".into(),
        findings: 0,
    });
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("running"), "header must read 'running'");
    assert!(
        rendered.contains("⏱"),
        "header must show the live elapsed timer"
    );
}

#[test]
fn slash_input_renders_the_command_palette() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.backend_commands = vec!["scan".into()];
    app.insert_text("/");
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Commands"));
    assert!(rendered.contains("/scan "));
}

#[test]
fn composer_placeholder_renders_on_a_single_row() {
    let (sender, _) = mpsc::channel();
    let app = App::new_disconnected(sender); // empty input -> placeholder path
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let buf = terminal.backend().buffer();
    let mut rows_with_placeholder = 0;
    for y in 0..24u16 {
        let line: String = (0..80u16)
            .map(|x| {
                buf.cell((x, y))
                    .map(|c| c.symbol().to_string())
                    .unwrap_or_default()
            })
            .collect();
        if line.contains("Type / for commands") {
            rows_with_placeholder += 1;
        }
    }
    assert_eq!(
        rows_with_placeholder, 1,
        "the composer placeholder must render on exactly one row"
    );
}

#[test]
fn task_confirmation_replaces_the_composer() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.pending_task = Some("/run target.test".into());
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Task confirmation required"));
    assert!(rendered.contains("Y confirm"));
}
