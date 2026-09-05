use std::sync::mpsc;
use std::time::Instant;

use ratatui::{backend::TestBackend, Terminal};

use vulnclaw_tui::{
    app::{App, OperationReceipt, PendingExecution},
    ui::layout::render,
};

fn pending_execution(command: String) -> PendingExecution {
    PendingExecution {
        request_hash: "a".repeat(64),
        kind: "shell".into(),
        command,
        cwd: "/tmp".into(),
        detail: "operator review required".into(),
        expires_at: String::new(),
        expires_in_secs: 300,
        received_at: Instant::now(),
        risk: "not sandboxed".into(),
        scroll_offset: 0,
    }
}

fn rendered_text(terminal: &Terminal<TestBackend>) -> String {
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>()
}

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
fn approval_modal_stays_inside_a_small_terminal() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.pending_execution = Some(pending_execution("whoami".into()));
    for (width, height) in [(1, 1), (10, 3), (30, 8)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        if width == 30 {
            let rendered = rendered_text(&terminal);
            assert!(rendered.contains("[Y]"));
            assert!(rendered.contains("[N/Esc]"));
        }
    }
}

#[test]
fn approval_modal_scrolls_full_code_with_fixed_footer() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = ratatui::layout::Rect::new(0, 0, 60, 18);
    let mut rows = vec!["FIRST-LINE".to_string()];
    rows.extend((1..29).map(|index| format!("middle-{index:02}")));
    rows.push("LAST-LINE".to_string());
    app.pending_execution = Some(pending_execution(rows.join("\n")));
    let mut terminal = Terminal::new(TestBackend::new(60, 18)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();
    let first = rendered_text(&terminal);
    assert!(first.contains("FIRST-LINE"));
    assert!(!first.contains("LAST-LINE"));
    assert!(first.contains("[Y]"));

    for _ in 0..10 {
        app.scroll_pending_execution(true, true);
    }
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let last = rendered_text(&terminal);
    assert!(last.contains("LAST-LINE"));
    assert!(last.contains("[Y]"));
    assert!(last.contains("[N/Esc]"));
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
