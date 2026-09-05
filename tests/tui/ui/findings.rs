use std::sync::mpsc;

use ratatui::{backend::TestBackend, Terminal};

use vulnclaw_tui::{app::App, protocol::Finding, theme, ui::findings::render};

#[test]
fn renders_findings_with_their_severity_color() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.findings.push(Finding {
        id: "critical-1".into(),
        severity: "critical".into(),
        title: "Hardcoded credential".into(),
        target: "src/app.py".into(),
        line: Some(12),
        code_location: None,
        chain_depends_on: Vec::new(),
    });
    let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();

    terminal
        .draw(|frame| render(frame, &app, frame.area()))
        .unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Findings inspector (1)"));
    assert!(buffer.content.iter().any(|cell| cell.fg == theme::ROSE));
}
