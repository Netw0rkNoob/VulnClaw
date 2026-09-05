use std::sync::mpsc;

use ratatui::{backend::TestBackend, Terminal};

use vulnclaw_tui::{app::App, views::skills_manager::render};

#[test]
fn renders_authoritative_backend_and_scope_state() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.backend_ready = true;
    app.backend_pid = Some(42);
    app.target = "app.test".into();
    app.phase = "executing".into();
    app.worker_active = true;
    app.task_constraints = serde_json::json!({
        "allowed_hosts": ["app.test"],
        "allowed_ports": [80, 443],
        "allowed_actions": ["scan"]
    });
    app.evidence = vec![serde_json::json!({"path": "evidence.json"})];
    app.constraint_violations = vec!["blocked host".into()];
    app.last_run = Some(serde_json::json!({"run": {"name": "audit-1"}}));
    let mut terminal = Terminal::new(TestBackend::new(60, 30)).unwrap();

    terminal
        .draw(|frame| frame.render_widget(render(&app), frame.area()))
        .unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Backend     pid 42"));
    assert!(rendered.contains("Target      app.test"));
    assert!(rendered.contains("Phase       executing"));
    assert!(rendered.contains("Activity    running"));
    assert!(rendered.contains("Scope       H1 P2 A1"));
    assert!(rendered.contains("Evidence    1  Violations 1"));
    assert!(rendered.contains("Last run    audit-1"));
}
