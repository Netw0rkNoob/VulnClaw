use std::sync::mpsc;

use ratatui::{backend::TestBackend, Terminal};
use vulnclaw_tui::{
    app::App,
    protocol::Finding,
    ui::attack_chain::{dependency_preview, render},
};

#[test]
fn dependency_preview_truncates_by_characters_not_bytes() {
    let dependency_id = "漏洞依赖编号甲乙丙丁戊己庚辛";

    let preview = dependency_preview(dependency_id);

    assert_eq!(preview, dependency_id.chars().take(10).collect::<String>());
    assert_eq!(preview.chars().count(), 10);
    assert!(dependency_id.starts_with(&preview));
}

#[test]
fn renders_attack_chain_with_unicode_dependency_ids() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    let dependency_id = "漏洞依赖编号甲乙丙丁戊己庚辛";
    app.findings.push(Finding {
        id: "finding-2".into(),
        severity: "high".into(),
        title: "Unicode dependency".into(),
        target: "app.test".into(),
        chain_depends_on: vec![dependency_id.into()],
        ..Default::default()
    });
    let mut terminal = Terminal::new(TestBackend::new(100, 12)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("VulnClaw Attack Chain"));
    assert!(rendered.contains("Unicode dependency"));
    assert!(dependency_preview(dependency_id).chars().all(|character| {
        buffer
            .content
            .iter()
            .any(|cell| cell.symbol().starts_with(character))
    }));
}
