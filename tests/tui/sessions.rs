use std::sync::mpsc;

use vulnclaw_tui::{
    app::{App, ExecutionMode, PermissionMode},
    sessions::SessionState,
};

#[test]
fn session_round_trip_preserves_composer_history_and_posture() {
    let (sender, _) = mpsc::channel();
    let mut source = App::new_disconnected(sender);
    source.insert_text("/help");
    source.submit();
    source.cycle_mode();
    source.cycle_permission();
    let state = SessionState::from_app(&source);

    let (target_sender, _) = mpsc::channel();
    let mut target = App::new_disconnected(target_sender);
    state.apply(&mut target);

    assert_eq!(target.command_history, vec!["/help"]);
    // Source started in Agent, cycled once to Plan — the round trip must
    // restore that exact posture.
    assert_eq!(target.mode, ExecutionMode::Plan);
    assert_eq!(target.permission, PermissionMode::FullAccess);
    assert!(target.input.is_empty());
    assert!(
        !target.transcript.iter().any(|item| item.text == "> /help"),
        "business transcript must be hydrated by Python, not Rust persistence"
    );
}

#[test]
fn serialized_session_excludes_authoritative_business_state() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.command_history = vec!["/run target.test".into()];
    app.transcript.push(vulnclaw_tui::app::TranscriptItem {
        kind: vulnclaw_tui::app::TranscriptKind::Finding,
        text: "sensitive transcript entry".into(),
    });
    app.findings.push(vulnclaw_tui::protocol::Finding {
        id: "f1".into(),
        title: "authoritative finding".into(),
        ..Default::default()
    });

    let value = serde_json::to_value(SessionState::from_app(&app)).unwrap();

    assert_eq!(value["history"], serde_json::json!(["/run target.test"]));
    assert!(value.get("transcript").is_none());
    assert!(value.get("messages").is_none());
    assert!(value.get("findings").is_none());
}
