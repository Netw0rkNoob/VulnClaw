use std::collections::BTreeSet;

use vulnclaw_tui::protocol::{
    parse_backend_line, validate_protocol_value, BackendEvent, ClientRequest, Finding,
    PROTOCOL_VERSION,
};

fn complete_state() -> serde_json::Value {
    serde_json::json!({
        "target": "app.test",
        "phase": "reporting",
        "task_constraints": {},
        "task": {"active": false, "task_id": null},
        "last_run": null,
        "findings": [],
        "evidence": [],
        "constraint_violations": []
    })
}

fn schema_server_event_types() -> BTreeSet<String> {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../protocol/tui-v1.schema.json")).unwrap();
    schema["$defs"]["serverEvent"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|variant| {
            let definition = variant["$ref"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap();
            schema["$defs"][definition]["allOf"][1]["properties"]["type"]["const"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn start_request_has_version_and_task_identity() {
    let request = ClientRequest::start_task(
        "r1".into(),
        "t1".into(),
        serde_json::json!({"command": "run", "target": "host"}),
    );
    let value = serde_json::to_value(request).unwrap();
    assert_eq!(value["protocol_version"], PROTOCOL_VERSION);
    assert_eq!(value["type"], "start_task");
    assert_eq!(value["request_id"], "r1");
    assert_eq!(value["task_id"], "t1");
    assert_eq!(value["payload"]["task"]["command"], "run");
    assert_eq!(value["payload"]["task"]["target"], "host");
}

#[test]
fn control_request_and_result_use_the_generic_management_envelope() {
    let request = ClientRequest::control(
        "r-control".into(),
        "example.inspect",
        serde_json::json!({"detail": true}),
    );
    let value = serde_json::to_value(request).unwrap();
    assert_eq!(value["type"], "control");
    assert_eq!(value["payload"]["operation"], "example.inspect");

    let event = parse_backend_line(
        r#"{"protocol_version":1,"type":"control_result","request_id":"r-control","operation":"example.inspect","result":{"ok":true}}"#,
    )
    .unwrap();
    match event {
        BackendEvent::ControlResult {
            operation, result, ..
        } => {
            assert_eq!(operation, "example.inspect");
            assert_eq!(result["ok"], true);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn completion_deserializes_authoritative_findings() {
    let line = serde_json::json!({
        "protocol_version": 1,
        "type": "task_completed",
        "request_id": "r1",
        "task_id": "t1",
        "findings": [{
            "id": "f1",
            "severity": "high",
            "title": "SQLi",
            "target": "app.test"
        }],
        "result": {},
        "state": complete_state()
    })
    .to_string();
    let event = parse_backend_line(&line).unwrap();
    match event {
        BackendEvent::TaskCompleted {
            task_id, findings, ..
        } => {
            assert_eq!(task_id, "t1");
            assert_eq!(findings[0].id, "f1");
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn rejects_every_missing_authoritative_state_field() {
    for field in [
        "target",
        "phase",
        "task_constraints",
        "task",
        "last_run",
        "findings",
        "evidence",
        "constraint_violations",
    ] {
        let mut state = complete_state();
        state.as_object_mut().unwrap().remove(field);
        let line = serde_json::json!({
            "protocol_version": 1,
            "type": "state",
            "state": state
        })
        .to_string();
        assert!(
            parse_backend_line(&line).is_err(),
            "missing state.{field} must be rejected"
        );
    }

    let mut state = complete_state();
    state["task"].as_object_mut().unwrap().remove("task_id");
    let line = serde_json::json!({
        "protocol_version": 1,
        "type": "state",
        "state": state
    })
    .to_string();
    assert!(
        parse_backend_line(&line).is_err(),
        "missing state.task.task_id must be rejected"
    );
}

#[test]
fn rejects_incompatible_backend_protocol() {
    let error =
        parse_backend_line(r#"{"protocol_version":2,"type":"shutdown_complete"}"#).unwrap_err();
    assert!(error.contains("expected 1"));
}

#[test]
fn every_rust_client_request_follows_the_authoritative_schema() {
    let requests = [
        ClientRequest::initialize("r-init".into(), serde_json::json!({})),
        ClientRequest::start_task(
            "r-start".into(),
            "t1".into(),
            serde_json::json!({"command": "run", "target": "target.test"}),
        ),
        ClientRequest::cancel_task("r-cancel".into(), "t1".into()),
        ClientRequest::get_state("r-state".into()),
        ClientRequest::control("r-control".into(), "example.inspect", serde_json::json!({})),
        ClientRequest::shutdown("r-shutdown".into()),
    ];

    for request in requests {
        let value = serde_json::to_value(request).unwrap();
        validate_protocol_value(&value).unwrap();
    }
}

#[test]
fn rust_accepts_every_server_event_in_the_shared_example_session() {
    let expected = schema_server_event_types();
    let mut observed = BTreeSet::new();

    for (index, line) in include_str!("../../protocol/examples/tui-v1-session.jsonl")
        .lines()
        .enumerate()
    {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        validate_protocol_value(&value)
            .unwrap_or_else(|error| panic!("fixture line {}: {error}", index + 1));
        let kind = value["type"].as_str().unwrap();
        if expected.contains(kind) {
            parse_backend_line(line).unwrap_or_else(|error| panic!("server event {kind}: {error}"));
            observed.insert(kind.to_owned());
        }
    }

    assert_eq!(
        observed, expected,
        "shared fixture must contain every server event type"
    );
}

#[test]
fn rejects_schema_invalid_required_event_fields_before_deserializing() {
    let ready = serde_json::json!({
        "protocol_version": 1,
        "type": "ready",
        "request_id": "r1",
        "backend": {"pid": 7, "version": "test", "protocol_version": 1},
        "capabilities": {
            "commands": ["run"],
            "control_operations": [],
            "cancellation": true,
            "authoritative_state": true
        },
        "runtime": {
            "config_ready": true,
            "provider": "test",
            "model": "test",
            "mcp_started": 0,
            "skills": []
        },
        "state": complete_state()
    });

    for path in [
        &["request_id"][..],
        &["backend", "protocol_version"][..],
        &["runtime", "mcp_started"][..],
        &["capabilities", "commands"][..],
    ] {
        let mut invalid = ready.clone();
        let (field, parents) = path.split_last().unwrap();
        let mut parent = &mut invalid;
        for segment in parents {
            parent = parent.get_mut(*segment).unwrap();
        }
        parent.as_object_mut().unwrap().remove(*field);
        let error = parse_backend_line(&invalid.to_string()).unwrap_err();
        assert!(
            error.contains("protocol schema violation"),
            "{path:?}: {error}"
        );
    }
}

#[test]
fn rejects_unknown_event_fields_and_malformed_json() {
    let unknown_field = parse_backend_line(
        r#"{"protocol_version":1,"type":"shutdown_complete","request_id":"r1","unexpected":true}"#,
    )
    .unwrap_err();
    assert!(unknown_field.contains("protocol schema violation"));

    let malformed = parse_backend_line("{not json}").unwrap_err();
    assert!(!malformed.contains("protocol schema violation"));
}

#[test]
fn finding_summary_uses_the_most_specific_available_location() {
    let mut finding = Finding {
        severity: "high".into(),
        title: "SQL injection".into(),
        target: "app.test".into(),
        code_location: Some("src/query.rs".into()),
        ..Default::default()
    };
    assert_eq!(finding.summary(), "[HIGH] SQL injection (src/query.rs)");

    finding.line = Some(27);
    assert_eq!(finding.summary(), "[HIGH] SQL injection (app.test:27)");

    finding.line = None;
    finding.code_location = None;
    assert_eq!(finding.summary(), "[HIGH] SQL injection (app.test)");
}
