use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use vulnclaw_tui::{
    exec::spawn_backend_command,
    protocol::{AppEvent, BackendEvent, ClientRequest},
};

const FAKE_BACKEND: &str = r#"
import json, os, sys
constraints = {"allowed_ports": [], "blocked_ports": [], "allowed_hosts": [], "blocked_hosts": [], "allowed_paths": [], "blocked_paths": [], "allowed_actions": [], "blocked_actions": [], "notes": [], "strict_mode": False}
def state(active=False, task_id=None):
    return {"target": "target.test", "phase": "idle", "task_constraints": constraints, "task": {"active": active, "task_id": task_id}, "last_run": None, "findings": [], "evidence": [], "constraint_violations": []}
for line in sys.stdin:
    msg = json.loads(line)
    base = {"protocol_version": 1}
    if msg["type"] == "initialize":
        print(json.dumps(base | {"type": "ready", "request_id": msg["request_id"], "backend": {"pid": os.getpid(), "version": "test", "protocol_version": 1}, "capabilities": {"commands": ["run"], "control_operations": ["example.inspect"], "cancellation": True, "authoritative_state": True}, "runtime": {"config_ready": True, "provider": "test", "model": "test", "mcp_started": 0, "skills": []}, "state": state()}), flush=True)
    elif msg["type"] == "control":
        print(json.dumps(base | {"type": "control_result", "request_id": msg["request_id"], "operation": msg["payload"]["operation"], "result": {"backend_pid": os.getpid()}}), flush=True)
    elif msg["type"] == "start_task":
        task_id = msg["task_id"]
        print(json.dumps(base | {"type": "task_started", "request_id": msg["request_id"], "task_id": task_id, "task": msg["payload"]["task"], "state": state(True, task_id)}), flush=True)
        print(json.dumps(base | {"type": "task_completed", "request_id": msg["request_id"], "task_id": task_id, "result": {"summary": {"backend_pid": os.getpid()}}, "findings": [], "state": state()}), flush=True)
    elif msg["type"] == "shutdown":
        print(json.dumps(base | {"type": "shutdown_complete", "request_id": msg["request_id"]}), flush=True)
        break
"#;

#[test]
fn one_transport_process_serves_two_sequential_tasks() {
    let python = if std::path::Path::new("../.venv/bin/python").exists() {
        "../.venv/bin/python"
    } else {
        "python"
    };
    let mut command = Command::new(python);
    command.arg("-u").arg("-c").arg(FAKE_BACKEND);
    let (sender, receiver) = mpsc::channel();
    let backend = spawn_backend_command(command, sender).unwrap();

    backend
        .send(&ClientRequest::initialize(
            "r-init".into(),
            serde_json::json!({}),
        ))
        .unwrap();
    let ready_pid = loop {
        match receiver.recv_timeout(Duration::from_secs(3)).unwrap() {
            AppEvent::Backend(event) => match *event {
                BackendEvent::Ready { backend, .. } => break backend.pid,
                _ => continue,
            },
            _ => continue,
        }
    };

    backend
        .send(&ClientRequest::control(
            "r-control".into(),
            "example.inspect",
            serde_json::json!({}),
        ))
        .unwrap();
    loop {
        match receiver.recv_timeout(Duration::from_secs(3)).unwrap() {
            AppEvent::Backend(event) => match *event {
                BackendEvent::ControlResult { result, .. } => {
                    assert_eq!(result["backend_pid"], ready_pid);
                    break;
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    for index in 1..=2 {
        backend
            .send(&ClientRequest::start_task(
                format!("r-{index}"),
                format!("t-{index}"),
                serde_json::json!({
                    "command": "run",
                    "target": format!("target-{index}.test")
                }),
            ))
            .unwrap();
        loop {
            match receiver.recv_timeout(Duration::from_secs(3)).unwrap() {
                AppEvent::Backend(event) => match *event {
                    BackendEvent::TaskCompleted {
                        task_id, result, ..
                    } if task_id == format!("t-{index}") => {
                        assert_eq!(result["summary"]["backend_pid"], ready_pid);
                        break;
                    }
                    _ => continue,
                },
                _ => continue,
            }
        }
    }

    backend
        .send(&ClientRequest::shutdown("r-shutdown".into()))
        .unwrap();
    backend.wait_or_kill(Duration::from_secs(2));
}

#[test]
fn invalid_stdout_and_stderr_are_forwarded_as_diagnostics() {
    let python = if std::path::Path::new("../.venv/bin/python").exists() {
        "../.venv/bin/python"
    } else {
        "python"
    };
    let mut command = Command::new(python);
    command.arg("-u").arg("-c").arg(
        "import sys; print('not-json', flush=True); print('backend warning', file=sys.stderr, flush=True)",
    );
    let (sender, receiver) = mpsc::channel();
    let backend = spawn_backend_command(command, sender).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_invalid_protocol = false;
    let mut saw_stderr = false;
    let mut saw_exit = false;

    while Instant::now() < deadline && !(saw_invalid_protocol && saw_stderr && saw_exit) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(AppEvent::BackendDiagnostic(message)) => {
                saw_invalid_protocol |= message.contains("invalid backend protocol line");
                saw_stderr |= message == "backend warning";
            }
            Ok(AppEvent::BackendExited(success)) => saw_exit = success,
            Ok(AppEvent::Backend(_)) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    backend.wait_or_kill(Duration::from_secs(1));
    assert!(saw_invalid_protocol);
    assert!(saw_stderr);
    assert!(saw_exit);
}
