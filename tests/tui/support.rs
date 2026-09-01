use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use vulnclaw_tui::{
    exec::spawn_backend_command,
    protocol::{AppEvent, BackendEvent},
    App,
};

const BACKEND_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const BACKEND_EVENT_TIMEOUT: Duration = Duration::from_secs(3);

const APP_BACKEND: &str = r#"
import json, os, sys

current_task = None
current_target = ""

def state(active=False, task_id=None, phase="idle", target=None, findings=None):
    return {
        "target": current_target if target is None else target,
        "phase": phase,
        "task_constraints": {},
        "task": {"active": active, "task_id": task_id},
        "last_run": None,
        "findings": findings or [],
        "evidence": [],
        "constraint_violations": [],
    }

for line in sys.stdin:
    msg = json.loads(line)
    base = {"protocol_version": 1}
    if msg["type"] == "initialize":
        print(json.dumps(base | {
            "type": "ready",
            "request_id": msg["request_id"],
            "backend": {"pid": os.getpid(), "version": "test", "protocol_version": 1},
            "capabilities": {
                "commands": ["scan", "run", "recon"],
                "control_operations": ["example.inspect", "session.scope.reset", "session.scope.update"],
                "cancellation": True,
                "authoritative_state": True,
            },
            "runtime": {
                "config_ready": True,
                "provider": "test",
                "model": "test",
                "mcp_started": 0,
                "skills": [],
            },
            "state": state(),
        }), flush=True)
    elif msg["type"] == "start_task":
        current_task = msg["task_id"]
        current_target = msg["payload"]["task"]["target"]
        print(json.dumps(base | {
            "type": "task_started",
            "request_id": msg["request_id"],
            "task_id": current_task,
            "task": msg["payload"]["task"],
            "state": state(True, current_task, "running"),
        }), flush=True)
        if current_target == "complete.test":
            finding = {"id": "f1", "severity": "high", "title": "Test finding", "target": current_target}
            print(json.dumps(base | {
                "type": "task_completed",
                "request_id": msg["request_id"],
                "task_id": current_task,
                "result": {},
                "findings": [finding],
                "state": state(False, None, "completed", findings=[finding]),
            }), flush=True)
        elif current_target == "fail.test":
            print(json.dumps(base | {
                "type": "task_failed",
                "request_id": msg["request_id"],
                "task_id": current_task,
                "error": {"code": "scanner_unavailable", "message": "scanner unavailable"},
                "state": state(False, None, "failed"),
            }), flush=True)
    elif msg["type"] == "control":
        print(json.dumps(base | {
            "type": "control_result",
            "request_id": msg["request_id"],
            "operation": msg["payload"]["operation"],
            "result": {"message": "scope updated"},
            "state": state(False, None, "idle", target="scope.test") | {
                "task_constraints": {"allowed_ports": [443]}
            },
        }), flush=True)
    elif msg["type"] == "cancel_task":
        if current_target == "cancel-reject.test":
            print(json.dumps(base | {
                "type": "error",
                "request_id": msg["request_id"],
                "task_id": msg["task_id"],
                "code": "cancellation_rejected",
                "message": "task passed its final checkpoint",
            }), flush=True)
        else:
            print(json.dumps(base | {
                "type": "task_cancelled",
                "request_id": msg["request_id"],
                "task_id": msg["task_id"],
                "state": state(False, None, "cancelled"),
            }), flush=True)
    elif msg["type"] == "shutdown":
        print(json.dumps(base | {"type": "shutdown_complete", "request_id": msg["request_id"]}), flush=True)
        break
"#;

pub struct AppHarness {
    pub app: App,
    receiver: Receiver<AppEvent>,
}

impl AppHarness {
    pub fn connected() -> Self {
        let python = if std::path::Path::new("../.venv/bin/python").exists() {
            "../.venv/bin/python"
        } else {
            "python"
        };
        let mut command = Command::new(python);
        command.arg("-u").arg("-c").arg(APP_BACKEND);
        let (sender, receiver) = mpsc::channel();
        let backend = spawn_backend_command(command, sender.clone()).unwrap();
        let app = App::with_backend(sender, backend, serde_json::json!({}));
        let mut harness = Self { app, receiver };
        assert!(matches!(
            harness.apply_next_with_timeout(BACKEND_STARTUP_TIMEOUT),
            BackendEvent::Ready { .. }
        ));
        harness
    }

    pub fn apply_next(&mut self) -> BackendEvent {
        self.apply_next_with_timeout(BACKEND_EVENT_TIMEOUT)
    }

    fn apply_next_with_timeout(&mut self, timeout: Duration) -> BackendEvent {
        let event = self.receiver.recv_timeout(timeout).unwrap_or_else(|error| {
            panic!("failed waiting {timeout:?} for backend event: {error}")
        });
        match event {
            AppEvent::Backend(event) => {
                let observed = (*event).clone();
                self.app.apply_event(AppEvent::Backend(event));
                observed
            }
            AppEvent::BackendDiagnostic(message) => {
                panic!("unexpected backend diagnostic: {message}")
            }
            AppEvent::BackendExited(success) => {
                panic!("backend exited before the expected event (success={success})")
            }
        }
    }
}

impl Drop for AppHarness {
    fn drop(&mut self) {
        self.app.shutdown_backend();
    }
}
