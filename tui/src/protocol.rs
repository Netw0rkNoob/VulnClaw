use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub enum AppEvent {
    Backend(Box<BackendEvent>),
    BackendDiagnostic(String),
    BackendExited(bool),
}

impl AppEvent {
    pub fn backend(event: BackendEvent) -> Self {
        Self::Backend(Box::new(event))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientRequest {
    pub protocol_version: u8,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    pub payload: Value,
}

impl ClientRequest {
    pub fn initialize(request_id: String, bootstrap: Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            kind: "initialize",
            request_id,
            task_id: None,
            payload: serde_json::json!({
                "client": {
                    "name": "vulnclaw-tui-native",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "bootstrap": bootstrap
            }),
        }
    }

    pub fn start_task(request_id: String, task_id: String, task: Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            kind: "start_task",
            request_id,
            task_id: Some(task_id),
            payload: serde_json::json!({"task": task}),
        }
    }

    pub fn cancel_task(request_id: String, task_id: String) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            kind: "cancel_task",
            request_id,
            task_id: Some(task_id),
            payload: serde_json::json!({}),
        }
    }

    #[allow(dead_code)]
    pub fn get_state(request_id: String) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            kind: "get_state",
            request_id,
            task_id: None,
            payload: serde_json::json!({}),
        }
    }

    pub fn control(request_id: String, operation: &str, arguments: Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            kind: "control",
            request_id,
            task_id: None,
            payload: serde_json::json!({
                "operation": operation,
                "arguments": arguments
            }),
        }
    }

    pub fn shutdown(request_id: String) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            kind: "shutdown",
            request_id,
            task_id: None,
            payload: serde_json::json!({}),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BackendInfo {
    pub pid: u32,
    pub version: String,
    #[serde(rename = "protocol_version")]
    pub _protocol_version: u8,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RuntimeInfo {
    pub config_ready: bool,
    pub provider: String,
    pub model: String,
    #[serde(rename = "mcp_started")]
    pub _mcp_started: u64,
    pub skills: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BackendCapabilities {
    pub commands: Vec<String>,
    #[serde(default)]
    pub control_operations: Vec<String>,
    pub cancellation: bool,
    pub authoritative_state: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BackendTaskState {
    pub active: bool,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub task_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StateSnapshot {
    pub target: String,
    pub phase: String,
    pub task_constraints: Value,
    pub findings: Vec<Finding>,
    pub task: BackendTaskState,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub last_run: Option<Value>,
    pub evidence: Vec<Value>,
    pub constraint_violations: Vec<String>,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendEvent {
    Ready {
        request_id: String,
        backend: BackendInfo,
        capabilities: BackendCapabilities,
        runtime: RuntimeInfo,
        state: StateSnapshot,
    },
    State {
        request_id: Option<String>,
        state: StateSnapshot,
    },
    TaskStarted {
        request_id: String,
        task_id: String,
        task: Value,
        state: StateSnapshot,
    },
    Status {
        task_id: String,
        status: String,
    },
    Reasoning {
        task_id: String,
        text: String,
    },
    Log {
        task_id: String,
        message: String,
    },
    ToolCall {
        task_id: String,
        tool: String,
        arguments: String,
    },
    ToolResult {
        task_id: String,
        result: String,
    },
    Finding {
        task_id: String,
        finding: Finding,
    },
    ApprovalRequired {
        task_id: String,
        question: String,
        #[serde(default)]
        request_hash: String,
        #[serde(default)]
        kind: String,
        #[serde(default)]
        cwd: String,
        #[serde(default)]
        detail: String,
        #[serde(default)]
        expires_at: String,
        #[serde(default)]
        risk: String,
    },
    TaskCompleted {
        request_id: String,
        task_id: String,
        result: Value,
        findings: Vec<Finding>,
        state: StateSnapshot,
    },
    TaskCancelled {
        request_id: String,
        task_id: String,
        state: StateSnapshot,
    },
    TaskFailed {
        request_id: String,
        task_id: String,
        error: Value,
        state: StateSnapshot,
    },
    ControlResult {
        request_id: String,
        operation: String,
        result: Value,
        state: Option<StateSnapshot>,
    },
    Error {
        request_id: Option<String>,
        task_id: Option<String>,
        code: String,
        message: String,
    },
    ShutdownComplete {
        request_id: String,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub target: String,
    pub line: Option<u64>,
    pub code_location: Option<String>,
    #[serde(default)]
    pub chain_depends_on: Vec<String>,
}

impl Finding {
    pub fn summary(&self) -> String {
        let location = self
            .line
            .map(|line| format!("{}:{line}", self.target))
            .or_else(|| self.code_location.clone())
            .unwrap_or_else(|| self.target.clone());
        format!(
            "[{}] {} ({})",
            self.severity.to_uppercase(),
            self.title,
            location
        )
    }
}

static PROTOCOL_VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();

fn protocol_validator() -> &'static jsonschema::Validator {
    PROTOCOL_VALIDATOR.get_or_init(|| {
        let schema = serde_json::from_str(include_str!("../../protocol/tui-v1.schema.json"))
            .expect("embedded TUI protocol schema must be valid JSON");
        jsonschema::draft202012::new(&schema)
            .expect("embedded TUI protocol schema must be a valid Draft 2020-12 schema")
    })
}

/// Validate a client request or backend event against the authoritative TUI
/// protocol schema.
pub fn validate_protocol_value(value: &Value) -> Result<(), String> {
    protocol_validator()
        .validate(value)
        .map_err(|error| format!("protocol schema violation: {error}"))
}

pub fn parse_backend_line(line: &str) -> Result<BackendEvent, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    if value.get("protocol_version").and_then(Value::as_u64) != Some(PROTOCOL_VERSION.into()) {
        return Err(format!(
            "unsupported backend protocol version; expected {PROTOCOL_VERSION}"
        ));
    }
    validate_protocol_value(&value)?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}
