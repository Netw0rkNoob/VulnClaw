use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::app::{App, ExecutionMode, TranscriptItem};
use crate::protocol::Finding;

#[derive(Deserialize, Serialize)]
pub struct SessionState {
    mode: String,
    // Accepted from legacy session files but never persisted or applied. The
    // Python backend is the sole authority for the execution permission mode.
    #[serde(default, skip_serializing)]
    permission: String,
    // Read legacy files, but never write or restore business transcript/state.
    #[serde(default, skip_serializing)]
    transcript: Vec<TranscriptItem>,
    #[serde(default)]
    history: Vec<String>,
    // Retained to open sessions written by the first VulnClaw TUI release.
    #[serde(default, skip_serializing)]
    messages: Vec<String>,
    #[serde(default, skip_serializing)]
    findings: Vec<Finding>,
}

impl SessionState {
    pub fn from_app(app: &App) -> Self {
        Self {
            mode: app.mode.label().to_owned(),
            permission: String::new(),
            transcript: Vec::new(),
            history: app.command_history.clone(),
            messages: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn apply(self, app: &mut App) {
        app.mode = match self.mode.as_str() {
            "Agent" => ExecutionMode::Agent,
            "YOLO" => ExecutionMode::Yolo,
            _ => ExecutionMode::Plan,
        };
        // Python is the only business-state source. Legacy transcript/findings
        // are intentionally ignored; a backend state event hydrates them.
        let _ = (
            self.permission,
            self.transcript,
            self.messages,
            self.findings,
        );
        app.command_history = self.history;
        app.clear_composer();
        app.findings_scroll = 0;
        app.transcript_scroll = 0;
    }
}

pub fn session_path() -> PathBuf {
    std::env::var_os("VULNCLAW_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~").join(".vulnclaw"))
        .join("tui")
        .join("session.json")
}

pub fn save(state: &SessionState) -> io::Result<PathBuf> {
    let path = expand_home(session_path());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &path,
        serde_json::to_vec_pretty(state).map_err(io::Error::other)?,
    )?;
    Ok(path)
}

pub fn load() -> io::Result<SessionState> {
    let path = expand_home(session_path());
    serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)
}

fn expand_home(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~\\").or_else(|| text.strip_prefix("~/")) {
        return std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest);
    }
    path
}
