use std::collections::{HashMap, HashSet};
use std::sync::mpsc::Sender;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::exec::BackendHandle;
use crate::prompts::text;
use crate::protocol::{AppEvent, BackendEvent, ClientRequest, Finding, StateSnapshot};
use crate::sessions::{self, SessionState};
use crate::skills::catalog::{skill_tree, SkillNode};
use crate::workbench::{Gesture, LayoutGeometry, LayoutState, ViewId};

use ratatui::{
    backend::TestBackend,
    buffer::Buffer,
    layout::Rect,
    widgets::{Paragraph, Wrap},
    Terminal,
};

/// Extract the visible text of a rectangular screen region from a rendered
/// buffer. Used to copy a single workbench pane without pulling in neighbouring
/// panes — the terminal's own drag-select is a whole-screen block selection and
/// cannot be confined to one logical pane.
fn extract_rect_text(buffer: &Buffer, rect: Rect) -> String {
    let area = buffer.area;
    let mut out = String::new();
    for y in rect.y..rect.bottom() {
        if y >= area.height {
            break;
        }
        let mut line = String::new();
        for x in rect.x..rect.right() {
            if x >= area.width {
                break;
            }
            let idx = (y * area.width + x) as usize;
            if let Some(cell) = buffer.content.get(idx) {
                line.push_str(cell.symbol());
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(not(windows))]
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Write text to the system clipboard without pulling in a third-party crate.
/// Windows: persist to a temp UTF-8 file and use the built-in `Set-Clipboard`
/// (handles Unicode correctly). Unix: emit an OSC 52 sequence to the terminal.
fn copy_to_clipboard(text: &str) -> bool {
    #[cfg(windows)]
    {
        use std::process::Command;
        let tmp = std::env::temp_dir().join(format!("vulnclaw-cb-{}.txt", std::process::id()));
        if std::fs::write(&tmp, text.as_bytes()).is_err() {
            return false;
        }
        let path = tmp.to_string_lossy().replace('\'', "''");
        let ps = format!("Set-Clipboard -LiteralPath '{}'", path);
        let status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &ps,
            ])
            .status();
        let _ = std::fs::remove_file(&tmp);
        matches!(status, Ok(s) if s.success())
    }
    #[cfg(not(windows))]
    {
        use std::io::Write;
        let b64 = base64_encode(text.as_bytes());
        let seq = format!("\x1b]52;c;{}\x07", b64);
        let _ = std::io::stdout().write_all(seq.as_bytes());
        let _ = std::io::stdout().flush();
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    Plan,
    Agent,
    Yolo,
}

impl ExecutionMode {
    pub fn next(self) -> Self {
        match self {
            // VulnClaw is a task-driven workbench: Tab cycles between the
            // read-only plan posture and the live agent posture. YOLO is
            // retired.
            Self::Plan => Self::Agent,
            Self::Agent => Self::Plan,
            Self::Yolo => Self::Plan,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Plan => "Plan",
            Self::Agent => "Agent",
            Self::Yolo => "YOLO",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionMode {
    Ask,
    AutoReview,
    FullAccess,
}

impl PermissionMode {
    pub fn next(self) -> Self {
        match self {
            Self::Ask => Self::AutoReview,
            Self::AutoReview => Self::FullAccess,
            Self::FullAccess => Self::Ask,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ask => "Ask",
            Self::AutoReview => "Auto-review",
            Self::FullAccess => "Full access",
        }
    }

    /// Parse the backend's authoritative policy string; unknown values stay
    /// at the safe Ask default.
    pub fn from_policy(value: &str) -> Self {
        match value {
            "auto_review" => Self::AutoReview,
            "full_access" => Self::FullAccess,
            _ => Self::Ask,
        }
    }
}

/// One pending ExecutionGate request awaiting an operator decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingExecution {
    pub request_hash: String,
    pub kind: String,
    /// Visualized (control-char-escaped) command or source.
    pub command: String,
    pub cwd: String,
    pub detail: String,
    pub expires_at: String,
    /// Budget announced by the backend at emit time.
    pub expires_in_secs: u64,
    /// Local receive instant — countdown = budget − elapsed, avoiding any
    /// clock-skew parsing of the ISO stamp.
    pub received_at: std::time::Instant,
    pub risk: String,
    /// Wrapped-row offset within the approval modal body.
    pub scroll_offset: u16,
}

impl PendingExecution {
    /// Live countdown for the modal, driven by the 75 ms redraw loop.
    pub fn remaining_secs(&self) -> u64 {
        self.expires_in_secs
            .saturating_sub(self.received_at.elapsed().as_secs())
    }
}

/// Editable rows of the LLM settings screen, in display order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LlmField {
    #[default]
    Provider,
    WebsiteUrl,
    BaseUrl,
    ApiKey,
    Model,
}

impl LlmField {
    /// Display order; also the order ↑/↓ walks.
    pub const ORDER: [LlmField; 5] = [
        LlmField::Provider,
        LlmField::WebsiteUrl,
        LlmField::BaseUrl,
        LlmField::ApiKey,
        LlmField::Model,
    ];

    pub fn label(self) -> &'static str {
        match self {
            LlmField::Provider => "Template",
            LlmField::WebsiteUrl => "Website URL",
            LlmField::BaseUrl => "API request URL",
            LlmField::ApiKey => "API key",
            LlmField::Model => "Model",
        }
    }

    /// The template row is chosen from the backend's preset list; every other
    /// row is typed into directly.
    pub fn is_editable_text(self) -> bool {
        !matches!(self, LlmField::Provider)
    }

    fn position(self) -> usize {
        Self::ORDER
            .iter()
            .position(|candidate| *candidate == self)
            .unwrap_or(0)
    }
}

/// One provider template advertised by the backend.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProviderEntry {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub website_url: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub default_model: String,
}

/// How many suggestion rows are visible under the model row at once.
///
/// This is a window height, not a cap on the list: the window scrolls to follow
/// the highlighted entry, so every match stays reachable however many the
/// provider returns.
pub const LLM_SUGGESTION_ROWS: usize = 6;

/// State of the `/config` LLM settings screen.
///
/// The screen has two modes. In navigation mode ↑/↓ walk the rows. Enter opens
/// the focused row for typing — after that ↑/↓ no longer leave the row, and only
/// a second Enter (commit) or Esc (discard) closes it again.
#[derive(Clone, Debug, Default)]
pub struct LlmSettings {
    pub provider: String,
    pub website_url: String,
    pub base_url: String,
    /// Only ever holds a key the operator just typed. The backend never returns
    /// stored credentials, so an empty value means "leave the saved one alone".
    pub api_key: String,
    pub api_key_set: bool,
    pub model: String,
    pub providers: Vec<ProviderEntry>,
    /// Models the provider advertises, offered as suggestions while typing the
    /// model name.
    pub models: Vec<String>,
    pub focus: LlmField,
    pub cursor: usize,
    /// True while the focused row is open for typing.
    pub editing: bool,
    /// What the focused row held when typing began; Esc puts it back. Owned by
    /// [`LlmSettings::begin_edit`] / [`LlmSettings::end_edit`], not by callers.
    pub edit_backup: String,
    /// True while the provider template list is open over the focused row.
    pub template_list_open: bool,
    pub list_index: usize,
    /// Highlighted entry of [`Self::suggestions`], once ↑/↓ has picked one.
    pub suggestion: Option<usize>,
    pub status: String,
    pub error: String,
    pub loading: bool,
}

impl LlmSettings {
    /// A screen awaiting its first `config.read` reply.
    pub fn loading() -> Self {
        Self {
            loading: true,
            status: "Loading configuration…".to_owned(),
            ..Self::default()
        }
    }

    pub fn focused_text(&self) -> &str {
        match self.focus {
            LlmField::WebsiteUrl => &self.website_url,
            LlmField::BaseUrl => &self.base_url,
            LlmField::ApiKey => &self.api_key,
            LlmField::Model => &self.model,
            // Not a text row; the template list owns it.
            LlmField::Provider => "",
        }
    }

    fn focused_text_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            LlmField::WebsiteUrl => Some(&mut self.website_url),
            LlmField::BaseUrl => Some(&mut self.base_url),
            LlmField::ApiKey => Some(&mut self.api_key),
            LlmField::Model => Some(&mut self.model),
            LlmField::Provider => None,
        }
    }

    /// Value shown for a row, masking a stored key that was never disclosed.
    pub fn display_value(&self, field: LlmField) -> String {
        match field {
            LlmField::Provider => {
                if self.provider.is_empty() {
                    String::new()
                } else {
                    self.providers
                        .iter()
                        .find(|entry| entry.id == self.provider)
                        .map_or_else(|| self.provider.clone(), |entry| entry.label.clone())
                }
            }
            LlmField::WebsiteUrl => self.website_url.clone(),
            LlmField::BaseUrl => self.base_url.clone(),
            LlmField::ApiKey => {
                if self.api_key.is_empty() && self.api_key_set {
                    "•••••••• (saved)".to_owned()
                } else if self.api_key.is_empty() {
                    String::new()
                } else {
                    "•".repeat(self.api_key.chars().count())
                }
            }
            LlmField::Model => self.model.clone(),
        }
    }

    pub fn focus_field(&mut self, field: LlmField) {
        self.focus = field;
        self.cursor = self.focused_text().len();
        self.editing = false;
        self.edit_backup.clear();
        self.template_list_open = false;
        self.list_index = 0;
        self.suggestion = None;
    }

    /// Walk the rows. Refuses to move while a row is open for typing, which is
    /// what makes the opening Enter a real confirmation step.
    pub fn move_focus(&mut self, forward: bool) {
        if self.editing || self.template_list_open {
            return;
        }
        let position = self.focus.position();
        let count = LlmField::ORDER.len();
        let next = if forward {
            (position + 1) % count
        } else {
            (position + count - 1) % count
        };
        self.focus_field(LlmField::ORDER[next]);
    }

    /// Enter on the focused row.
    ///
    /// Returns true when a text row was opened, which is the caller's cue to
    /// fetch the model list for the row that needs one.
    pub fn begin_edit(&mut self) -> bool {
        self.error.clear();
        if self.focus == LlmField::Provider {
            if self.providers.is_empty() {
                self.error = "No provider templates loaded yet.".to_owned();
                return false;
            }
            self.template_list_open = true;
            let current = self.provider.clone();
            self.list_index = self
                .providers
                .iter()
                .position(|entry| entry.id == current)
                .unwrap_or(0);
            return false;
        }
        self.editing = true;
        self.edit_backup = self.focused_text().to_owned();
        self.move_cursor_to_edge(true);
        self.suggestion = None;
        true
    }

    /// The second Enter closes the row; Esc rolls it back instead.
    pub fn end_edit(&mut self, commit: bool) {
        if !self.editing {
            return;
        }
        if commit {
            // A suggestion picked with ↑/↓ wins over the raw text.
            self.adopt_suggestion();
        } else {
            let backup = std::mem::take(&mut self.edit_backup);
            if let Some(text) = self.focused_text_mut() {
                *text = backup;
            }
        }
        self.editing = false;
        self.edit_backup.clear();
        self.suggestion = None;
        self.move_cursor_to_edge(true);
    }

    /// Model names offered while typing, filtered by what has been typed.
    ///
    /// Returns every match — a provider can advertise hundreds (OpenRouter
    /// reports 445) and the screen only windows them for display.
    pub fn suggestions(&self) -> Vec<String> {
        if !self.editing || self.focus != LlmField::Model {
            return Vec::new();
        }
        let typed = self.model.trim().to_lowercase();
        let matches =
            |model: &String| typed.is_empty() || model.to_lowercase().contains(typed.as_str());
        // Prefix matches first: they are almost always what was meant.
        let mut prefixed: Vec<String> = self
            .models
            .iter()
            .filter(|model| typed.is_empty() || model.to_lowercase().starts_with(&typed))
            .cloned()
            .collect();
        let rest: Vec<String> = self
            .models
            .iter()
            .filter(|model| !prefixed.contains(model) && matches(model))
            .cloned()
            .collect();
        prefixed.extend(rest);
        prefixed
    }

    pub fn move_suggestion(&mut self, forward: bool) {
        let count = self.suggestions().len();
        if count == 0 {
            return;
        }
        self.suggestion = Some(match self.suggestion {
            None => {
                if forward {
                    0
                } else {
                    count - 1
                }
            }
            Some(index) if forward => (index + 1) % count,
            Some(index) => (index + count - 1) % count,
        });
    }

    /// Replace the typed model with the highlighted suggestion, if any.
    fn adopt_suggestion(&mut self) -> bool {
        let Some(index) = self.suggestion else {
            return false;
        };
        let Some(model) = self.suggestions().get(index).cloned() else {
            return false;
        };
        self.model = model;
        true
    }

    /// Close the template list, optionally adopting the highlighted template.
    pub fn close_template_list(&mut self, commit: bool) -> Option<String> {
        if !self.template_list_open {
            return None;
        }
        self.template_list_open = false;
        if !commit {
            return None;
        }
        self.providers
            .get(self.list_index)
            .map(|entry| entry.id.clone())
    }

    /// Labels of the open template list.
    pub fn template_labels(&self) -> Vec<String> {
        self.providers
            .iter()
            .map(|entry| entry.label.clone())
            .collect()
    }

    pub fn insert_char(&mut self, character: char) {
        // Rows only accept input once Enter has opened them, so a stray
        // keystroke or paste can never mutate an unconfirmed row.
        if !self.editing {
            return;
        }
        let cursor = self.cursor.min(self.focused_text().len());
        if let Some(text) = self.focused_text_mut() {
            text.insert(cursor, character);
        }
        self.cursor = cursor + character.len_utf8();
        // Any edit invalidates a highlight chosen against the older text.
        self.suggestion = None;
    }

    pub fn insert_text(&mut self, value: &str) {
        for character in value
            .chars()
            .filter(|character| *character != '\r' && *character != '\n')
        {
            self.insert_char(character);
        }
    }

    pub fn delete_backward(&mut self) {
        if !self.editing {
            return;
        }
        let cursor = self.cursor;
        if cursor == 0 {
            return;
        }
        let previous = previous_char_boundary(self.focused_text(), cursor);
        if let Some(text) = self.focused_text_mut() {
            text.drain(previous..cursor);
        }
        self.cursor = previous;
        self.suggestion = None;
    }

    pub fn delete_forward(&mut self) {
        if !self.editing {
            return;
        }
        let cursor = self.cursor;
        if cursor >= self.focused_text().len() {
            return;
        }
        let next = next_char_boundary(self.focused_text(), cursor);
        if let Some(text) = self.focused_text_mut() {
            text.drain(cursor..next);
        }
        self.suggestion = None;
    }

    pub fn move_cursor(&mut self, right: bool) {
        if !self.editing {
            return;
        }
        self.cursor = if right {
            next_char_boundary(self.focused_text(), self.cursor)
        } else {
            previous_char_boundary(self.focused_text(), self.cursor)
        };
    }

    pub fn move_cursor_to_edge(&mut self, end: bool) {
        self.cursor = if end { self.focused_text().len() } else { 0 };
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum TranscriptKind {
    User,
    System,
    Status,
    Log,
    Reasoning,
    Error,
    Finding,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TranscriptItem {
    pub kind: TranscriptKind,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct SlashCommand {
    pub command: String,
    pub description: &'static str,
}

/// Slash commands rendered locally in the TUI composer palette. The first
/// five are presentation-layer helpers; the remainder mirror the task verbs
/// advertised by the Python backend via `capabilities.commands`. Keeping them
/// here ensures the palette is never empty (or misleadingly tiny) while the
/// backend is still initializing, and gives users a discoverable path to the
/// core pentest workflows even if the capability handshake is delayed.
const LOCAL_SLASH_COMMANDS: &[(&str, &str)] = &[
    ("/scope ", "update session scope defaults"),
    ("/report", "show report export guidance"),
    ("/config", "configure the LLM provider"),
    ("/clear", "clear the transcript"),
    ("/help", "list available commands"),
    ("/run ", "run a task through the Python backend"),
    ("/recon ", "run a task through the Python backend"),
    ("/scan ", "run a task through the Python backend"),
    ("/exploit ", "run a task through the Python backend"),
    ("/persistent ", "run a task through the Python backend"),
    ("/codescan ", "run a task through the Python backend"),
];

const MAX_COMMAND_HISTORY: usize = 50;

/// Rows the composer frame occupies: top rule, input row, bottom rule.
pub const COMPOSER_FRAME_ROWS: u16 = 3;
/// Rows for the mode / guard / model line beneath the composer frame. These
/// indicators used to live in the header; they moved down so the header carries
/// only brand, live worker state and the provider badge.
pub const COMPOSER_STATUS_ROWS: u16 = 1;
/// Rows the command palette occupies above the composer.
pub const PALETTE_ROWS: u16 = 6;
/// Rows the blocking task-confirmation box occupies.
pub const CONFIRM_BOX_ROWS: u16 = 3;

#[derive(Clone, Debug)]
pub struct OperationReceipt {
    pub command: String,
    pub phase: String,
    pub findings: usize,
}

#[derive(Clone, Debug)]
enum PendingRequest {
    Initialize,
    #[allow(dead_code)]
    GetState,
    StartTask(String),
    CancelTask(String),
    Control(String),
    Shutdown,
}

pub struct App {
    pub mode: ExecutionMode,
    pub permission: PermissionMode,
    pub layout: LayoutState,
    pub layout_gesture: Option<Gesture>,
    pub layout_path: Option<std::path::PathBuf>,
    pub input: String,
    pub input_cursor: usize,
    /// Outstanding ExecutionGate request rendered as a blocking modal.
    /// Set by the structured `approval_required` event; resolved with
    /// Y/N/Esc only.
    pub pending_execution: Option<PendingExecution>,
    pub command_history: Vec<String>,
    history_index: Option<usize>,
    history_draft: String,
    pub transcript: Vec<TranscriptItem>,
    pub subagents: crate::subagents::Subagents,
    pub findings: Vec<Finding>,
    /// Finding whose evidence references are expanded. At most one at a time,
    /// so the list does not grow without bound while comparing findings.
    pub expanded_finding: Option<String>,
    /// Row the Findings view has selected, as an index into `findings`.
    pub findings_selection: usize,
    pub palette_selection: usize,
    pub show_reasoning: bool,
    pub running: bool,
    pub worker_active: bool,
    /// One persistent Python backend for the entire terminal session.
    pub backend: Option<BackendHandle>,
    pub backend_ready: bool,
    pub backend_pid: Option<u32>,
    pub config_ready: Option<bool>,
    /// LLM provider and model reported by the backend in `ready.runtime`.
    /// Captured once when the backend starts; it loads config a single time, so
    /// switching provider elsewhere shows up only after the TUI is restarted.
    pub provider: Option<String>,
    pub model: Option<String>,
    /// Task verbs advertised by the backend in `ready.capabilities.commands`.
    /// Local presentation commands such as `/help` are deliberately separate.
    pub backend_commands: Vec<String>,
    /// Optional management operations advertised by the Python backend.
    pub backend_control_operations: Vec<String>,
    pub backend_supports_cancellation: bool,
    pub target: String,
    pub phase: String,
    pub active_task_id: Option<String>,
    pub task_constraints: serde_json::Value,
    pub last_run: Option<serde_json::Value>,
    pub evidence: Vec<serde_json::Value>,
    pub constraint_violations: Vec<String>,
    request_counter: u64,
    pending_requests: HashMap<String, PendingRequest>,
    pub active_receipt: Option<OperationReceipt>,
    pub last_receipt: Option<OperationReceipt>,
    /// Monotonic instant the current worker started, used to render a live
    /// elapsed-time readout (`mm:ss`) in the header while a command runs.
    pub worker_started_at: Option<Instant>,
    pub show_attack_chain: bool,
    pub pending_task: Option<String>,
    /// `/config` LLM settings screen. `Some` while it is open; like the other
    /// overlays it is a plain field rather than an entry in a modal stack.
    pub llm_settings: Option<LlmSettings>,
    pub skills: Vec<SkillNode>,
    /// Last known terminal viewport size, captured each frame. Used to render an
    /// offscreen copy of the focused pane for independent clipboard copies.
    pub terminal_size: Rect,
    /// Transient feedback line shown in the hotbar (e.g. "Copied …"). Cleared on
    /// the next key press.
    pub toast: String,
    #[cfg_attr(test, allow(dead_code))]
    sender: Sender<AppEvent>,
}

impl App {
    /// Create an application and connect it to the default Python backend.
    pub fn new(sender: Sender<AppEvent>) -> Self {
        let mut app = Self::new_disconnected(sender);
        app.connect_backend();
        app
    }

    /// Create application state without starting a backend process.
    ///
    /// This is useful for embedding, UI previews, and tests that exercise pure
    /// state and rendering behavior.
    pub fn new_disconnected(sender: Sender<AppEvent>) -> Self {
        Self {
            mode: ExecutionMode::Agent,
            permission: PermissionMode::Ask,
            layout: LayoutState::default(),
            layout_gesture: None,
            layout_path: None,
            input: String::new(),
            input_cursor: 0,
            pending_execution: None,
            command_history: Vec::new(),
            history_index: None,
            history_draft: String::new(),
            transcript: vec![
                TranscriptItem {
                    kind: TranscriptKind::System,
                    text: text::WELCOME.to_owned(),
                },
                TranscriptItem {
                    kind: TranscriptKind::Status,
                    text: text::READY.to_owned(),
                },
            ],
            subagents: crate::subagents::Subagents::default(),
            findings: Vec::new(),
            expanded_finding: None,
            findings_selection: 0,
            palette_selection: 0,
            show_reasoning: true,
            running: true,
            worker_active: false,
            backend: None,
            backend_ready: false,
            backend_pid: None,
            config_ready: None,
            provider: None,
            model: None,
            backend_commands: Vec::new(),
            backend_control_operations: Vec::new(),
            backend_supports_cancellation: false,
            target: String::new(),
            phase: "idle".to_owned(),
            active_task_id: None,
            task_constraints: serde_json::json!({}),
            last_run: None,
            evidence: Vec::new(),
            constraint_violations: Vec::new(),
            request_counter: 0,
            pending_requests: HashMap::new(),
            active_receipt: None,
            last_receipt: None,
            worker_started_at: None,
            show_attack_chain: false,
            pending_task: None,
            llm_settings: None,
            skills: skill_tree(),
            terminal_size: Rect::default(),
            toast: String::new(),
            sender,
        }
    }

    /// Create application state around an already spawned backend transport.
    ///
    /// The constructor sends the protocol initialization request immediately,
    /// allowing callers to inject a controlled backend implementation.
    pub fn with_backend(
        sender: Sender<AppEvent>,
        backend: BackendHandle,
        bootstrap: serde_json::Value,
    ) -> Self {
        let mut app = Self::new_disconnected(sender);
        app.initialize_backend(backend, bootstrap);
        app
    }

    fn next_request_id(&mut self) -> String {
        self.request_counter = self.request_counter.saturating_add(1);
        format!("rust-{}-{}", std::process::id(), self.request_counter)
    }

    fn connect_backend(&mut self) {
        match crate::exec::spawn_backend(self.sender.clone()) {
            Ok(handle) => {
                let bootstrap = std::env::var("VULNCLAW_TUI_BOOTSTRAP")
                    .ok()
                    .and_then(|raw| serde_json::from_str(&raw).ok())
                    .unwrap_or_else(|| serde_json::json!({}));
                self.initialize_backend(handle, bootstrap);
            }
            Err(error) => self.error(format!("Could not start VulnClaw Python backend: {error}")),
        }
    }

    fn initialize_backend(&mut self, handle: BackendHandle, bootstrap: serde_json::Value) {
        let request_id = self.next_request_id();
        let request = ClientRequest::initialize(request_id.clone(), bootstrap);
        if let Err(error) = handle.send(&request) {
            handle.wait_or_kill(std::time::Duration::from_millis(100));
            self.error(format!("Could not initialize Python backend: {error}"));
        } else {
            self.pending_requests
                .insert(request_id, PendingRequest::Initialize);
            self.backend = Some(handle);
            self.status("Connecting to the VulnClaw Python backend...");
        }
    }

    pub fn submit(&mut self) {
        let command = strip_prompt_prefix(self.input.trim());
        if command.is_empty() {
            return;
        }
        self.record_command(&command);
        self.push(TranscriptKind::User, format!("> {command}"));
        self.clear_composer();
        if command == "/help" {
            let backend = if self.backend_commands.is_empty() {
                "none advertised yet".to_owned()
            } else {
                self.backend_commands
                    .iter()
                    .map(|command| format!("/{command} <target>"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            self.status(format!(
                "Backend tasks: {backend}. Local commands: /scope, /report, /config, /clear, /help. Ctrl+C aborts a running command."
            ));
        } else if command == "/clear" {
            self.transcript.clear();
            self.layout.output.scroll = 0;
            self.layout.output.follow = true;
            self.status("Transcript cleared. Findings remain available in the inspector.");
        } else if command == "/report" {
            self.status(
                "Use vulnclaw report <result.json> [--pdf] to write the report; the TUI shows findings live.",
            );
        } else if command == "/config" {
            self.open_llm_settings();
        } else if let Some((verb, arguments)) = split_slash_command(&command) {
            if verb == "scope" {
                self.request_scope_control(arguments);
            } else if is_task_verb(verb) {
                self.request_task(verb, arguments);
            } else {
                self.error(format!("Unknown command: {command}"));
            }
        } else {
            self.error(format!("Unknown command: {command}"));
        }
    }

    pub fn cycle_mode(&mut self) {
        self.set_mode(self.mode.next());
    }

    pub fn cycle_permission(&mut self) {
        let next = self.permission.next();
        let mode_value = match next {
            PermissionMode::Ask => "ask",
            PermissionMode::AutoReview => "auto_review",
            PermissionMode::FullAccess => "full_access",
        };
        // The backend owns the authoritative policy; the local label only
        // updates when the control call succeeds.
        let arguments = serde_json::json!({ "mode": mode_value });
        let sent = if self.worker_active {
            self.send_control_during_task("session.permission.set", arguments)
        } else {
            self.request_control("session.permission.set", arguments)
        };
        if sent {
            self.status(format!(
                "Permission mode change to {} requested.",
                next.label()
            ));
        }
    }

    pub fn scroll_pending_execution(&mut self, down: bool, page: bool) {
        let Some(pending) = self.pending_execution.as_ref() else {
            return;
        };
        let max = crate::ui::layout::approval_max_scroll(pending, self.terminal_size);
        let step = if page {
            usize::from(crate::ui::layout::approval_body_height(self.terminal_size).max(1))
        } else {
            1
        };
        let current = usize::from(pending.scroll_offset).min(max);
        let next = if down {
            current.saturating_add(step).min(max)
        } else {
            current.saturating_sub(step)
        };
        if let Some(pending) = self.pending_execution.as_mut() {
            pending.scroll_offset = u16::try_from(next).unwrap_or(u16::MAX);
        }
    }

    pub fn required_input_height(&self) -> u16 {
        if self.pending_task.is_some() {
            // The confirmation box replaces the framed input but still carries
            // the mode/guard line beneath it.
            CONFIRM_BOX_ROWS + COMPOSER_STATUS_ROWS
        } else {
            let palette = if self.palette_visible() {
                PALETTE_ROWS
            } else {
                0
            };
            palette + COMPOSER_FRAME_ROWS + COMPOSER_STATUS_ROWS
        }
    }

    pub fn geometry(&self, area: Rect) -> LayoutGeometry {
        LayoutGeometry::compute(area, &self.layout, self.required_input_height())
    }

    pub fn cycle_active_view(&mut self, backwards: bool) {
        self.layout.cycle_focus(backwards);
    }

    pub fn scroll_active_view(&mut self, down: bool) {
        self.scroll_view(self.layout.focus, down);
    }

    pub fn scroll_view(&mut self, id: ViewId, down: bool) {
        if self.layout.view(id).collapsed {
            return;
        }
        let geometry = self.geometry(self.terminal_size);
        if geometry.too_small {
            return;
        }
        let max = self.view_max_scroll(id, &geometry);
        let view = self.layout.view_mut(id);
        let current = view.scroll.min(max);
        view.scroll = if down {
            current.saturating_add(1).min(max)
        } else {
            current.saturating_sub(1)
        };
        if id == ViewId::Output {
            view.follow = view.scroll == max;
        }
    }

    fn view_max_scroll(&self, id: ViewId, geometry: &LayoutGeometry) -> u16 {
        let Some(region) = geometry.view(id) else {
            return 0;
        };
        if region.content.width == 0 || region.content.height == 0 {
            return 0;
        }
        let total = match id {
            ViewId::Output => Paragraph::new(crate::ui::transcript::build_lines(self))
                .wrap(Wrap { trim: false })
                .line_count(region.content.width),
            ViewId::Status => Paragraph::new(crate::views::status::build_lines(self))
                .wrap(Wrap { trim: false })
                .line_count(region.content.width),
            ViewId::Capabilities => Paragraph::new(crate::views::capabilities::build_lines(self))
                .wrap(Wrap { trim: false })
                .line_count(region.content.width),
            ViewId::Findings => self.finding_rows(),
            ViewId::Subagents => self.subagents.rows().len(),
        };
        u16::try_from(total.saturating_sub(usize::from(region.content.height))).unwrap_or(u16::MAX)
    }

    pub fn refresh_view_scrolls(&mut self) {
        let geometry = self.geometry(self.terminal_size);
        if geometry.too_small {
            return;
        }
        for region in &geometry.views {
            if region.content.height == 0 {
                continue;
            }
            let max = self.view_max_scroll(region.id, &geometry);
            let view = self.layout.view_mut(region.id);
            if region.id == ViewId::Output && view.follow {
                view.scroll = max;
            } else {
                view.scroll = view.scroll.min(max);
            }
        }
    }

    pub fn active_view_rect(&self, area: Rect) -> Rect {
        self.geometry(area)
            .view(self.layout.focus)
            .map_or(Rect::default(), |view| view.rect)
    }

    pub fn load_layout(&mut self, path: std::path::PathBuf) {
        match crate::preferences::load(&path) {
            Ok(layout) => self.layout = layout,
            Err(error) => {
                self.layout = LayoutState::default();
                self.toast = format!("Layout load failed: {error}; using defaults");
            }
        }
        self.layout_path = Some(path);
    }

    pub fn save_layout(&mut self) {
        if let Some(path) = &self.layout_path {
            if let Err(error) = crate::preferences::save(path, &self.layout) {
                self.toast = format!("Layout save failed: {error}");
            }
        }
    }

    pub fn cancel_layout_gesture(&mut self) {
        if let Some(gesture) = self.layout_gesture.take() {
            self.restore_layout(&gesture);
        }
    }

    /// Put back the geometry a resize gesture changed, leaving scroll and focus
    /// alone. Every view in a free container is restored, not a fixed list:
    /// `workbench::resize` materializes the height of each of them.
    pub fn restore_layout(&mut self, gesture: &Gesture) {
        let Gesture::Resize { original, .. } = gesture else {
            return;
        };
        self.layout.primary_width = original.primary_width;
        self.layout.secondary_width = original.secondary_width;
        for view in self
            .layout
            .primary
            .iter_mut()
            .chain(&mut self.layout.secondary)
        {
            view.expanded_height = original.view(view.id).expanded_height;
        }
    }

    /// Copy the focused workbench pane to the system clipboard. Each pane is
    /// copied independently — copying one never drags in the others. The
    /// terminal's own drag-select is a whole-screen block selection that cannot
    /// be confined to a single logical pane, so this is the reliable per-pane
    /// copy path.
    pub fn copy_active_view(&mut self) {
        let area = self.terminal_size;
        if area.width == 0 || area.height == 0 {
            self.toast = "Copy unavailable: terminal size unknown".into();
            return;
        }
        let backend = TestBackend::new(area.width, area.height);
        let mut term = match Terminal::new(backend) {
            Ok(t) => t,
            Err(_) => {
                self.toast = "Copy failed: cannot render pane".into();
                return;
            }
        };
        let app_ref: &App = self;
        if term.draw(|f| crate::ui::draw(f, app_ref)).is_err() {
            self.toast = "Copy failed: cannot render pane".into();
            return;
        }
        let buffer = term.backend().buffer();
        let rect = self.active_view_rect(area);
        let text = extract_rect_text(buffer, rect);
        let label = self.layout.focus.label();
        if copy_to_clipboard(&text) {
            self.toast = format!(
                "Copied {} to clipboard ({} chars)",
                label,
                text.chars().count()
            );
        } else {
            self.toast = "Copy failed: clipboard unavailable".into();
        }
    }

    pub fn append_input(&mut self, character: char) {
        self.insert_text(&character.to_string());
    }

    pub fn clear_composer(&mut self) {
        self.input.clear();
        self.input_cursor = 0;
        self.palette_selection = 0;
        self.clear_history_navigation();
    }

    /// Insert pasted/IME text into the presentation-only composer. Newlines are
    /// dropped so a multi-line paste never submits more than one command.
    pub fn insert_text(&mut self, text: &str) {
        for character in text
            .chars()
            .filter(|character| *character != '\r' && *character != '\n')
        {
            self.input.insert(self.input_cursor, character);
            self.input_cursor += character.len_utf8();
        }
        self.palette_selection = 0;
        self.clear_history_navigation();
    }

    pub fn delete_input(&mut self) {
        if self.input_cursor == 0 {
            return;
        }
        let previous = previous_char_boundary(&self.input, self.input_cursor);
        self.input.drain(previous..self.input_cursor);
        self.input_cursor = previous;
        self.palette_selection = 0;
        self.clear_history_navigation();
    }

    pub fn delete_forward_input(&mut self) {
        if self.input_cursor >= self.input.len() {
            return;
        }
        let next = next_char_boundary(&self.input, self.input_cursor);
        self.input.drain(self.input_cursor..next);
        self.palette_selection = 0;
        self.clear_history_navigation();
    }

    pub fn move_input_cursor(&mut self, right: bool) {
        self.input_cursor = if right {
            next_char_boundary(&self.input, self.input_cursor)
        } else {
            previous_char_boundary(&self.input, self.input_cursor)
        };
        self.palette_selection = 0;
    }

    pub fn move_input_cursor_to_edge(&mut self, end: bool) {
        self.input_cursor = if end { self.input.len() } else { 0 };
        self.palette_selection = 0;
    }

    pub fn recall_history(&mut self, older: bool) {
        if self.command_history.is_empty() {
            return;
        }
        let next_index = if older {
            match self.history_index {
                Some(index) => index.saturating_sub(1),
                None => {
                    self.history_draft = self.input.clone();
                    self.command_history.len() - 1
                }
            }
        } else {
            let Some(index) = self.history_index else {
                return;
            };
            if index + 1 == self.command_history.len() {
                self.history_index = None;
                self.set_input(self.history_draft.clone());
                self.history_draft.clear();
                return;
            }
            index + 1
        };
        self.history_index = Some(next_index);
        self.set_input(self.command_history[next_index].clone());
    }

    pub fn palette_visible(&self) -> bool {
        self.input_cursor == self.input.len()
            && self.input.trim_start().starts_with('/')
            && !self.suggested_commands().is_empty()
    }

    pub fn suggested_commands(&self) -> Vec<SlashCommand> {
        let query = self.input.trim_start().to_ascii_lowercase();
        if !query.starts_with('/') {
            return Vec::new();
        }
        let backend = self.backend_commands.iter().map(|command| SlashCommand {
            command: format!("/{command} "),
            description: "run a task through the Python backend",
        });
        let local = LOCAL_SLASH_COMMANDS
            .iter()
            .map(|(command, description)| SlashCommand {
                command: (*command).to_owned(),
                description,
            });
        // `LOCAL_SLASH_COMMANDS` repeats the backend's task verbs so the
        // palette is never empty before the capability handshake lands. Once
        // the backend reports them the same verb would appear twice, so keep
        // the first (authoritative) occurrence and drop the local fallback.
        let mut seen = HashSet::new();
        backend
            .chain(local)
            .filter(|item| item.command.starts_with(&query))
            .filter(|item| seen.insert(item.command.clone()))
            .collect()
    }

    pub fn select_next_command(&mut self, down: bool) {
        let count = self.suggested_commands().len();
        if count == 0 {
            return;
        }
        self.palette_selection = if down {
            (self.palette_selection + 1) % count
        } else {
            (self.palette_selection + count - 1) % count
        };
    }

    pub fn accept_selected_command(&mut self) -> bool {
        let commands = self.suggested_commands();
        let Some(command) = commands.get(self.palette_selection) else {
            return false;
        };
        self.set_input(command.command.to_owned());
        true
    }

    pub fn should_complete_selected_command(&self) -> bool {
        let commands = self.suggested_commands();
        let Some(command) = commands.get(self.palette_selection) else {
            return false;
        };
        (command.command.ends_with(' ') && self.input == command.command.trim_end())
            || (self.input.trim() != command.command.trim() && !self.input.ends_with(' '))
    }

    pub fn confirm_task(&mut self) {
        let Some(command_line) = self.pending_task.take() else {
            return;
        };
        self.status("TUI confirmation recorded. Starting task.");
        self.start_task(command_line);
    }

    pub fn dismiss_task(&mut self) {
        if self.pending_task.take().is_some() {
            self.status("Task command cancelled before execution.");
        }
    }

    pub fn apply_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Backend(stream) => match *stream {
                BackendEvent::Ready {
                    request_id,
                    backend,
                    capabilities,
                    runtime,
                    state,
                } => {
                    if !matches!(
                        self.pending_requests.remove(&request_id),
                        Some(PendingRequest::Initialize)
                    ) {
                        self.error(format!("Unexpected ready response: {request_id}"));
                        return;
                    }
                    self.backend_ready = true;
                    self.backend_pid = Some(backend.pid);
                    self.config_ready = Some(runtime.config_ready);
                    self.provider = Some(runtime.provider.clone());
                    self.model = Some(runtime.model.clone());
                    self.backend_commands = capabilities
                        .commands
                        .into_iter()
                        .filter_map(normalize_backend_command)
                        .collect();
                    self.backend_commands.sort();
                    self.backend_commands.dedup();
                    self.backend_control_operations = capabilities
                        .control_operations
                        .into_iter()
                        .filter(|operation| !operation.trim().is_empty())
                        .collect();
                    self.backend_control_operations.sort();
                    self.backend_control_operations.dedup();
                    self.backend_supports_cancellation = capabilities.cancellation;
                    // Sync the client label to the backend's authoritative
                    // policy so the status bar is correct from startup.
                    if !capabilities.permission_mode.is_empty() {
                        self.permission =
                            PermissionMode::from_policy(&capabilities.permission_mode);
                    }
                    if !capabilities.authoritative_state {
                        self.error(
                            "Backend does not advertise authoritative state; refusing task commands.",
                        );
                        self.backend_commands.clear();
                    }
                    self.apply_backend_state(state);
                    if !runtime.skills.is_empty() {
                        self.skills = vec![SkillNode {
                            name: "Python skills".into(),
                            children: runtime
                                .skills
                                .into_iter()
                                .map(|name| SkillNode {
                                    name,
                                    children: Vec::new(),
                                })
                                .collect(),
                        }];
                    }
                    self.status(format!(
                        "Python backend ready (pid {}, VulnClaw {}, {}/{}).",
                        backend.pid, backend.version, runtime.provider, runtime.model
                    ));
                    if !runtime.config_ready {
                        self.error(
                            "LLM credentials are not configured. Run `vulnclaw config set` before starting a task.",
                        );
                    }
                }
                BackendEvent::State { request_id, state } => {
                    if let Some(request_id) = request_id {
                        if !matches!(
                            self.pending_requests.remove(&request_id),
                            Some(PendingRequest::GetState)
                        ) {
                            self.error(format!("Unexpected state response: {request_id}"));
                            return;
                        }
                    }
                    self.apply_backend_state(state);
                }
                BackendEvent::TaskStarted {
                    request_id,
                    task_id,
                    task,
                    state,
                } => {
                    if !matches!(
                        self.pending_requests.get(&request_id),
                        Some(PendingRequest::StartTask(expected)) if expected == &task_id
                    ) {
                        self.error(format!("Unexpected task_started response: {request_id}"));
                        return;
                    }
                    if self.active_task_id.as_deref() != Some(task_id.as_str()) {
                        return;
                    }
                    self.subagents.selection = None;
                    self.open_selected_subagent();
                    self.subagents = crate::subagents::Subagents::default();
                    self.layout.view_mut(ViewId::Subagents).scroll = 0;
                    self.worker_active = true;
                    self.worker_started_at = Some(Instant::now());
                    self.apply_backend_state(state);
                    if let Some(receipt) = self.active_receipt.as_mut() {
                        let command = task["command"].as_str().unwrap_or("task");
                        receipt.phase = format!("{command} running");
                    }
                }
                BackendEvent::Subagent { task_id, agent } => {
                    if self.is_current_task(&task_id) {
                        self.subagents.upsert(agent);
                    }
                }
                BackendEvent::Status {
                    task_id,
                    agent_id,
                    status: message,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    if agent_id.is_none() {
                        self.update_receipt(&message);
                    }
                    self.push_stream(agent_id, TranscriptKind::Status, message, false);
                }
                BackendEvent::Finding { task_id, finding } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.upsert_finding(finding);
                }
                BackendEvent::Reasoning {
                    task_id,
                    agent_id,
                    append,
                    text: chunk,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    if agent_id.is_none() {
                        self.update_receipt("Thinking");
                    }
                    self.push_stream(agent_id, TranscriptKind::Reasoning, chunk, append);
                }
                BackendEvent::Log {
                    task_id,
                    agent_id,
                    append,
                    message: line,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    if agent_id.is_none() {
                        self.update_receipt("Running");
                    }
                    self.push_stream(agent_id, TranscriptKind::Log, line, append);
                }
                BackendEvent::ToolCall {
                    task_id,
                    agent_id,
                    tool,
                    arguments,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    if agent_id.is_none() {
                        self.update_receipt("Using tool");
                    }
                    self.push_stream(
                        agent_id,
                        TranscriptKind::Log,
                        format!("→ tool: {tool} {}", truncate_text(&arguments, 160)),
                        false,
                    );
                }
                BackendEvent::ToolResult {
                    task_id,
                    agent_id,
                    result,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    if agent_id.is_none() {
                        self.update_receipt("Running");
                    }
                    self.push_stream(
                        agent_id,
                        TranscriptKind::Log,
                        format!("→ result: {}", truncate_text(&result, 240)),
                        false,
                    );
                }
                BackendEvent::ApprovalRequired {
                    task_id,
                    question,
                    request_hash,
                    kind,
                    cwd,
                    detail,
                    expires_at,
                    expires_in_seconds,
                    risk,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    let structured = !request_hash.is_empty();
                    if structured {
                        // Blocking modal: the operator answers with Y/N/Esc.
                        self.pending_execution = Some(PendingExecution {
                            request_hash: request_hash.clone(),
                            kind: kind.clone(),
                            command: question.clone(),
                            cwd: cwd.clone(),
                            detail: detail.clone(),
                            expires_at: expires_at.clone(),
                            expires_in_secs: expires_in_seconds,
                            received_at: std::time::Instant::now(),
                            risk: risk.clone(),
                            scroll_offset: 0,
                        });
                    }
                    let mut lines = vec![format!("Approval required [{kind}]: {question}")];
                    if !cwd.is_empty() {
                        lines.push(format!("  cwd: {cwd}"));
                    }
                    if !detail.is_empty() {
                        lines.push(format!("  detail: {detail}"));
                    }
                    if !expires_at.is_empty() {
                        lines.push(format!("  expires: {expires_at}"));
                    }
                    if !risk.is_empty() {
                        lines.push(format!("  risk: {risk}"));
                    }
                    if structured {
                        lines.push("  Y 批准 · N/Esc 拒绝(默认拒绝)".to_string());
                    }
                    self.push(TranscriptKind::Status, lines.join("\n"));
                }
                BackendEvent::ApprovalClosed {
                    task_id,
                    request_hash,
                    status,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    let matches = self
                        .pending_execution
                        .as_ref()
                        .map(|p| p.request_hash == request_hash)
                        .unwrap_or(false);
                    if matches {
                        self.pending_execution = None;
                    }
                    let text = match status.as_str() {
                        "expired" => "审批超时,已自动拒绝",
                        "denied" => "操作者拒绝了该请求",
                        "approved" => "已批准并执行",
                        "cancelled" => "审批请求已取消",
                        other => other,
                    };
                    self.push(TranscriptKind::Status, format!("审批关闭: {text}"));
                }
                BackendEvent::TaskCompleted {
                    request_id,
                    task_id,
                    result,
                    findings: _,
                    state,
                } => {
                    if !self.matches_task_response(&request_id, &task_id) {
                        return;
                    }
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.apply_backend_state(state);
                    self.clear_task_requests(&task_id);
                    self.finish_task("Completed");
                    let run_name = result
                        .get("run")
                        .and_then(|run| run.get("name"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    self.status(if run_name.is_empty() {
                        "VulnClaw task completed.".to_owned()
                    } else {
                        format!("VulnClaw task completed. Run: {run_name}")
                    });
                }
                BackendEvent::TaskCancelled {
                    request_id,
                    task_id,
                    state,
                } => {
                    if !self.matches_task_response(&request_id, &task_id) {
                        return;
                    }
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.apply_backend_state(state);
                    self.clear_task_requests(&task_id);
                    self.finish_task("Cancelled");
                    self.status("VulnClaw task cancelled; backend session remains available.");
                }
                BackendEvent::TaskFailed {
                    request_id,
                    task_id,
                    error,
                    state,
                } => {
                    if !self.matches_task_response(&request_id, &task_id) {
                        return;
                    }
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.apply_backend_state(state);
                    self.clear_task_requests(&task_id);
                    self.finish_task("Failed");
                    let message = error
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("task failed");
                    self.error(format!("VulnClaw task failed: {message}"));
                }
                BackendEvent::ControlResult {
                    request_id,
                    operation,
                    result,
                    state,
                } => {
                    if !matches!(
                        self.pending_requests.remove(&request_id),
                        Some(PendingRequest::Control(expected)) if expected == operation
                    ) {
                        self.error(format!("Unexpected control response: {request_id}"));
                        return;
                    }
                    if let Some(state) = state {
                        self.apply_backend_state(state);
                    }
                    if operation == "session.permission.set" {
                        if let Some(mode_str) =
                            result.get("mode").and_then(serde_json::Value::as_str)
                        {
                            self.permission = match mode_str {
                                "ask" => PermissionMode::Ask,
                                "auto_review" => PermissionMode::AutoReview,
                                "full_access" => PermissionMode::FullAccess,
                                _ => self.permission,
                            };
                        }
                    }
                    // The settings operations own their feedback: it belongs in
                    // the modal, which covers the hotbar the status line uses.
                    match operation.as_str() {
                        "config.read" => {
                            self.apply_config_read(&result);
                            return;
                        }
                        "config.preset" => {
                            self.apply_config_preset(&result);
                            return;
                        }
                        "config.models" => {
                            self.apply_config_models(&result);
                            return;
                        }
                        "config.write" => {
                            self.apply_config_write(&result);
                            return;
                        }
                        _ => {}
                    }
                    self.status(
                        result
                            .get("message")
                            .and_then(serde_json::Value::as_str)
                            .map_or_else(
                                || format!("Backend control {operation} completed."),
                                str::to_owned,
                            ),
                    );
                }
                BackendEvent::Error {
                    request_id,
                    task_id,
                    code,
                    message,
                } => {
                    let mut failed_config_operation: Option<String> = None;
                    let rejected_start = if let Some(request_id) = request_id {
                        match self.pending_requests.remove(&request_id) {
                            None => {
                                self.error(format!(
                                    "Unexpected backend error response: {request_id}"
                                ));
                                return;
                            }
                            Some(PendingRequest::StartTask(expected)) => {
                                if task_id.as_deref() != Some(expected.as_str()) {
                                    self.error(format!(
                                        "Mismatched task error response: {request_id}"
                                    ));
                                    return;
                                }
                                true
                            }
                            Some(PendingRequest::CancelTask(expected)) => {
                                if task_id.as_deref() != Some(expected.as_str()) {
                                    self.error(format!(
                                        "Mismatched task error response: {request_id}"
                                    ));
                                    return;
                                }
                                false
                            }
                            Some(PendingRequest::Control(operation)) => {
                                // A rejected settings edit keeps the modal open
                                // so the operator can correct and retry.
                                if operation.starts_with("config.") {
                                    failed_config_operation = Some(operation);
                                }
                                false
                            }
                            Some(_) => false,
                        }
                    } else {
                        false
                    };
                    if rejected_start {
                        if task_id != self.active_task_id {
                            self.error("Mismatched active task error response.");
                            return;
                        }
                        self.finish_task("Rejected");
                    }
                    self.error(format!("Backend {code}: {message}"));
                    if let Some(operation) = failed_config_operation {
                        self.apply_config_failure(&operation, &message);
                    }
                }
                BackendEvent::ShutdownComplete { request_id } => {
                    if !matches!(
                        self.pending_requests.remove(&request_id),
                        Some(PendingRequest::Shutdown)
                    ) {
                        return;
                    }
                    self.backend_ready = false;
                    self.backend_commands.clear();
                    self.backend_control_operations.clear();
                }
            },
            AppEvent::BackendDiagnostic(message) => {
                self.push(TranscriptKind::Log, format!("backend: {message}"));
            }
            AppEvent::BackendExited(success) => {
                self.backend = None;
                self.backend_ready = false;
                self.backend_pid = None;
                self.backend_commands.clear();
                self.backend_control_operations.clear();
                self.backend_supports_cancellation = false;
                self.pending_requests.clear();
                self.worker_active = false;
                self.worker_started_at = None;
                if let Some(mut receipt) = self.active_receipt.take() {
                    receipt.phase = "Backend disconnected".to_owned();
                    self.last_receipt = Some(receipt);
                }
                self.active_task_id = None;
                if self.running {
                    self.error(if success {
                        "Python backend exited."
                    } else {
                        "Python backend exited with a non-zero status."
                    });
                }
            }
        }
    }

    fn is_current_task(&self, task_id: &str) -> bool {
        self.active_task_id.as_deref() == Some(task_id)
    }

    fn matches_task_response(&mut self, request_id: &str, task_id: &str) -> bool {
        let matches = matches!(
            self.pending_requests.get(request_id),
            Some(PendingRequest::StartTask(expected) | PendingRequest::CancelTask(expected))
                if expected == task_id
        );
        if !matches {
            self.error(format!("Unexpected task response: {request_id}"));
        }
        matches
    }

    pub fn clear_task_requests(&mut self, task_id: &str) {
        // The task ended: any outstanding approval modal is moot (the gate
        // expires its pending server-side, default deny).
        self.pending_execution = None;
        self.pending_requests.retain(|_, pending| {
            !matches!(
                pending,
                PendingRequest::StartTask(expected) | PendingRequest::CancelTask(expected)
                    if expected == task_id
            )
        });
    }

    fn apply_backend_state(&mut self, state: StateSnapshot) {
        self.target = state.target;
        self.phase = state.phase;
        self.findings = state.findings;
        self.worker_active = state.task.active;
        self.active_task_id = state.task.task_id;
        self.task_constraints = state.task_constraints;
        self.last_run = state.last_run;
        self.evidence = state.evidence;
        self.constraint_violations = state.constraint_violations;
        if let Some(receipt) = self.active_receipt.as_mut() {
            receipt.findings = self.findings.len();
        }
    }

    /// Findings view row count, including the evidence rows of the expanded
    /// finding. Kept here so scroll clamping and rendering agree.
    pub fn finding_rows(&self) -> usize {
        self.findings.len()
            + self
                .expanded_finding
                .as_ref()
                .and_then(|id| self.findings.iter().find(|finding| &finding.id == id))
                .map_or(0, |finding| finding.evidence_refs.len())
    }

    /// Row offset of the selected finding within the Findings view. Differs from
    /// `findings_selection` whenever an earlier finding is expanded.
    pub fn selected_finding_row(&self) -> usize {
        let expanded = self.expanded_finding.as_deref();
        self.findings
            .iter()
            .take(self.findings_selection)
            .map(|finding| {
                1 + if Some(finding.id.as_str()) == expanded {
                    finding.evidence_refs.len()
                } else {
                    0
                }
            })
            .sum()
    }

    /// Scroll the Findings view just enough to keep the selected row visible.
    pub fn reveal_selected_finding(&mut self) {
        let geometry = self.geometry(self.terminal_size);
        let Some(region) = geometry.view(ViewId::Findings) else {
            return;
        };
        let row = self.selected_finding_row();
        crate::workbench::scroll_to_row(
            self.layout.view_mut(ViewId::Findings),
            row,
            usize::from(region.content.height),
        );
    }

    pub fn move_findings_selection(&mut self, down: bool) {
        if self.findings.is_empty() {
            self.findings_selection = 0;
            return;
        }
        let last = self.findings.len() - 1;
        self.findings_selection = if down {
            (self.findings_selection + 1).min(last)
        } else {
            self.findings_selection.saturating_sub(1)
        };
    }

    pub fn select_finding(&mut self, index: usize) {
        if self.findings.is_empty() {
            self.findings_selection = 0;
            return;
        }
        self.findings_selection = index.min(self.findings.len() - 1);
    }

    /// Expand the selected finding, collapsing whatever was open before.
    pub fn toggle_selected_finding(&mut self) -> bool {
        let Some(finding) = self.findings.get(self.findings_selection) else {
            return false;
        };
        if finding.evidence_refs.is_empty() {
            return false;
        }
        let id = finding.id.clone();
        self.expanded_finding = if self.expanded_finding.as_deref() == Some(id.as_str()) {
            None
        } else {
            Some(id)
        };
        true
    }

    fn upsert_finding(&mut self, finding: Finding) {
        let summary = finding.summary();
        if let Some(existing) = self
            .findings
            .iter_mut()
            .find(|item| !finding.id.is_empty() && item.id == finding.id)
        {
            *existing = finding;
        } else {
            self.findings.push(finding);
            self.push(TranscriptKind::Finding, summary);
        }
        if let Some(receipt) = self.active_receipt.as_mut() {
            receipt.findings = self.findings.len();
            receipt.phase = "Receiving findings".to_owned();
        }
    }

    fn finish_task(&mut self, phase: &str) {
        self.worker_active = false;
        self.worker_started_at = None;
        self.active_task_id = None;
        if let Some(mut receipt) = self.active_receipt.take() {
            receipt.phase = phase.to_owned();
            receipt.findings = self.findings.len();
            self.last_receipt = Some(receipt);
        }
    }

    pub fn save_session(&mut self) {
        let state = SessionState::from_app(self);
        match sessions::save(&state) {
            Ok(path) => self.status(format!("Session saved: {}", path.display())),
            Err(error) => self.error(format!("Could not save session: {error}")),
        }
    }

    pub fn restore_session(&mut self) {
        match sessions::load() {
            Ok(state) => {
                state.apply(self);
                self.status("Session restored.");
            }
            Err(error) => self.error(format!("Could not restore session: {error}")),
        }
    }

    fn set_mode(&mut self, mode: ExecutionMode) {
        self.mode = mode;
        self.status(format!("Execution mode switched to {}.", mode.label()));
    }

    fn request_task(&mut self, command: &str, arguments: &str) {
        if self.mode == ExecutionMode::Plan {
            self.error(
                "Plan mode is read-only. Press Tab to switch to Agent before running a task.",
            );
            return;
        }
        let arguments = arguments.trim();
        if arguments.is_empty() {
            self.error(format!("/{command} requires a target: /{command} <target>"));
            return;
        }
        let target = arguments.split_whitespace().next().unwrap_or(arguments);
        self.pending_task = Some(format!("/{command} {arguments}"));
        self.status(format!(
            "/{command} armed for {target}. Press Y to run, or Esc to cancel."
        ));
    }

    /// Submit an operator decision for the outstanding ExecutionGate request.
    ///
    /// The modal clears immediately after the control request is sent
    /// (fire-and-forget): a transport failure surfaces as an error and the
    /// pending request expires server-side (default deny), which keeps the
    /// UI unblocked either way.
    pub fn resolve_pending_execution(&mut self, approve: bool) {
        let Some(pending) = self.pending_execution.clone() else {
            return;
        };
        let decision = if approve { "approve" } else { "deny" };
        let verb = if approve { "批准" } else { "拒绝" };
        // Record the operator decision first, then attempt delivery: even
        // when the backend is unreachable the request expires server-side
        // (default deny), so the UI must never sit blocked on the modal.
        self.push(TranscriptKind::Status, format!("已提交{}", verb));
        self.pending_execution = None;
        let sent = self.send_control_during_task(
            "execution.approval.resolve",
            serde_json::json!({
                "request_hash": pending.request_hash,
                "decision": decision,
            }),
        );
        if sent {
            self.status("等待后端确认。");
        }
    }

    fn send_control_during_task(&mut self, operation: &str, arguments: serde_json::Value) -> bool {
        if !self.backend_ready {
            self.error("The Python backend is not ready.");
            return false;
        }
        if !self
            .backend_control_operations
            .iter()
            .any(|candidate| candidate == operation)
        {
            self.error(format!(
                "The connected backend does not support control operation {operation}."
            ));
            return false;
        }
        let request_id = self.next_request_id();
        let request = ClientRequest::control(request_id.clone(), operation, arguments);
        let send_result = self
            .backend
            .as_ref()
            .ok_or_else(|| std::io::Error::other("backend disconnected"))
            .and_then(|backend| backend.send(&request));
        if let Err(error) = send_result {
            self.error(format!(
                "Could not send {operation} to Python backend: {error}"
            ));
            return false;
        }
        self.pending_requests
            .insert(request_id, PendingRequest::Control(operation.to_owned()));
        true
    }

    fn request_control(&mut self, operation: &str, arguments: serde_json::Value) -> bool {
        if self.worker_active {
            self.error("Administrative settings cannot change while a task is running.");
            return false;
        }
        if !self.backend_ready {
            self.error("The Python backend is not ready.");
            return false;
        }
        if !self
            .backend_control_operations
            .iter()
            .any(|candidate| candidate == operation)
        {
            self.error(format!(
                "The connected backend does not support control operation {operation}."
            ));
            return false;
        }
        let request_id = self.next_request_id();
        let request = ClientRequest::control(request_id.clone(), operation, arguments);
        let send_result = self
            .backend
            .as_ref()
            .ok_or_else(|| std::io::Error::other("backend disconnected"))
            .and_then(|backend| backend.send(&request));
        if let Err(error) = send_result {
            self.error(format!(
                "Could not send {operation} to Python backend: {error}"
            ));
            return false;
        }
        self.pending_requests
            .insert(request_id, PendingRequest::Control(operation.to_owned()));
        true
    }

    fn request_scope_control(&mut self, arguments: &str) {
        let arguments = arguments.trim();
        if arguments.is_empty() {
            self.status(
                "Usage: /scope [--only-host H] [--only-port N] [--only-path P] [--blocked-host H] [--blocked-path P] [--allow-actions A,B] [--block-actions A,B], or /scope --clear.",
            );
            return;
        }
        let (operation, payload) = if arguments == "--clear" {
            ("session.scope.reset", serde_json::json!({}))
        } else {
            (
                "session.scope.update",
                match parse_scope_payload(arguments) {
                    Ok(scope) => serde_json::json!({"scope": scope}),
                    Err(error) => {
                        self.error(error);
                        return;
                    }
                },
            )
        };
        if self.request_control(operation, payload) {
            self.status("Session scope change requested.");
        }
    }

    // -- /config LLM settings screen --------------------------------------

    /// Open the settings screen and ask the backend for the current values.
    pub fn open_llm_settings(&mut self) {
        if self.worker_active {
            self.error("Administrative settings cannot change while a task is running.");
            return;
        }
        if !self.backend_ready {
            self.error("The Python backend is not ready.");
            return;
        }
        self.llm_settings = Some(LlmSettings::loading());
        if !self.request_control("config.read", serde_json::json!({})) {
            self.fail_llm_settings();
        }
    }

    pub fn close_llm_settings(&mut self) {
        self.llm_settings = None;
    }

    /// Surface a failed control request inside the modal, which covers the
    /// transcript that `request_control` wrote the specific reason to.
    fn fail_llm_settings(&mut self) {
        if let Some(settings) = self.llm_settings.as_mut() {
            settings.loading = false;
            settings.error =
                "Request failed — press Esc and check the transcript for the reason.".to_owned();
        }
    }

    /// Seeds the form from the chosen template. The backend owns the preset
    /// table, so selecting `custom` blanks the fields there, not here.
    pub fn select_llm_template(&mut self, provider: &str) {
        let arguments = serde_json::json!({ "provider": provider });
        if self.request_control("config.preset", arguments) {
            if let Some(settings) = self.llm_settings.as_mut() {
                settings.loading = true;
                settings.error.clear();
            }
        } else {
            self.fail_llm_settings();
        }
    }

    /// Ask the provider for its model list. An empty key makes the backend
    /// reuse the stored credential, so a refresh needs no retype.
    pub fn fetch_llm_models(&mut self) {
        let Some(settings) = self.llm_settings.as_ref() else {
            return;
        };
        if settings.loading {
            return;
        }
        if settings.base_url.trim().is_empty() {
            if let Some(settings) = self.llm_settings.as_mut() {
                settings.error = "Set an API request URL before fetching models.".to_owned();
            }
            return;
        }
        let arguments = serde_json::json!({
            "base_url": settings.base_url,
            "api_key": settings.api_key,
        });
        if self.request_control("config.models", arguments) {
            if let Some(settings) = self.llm_settings.as_mut() {
                settings.loading = true;
                settings.error.clear();
                settings.status = "Fetching models…".to_owned();
            }
        } else {
            self.fail_llm_settings();
        }
    }

    pub fn save_llm_settings(&mut self) {
        let Some(settings) = self.llm_settings.as_ref() else {
            return;
        };
        if settings.loading {
            return;
        }
        let arguments = serde_json::json!({
            "provider": settings.provider,
            "website_url": settings.website_url,
            "base_url": settings.base_url,
            "model": settings.model,
            "api_key": settings.api_key,
        });
        if self.request_control("config.write", arguments) {
            if let Some(settings) = self.llm_settings.as_mut() {
                settings.loading = true;
                settings.error.clear();
                settings.status = "Saving…".to_owned();
            }
        } else {
            self.fail_llm_settings();
        }
    }

    /// Enter on the focused row: open its list, or place the caret at the end
    /// of a text field.
    /// The first Enter: open the focused row for typing, or the template list.
    ///
    /// Opening the model row also refreshes the provider's model list, which is
    /// what feeds the suggestions shown while typing.
    pub fn begin_llm_edit(&mut self) {
        let opened_text_row = match self.llm_settings.as_mut() {
            Some(settings) => {
                let is_model = settings.focus == LlmField::Model;
                let opened = settings.begin_edit();
                opened && is_model
            }
            None => false,
        };
        if opened_text_row {
            self.fetch_llm_models();
        }
    }

    /// The second Enter: close the row, keeping what was typed.
    pub fn commit_llm_edit(&mut self) {
        if let Some(settings) = self.llm_settings.as_mut() {
            settings.end_edit(true);
        }
    }

    /// Esc on an open row rolls the text back to what it held when it opened.
    pub fn cancel_llm_edit(&mut self) {
        if let Some(settings) = self.llm_settings.as_mut() {
            settings.end_edit(false);
        }
    }

    /// Move the open template list's highlight, wrapping around either end.
    pub fn move_llm_template_list(&mut self, forward: bool) {
        let Some(settings) = self.llm_settings.as_mut() else {
            return;
        };
        let count = settings.template_labels().len();
        if count == 0 {
            return;
        }
        settings.list_index = if forward {
            (settings.list_index + 1) % count
        } else {
            (settings.list_index + count - 1) % count
        };
    }

    pub fn commit_llm_template_list(&mut self) {
        let choice = self
            .llm_settings
            .as_mut()
            .and_then(|settings| settings.close_template_list(true));
        if let Some(provider) = choice {
            self.select_llm_template(&provider);
        }
    }

    pub fn close_llm_template_list(&mut self) {
        if let Some(settings) = self.llm_settings.as_mut() {
            settings.close_template_list(false);
        }
    }

    /// Move the highlighted model suggestion while the model row is open.
    pub fn move_llm_suggestion(&mut self, forward: bool) {
        if let Some(settings) = self.llm_settings.as_mut() {
            settings.move_suggestion(forward);
        }
    }

    /// Walk the settings rows, wrapping at either end. A no-op while a row is
    /// open, so an unconfirmed edit cannot be abandoned by changing rows.
    pub fn move_llm_focus(&mut self, forward: bool) {
        if let Some(settings) = self.llm_settings.as_mut() {
            settings.error.clear();
            settings.move_focus(forward);
        }
    }

    fn apply_config_read(&mut self, result: &serde_json::Value) {
        let Some(settings) = self.llm_settings.as_mut() else {
            return;
        };
        settings.provider = result_text(result, "provider");
        settings.website_url = result_text(result, "website_url");
        settings.base_url = result_text(result, "base_url");
        settings.model = result_text(result, "model");
        settings.api_key_set = result
            .get("api_key_set")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        settings.providers = result
            .get("providers")
            .cloned()
            .and_then(|value| serde_json::from_value::<Vec<ProviderEntry>>(value).ok())
            .unwrap_or_default();
        settings.loading = false;
        settings.status.clear();
        settings.error.clear();
        let focus = settings.focus;
        settings.focus_field(focus);
    }

    fn apply_config_preset(&mut self, result: &serde_json::Value) {
        let Some(settings) = self.llm_settings.as_mut() else {
            return;
        };
        settings.provider = result_text(result, "provider");
        settings.website_url = result_text(result, "website_url");
        settings.base_url = result_text(result, "base_url");
        settings.model = result_text(result, "model");
        // A new template invalidates any list fetched against the old endpoint.
        settings.models.clear();
        settings.template_list_open = false;
        settings.list_index = 0;
        settings.suggestion = None;
        settings.loading = false;
        settings.error.clear();
    }

    fn apply_config_models(&mut self, result: &serde_json::Value) {
        let Some(settings) = self.llm_settings.as_mut() else {
            return;
        };
        settings.loading = false;
        let models = result
            .get("models")
            .and_then(|value| serde_json::from_value::<Vec<String>>(value.clone()).ok())
            .unwrap_or_default();
        if models.is_empty() {
            // Nothing came back: fall back to the template's default rather
            // than leaving the field unusable.
            if settings.model.trim().is_empty() {
                let fallback = settings
                    .providers
                    .iter()
                    .find(|entry| entry.id == settings.provider)
                    .map(|entry| entry.default_model.clone())
                    .unwrap_or_default();
                settings.model = fallback;
            }
            settings.models.clear();
            settings.error =
                "No models returned; keeping the template default. You can type a model id."
                    .to_owned();
            return;
        }
        // The list only feeds suggestions from here on; nothing is adopted
        // automatically, so an in-progress model name is never clobbered.
        settings.status = format!("{} models available.", models.len());
        settings.models = models;
        settings.error.clear();
    }

    fn apply_config_failure(&mut self, operation: &str, message: &str) {
        let Some(settings) = self.llm_settings.as_mut() else {
            return;
        };
        settings.loading = false;
        settings.status.clear();
        settings.error = format!("{operation} failed: {message}");
    }

    fn apply_config_write(&mut self, result: &serde_json::Value) {
        // The header badge is only ever seeded from `ready`, so a successful
        // save has to refresh it here or it keeps reporting the old provider.
        if let Some(provider) = result.get("provider").and_then(serde_json::Value::as_str) {
            self.provider = Some(provider.to_owned());
        }
        if let Some(model) = result.get("model").and_then(serde_json::Value::as_str) {
            self.model = Some(model.to_owned());
        }
        if let Some(ready) = result
            .get("config_ready")
            .and_then(serde_json::Value::as_bool)
        {
            self.config_ready = Some(ready);
        }
        let message = result_text(result, "message");
        self.llm_settings = None;
        self.status(if message.is_empty() {
            "Configuration saved.".to_owned()
        } else {
            message
        });
    }

    fn start_task(&mut self, command_line: String) {
        if self.worker_active {
            self.error("A VulnClaw command is already running.");
            return;
        }
        if !self.backend_ready {
            self.error("The Python backend is not ready.");
            return;
        }
        let task = match parse_task_payload(&command_line) {
            Ok(task) => task,
            Err(error) => {
                self.error(error);
                return;
            }
        };
        let task_id = format!("task-{}-{}", std::process::id(), self.request_counter + 1);
        let request_id = self.next_request_id();
        let request = ClientRequest::start_task(request_id.clone(), task_id.clone(), task);
        self.active_receipt = Some(OperationReceipt {
            command: command_line,
            phase: "Submitting".to_owned(),
            findings: 0,
        });
        self.worker_active = true;
        self.worker_started_at = Some(Instant::now());
        self.active_task_id = Some(task_id.clone());
        let send_result = self
            .backend
            .as_ref()
            .ok_or_else(|| std::io::Error::other("backend disconnected"))
            .and_then(|backend| backend.send(&request));
        if let Err(error) = send_result {
            self.finish_task("Failed to submit");
            self.error(format!("Could not submit task to Python backend: {error}"));
        } else {
            self.pending_requests
                .insert(request_id, PendingRequest::StartTask(task_id));
        }
    }

    /// Request cancellation of the active task without terminating the backend.
    pub fn stop_worker(&mut self) {
        let Some(task_id) = self.active_task_id.clone() else {
            return;
        };
        if !self.backend_supports_cancellation {
            self.error("The connected backend does not support task cancellation.");
            return;
        }
        let request_id = self.next_request_id();
        let request = ClientRequest::cancel_task(request_id.clone(), task_id.clone());
        match self.backend.as_ref().map(|backend| backend.send(&request)) {
            Some(Ok(())) => {
                self.pending_requests
                    .insert(request_id, PendingRequest::CancelTask(task_id));
                self.update_receipt("Cancelling");
                self.status("Cancellation requested; waiting for Python checkpoint.");
            }
            Some(Err(error)) => self.error(format!("Could not cancel task: {error}")),
            None => self.error("Could not cancel task: backend disconnected."),
        }
    }

    pub fn shutdown_backend(&mut self) {
        let Some(backend) = self.backend.take() else {
            return;
        };
        let request_id = self.next_request_id();
        let request = ClientRequest::shutdown(request_id.clone());
        let _ = backend.send(&request);
        self.pending_requests
            .insert(request_id, PendingRequest::Shutdown);
        backend.wait_or_kill(std::time::Duration::from_secs(2));
        self.backend_ready = false;
        self.backend_commands.clear();
        self.backend_control_operations.clear();
        self.backend_supports_cancellation = false;
    }

    fn push_stream(
        &mut self,
        agent_id: Option<String>,
        kind: TranscriptKind,
        text: String,
        append: bool,
    ) {
        let transcript = if let Some(id) = agent_id {
            let Some(agent) = self.subagents.agent_mut(&id) else {
                return;
            };
            &mut agent.transcript
        } else {
            &mut self.transcript
        };
        if append {
            if let Some(last) = transcript.last_mut().filter(|item| item.kind == kind) {
                last.text.push_str(&text);
                return;
            }
        }
        transcript.push(TranscriptItem { kind, text });
    }

    fn push(&mut self, kind: TranscriptKind, text: impl Into<String>) {
        self.transcript.push(TranscriptItem {
            kind,
            text: text.into(),
        });
    }

    fn status(&mut self, text: impl Into<String>) {
        self.push(TranscriptKind::Status, text);
    }

    fn error(&mut self, text: impl Into<String>) {
        self.push(TranscriptKind::Error, text);
    }

    fn update_receipt(&mut self, phase: impl Into<String>) {
        if let Some(receipt) = self.active_receipt.as_mut() {
            receipt.phase = phase.into();
        }
    }

    fn record_command(&mut self, command: &str) {
        if self
            .command_history
            .last()
            .is_none_or(|last| last != command)
        {
            self.command_history.push(command.to_owned());
            if self.command_history.len() > MAX_COMMAND_HISTORY {
                self.command_history.remove(0);
            }
        }
        self.clear_history_navigation();
    }

    fn clear_history_navigation(&mut self) {
        self.history_index = None;
        self.history_draft.clear();
    }

    fn set_input(&mut self, input: String) {
        self.input = input;
        self.input_cursor = self.input.len();
        self.palette_selection = 0;
    }
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let preview = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{preview}…")
    } else {
        preview
    }
}

/// Strip a leading transcript/prompt artifact such as `You > ` or `> ` that a
/// user may accidentally paste along with a command copied from the TUI output.
/// The real command always starts with `/`, so we keep everything after the
/// last `>` whose trailing content begins with `/`. Inputs without a `>` are
/// returned unchanged, so valid commands are never corrupted.
/// Remove transcript-style prompt prefixes from pasted slash commands.
pub fn strip_prompt_prefix(command: &str) -> String {
    let trimmed = command.trim_start();
    if let Some(pos) = trimmed.rfind('>') {
        let rest = trimmed[pos + 1..].trim_start();
        if rest.starts_with('/') {
            return rest.to_owned();
        }
    }
    trimmed.to_owned()
}

fn split_slash_command(command: &str) -> Option<(&str, &str)> {
    let raw = command.strip_prefix('/')?;
    let split_at = raw.find(char::is_whitespace).unwrap_or(raw.len());
    let (verb, remainder) = raw.split_at(split_at);
    (!verb.is_empty()).then_some((verb, remainder.trim_start()))
}

/// Check whether a slash verb maps to a known task command.
///
/// This mirrors `TaskCommand` in `vulnclaw/task_service.py`. Keeping the set
/// explicit on the frontend lets the TUI offer meaningful completions even
/// before the backend capability handshake finishes, while still routing the
/// command through the same protocol path once executed.
fn is_task_verb(verb: &str) -> bool {
    matches!(
        verb,
        "run" | "recon" | "scan" | "exploit" | "persistent" | "codescan"
    )
}

/// Adapt a presentation-layer slash command into the structured task DTO sent
/// over the TUI protocol.
pub fn parse_task_payload(command_line: &str) -> Result<serde_json::Value, String> {
    let (command, arguments) = split_slash_command(command_line)
        .ok_or_else(|| "task must start with a slash command".to_owned())?;
    let mut tokens = shell_words::split(arguments).map_err(|error| error.to_string())?;
    if tokens.is_empty() || tokens[0].starts_with('-') {
        return Err(format!("/{command} requires a target"));
    }
    let target = tokens.remove(0);
    let (root, options) = parse_option_fields(&tokens)?;
    let mut task = serde_json::Map::from_iter([
        (
            "command".to_owned(),
            serde_json::Value::String(command.to_owned()),
        ),
        ("target".to_owned(), serde_json::Value::String(target)),
        ("options".to_owned(), serde_json::Value::Object(options)),
    ]);
    task.extend(root);
    Ok(serde_json::Value::Object(task))
}

/// Parse `/scope` arguments into the backend's structured scope options.
pub fn parse_scope_payload(arguments: &str) -> Result<serde_json::Value, String> {
    let tokens = shell_words::split(arguments).map_err(|error| error.to_string())?;
    let (root, options) = parse_option_fields(&tokens)?;
    if !root.is_empty() {
        return Err("scope accepts scope options only".to_owned());
    }
    const ALLOWED: &[&str] = &[
        "only_port",
        "only_host",
        "only_path",
        "blocked_host",
        "blocked_path",
        "allow_actions",
        "block_actions",
    ];
    if let Some(field) = options
        .keys()
        .find(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(format!(
            "unsupported scope option: --{}",
            field.replace('_', "-")
        ));
    }
    Ok(serde_json::Value::Object(options))
}

type JsonObject = serde_json::Map<String, serde_json::Value>;
type ParsedOptionFields = (JsonObject, JsonObject);

fn parse_option_fields(tokens: &[String]) -> Result<ParsedOptionFields, String> {
    let mut root = serde_json::Map::new();
    let mut options = serde_json::Map::new();
    let mut index = 0;
    while index < tokens.len() {
        let raw = tokens[index].as_str();
        let (name, inline) = raw
            .split_once('=')
            .map_or((raw, None), |(name, value)| (name, Some(value)));
        let boolean = matches!(
            name,
            "--resume"
                | "--no-resume"
                | "--mount"
                | "--repair"
                | "--force-fresh"
                | "--no-import"
                | "--no-report"
        );
        let value = if boolean {
            if inline.is_some() {
                return Err(format!("{name} does not accept a value"));
            }
            None
        } else if let Some(value) = inline {
            Some(value.to_owned())
        } else {
            index += 1;
            Some(
                tokens
                    .get(index)
                    .ok_or_else(|| format!("{name} requires a value"))?
                    .to_owned(),
            )
        };

        match name {
            "--resume" => root.insert("resume".into(), true.into()),
            "--no-resume" => root.insert("resume".into(), false.into()),
            "--mount" | "--repair" | "--force-fresh" | "--no-import" => {
                root.insert(name.trim_start_matches("--").replace('-', "_"), true.into())
            }
            "--no-report" => options.insert("auto_report".into(), false.into()),
            "--prompt" | "--snapshot" | "--run-name" | "--resume-run" | "--runs-dir"
            | "--target-type" => {
                let field = match name {
                    "--snapshot" => "snapshot_id",
                    "--resume-run" => "resume_run_name",
                    _ => name.trim_start_matches("--"),
                }
                .replace('-', "_");
                root.insert(field, value.unwrap().into())
            }
            "--target" => {
                root.entry("additional_targets")
                    .or_insert_with(|| serde_json::json!([]))
                    .as_array_mut()
                    .expect("additional_targets is an array")
                    .push(value.unwrap().into());
                None
            }
            "--allow-actions" | "--block-actions" => options.insert(
                name.trim_start_matches("--").replace('-', "_"),
                serde_json::Value::Array(
                    value
                        .unwrap()
                        .split(',')
                        .filter(|item| !item.trim().is_empty())
                        .map(|item| item.trim().into())
                        .collect(),
                ),
            ),
            "--only-port" | "--max-steps" | "--max-directions" | "--max-tool-rounds"
            | "--max-parallel" | "--max-rounds" | "--rounds" | "-r" | "--cycles" | "-c" => {
                let number = value
                    .unwrap()
                    .parse::<u64>()
                    .map_err(|_| format!("{name} must be an integer"))?;
                let field = match name {
                    "--rounds" | "-r" => "rounds_per_cycle",
                    "--cycles" | "-c" => "max_cycles",
                    _ => name.trim_start_matches("--"),
                }
                .replace('-', "_");
                options.insert(field, number.into())
            }
            _ if name.starts_with("--") => options.insert(
                name.trim_start_matches("--").replace('-', "_"),
                value.unwrap().into(),
            ),
            _ => return Err(format!("unsupported option: {name}")),
        };
        index += 1;
    }
    Ok((root, options))
}

fn normalize_backend_command(command: String) -> Option<String> {
    let normalized = command.trim().trim_start_matches('/');
    if normalized.is_empty()
        || !normalized
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return None;
    }
    Some(normalized.to_owned())
}

/// Read a string field from a `control_result` payload, defaulting to empty.
fn result_text(result: &serde_json::Value, key: &str) -> String {
    result
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn previous_char_boundary(text: &str, index: usize) -> usize {
    text[..index]
        .char_indices()
        .last()
        .map_or(0, |(index, _)| index)
}

fn next_char_boundary(text: &str, index: usize) -> usize {
    text[index..]
        .chars()
        .next()
        .map_or(index, |character| index + character.len_utf8())
}
