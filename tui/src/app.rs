use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::exec::BackendHandle;
use crate::prompts::text;
use crate::protocol::{AppEvent, BackendEvent, ClientRequest, Finding, StateSnapshot};
use crate::sessions::{self, SessionState};
use crate::skills::catalog::{skill_tree, SkillNode};

use ratatui::{
    backend::TestBackend,
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, Borders, Paragraph, Wrap},
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivePane {
    Workspace,
    Transcript,
    Findings,
}

impl ActivePane {
    pub fn next(self) -> Self {
        match self {
            Self::Workspace => Self::Transcript,
            Self::Transcript => Self::Findings,
            Self::Findings => Self::Workspace,
        }
    }

    pub fn previous(self) -> Self {
        match self {
            Self::Workspace => Self::Findings,
            Self::Transcript => Self::Workspace,
            Self::Findings => Self::Transcript,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

const LOCAL_SLASH_COMMANDS: &[(&str, &str)] = &[
    ("/scope ", "update session scope defaults"),
    ("/report", "show report export guidance"),
    ("/config", "show configuration guidance"),
    ("/clear", "clear the transcript"),
    ("/help", "list available commands"),
];

const MAX_COMMAND_HISTORY: usize = 50;

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
    pub active_pane: ActivePane,
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
    pub findings: Vec<Finding>,
    pub findings_scroll: u16,
    pub transcript_scroll: u16,
    /// When true the Session transcript tracks new output automatically,
    /// pinning the view to the bottom as lines arrive. Set false the moment the
    /// user scrolls up to read history; re-enabled once they scroll back to the
    /// bottom. See `autoscroll_transcript`.
    pub transcript_follow: bool,
    pub palette_selection: usize,
    pub show_reasoning: bool,
    pub running: bool,
    pub worker_active: bool,
    /// One persistent Python backend for the entire terminal session.
    pub backend: Option<BackendHandle>,
    pub backend_ready: bool,
    pub backend_pid: Option<u32>,
    pub config_ready: Option<bool>,
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
            active_pane: ActivePane::Transcript,
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
            findings: Vec::new(),
            findings_scroll: 0,
            transcript_scroll: 0,
            transcript_follow: true,
            palette_selection: 0,
            show_reasoning: true,
            running: true,
            worker_active: false,
            backend: None,
            backend_ready: false,
            backend_pid: None,
            config_ready: None,
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
            self.transcript_scroll = 0;
            self.transcript_follow = true;
            self.status("Transcript cleared. Findings remain available in the inspector.");
        } else if command == "/report" {
            self.status(
                "Use vulnclaw report <result.json> [--pdf] to write the report; the TUI shows findings live.",
            );
        } else if command == "/config" {
            self.status("Use vulnclaw config set <key> <value> for llm.provider / llm.api_key / llm.base_url / llm.model.");
        } else if let Some((verb, arguments)) = split_slash_command(&command) {
            if verb == "scope" {
                self.request_scope_control(arguments);
            } else if self.backend_commands.iter().any(|item| item == verb) {
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

    pub fn cycle_active_pane(&mut self, backwards: bool) {
        self.active_pane = if backwards {
            self.active_pane.previous()
        } else {
            self.active_pane.next()
        };
    }

    pub fn scroll_active_pane(&mut self, down: bool) {
        match self.active_pane {
            // Findings keeps the original unbounded behaviour so a lone Down press
            // still increments even when the list is short (preserves existing tests).
            ActivePane::Findings => {
                if down {
                    self.findings_scroll = self.findings_scroll.saturating_add(1);
                } else {
                    self.findings_scroll = self.findings_scroll.saturating_sub(1);
                }
            }
            ActivePane::Workspace | ActivePane::Transcript => {
                let max = self.transcript_max_scroll();
                if down {
                    self.transcript_scroll = self.transcript_scroll.saturating_add(1);
                } else {
                    self.transcript_scroll = self.transcript_scroll.saturating_sub(1);
                }
                let max_u16 = u16::try_from(max).unwrap_or(u16::MAX);
                if self.transcript_scroll > max_u16 {
                    self.transcript_scroll = max_u16;
                }
                // Reaching the bottom resumes auto-follow; leaving it disables it.
                self.transcript_follow = (self.transcript_scroll as usize) >= max;
            }
        }
    }

    /// Rectangle of the Session transcript panel (the wide centre pane), computed
    /// from the same split used by `ui::layout::render_workbench`. Independent of
    /// which pane is currently focused so auto-follow always anchors the
    /// transcript view, not the narrow Workspace sidebar.
    fn transcript_panel_rect(&self) -> Rect {
        let area = self.terminal_size;
        let composer_height: u16 = if self.pending_task.is_some() {
            3
        } else if self.palette_visible() {
            7
        } else {
            1
        };
        let workbench = Rect {
            x: area.x,
            y: area.y.saturating_add(2),
            width: area.width,
            height: area.height.saturating_sub(2 + composer_height + 1),
        };
        let panels = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(28),
                Constraint::Min(36),
                Constraint::Length(40),
            ])
            .split(workbench);
        panels[1]
    }

    /// Maximum vertical scroll offset for the transcript: total wrapped rows
    /// minus the visible rows. Uses ratatui's own `Paragraph::line_count` so the
    /// wrap accounting (CJK widths, word breaks) matches the real render exactly.
    fn transcript_max_scroll(&self) -> usize {
        let rect = self.transcript_panel_rect();
        if rect.width < 3 || rect.height < 3 {
            return 0;
        }
        let inner_width = rect.width.saturating_sub(2);
        let lines = crate::ui::transcript::build_lines(self);
        let paragraph = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL));
        let total_rows = paragraph.line_count(inner_width);
        total_rows.saturating_sub(rect.height as usize)
    }

    /// Keep the transcript pinned to the newest output. Called once per frame
    /// (before drawing) while `transcript_follow` is set; a manual scroll-up
    /// clears the flag so we stop yanking the view away from the user.
    pub fn autoscroll_transcript(&mut self) {
        if self.transcript_follow {
            self.transcript_scroll =
                u16::try_from(self.transcript_max_scroll()).unwrap_or(u16::MAX);
        }
    }

    pub fn active_pane_label(&self) -> &'static str {
        match self.active_pane {
            ActivePane::Workspace => "Workspace",
            ActivePane::Transcript => "Session transcript",
            ActivePane::Findings => "Findings inspector",
        }
    }

    /// Screen rectangle occupied by the currently focused workbench pane.
    /// Mirrors the split used by `ui::layout::render_workbench` so the copied
    /// region never bleeds into neighbouring panes.
    pub fn active_pane_rect(&self, area: Rect) -> Rect {
        let composer_height: u16 = if self.pending_task.is_some() {
            3
        } else if self.palette_visible() {
            7
        } else {
            1
        };
        let workbench = Rect {
            x: area.x,
            y: area.y.saturating_add(2),
            width: area.width,
            height: area.height.saturating_sub(2 + composer_height + 1),
        };
        let panels = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(28),
                Constraint::Min(36),
                Constraint::Length(40),
            ])
            .split(workbench);
        match self.active_pane {
            ActivePane::Workspace => panels[0],
            ActivePane::Transcript => panels[1],
            ActivePane::Findings => panels[2],
        }
    }

    /// Copy the focused workbench pane to the system clipboard. Each pane is
    /// copied independently — copying one never drags in the others. The
    /// terminal's own drag-select is a whole-screen block selection that cannot
    /// be confined to a single logical pane, so this is the reliable per-pane
    /// copy path.
    pub fn copy_active_pane(&mut self) {
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
        let rect = self.active_pane_rect(area);
        let text = extract_rect_text(buffer, rect);
        let label = self.active_pane_label();
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
        backend
            .chain(local)
            .filter(|item| item.command.starts_with(&query))
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
                    self.worker_active = true;
                    self.worker_started_at = Some(Instant::now());
                    self.apply_backend_state(state);
                    if let Some(receipt) = self.active_receipt.as_mut() {
                        let command = task["command"].as_str().unwrap_or("task");
                        receipt.phase = format!("{command} running");
                    }
                }
                BackendEvent::Status {
                    task_id,
                    status: message,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.update_receipt(&message);
                    self.status(message);
                }
                BackendEvent::Finding { task_id, finding } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.upsert_finding(finding);
                }
                BackendEvent::Reasoning {
                    task_id,
                    text: chunk,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.update_receipt("Thinking");
                    self.push(TranscriptKind::Reasoning, chunk);
                }
                BackendEvent::Log {
                    task_id,
                    message: line,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.update_receipt("Running");
                    self.push(TranscriptKind::Log, line);
                }
                BackendEvent::ToolCall {
                    task_id,
                    tool,
                    arguments,
                } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.update_receipt("Using tool");
                    self.push(
                        TranscriptKind::Log,
                        format!("→ tool: {tool} {}", truncate_text(&arguments, 160)),
                    );
                }
                BackendEvent::ToolResult { task_id, result } => {
                    if !self.is_current_task(&task_id) {
                        return;
                    }
                    self.update_receipt("Running");
                    self.push(
                        TranscriptKind::Log,
                        format!("→ result: {}", truncate_text(&result, 240)),
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
