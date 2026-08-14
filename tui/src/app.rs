use std::env;
use std::sync::mpsc::Sender;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::exec::{self, WorkerHandle};
use crate::prompts::text;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crate::protocol::{AppEvent, Finding, StreamEvent};
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
    const CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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

#[derive(Clone, Copy, Debug)]
pub struct SlashCommand {
    pub command: &'static str,
    pub description: &'static str,
}

const SLASH_COMMANDS: &[SlashCommand] = &[
    SlashCommand {
        command: "/scan ",
        description: "scan a target (port/service sweep)",
    },
    SlashCommand {
        command: "/run ",
        description: "run a penetration task",
    },
    SlashCommand {
        command: "/recon ",
        description: "run reconnaissance",
    },
    SlashCommand {
        command: "/exploit ",
        description: "attempt an exploit against a target",
    },
    SlashCommand {
        command: "/report",
        description: "show report export guidance",
    },
    SlashCommand {
        command: "/config",
        description: "open the configuration editor",
    },
    SlashCommand {
        command: "/clear",
        description: "clear the transcript",
    },
    SlashCommand {
        command: "/help",
        description: "list available commands",
    },
];

/// First-run / on-demand API configuration wizard state.
#[derive(Clone, Debug)]
pub struct SetupState {
    pub step: u8, // 0 provider, 1 api_key, 2 base_url, 3 model
    pub provider_index: usize,
    pub api_key: String,
    pub base_url: String,
    pub model: String,
    pub cursor: usize,
    pub message: String,
    pub error: bool,
}

impl SetupState {
    pub fn new() -> Self {
        Self {
            step: 0,
            provider_index: 0,
            api_key: String::new(),
            base_url: String::new(),
            model: String::new(),
            cursor: 0,
            message: String::new(),
            error: false,
        }
    }

    /// Insert at the editing cursor for the current text step.
    pub fn insert_char(&mut self, c: char) {
        match self.step {
            1 => {
                self.api_key.insert(self.cursor, c);
                self.cursor += 1;
            }
            2 => {
                self.base_url.insert(self.cursor, c);
                self.cursor += 1;
            }
            3 => {
                self.model.insert(self.cursor, c);
                self.cursor += 1;
            }
            _ => {}
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        match self.step {
            1 => {
                self.api_key.remove(self.cursor - 1);
            }
            2 => {
                self.base_url.remove(self.cursor - 1);
            }
            3 => {
                self.model.remove(self.cursor - 1);
            }
            _ => {}
        }
        self.cursor -= 1;
    }

    pub fn move_cursor(&mut self, right: bool) {
        let len = match self.step {
            1 => self.api_key.chars().count(),
            2 => self.base_url.chars().count(),
            3 => self.model.chars().count(),
            _ => 0,
        };
        if right {
            self.cursor = (self.cursor + 1).min(len);
        } else {
            self.cursor = self.cursor.saturating_sub(1);
        }
    }
}

/// Provider presets surfaced in the setup wizard. `name` is the value written
/// to `llm.provider`; base_url/model defaults mirror the `vulnclaw` schema
/// presets so the user can accept them as-is.
pub struct ProviderPreset {
    pub name: &'static str,
    pub label: &'static str,
    pub base_url: &'static str,
    pub model: &'static str,
}

pub const PROVIDERS: &[ProviderPreset] = &[
    ProviderPreset {
        name: "deepseek",
        label: "DeepSeek",
        base_url: "https://api.deepseek.com/v1",
        model: "deepseek-chat",
    },
    ProviderPreset {
        name: "openai",
        label: "OpenAI",
        base_url: "https://api.openai.com/v1",
        model: "gpt-4o",
    },
    ProviderPreset {
        name: "siliconflow",
        label: "SiliconFlow",
        base_url: "https://api.siliconflow.cn/v1",
        model: "deepseek-ai/DeepSeek-V4-Flash",
    },
    ProviderPreset {
        name: "qwen",
        label: "Qwen (通义千问)",
        base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1",
        model: "qwen3-max",
    },
    ProviderPreset {
        name: "zhipu",
        label: "Zhipu (智谱 GLM)",
        base_url: "https://open.bigmodel.cn/api/paas/v4",
        model: "glm-4.7",
    },
    ProviderPreset {
        name: "moonshot",
        label: "Moonshot (Kimi)",
        base_url: "https://api.moonshot.cn/v1",
        model: "kimi-k2.6",
    },
    ProviderPreset {
        name: "doubao",
        label: "Doubao (豆包)",
        base_url: "https://ark.cn-beijing.volces.com/api/v3",
        model: "Doubao-Seed-2.0-Pro",
    },
    ProviderPreset {
        name: "anthropic",
        label: "Anthropic Claude",
        base_url: "https://api.anthropic.com/v1",
        model: "claude-sonnet-5",
    },
    ProviderPreset {
        name: "custom",
        label: "Custom",
        base_url: "",
        model: "",
    },
];

const MAX_COMMAND_HISTORY: usize = 50;

#[derive(Clone, Debug)]
pub struct OperationReceipt {
    pub command: String,
    pub phase: String,
    pub findings: usize,
}

pub struct App {
    pub mode: ExecutionMode,
    pub permission: PermissionMode,
    pub active_pane: ActivePane,
    pub input: String,
    pub input_cursor: usize,
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
    /// Killable handle to the spawned VulnClaw Python core process, if one is
    /// running. Stored so we can abort it on demand (Ctrl+C while a command is
    /// active) and so it cannot outlive the TUI as an orphan on quit.
    pub worker: Option<WorkerHandle>,
    pub active_receipt: Option<OperationReceipt>,
    pub last_receipt: Option<OperationReceipt>,
    /// Monotonic instant the current worker started, used to render a live
    /// elapsed-time readout (`mm:ss`) in the header while a command runs.
    pub worker_started_at: Option<Instant>,
    pub show_attack_chain: bool,
    pub pending_task: Option<Vec<String>>,
    pub skills: Vec<SkillNode>,
    pub setup: Option<SetupState>,
    /// Last known terminal viewport size, captured each frame. Used to render an
    /// offscreen copy of the focused pane for independent clipboard copies.
    pub terminal_size: Rect,
    /// Transient feedback line shown in the hotbar (e.g. "Copied …"). Cleared on
    /// the next key press.
    pub toast: String,
    sender: Sender<AppEvent>,
}

impl App {
    pub fn new(sender: Sender<AppEvent>) -> Self {
        let mut app = Self {
            mode: ExecutionMode::Agent,
            permission: PermissionMode::AutoReview,
            active_pane: ActivePane::Transcript,
            input: String::new(),
            input_cursor: 0,
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
            worker: None,
            active_receipt: None,
            last_receipt: None,
            worker_started_at: None,
            show_attack_chain: false,
            pending_task: None,
            skills: skill_tree(),
            setup: None,
            terminal_size: Rect::default(),
            toast: String::new(),
            sender,
        };
        // First-run / on-demand wizard: only enter setup when we can confirm
        // the LLM key is missing (vulnclaw CLI reachable). If the CLI is
        // unavailable we stay out of setup so the app never hard-blocks.
        if !app.config_is_ready() {
            app.setup = Some(SetupState::new());
        }
        app
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
            self.status(text::HELP);
        } else if command == "/clear" {
            self.transcript.clear();
            self.transcript_scroll = 0;
            self.transcript_follow = true;
            self.status("Transcript cleared. Findings remain available in the inspector.");
        } else if let Some(arguments) = command.strip_prefix("/run ") {
            self.request_task("run", arguments);
        } else if let Some(arguments) = command.strip_prefix("/scan ") {
            self.request_task("scan", arguments);
        } else if let Some(arguments) = command.strip_prefix("/recon ") {
            self.request_task("recon", arguments);
        } else if let Some(arguments) = command.strip_prefix("/exploit ") {
            self.request_task("exploit", arguments);
        } else if command == "/report" {
            self.status(
                "Use vulnclaw report <result.json> [--pdf] to write the report; the TUI shows findings live.",
            );
        } else if command == "/config" {
            self.status("Use vulnclaw config set <key> <value> for llm.provider / llm.api_key / llm.base_url / llm.model.");
        } else {
            self.error(format!("Unknown command: {command}"));
        }
    }

    pub fn cycle_mode(&mut self) {
        self.set_mode(self.mode.next());
    }

    pub fn cycle_permission(&mut self) {
        self.permission = self.permission.next();
        self.status(format!(
            "Permission posture switched to {}. Explicit confirmation still required before a task starts.",
            self.permission.label()
        ));
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
                let max_u16 = (max as u16).min(u16::MAX);
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
            .constraints([Constraint::Length(28), Constraint::Min(36), Constraint::Length(40)])
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
            self.transcript_scroll = (self.transcript_max_scroll() as u16).min(u16::MAX);
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
            .constraints([Constraint::Length(28), Constraint::Min(36), Constraint::Length(40)])
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

    /// Whether an LLM API key is already configured. When the `vulnclaw` CLI is
    /// unreachable we optimistically return `true` so the wizard never hard-
    /// blocks the app in odd environments (or during tests).
    pub fn config_is_ready(&self) -> bool {
        let output = match exec::run_vulnclaw_sync(&["config", "show"]) {
            Ok(o) if o.status.success() => o,
            _ => return true,
        };
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("api_key:") {
                let value = rest.trim().trim_matches('\'').trim();
                if !value.is_empty() {
                    return true;
                }
            }
        }
        false
    }

    /// Advance the setup wizard one step; the final step persists the config.
    fn setup_advance(&mut self) {
        let step = match &self.setup {
            Some(s) => s.step,
            None => return,
        };
        match step {
            0 => {
                if let Some(setup) = &mut self.setup {
                    if let Some(preset) = PROVIDERS.get(setup.provider_index) {
                        setup.base_url = preset.base_url.to_string();
                        setup.model = preset.model.to_string();
                        setup.api_key.clear();
                        setup.cursor = 0;
                    }
                    setup.step = 1;
                    setup.error = false;
                    setup.message = "Paste your API key, then press Enter.".into();
                }
            }
            1 => {
                if let Some(setup) = &mut self.setup {
                    if setup.api_key.trim().is_empty() {
                        setup.error = true;
                        setup.message = "API key cannot be empty. Esc to skip setup.".into();
                        return;
                    }
                    setup.step = 2;
                    setup.cursor = setup.base_url.chars().count();
                    setup.error = false;
                    setup.message = "Base URL — Enter to accept, or type to edit.".into();
                }
            }
            2 => {
                if let Some(setup) = &mut self.setup {
                    setup.step = 3;
                    setup.cursor = setup.model.chars().count();
                    setup.error = false;
                    setup.message = "Model — Enter to accept, or type to edit.".into();
                }
            }
            3 => {
                self.finish_setup();
            }
            _ => {}
        }
    }

    /// Persist the wizard's choices via `vulnclaw config set` (unified YAML).
    fn finish_setup(&mut self) {
        let provider = match &self.setup {
            Some(s) => PROVIDERS
                .get(s.provider_index)
                .map(|p| p.name)
                .unwrap_or("deepseek"),
            None => "deepseek",
        };
        let api_key = self
            .setup
            .as_ref()
            .map(|s| s.api_key.clone())
            .unwrap_or_default();
        let base_url = self
            .setup
            .as_ref()
            .map(|s| s.base_url.clone())
            .unwrap_or_default();
        let model = self
            .setup
            .as_ref()
            .map(|s| s.model.clone())
            .unwrap_or_default();

        let _ = exec::run_vulnclaw_sync(&["config", "set", "llm.provider", provider]);
        let _ = exec::run_vulnclaw_sync(&["config", "set", "llm.api_key", &api_key]);
        if !base_url.is_empty() {
            let _ = exec::run_vulnclaw_sync(&["config", "set", "llm.base_url", &base_url]);
        }
        if !model.is_empty() {
            let _ = exec::run_vulnclaw_sync(&["config", "set", "llm.model", &model]);
        }
        self.setup = None;
        self.status("API configured. VulnClaw is ready — L3 review and Agent modes enabled.");
    }

    /// Route key events while the setup wizard is active.
    pub fn setup_handle_key(&mut self, key: KeyEvent) {
        let step = match &self.setup {
            Some(s) => s.step,
            None => return,
        };
        match (key.code, key.modifiers) {
            (KeyCode::Up, _) if step == 0 => {
                if let Some(setup) = &mut self.setup {
                    setup.provider_index = setup.provider_index.saturating_sub(1);
                }
            }
            (KeyCode::Down, _) if step == 0 => {
                if let Some(setup) = &mut self.setup {
                    setup.provider_index =
                        (setup.provider_index + 1).min(PROVIDERS.len().saturating_sub(1));
                }
            }
            (KeyCode::Left, _) if step != 0 => {
                if let Some(setup) = &mut self.setup {
                    setup.move_cursor(false);
                }
            }
            (KeyCode::Right, _) if step != 0 => {
                if let Some(setup) = &mut self.setup {
                    setup.move_cursor(true);
                }
            }
            (KeyCode::Backspace, _) if step != 0 => {
                if let Some(setup) = &mut self.setup {
                    setup.backspace();
                }
            }
            (KeyCode::Char(c), modifiers)
                if step != 0 && !modifiers.contains(KeyModifiers::CONTROL) =>
            {
                if let Some(setup) = &mut self.setup {
                    setup.insert_char(c);
                }
            }
            (KeyCode::Enter, _) => {
                self.setup_advance();
            }
            (KeyCode::Esc, _) => {
                self.setup = None;
                self.status("Setup skipped. Configure later: vulnclaw config set llm.api_key <key>");
            }
            _ => {}
        }
    }

    /// Insert pasted/IME text. Routes to the setup wizard's current field when
    /// the wizard is active (so pasting an API key lands in `api_key`, not the
    /// hidden main command line), otherwise to the main input. Newlines are
    /// dropped so a multi-line paste never advances the wizard a step.
    pub fn insert_text(&mut self, text: &str) {
        if let Some(setup) = &mut self.setup {
            if setup.step != 0 {
                for character in text
                    .chars()
                    .filter(|character| *character != '\r' && *character != '\n')
                {
                    setup.insert_char(character);
                }
            }
            return;
        }
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
        SLASH_COMMANDS
            .iter()
            .copied()
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
        let Some(args) = self.pending_task.take() else {
            return;
        };
        self.status("TUI confirmation recorded. Starting task.");
        self.start_worker(args);
    }

    pub fn dismiss_task(&mut self) {
        if self.pending_task.take().is_some() {
            self.status("Task command cancelled before execution.");
        }
    }

    pub fn apply_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Stream(stream) => match stream {
                StreamEvent::Status(message) => {
                    self.update_receipt(&message);
                    self.status(message);
                }
                StreamEvent::Finding(finding) => {
                    if let Some(receipt) = self.active_receipt.as_mut() {
                        receipt.findings += 1;
                        receipt.phase = "Receiving findings".to_owned();
                    }
                    self.push(TranscriptKind::Finding, finding.summary());
                    self.findings.push(finding);
                }
                StreamEvent::Reasoning(chunk) => {
                    self.update_receipt("Thinking");
                    self.push(TranscriptKind::Reasoning, chunk);
                }
                StreamEvent::Log(line) => {
                    self.update_receipt("Running");
                    self.push(TranscriptKind::Log, line);
                }
                StreamEvent::Complete(summary) => {
                    self.update_receipt("Finalizing");
                    self.status(summary);
                }
            },
            AppEvent::Error(message) => {
                self.update_receipt("Error");
                self.error(message)
            }
            AppEvent::Finished(success) => {
                self.worker = None;
                self.worker_active = false;
                self.worker_started_at = None;
                if let Some(mut receipt) = self.active_receipt.take() {
                    receipt.phase = if success {
                        "Completed".to_owned()
                    } else {
                        "Failed".to_owned()
                    };
                    self.last_receipt = Some(receipt);
                }
                self.status(if success {
                    "VulnClaw command completed."
                } else {
                    "VulnClaw command completed with a non-zero status."
                });
            }
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
        let mut parts = match split_arguments(arguments) {
            Ok(parts) => parts,
            Err(error) => {
                self.error(error);
                return;
            }
        };
        if parts.is_empty() {
            self.error(format!(
                "/{command} requires a target: /{command} <target> [--only-port N] [--only-host H] [--blocked-host H]"
            ));
            return;
        }
        let target = parts[0].clone();
        let mut args = vec![command.to_owned()];
        args.append(&mut parts);
        // The Rust TUI consumes the JSONL stream protocol; always ask the
        // Python core to emit events instead of Rich text.
        args.push("--stream".to_owned());
        self.pending_task = Some(args);
        self.status(format!(
            "/{command} armed for {target}. Press Y to run, or Esc to cancel."
        ));
    }

    fn start_worker(&mut self, args: Vec<String>) {
        if self.worker_active {
            self.error("A VulnClaw command is already running.");
            return;
        }
        self.worker_active = true;
        self.worker_started_at = Some(Instant::now());
        self.active_receipt = Some(OperationReceipt {
            command: args.join(" "),
            phase: "Starting".to_owned(),
            findings: 0,
        });
        match exec::spawn_vulnclaw(args, self.sender.clone()) {
            Ok(handle) => self.worker = Some(handle),
            Err(error) => {
                self.worker_active = false;
                if let Some(mut receipt) = self.active_receipt.take() {
                    receipt.phase = "Failed to start".to_owned();
                    self.last_receipt = Some(receipt);
                }
                self.error(format!("Could not start VulnClaw Python core: {error}"));
            }
        }
    }

    /// Abort a running VulnClaw worker (e.g. an in-flight Task agent) and reap
    /// the child process so it cannot outlive the TUI as an orphan. The TUI is
    /// the sole taker of the `Child`, so this reliably terminates it even on
    /// Windows (where dropping a `Child` does not kill the process).
    pub fn stop_worker(&mut self) {
        if let Some(handle) = self.worker.take() {
            if let Ok(mut guard) = handle.lock() {
                if let Some(mut child) = guard.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        self.worker_active = false;
        self.worker_started_at = None;
        if let Some(mut receipt) = self.active_receipt.take() {
            receipt.phase = "Aborted".to_owned();
            self.last_receipt = Some(receipt);
        }
        self.status("VulnClaw command aborted by user (Ctrl+C).");
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

fn split_arguments(arguments: &str) -> Result<Vec<String>, String> {
    let mut arguments_out = Vec::new();    let mut current = String::new();
    let mut quote = None;
    for character in arguments.chars() {
        match character {
            '\'' | '"' if quote.is_none() => quote = Some(character),
            character if quote == Some(character) => quote = None,
            character if character.is_whitespace() && quote.is_none() => {
                if !current.is_empty() {
                    arguments_out.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if quote.is_some() {
        return Err("Task command has an unclosed quoted argument.".to_owned());
    }
    if !current.is_empty() {
        arguments_out.push(current);
    }
    Ok(arguments_out)
}

/// Strip a leading transcript/prompt artifact such as `You > ` or `> ` that a
/// user may accidentally paste along with a command copied from the TUI output.
/// The real command always starts with `/`, so we keep everything after the
/// last `>` whose trailing content begins with `/`. Inputs without a `>` are
/// returned unchanged, so valid commands are never corrupted.
fn strip_prompt_prefix(command: &str) -> String {
    let trimmed = command.trim_start();
    if let Some(pos) = trimmed.rfind('>') {
        let rest = trimmed[pos + 1..].trim_start();
        if rest.starts_with('/') {
            return rest.to_owned();
        }
    }
    trimmed.to_owned()
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::{
        App, ActivePane, ExecutionMode, PermissionMode, SetupState, strip_prompt_prefix,
    };

    #[test]
    fn strip_prompt_prefix_tolerates_pasted_transcript_prefix() {
        assert_eq!(
            strip_prompt_prefix("You  > /run https://example.com"),
            "/run https://example.com"
        );
        // Doubled prefix (composer prompt + pasted prefix) also resolves.
        assert_eq!(
            strip_prompt_prefix("You  > You  > /run https://example.com"),
            "/run https://example.com"
        );
        // Bare "> " prefix from the transcript echo.
        assert_eq!(strip_prompt_prefix("> /shield scan ."), "/shield scan .");
        // Clean command without a prompt artifact is left untouched.
        assert_eq!(strip_prompt_prefix("/help"), "/help");
    }

    #[test]
    fn composer_suggests_and_completes_slash_commands() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.append_input('/');
        app.select_next_command(true);

        assert!(app.palette_visible());
        assert!(app.accept_selected_command());
        assert_eq!(app.input, "/run ");
    }

    #[test]
    fn mode_and_permission_cycles_are_independent() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.cycle_mode();
        app.cycle_permission();

        // Default posture is Agent; one Tab cycles to the read-only Plan.
        assert_eq!(app.mode, ExecutionMode::Plan);
        assert_eq!(app.permission, PermissionMode::FullAccess);
        assert!(app.pending_task.is_none());
    }

    #[test]
    fn composer_supports_cursor_editing_and_history() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.insert_text("/hep");
        app.move_input_cursor(false);
        app.insert_text("l");
        app.submit();
        app.insert_text("draft");
        app.recall_history(true);

        assert_eq!(app.input, "/help");
        app.recall_history(false);
        assert_eq!(app.input, "draft");
    }

    #[test]
    fn plan_mode_blocks_task_before_a_confirmation_can_be_armed() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.mode = ExecutionMode::Plan;
        app.insert_text("/run https://lab.example");
        app.submit();

        assert!(app.pending_task.is_none());
        assert!(!app.worker_active);
        assert!(app
            .transcript
            .iter()
            .any(|item| item.text.contains("Plan mode is read-only")));
    }

    #[test]
    fn agent_mode_arms_a_task_and_waits_for_confirmation() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.mode = ExecutionMode::Agent;
        app.permission = PermissionMode::FullAccess;

        app.request_task("run", "https://lab.example");

        assert!(app.pending_task.is_some());
        assert!(!app.worker_active);
    }

    #[test]
    fn paste_routes_into_setup_wizard_field() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        let mut setup = SetupState::new();
        setup.step = 1; // API key step
        app.setup = Some(setup);

        app.insert_text("sk-pasted-key");

        assert_eq!(app.setup.as_ref().unwrap().api_key, "sk-pasted-key");
        assert!(app.input.is_empty(), "main input must stay untouched");
    }

    #[test]
    fn paste_in_main_input_still_works() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.insert_text("hello world");
        assert_eq!(app.input, "hello world");
    }

    #[test]
    fn paste_newlines_dropped_in_setup_do_not_advance_step() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        let mut setup = SetupState::new();
        setup.step = 1;
        app.setup = Some(setup);

        app.insert_text("sk-key\n\n");

        assert_eq!(app.setup.as_ref().unwrap().step, 1);
        assert_eq!(app.setup.as_ref().unwrap().api_key, "sk-key");
    }

    #[test]
    fn task_requires_a_target() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.mode = ExecutionMode::Agent;

        app.request_task("run", "");

        assert!(app.pending_task.is_none());
        assert!(app
            .transcript
            .iter()
            .any(|item| item.text.contains("requires a target")));
    }

    #[test]
    fn streamed_events_update_and_finalize_the_work_receipt() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.active_receipt = Some(super::OperationReceipt {
            command: "run https://lab.example --stream".into(),
            phase: "Starting".into(),
            findings: 0,
        });
        app.worker_active = true;
        app.apply_event(crate::protocol::AppEvent::Stream(
            crate::protocol::StreamEvent::Finding(crate::protocol::Finding {
                severity: "high".into(),
                title: "Test finding".into(),
                ..Default::default()
            }),
        ));
        app.apply_event(crate::protocol::AppEvent::Finished(true));

        assert!(app.active_receipt.is_none());
        assert_eq!(app.last_receipt.as_ref().unwrap().findings, 1);
        assert_eq!(app.last_receipt.as_ref().unwrap().phase, "Completed");
    }

    #[test]
    fn active_pane_rect_partitions_the_workbench_without_overlap() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 28);

        app.active_pane = ActivePane::Workspace;
        let workspace = app.active_pane_rect(app.terminal_size);
        app.active_pane = ActivePane::Transcript;
        let transcript = app.active_pane_rect(app.terminal_size);
        app.active_pane = ActivePane::Findings;
        let findings = app.active_pane_rect(app.terminal_size);

        // The three panes are laid out left-to-right and must not overlap.
        assert_eq!(workspace.x, 0);
        assert!(workspace.right() <= transcript.x, "workspace right of transcript start");
        assert!(transcript.right() <= findings.x, "transcript right of findings start");
        assert!(findings.right() <= 120);
        // None of them spans the full screen — each is an independent region.
        assert!(workspace.width < 120);
        assert!(transcript.width < 120);
        assert!(findings.width < 120);
    }

    #[test]
    fn copy_active_pane_renders_only_the_focused_region() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 28);
        app.active_pane = ActivePane::Transcript;

        // Drive the same offscreen render path the real copy uses, then pull the
        // transcript region and confirm it contains transcript content but not
        // the findings title (proving the copy is pane-scoped, not whole-screen).
        let rect = app.active_pane_rect(app.terminal_size);
        let backend = ratatui::backend::TestBackend::new(120, 28);
        let mut term = ratatui::Terminal::new(backend).unwrap();
        term.draw(|f| crate::ui::draw(f, &app)).unwrap();
        let text = super::extract_rect_text(term.backend().buffer(), rect);

        assert!(text.contains("Session transcript"));
        assert!(
            !text.contains("Findings inspector"),
            "transcript copy must not bleed into the findings pane"
        );
    }

    #[test]
    fn transcript_autoscroll_pins_to_bottom_and_tracks_growth() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        // 120x30 -> transcript panel height 26, visible inner rows = 24.
        app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 30);
        app.active_pane = ActivePane::Transcript;

        // Short lines never wrap at the ~50-col inner width, so the pin point is
        // purely a function of content length.
        for i in 0..5 {
            app.push(crate::app::TranscriptKind::Log, format!("line {i}"));
        }
        app.autoscroll_transcript();
        let small = app.transcript_scroll as usize;
        assert!(app.transcript_follow);
        assert_eq!(small, app.transcript_max_scroll());

        for i in 5..45 {
            app.push(crate::app::TranscriptKind::Log, format!("line {i}"));
        }
        app.autoscroll_transcript();
        let large = app.transcript_scroll as usize;
        assert!(app.transcript_follow);
        assert_eq!(large, app.transcript_max_scroll());
        // More content => larger bottom offset => the view followed the growth.
        assert!(large > small);
    }

    #[test]
    fn transcript_short_content_has_zero_scroll() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 30);
        app.active_pane = ActivePane::Transcript;
        app.autoscroll_transcript();
        // Only the two welcome lines — they fit, so no scrolling is needed.
        assert_eq!(app.transcript_max_scroll(), 0);
        assert_eq!(app.transcript_scroll, 0);
        assert!(app.transcript_follow);
    }

    #[test]
    fn scrolling_up_pauses_follow_and_bottom_resumes_it() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.terminal_size = ratatui::layout::Rect::new(0, 0, 120, 30);
        app.active_pane = ActivePane::Transcript;
        for i in 0..45 {
            app.push(crate::app::TranscriptKind::Log, format!("line {i}"));
        }
        app.autoscroll_transcript();
        let max = app.transcript_max_scroll() as u16;
        assert!(max > 0);
        assert_eq!(app.transcript_scroll, max);
        assert!(app.transcript_follow);

        // Scroll up once to read history: follow must switch off.
        app.scroll_active_pane(false);
        assert!(!app.transcript_follow);
        assert_eq!(app.transcript_scroll, max - 1);

        // Scroll back down to the bottom: follow must switch back on.
        for _ in 0..(max as usize + 2) {
            app.scroll_active_pane(true);
        }
        assert!(app.transcript_follow);
        assert_eq!(app.transcript_scroll, max);
    }
}
