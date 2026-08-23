use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::app::{ActivePane, App};
use crate::theme;
use crate::views::skills_manager;

pub fn render(frame: &mut Frame, app: &App) {
    frame.render_widget(
        Block::default().style(Style::default().bg(theme::BG)),
        frame.area(),
    );
    // Compact single-line composer (CodeWhale Compact density): one input row,
    // no bordered title box that reads as a second line. The command palette and
    // the task-confirmation prompt get their own taller regions when active.
    let composer_height = if app.pending_task.is_some() {
        3
    } else if app.palette_visible() {
        7
    } else {
        1
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(composer_height),
            Constraint::Length(1),
        ])
        .split(frame.area());
    render_header(frame, app, rows[0]);
    render_phase_strip(frame, app, rows[1]);
    render_workbench(frame, app, rows[2]);
    render_composer(frame, app, rows[3]);
    render_hotbar(frame, app, rows[4]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![
        Span::styled(
            " VulnClaw ",
            Style::default()
                .fg(theme::ACTION)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", app.mode.label()),
            Style::default()
                .fg(theme::mode_color(app.mode.label()))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("| {} ", app.permission.label()),
            Style::default().fg(theme::permission_color(app.permission.label())),
        ),
        Span::raw("| "),
    ];
    if app.worker_active {
        // Live "working" cluster: spinning glyph, bouncing equalizer, and a
        // running elapsed-time readout — all animate off the wall clock so the
        // surface feels alive without any extra state.
        spans.push(Span::styled(
            format!("{} running", theme::spinner_frame(true)),
            Style::default().fg(theme::GOLD),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            theme::equalizer_frame(),
            Style::default().fg(theme::SEAFOAM),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            theme::elapsed_label(app.worker_started_at),
            Style::default().fg(theme::TEXT_SOFT),
        ));
    } else {
        spans.push(Span::styled("idle", Style::default().fg(theme::TEXT_HINT)));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme::CHROME)),
        area,
    );
}

/// Live progress bar — mirrors CodeWhale's phase strip so a running scan shows
/// its current phase and finding count instead of a frozen transcript.
fn render_phase_strip(frame: &mut Frame, app: &App, area: Rect) {
    let line = if app.worker_active {
        if let Some(receipt) = app.active_receipt.as_ref() {
            let mut spans = vec![Span::styled(
                format!(" {} {}  ·  ", theme::spinner_frame(true), receipt.phase),
                Style::default().fg(theme::SEAFOAM),
            )];
            // The finding count pulses gold while a run is live and has already
            // surfaced something, so a fresh hit reads as a heartbeat.
            let fc_style = if receipt.findings > 0 && theme::blink_on() {
                Style::default()
                    .fg(theme::GOLD)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::SEAFOAM)
            };
            spans.push(Span::styled(
                format!("{} finding(s)", receipt.findings),
                fc_style,
            ));
            spans.push(Span::styled(
                format!("  ·  {}", receipt.command),
                Style::default().fg(theme::SEAFOAM),
            ));
            Line::from(spans)
        } else {
            Line::from(Span::styled(
                format!(" {} working", theme::spinner_frame(true)),
                Style::default().fg(theme::SEAFOAM),
            ))
        }
    } else if let Some(receipt) = app.last_receipt.as_ref() {
        Line::from(Span::styled(
            format!(
                " {}  ·  {} finding(s)  ·  {}",
                receipt.phase, receipt.findings, receipt.command
            ),
            Style::default().fg(theme::TEXT_HINT),
        ))
    } else {
        Line::from(Span::styled(
            " ready",
            Style::default().fg(theme::TEXT_HINT),
        ))
    };
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(theme::CHROME)),
        area,
    );
}

fn render_workbench(frame: &mut Frame, app: &App, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(28),
            Constraint::Min(36),
            Constraint::Length(40),
        ])
        .split(area);
    let sidebar = skills_manager::render(app).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::BORDER)
            .style(Style::default().bg(theme::PANEL))
            .title(if app.active_pane == ActivePane::Workspace {
                "Workspace *"
            } else {
                "Workspace"
            }),
    );
    frame.render_widget(sidebar, panels[0]);
    crate::ui::transcript::render(frame, app, panels[1]);
    crate::ui::findings::render(frame, app, panels[2]);
}

fn render_composer(frame: &mut Frame, app: &App, area: Rect) {
    if app.pending_task.is_some() {
        frame.render_widget(
            Paragraph::new("TUI confirmation is required. Press Y to start, or Esc to cancel.")
                .wrap(Wrap { trim: true })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(theme::CORAL)
                        .title("Task confirmation required"),
                ),
            area,
        );
        return;
    }

    if app.palette_visible() {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Length(1)])
            .split(area);
        render_command_palette(frame, app, rows[0]);
        render_composer_input(frame, app, rows[1]);
    } else {
        render_composer_input(frame, app, area);
    }
}

fn render_composer_input(frame: &mut Frame, app: &App, composer_area: Rect) {
    let content = if app.input.is_empty() {
        "Type / for commands"
    } else {
        app.input.as_str()
    };
    let style = if app.input.is_empty() {
        Style::default().fg(theme::TEXT_HINT)
    } else {
        Style::default().fg(theme::TEXT_BODY)
    };
    // Single-line prompt — no bordered title box (which read as a second line).
    // The leading marker + text + cursor all live on this one row.
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " > ",
                Style::default()
                    .fg(theme::ACTION)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(content, style),
        ]))
        .style(Style::default().bg(theme::PLATE)),
        composer_area,
    );
    if !app.input.is_empty() {
        let cursor_x = composer_area
            .x
            .saturating_add(3)
            .saturating_add(app.input[..app.input_cursor].chars().count() as u16)
            .min(composer_area.right().saturating_sub(1));
        frame.set_cursor_position((cursor_x, composer_area.y));
    }
}

fn render_command_palette(frame: &mut Frame, app: &App, area: Rect) {
    let commands = app.suggested_commands();
    let items = commands
        .iter()
        .map(|item| {
            ListItem::new(Line::from(vec![
                Span::styled(item.command.as_str(), Style::default().fg(theme::ACTION)),
                Span::raw("  "),
                Span::styled(item.description, Style::default().fg(theme::TEXT_MUTED)),
            ]))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.palette_selection));
    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(
                Style::default()
                    .fg(theme::TEXT_BODY)
                    .bg(theme::PLATE)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::BORDER)
                    .title("Commands"),
            ),
        area,
        &mut state,
    );
}

fn render_hotbar(frame: &mut Frame, app: &App, area: Rect) {
    let (text, style) = if !app.toast.is_empty() {
        (
            app.toast.as_str(),
            Style::default()
                .fg(theme::SEAFOAM)
                .add_modifier(Modifier::BOLD),
        )
    } else if app.pending_task.is_some() {
        (
            " Y confirm | Esc cancel",
            Style::default().fg(theme::TEXT_HINT),
        )
    } else if app.worker_active {
        (
            " Running — Ctrl+C abort | Tab mode | ↑/↓ scroll | Ctrl+Y copy pane",
            Style::default().fg(theme::TEXT_HINT),
        )
    } else {
        (
            " Tab mode | Shift+Tab safeguard | Ctrl+P/N history | Ctrl+←/→ panel | ↑/↓ scroll | Ctrl+T thinking | F5 chain | Ctrl+S save | Ctrl+R restore | Ctrl+Y copy pane | Ctrl+C exit",
            Style::default().fg(theme::TEXT_HINT),
        )
    };
    frame.render_widget(
        Paragraph::new(Span::styled(text, style)).style(Style::default().bg(theme::CHROME)),
        area,
    );
}
