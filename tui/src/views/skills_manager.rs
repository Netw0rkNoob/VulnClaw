use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::App;
use crate::skills::catalog::SkillNode;
use crate::theme;

pub fn render(app: &App) -> Paragraph<'static> {
    let mut lines = vec![
        Line::from(Span::styled(
            "Workspace",
            Style::default()
                .fg(theme::ACTION)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("Mode        {}", app.mode.label()),
            Style::default().fg(theme::TEXT_MUTED),
        )),
        Line::from(Span::styled(
            format!("Guard       {}", app.permission.label()),
            Style::default().fg(theme::TEXT_MUTED),
        )),
        Line::from(Span::styled(
            format!(
                "Backend     {}",
                app.backend_pid
                    .map(|pid| format!("pid {pid}"))
                    .unwrap_or_else(|| "disconnected".into())
            ),
            Style::default().fg(if app.backend_ready {
                theme::SUCCESS
            } else {
                theme::CORAL
            }),
        )),
        Line::from(Span::styled(
            format!(
                "Target      {}",
                if app.target.is_empty() {
                    "not selected"
                } else {
                    app.target.as_str()
                }
            ),
            Style::default().fg(theme::TEXT_MUTED),
        )),
        Line::from(Span::styled(
            format!("Phase       {}", app.phase),
            Style::default().fg(theme::TEXT_MUTED),
        )),
        Line::from(Span::styled(
            if app.worker_active {
                "Activity    running"
            } else {
                "Activity    idle"
            },
            Style::default().fg(if app.worker_active {
                theme::GOLD
            } else {
                theme::TEXT_HINT
            }),
        )),
        Line::from(Span::styled(
            format!(
                "Scope       H{} P{} A{}",
                json_array_len(&app.task_constraints, "allowed_hosts"),
                json_array_len(&app.task_constraints, "allowed_ports"),
                json_array_len(&app.task_constraints, "allowed_actions")
            ),
            Style::default().fg(theme::TEXT_MUTED),
        )),
        Line::from(Span::styled(
            format!(
                "Evidence    {}  Violations {}",
                app.evidence.len(),
                app.constraint_violations.len()
            ),
            Style::default().fg(if app.constraint_violations.is_empty() {
                theme::TEXT_MUTED
            } else {
                theme::CORAL
            }),
        )),
        Line::from(Span::styled(
            format!("Last run    {}", last_run_label(app.last_run.as_ref())),
            Style::default().fg(theme::TEXT_MUTED),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Execution receipt",
            Style::default()
                .fg(theme::SEAFOAM)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    if let Some(receipt) = app.active_receipt.as_ref() {
        lines.push(Line::from(Span::styled(
            format!("LIVE  {}", receipt.phase),
            Style::default()
                .fg(theme::GOLD)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            format!("Found {}", receipt.findings),
            Style::default().fg(theme::SUCCESS),
        )));
        lines.push(Line::from(Span::styled(
            truncate(&receipt.command, 22),
            Style::default().fg(theme::TEXT_MUTED),
        )));
    } else if let Some(receipt) = app.last_receipt.as_ref() {
        lines.push(Line::from(Span::styled(
            format!("{}  {} finding(s)", receipt.phase, receipt.findings),
            Style::default().fg(theme::TEXT_SOFT),
        )));
        lines.push(Line::from(Span::styled(
            truncate(&receipt.command, 22),
            Style::default().fg(theme::TEXT_MUTED),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "No command started",
            Style::default().fg(theme::TEXT_HINT),
        )));
    }
    lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "Capabilities",
            Style::default()
                .fg(theme::SEAFOAM)
                .add_modifier(Modifier::BOLD),
        )),
    ]);
    append_nodes(&app.skills, "", &mut lines);
    Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::BORDER)
            .style(Style::default().bg(theme::PANEL)),
    )
}

fn json_array_len(value: &serde_json::Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len)
}

fn last_run_label(value: Option<&serde_json::Value>) -> &str {
    value
        .and_then(|run| run.get("run"))
        .and_then(|run| run.get("name"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .and_then(|run| run.get("status"))
                .and_then(serde_json::Value::as_str)
        })
        .unwrap_or("none")
}

fn truncate(text: &str, max_chars: usize) -> String {
    let mut characters = text.chars();
    let preview = characters.by_ref().take(max_chars).collect::<String>();
    if characters.next().is_some() {
        format!("{preview}...")
    } else {
        preview
    }
}

fn append_nodes(nodes: &[SkillNode], prefix: &str, lines: &mut Vec<Line<'static>>) {
    for (index, node) in nodes.iter().enumerate() {
        let is_last = index + 1 == nodes.len();
        let branch = if prefix.is_empty() {
            ""
        } else if is_last {
            "`-- "
        } else {
            "|-- "
        };
        let label = format!("{prefix}{branch}{}", node.name);
        let style = if node.children.is_empty() {
            Style::default().fg(theme::TEXT_SOFT)
        } else {
            Style::default()
                .fg(theme::TEXT_BODY)
                .add_modifier(Modifier::BOLD)
        };
        lines.push(Line::from(Span::styled(label, style)));
        if !node.children.is_empty() {
            let next_prefix = if prefix.is_empty() {
                "  ".to_owned()
            } else if is_last {
                format!("{prefix}    ")
            } else {
                format!("{prefix}|   ")
            };
            append_nodes(&node.children, &next_prefix, lines);
        }
    }
}
