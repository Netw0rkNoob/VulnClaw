use ratatui::{
    layout::{Constraint, Direction, Layout},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;
use crate::theme;

const DEPENDENCY_PREVIEW_CHARS: usize = 10;

/// Shorten a finding dependency for the compact DAG view without splitting a
/// UTF-8 code point.
pub fn dependency_preview(id: &str) -> String {
    id.chars().take(DEPENDENCY_PREVIEW_CHARS).collect()
}

pub fn render(frame: &mut Frame, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(frame.area());
    frame.render_widget(
        Paragraph::new(Span::styled(
            " VulnClaw Attack Chain",
            ratatui::style::Style::default()
                .fg(theme::ACTION)
                .add_modifier(ratatui::style::Modifier::BOLD),
        )),
        rows[0],
    );
    let lines = if app.findings.is_empty() {
        vec![Line::from("No streamed findings available. Run a backend task or open a report-generated attack-chain JSON.")]
    } else {
        app.findings
            .iter()
            .map(|finding| {
                let prefix = if finding.chain_depends_on.is_empty() {
                    "*"
                } else {
                    "|->"
                };
                let dependency = if finding.chain_depends_on.is_empty() {
                    String::new()
                } else {
                    format!(
                        " <- {}",
                        finding
                            .chain_depends_on
                            .iter()
                            .map(|id| dependency_preview(id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                Line::from(vec![
                    Span::raw(format!(" {prefix} ")),
                    Span::styled(
                        format!("[{}] ", finding.severity.to_uppercase()),
                        theme::severity_style(&finding.severity),
                    ),
                    Span::styled(
                        format!("{} ({}){}", finding.title, finding.target, dependency),
                        ratatui::style::Style::default().fg(theme::TEXT_SOFT),
                    ),
                ])
            })
            .collect()
    };
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::BORDER)
                .title(Span::styled(
                    "Findings DAG",
                    ratatui::style::Style::default().fg(theme::TEXT_SOFT),
                )),
        ),
        rows[1],
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            " F5 back | Edges are supplied by chain_depends_on when present.",
            ratatui::style::Style::default().fg(theme::TEXT_HINT),
        )),
        rows[2],
    );
}
