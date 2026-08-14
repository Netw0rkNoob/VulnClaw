use ratatui::{
    layout::Rect,
    style::Style,
    text::Span,
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

use crate::app::{ActivePane, App};
use crate::theme;

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let items = app
        .findings
        .iter()
        .map(|finding| {
            let location = finding
                .line
                .map(|line| format!("{}:{line}", finding.target))
                .unwrap_or_else(|| finding.target.clone());
            let label = format!(
                "[{}] {} - {}",
                finding.severity.to_uppercase(),
                finding.title,
                location
            );
            ListItem::new(label).style(theme::severity_style(&finding.severity))
        })
        .collect::<Vec<_>>();
    let title = if app.active_pane == ActivePane::Findings {
        format!("Findings inspector ({}) *", app.findings.len())
    } else {
        format!("Findings inspector ({})", app.findings.len())
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::pulse_border(
                app.active_pane == ActivePane::Findings && app.worker_active,
            ))
            .style(Style::default().bg(theme::PANEL))
            .title(Span::styled(title, Style::default().fg(theme::TEXT_SOFT))),
    );
    let mut state = ListState::default().with_offset(app.findings_scroll as usize);
    frame.render_stateful_widget(list, area, &mut state);
}
