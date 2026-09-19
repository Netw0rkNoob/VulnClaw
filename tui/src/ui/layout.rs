use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::app::{
    App, COMPOSER_FRAME_ROWS, COMPOSER_STATUS_ROWS, LLM_SUGGESTION_ROWS, PALETTE_ROWS,
};
use crate::theme;
use crate::views::status;
use crate::workbench::{ContainerId, Gesture, LayoutGeometry, ViewId};

pub fn render(frame: &mut Frame, app: &App) {
    frame.render_widget(
        Block::default().style(Style::default().bg(theme::BG)),
        frame.area(),
    );
    let geometry = app.geometry(frame.area());
    render_header(frame, app, geometry.header);
    if geometry.too_small {
        frame.render_widget(
            Paragraph::new(format!(
                "Terminal too small. Need at least {} columns x {} rows.",
                geometry.minimum_size.0, geometry.minimum_size.1
            ))
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(theme::GOLD)),
            geometry.workbench,
        );
    } else {
        render_workbench(frame, app, &geometry);
        render_composer(frame, app, geometry.container(ContainerId::Bottom));
    }
    render_hotbar(frame, app, geometry.hotbar);

    if let Some(pending) = &app.pending_execution {
        render_approval_modal(frame, pending, frame.area());
    }
    if let Some(settings) = &app.llm_settings {
        render_llm_settings_modal(frame, settings, frame.area());
    }
}

/// Columns reserved for a settings row's label, so every value lines up.
const LLM_LABEL_COLUMNS: u16 = 18;
/// Rows the settings body needs on top of the fields: header plus footer.
const LLM_CHROME_ROWS: u16 = 3;
/// Width of the marker column ("› ").
const LLM_MARKER_COLUMNS: u16 = 2;

/// The `/config` LLM settings screen: a centered blocking modal editing the
/// provider template and the four fields it drives.
fn render_llm_settings_modal(frame: &mut Frame, settings: &crate::app::LlmSettings, area: Rect) {
    let modal_area = llm_modal_area(area);
    if modal_area.width == 0 || modal_area.height == 0 {
        return;
    }
    frame.render_widget(ratatui::widgets::Clear, modal_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACTION))
        .style(Style::default().bg(theme::PANEL));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let footer_rows = inner.height.min(2);
    let body_height = inner.height.saturating_sub(footer_rows);
    let (lines, caret) = llm_settings_body(settings, inner.width, body_height);
    if body_height > 0 {
        frame.render_widget(
            Paragraph::new(lines),
            Rect {
                x: inner.x,
                y: inner.y,
                width: inner.width,
                height: body_height,
            },
        );
    }

    // A caret needs a real cursor, and ratatui keeps only one per frame — this
    // is why the composer's own cursor is suppressed while the modal is up.
    if let Some((row, column)) = caret {
        if row < body_height {
            let x = inner
                .x
                .saturating_add(column)
                .min(inner.right().saturating_sub(1));
            frame.set_cursor_position((x, inner.y.saturating_add(row)));
        }
    }

    let footer_y = inner.y.saturating_add(body_height);
    let feedback = if settings.error.is_empty() {
        settings.status.clone()
    } else {
        settings.error.clone()
    };
    if footer_rows >= 2 {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                feedback,
                Style::default().fg(if settings.error.is_empty() {
                    theme::TEXT_HINT
                } else {
                    theme::ROSE
                }),
            ))),
            Rect::new(inner.x, footer_y, inner.width, 1),
        );
    }
    // The hint follows the mode, so the current Enter/Esc meaning is explicit.
    let hint = if settings.template_list_open {
        " ↑↓ choose template · Enter apply · Esc cancel"
    } else if settings.editing {
        " typing · ↑↓ pick suggestion · Enter confirm · Esc revert"
    } else {
        " ↑↓ row · Enter edit · Ctrl+S save · Esc close"
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hint,
            Style::default().fg(theme::TEXT_HINT),
        ))),
        Rect::new(
            inner.x,
            footer_y.saturating_add(footer_rows.saturating_sub(1)),
            inner.width,
            1,
        ),
    );
}

fn llm_modal_area(area: Rect) -> Rect {
    let width = area.width.min(92);
    let height = area.height.min(22);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

/// Build the settings body plus the caret location, in body-relative rows.
fn llm_settings_body(
    settings: &crate::app::LlmSettings,
    width: u16,
    body_height: u16,
) -> (Vec<Line<'static>>, Option<(u16, u16)>) {
    use crate::app::LlmField;

    let mut lines = vec![Line::from(Span::styled(
        " LLM settings ",
        Style::default()
            .fg(Color::Rgb(10, 6, 2))
            .bg(theme::ACTION)
            .add_modifier(Modifier::BOLD),
    ))];
    let mut caret = None;

    let value_columns = width
        .saturating_sub(LLM_MARKER_COLUMNS)
        .saturating_sub(LLM_LABEL_COLUMNS);
    let aux_budget = body_height.saturating_sub(LLM_CHROME_ROWS + 5);

    for field in LlmField::ORDER {
        let focused = settings.focus == field;
        let list_here = focused && settings.template_list_open;
        let editing_here = focused && settings.editing;
        let label = format!(
            "{:<width$}",
            field.label(),
            width = usize::from(LLM_LABEL_COLUMNS)
        );
        let value = if list_here {
            "▾".to_owned()
        } else {
            truncate_to_columns(&settings.display_value(field), value_columns)
        };
        // A distinct marker is the operator's cue that the row is open for
        // typing, and that Enter now closes rather than opens it.
        let marker = if editing_here {
            "✎ "
        } else if focused {
            "› "
        } else {
            "  "
        };
        let text = format!("{marker}{label}{value}");
        let style = if focused {
            Style::default()
                .fg(theme::BG)
                .bg(theme::ACTION)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::TEXT_SOFT)
        };
        lines.push(Line::from(Span::styled(text, style)));

        if editing_here && field.is_editable_text() {
            // The caret sits after whatever prefix precedes the value.
            let offset = Line::from(settings.focused_text().get(..settings.cursor).unwrap_or(""))
                .width()
                .min(usize::from(value_columns));
            caret = Some((
                u16::try_from(lines.len().saturating_sub(1)).unwrap_or(u16::MAX),
                LLM_MARKER_COLUMNS + LLM_LABEL_COLUMNS + u16::try_from(offset).unwrap_or(u16::MAX),
            ));
        }

        if aux_budget == 0 {
            continue;
        }
        // Whatever the terminal leaves below the rows already drawn.
        let visible_rows = usize::from(body_height).saturating_sub(lines.len());
        if list_here {
            let options = settings.template_labels();
            push_options(
                &mut lines,
                &options,
                Some(settings.list_index),
                value_columns,
                body_height,
                visible_rows,
            );
        } else if editing_here && field == LlmField::Model {
            let options = settings.suggestions();
            push_options(
                &mut lines,
                &options,
                settings.suggestion,
                value_columns,
                body_height,
                visible_rows.min(LLM_SUGGESTION_ROWS),
            );
        }
    }

    (lines, caret)
}

/// Draw a window of *options* beneath the focused row, highlighting *selected*.
///
/// Only `window_rows` entries are drawn, but `options` is the whole list and
/// the window scrolls with the selection, so nothing becomes unreachable just
/// because the provider returned more models than fit.
fn push_options(
    lines: &mut Vec<Line<'static>>,
    options: &[String],
    selected: Option<usize>,
    value_columns: u16,
    body_height: u16,
    window_rows: usize,
) {
    let (start, size) = option_window(options.len(), selected, window_rows);
    for (index, option) in options.iter().enumerate().skip(start).take(size) {
        if lines.len() >= usize::from(body_height) {
            break;
        }
        let text = format!(
            "    {}",
            truncate_to_columns(option, value_columns.saturating_sub(2))
        );
        let style = if selected == Some(index) {
            Style::default()
                .fg(theme::BG)
                .bg(theme::GOLD)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::TEXT_MUTED)
        };
        lines.push(Line::from(Span::styled(text, style)));
    }
    // How much of the list is still below the window. Counted from the window
    // rather than the list, so it ticks down as the selection scrolls and drops
    // away entirely once the window reaches the last entry.
    let below = options.len().saturating_sub(start + size);
    if below > 0 && lines.len() < usize::from(body_height) {
        lines.push(Line::from(Span::styled(
            format!("    {MORE_ROWS_HINT}{below} more"),
            Style::default().fg(theme::TEXT_HINT),
        )));
    }
}

/// The slice of a list the screen should show, as `(start, count)`.
///
/// The window keeps a fixed height and follows the highlighted entry, scrolling
/// only once the selection would otherwise fall outside it.
fn option_window(total: usize, selected: Option<usize>, rows: usize) -> (usize, usize) {
    if total == 0 || rows == 0 {
        return (0, 0);
    }
    let size = rows.min(total);
    let selected = selected.unwrap_or(0).min(total - 1);
    // Zero while the selection still fits; otherwise scroll just enough to keep
    // it on the last visible row.
    let start = (selected + 1).saturating_sub(size);
    (start.min(total - size), size)
}

/// Clip *text* to *columns* display cells, marking a cut with an ellipsis.
///
/// Measured in cells rather than characters so CJK labels do not overflow into
/// the next column of the modal.
fn truncate_to_columns(text: &str, columns: u16) -> String {
    let limit = usize::from(columns);
    if limit == 0 {
        return String::new();
    }
    if Line::from(text).width() <= limit {
        return text.to_owned();
    }
    let mut clipped = String::new();
    let mut used = 0usize;
    for character in text.chars() {
        let width = Line::from(character.to_string()).width();
        if used + width > limit.saturating_sub(1) {
            break;
        }
        clipped.push(character);
        used += width;
    }
    clipped.push('…');
    clipped
}

/// Blocking execution-approval modal. Mirrors the pending_task confirm
/// pattern: Y approves, N/Esc denies (default deny), other keys swallowed.
fn render_approval_modal(frame: &mut Frame, pending: &crate::app::PendingExecution, area: Rect) {
    let modal_area = approval_modal_area(area);
    if modal_area.width == 0 || modal_area.height == 0 {
        return;
    }
    frame.render_widget(ratatui::widgets::Clear, modal_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(theme::PANEL));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let footer_rows = inner.height.min(3);
    let body_height = inner.height.saturating_sub(footer_rows);
    if body_height > 0 {
        let body_area = Rect {
            x: inner.x,
            y: inner.y,
            width: inner.width,
            height: body_height,
        };
        let max_scroll = approval_max_scroll(pending, area);
        let scroll = usize::from(pending.scroll_offset).min(max_scroll);
        frame.render_widget(
            Paragraph::new(approval_body_lines(pending))
                .wrap(Wrap { trim: false })
                .scroll((u16::try_from(scroll).unwrap_or(u16::MAX), 0)),
            body_area,
        );
    }

    let footer_y = inner.y.saturating_add(body_height);
    let mut footer_row = 0;
    if footer_rows == 3 {
        let remaining = pending.remaining_secs();
        let text = if remaining > 0 {
            format!("将在 {remaining}s 后超时自动拒绝")
        } else {
            String::new()
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                text,
                Style::default().fg(theme::TEXT_HINT),
            ))),
            Rect::new(inner.x, footer_y, inner.width, 1),
        );
        footer_row += 1;
    }
    if footer_rows >= 2 {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                pending.risk.clone(),
                Style::default().fg(theme::GOLD),
            ))),
            Rect::new(inner.x, footer_y.saturating_add(footer_row), inner.width, 1),
        );
        footer_row += 1;
    }
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " [Y] ",
                Style::default()
                    .fg(theme::SEAFOAM)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("批准 ", Style::default().fg(theme::TEXT_SOFT)),
            Span::styled(
                "[N/Esc] ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled("拒绝 ", Style::default().fg(theme::TEXT_SOFT)),
            Span::styled("↑/↓ 滚动", Style::default().fg(theme::TEXT_HINT)),
        ])),
        Rect::new(inner.x, footer_y.saturating_add(footer_row), inner.width, 1),
    );
}

fn approval_modal_area(area: Rect) -> Rect {
    let width = area.width.min(78);
    let height = area.height.min(18);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn approval_body_lines(pending: &crate::app::PendingExecution) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        format!(" {} 执行审批 ", pending.kind),
        Style::default()
            .fg(Color::Rgb(10, 6, 2))
            .bg(theme::ACTION)
            .add_modifier(Modifier::BOLD),
    ))];
    if !pending.cwd.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("cwd   {}", pending.cwd),
            Style::default().fg(theme::TEXT_SOFT),
        )));
    }
    lines.push(Line::from(Span::styled(
        "命令/代码:",
        Style::default().fg(theme::TEXT_MUTED),
    )));
    if pending.command.is_empty() {
        lines.push(Line::from(Span::styled(
            "  │ (empty)",
            Style::default().fg(theme::TEXT_BODY),
        )));
    } else {
        for raw in pending.command.lines() {
            lines.push(Line::from(Span::styled(
                format!("  │ {raw}"),
                Style::default().fg(theme::TEXT_BODY),
            )));
        }
    }
    if !pending.detail.is_empty() {
        for (idx, raw) in pending.detail.split('\n').enumerate() {
            let prefix = if idx == 0 { "原因  " } else { "      " };
            lines.push(Line::from(Span::styled(
                format!("{prefix}{raw}"),
                Style::default().fg(theme::GOLD),
            )));
        }
    }
    lines
}

pub(crate) fn approval_body_area(area: Rect) -> Rect {
    let modal = approval_modal_area(area);
    let inner = Block::default().borders(Borders::ALL).inner(modal);
    Rect::new(inner.x, inner.y, inner.width, approval_body_height(area))
}

pub(crate) fn approval_body_height(area: Rect) -> u16 {
    let inner_height = approval_modal_area(area).height.saturating_sub(2);
    inner_height.saturating_sub(inner_height.min(3))
}

pub(crate) fn approval_max_scroll(pending: &crate::app::PendingExecution, area: Rect) -> usize {
    let modal = approval_modal_area(area);
    let inner_width = modal.width.saturating_sub(2);
    let body_height = approval_body_height(area);
    if inner_width == 0 || body_height == 0 {
        return 0;
    }
    let paragraph = Paragraph::new(approval_body_lines(pending)).wrap(Wrap { trim: false });
    paragraph
        .line_count(inner_width)
        .saturating_sub(usize::from(body_height))
}

/// Width reserved for the left cluster before the provider badge is dropped, so
/// a narrow terminal truncates the badge rather than the brand, mode and
/// permission indicators.
const HEADER_LEFT_MIN_WIDTH: u16 = 24;

/// Right-aligned provider badge text, or `None` before the backend reports one.
///
/// Only the provider stays in the header — the model name moved down to the
/// composer status line. The backend sends the provider it loaded at startup, so
/// a later switch shows up only after the TUI restarts.
fn provider_badge(app: &App) -> Option<String> {
    if app.config_ready == Some(false) {
        return Some("provider: not configured".to_owned());
    }
    Some(format!("provider: {}", app.provider.as_deref()?))
}

/// Spinner, equalizer and elapsed readout for a running task, or `None` when
/// idle so the header stays a quiet title bar.
fn worker_cluster(app: &App) -> Option<Line<'static>> {
    if !app.worker_active {
        return None;
    }
    Some(Line::from(vec![
        Span::styled(
            format!("{} running", theme::spinner_frame(true)),
            Style::default().fg(theme::GOLD),
        ),
        Span::raw(" "),
        Span::styled(
            theme::equalizer_frame(),
            Style::default().fg(theme::SEAFOAM),
        ),
        Span::raw(" "),
        Span::styled(
            theme::elapsed_label(app.worker_started_at),
            Style::default().fg(theme::TEXT_SOFT),
        ),
    ]))
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    // A title bar: brand left, live worker cluster centred, provider badge
    // right. There is no `idle` text -- an idle header simply carries no
    // cluster, because the Status view already reports the worker state.
    if area.width == 0 || area.height == 0 {
        return;
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER))
        .style(Style::default().bg(theme::CHROME));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let header_bg = Style::default().bg(theme::CHROME);
    let brand = Line::from(Span::styled(
        " VulnClaw ",
        Style::default()
            .fg(theme::BG)
            .bg(theme::ACTION)
            .add_modifier(Modifier::BOLD),
    ));
    let brand_width = u16::try_from(brand.width()).unwrap_or(u16::MAX);
    // The badge is a fixed-width right cluster; measure it in display cells, not
    // bytes, because provider names can contain full-width glyphs. One extra
    // column keeps the badge rail off the header's own right border.
    let badge = provider_badge(app);
    let badge_width = badge
        .as_deref()
        .map(|text| u16::try_from(Line::from(text).width()).unwrap_or(u16::MAX) + 5)
        .unwrap_or(0);
    let show_badge = badge_width > 0 && inner.width >= badge_width + HEADER_LEFT_MIN_WIDTH;
    let cluster = worker_cluster(app);
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(brand_width),
            Constraint::Min(0),
            Constraint::Length(if show_badge { badge_width } else { 0 }),
        ])
        .split(inner);
    frame.render_widget(Paragraph::new(brand).style(header_bg), panes[0]);
    if let Some(cluster) = cluster {
        frame.render_widget(
            Paragraph::new(cluster)
                .alignment(Alignment::Center)
                .style(header_bg),
            panes[1],
        );
    }
    let Some(text) = badge.filter(|_| show_badge) else {
        return;
    };
    // A missing or unusable provider reads as a faint placeholder rather than a
    // confident value.
    let placeholder = app.config_ready == Some(false);
    let badge_area = Rect {
        width: panes[2].width.saturating_sub(1),
        ..panes[2]
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(" {text} "),
            Style::default().fg(if placeholder {
                theme::TEXT_HINT
            } else {
                theme::TEXT_SOFT
            }),
        )))
        .block(
            Block::default()
                .borders(Borders::LEFT | Borders::RIGHT)
                .border_style(Style::default().fg(theme::BORDER))
                .style(header_bg),
        ),
        badge_area,
    );
}

pub(crate) fn view_block(app: &App, id: ViewId) -> Block<'static> {
    let instance = app.layout.view(id);
    let marker = if id.movable() {
        if instance.collapsed {
            // A collapsed view is a bare rule with its title set into it, so the
            // leading corner is part of the title rather than a box corner.
            "─▶ "
        } else {
            "▼ "
        }
    } else {
        ""
    };
    let count = if id == ViewId::Findings {
        format!(" ({})", app.findings.len())
    } else {
        String::new()
    };
    let source = if id == ViewId::Output {
        app.subagents
            .viewing
            .as_deref()
            .and_then(|agent_id| app.subagents.agent(agent_id))
            .map_or(String::new(), |a| {
                format!(" · {} [{}]", a.info.name, a.info.agent_id)
            })
    } else {
        String::new()
    };
    let focused = app.layout.focus == id;
    let focus = if focused { " *" } else { "" };
    let activity = if id == ViewId::Output && app.worker_active && theme::blink_on() {
        " ●"
    } else {
        ""
    };
    Block::default()
        .borders(if instance.collapsed {
            Borders::TOP
        } else {
            Borders::ALL
        })
        .border_type(if focused {
            BorderType::Thick
        } else {
            BorderType::Plain
        })
        .border_style(if focused {
            if app.worker_active {
                theme::pulse_border(true)
            } else {
                theme::ACTION
            }
        } else {
            theme::BORDER
        })
        .style(Style::default().bg(theme::PANEL))
        .title(Span::styled(
            format!("{marker}{}{count}{source}{focus}{activity}", id.label()),
            Style::default().fg(if focused {
                theme::ACTION
            } else {
                theme::BORDER
            }),
        ))
}

fn render_workbench(frame: &mut Frame, app: &App, geometry: &LayoutGeometry) {
    for region in &geometry.views {
        let id = region.id;
        if app.layout.view(id).collapsed {
            frame.render_widget(view_block(app, id), region.rect);
            continue;
        }
        match id {
            ViewId::Status => {
                frame.render_widget(status::render(app).block(view_block(app, id)), region.rect)
            }
            ViewId::Capabilities => crate::views::capabilities::render(frame, app, region.rect),
            ViewId::Output => crate::ui::transcript::render(frame, app, region.rect),
            ViewId::Findings => crate::ui::findings::render(frame, app, region.rect),
            ViewId::Subagents => crate::ui::subagents::render(frame, app, region.rect),
        }
    }
    if let Some(Gesture::Move {
        id,
        dragging: true,
        target,
        ..
    }) = &app.layout_gesture
    {
        if let Some(target) = target {
            frame.render_widget(
                Block::default()
                    .borders(if app.layout.view(*id).collapsed {
                        Borders::TOP
                    } else {
                        Borders::ALL
                    })
                    .border_type(BorderType::Thick)
                    .border_style(theme::ACTION)
                    .style(Style::default().bg(theme::DOCK_PREVIEW))
                    .title(format!(" {} ", id.label())),
                target.indicator,
            );
        } else if app.layout.can_move_view(*id, ContainerId::Secondary) {
            if let Some(dock) = geometry.secondary_dock {
                frame.render_widget(
                    Block::default()
                        .borders(Borders::RIGHT)
                        .border_style(theme::ACTION),
                    Rect::new(dock.right() - 1, dock.y, 1, dock.height),
                );
            }
        }
    }
}

fn render_composer(frame: &mut Frame, app: &App, area: Rect) {
    frame.render_widget(
        Block::default().style(Style::default().bg(theme::PLATE)),
        area,
    );
    let height = app.required_input_height().min(area.height);
    let area = Rect::new(
        area.x,
        area.bottom().saturating_sub(height),
        area.width,
        height,
    );
    if area.height == 0 {
        return;
    }
    // The mode / guard / model line sits under the composer in every state, so
    // reserve it before laying out whatever sits above.
    let status_height = COMPOSER_STATUS_ROWS.min(area.height);
    let body = Rect::new(
        area.x,
        area.y,
        area.width,
        area.height.saturating_sub(status_height),
    );
    let status = Rect::new(
        area.x,
        area.y.saturating_add(body.height),
        area.width,
        status_height,
    );
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
            body,
        );
        render_composer_status(frame, app, status);
        return;
    }

    if app.palette_visible() {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(PALETTE_ROWS),
                Constraint::Length(COMPOSER_FRAME_ROWS),
            ])
            .split(body);
        render_command_palette(frame, app, rows[0]);
        render_composer_input(frame, app, rows[1]);
    } else {
        render_composer_input(frame, app, body);
    }
    render_composer_status(frame, app, status);
}

/// Mode, execution guard and model — the indicators that used to sit in the
/// header. They live beneath the composer frame now, so the header carries only
/// brand, live worker state and the provider badge.
fn render_composer_status(frame: &mut Frame, app: &App, area: Rect) {
    if area.height == 0 {
        return;
    }
    let background = Style::default().bg(theme::PLATE);
    // A model name is meaningless while no provider is configured.
    let model = match app.config_ready {
        Some(false) => None,
        _ => app.model.as_deref().filter(|model| !model.is_empty()),
    };
    let separator = Style::default().fg(theme::TEXT_HINT);
    let indicators = Line::from(vec![
        Span::styled(
            format!(" {} ", app.mode.label()),
            Style::default()
                .fg(theme::mode_color(app.mode.label()))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("· ", separator),
        Span::styled(
            format!("{} ", app.permission.label()),
            Style::default().fg(theme::permission_color(app.permission.label())),
        ),
    ]);
    let indicators_width = u16::try_from(indicators.width()).unwrap_or(u16::MAX);
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(indicators_width), Constraint::Min(0)])
        .split(area);
    frame.render_widget(Paragraph::new(indicators).style(background), panes[0]);
    let Some(model) = model else {
        return;
    };
    // Right-aligned by the renderer rather than by a width this module
    // computes: the model marker is an ambiguous-width glyph, so measuring it
    // here and rendering it there can disagree by a cell.
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{MODEL_MARKER}{model} "),
            Style::default().fg(theme::TEXT_SOFT),
        )))
        .alignment(Alignment::Right)
        .style(background),
        panes[1],
    );
}

/// Leading prompt marker and its display width, kept together so the cursor
/// offset stays correct if the marker is ever changed.
const PROMPT_MARKER: &str = " > ";

/// Marks the model name on the right of the composer status line.
const MODEL_MARKER: &str = "◈ ";
/// Introduces the "N more" row that closes a list too long for its window.
const MORE_ROWS_HINT: &str = "… ";
const PROMPT_MARKER_WIDTH: u16 = PROMPT_MARKER.len() as u16;

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
    // Rules above and below the prompt separate it from the transcript above and
    // the mode/guard line below; the marker, text and cursor share one row.
    let block = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
        .border_style(Style::default().fg(theme::BORDER))
        .style(Style::default().bg(theme::PLATE));
    let inner = block.inner(composer_area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                PROMPT_MARKER,
                Style::default()
                    .fg(theme::ACTION)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(content, style),
        ]))
        .block(block),
        composer_area,
    );
    if app.input.is_empty() || inner.height == 0 || inner.width == 0 {
        return;
    }
    // ratatui holds a single cursor per frame; the settings modal draws after
    // the composer and owns it while it is open.
    if app.llm_settings.is_some() {
        return;
    }
    let cursor_x = inner
        .x
        .saturating_add(PROMPT_MARKER_WIDTH)
        .saturating_add(input_cursor_offset(&app.input, app.input_cursor))
        .min(inner.right().saturating_sub(1));
    frame.set_cursor_position((cursor_x, inner.y));
}

/// Distance in display cells from the start of the prompt text to the cursor.
///
/// Measured in cells rather than characters: a CJK glyph occupies two columns,
/// so counting characters leaves the caret trailing behind the text it follows.
fn input_cursor_offset(input: &str, cursor: usize) -> u16 {
    let cells = input
        .get(..cursor)
        .map(|prefix| Line::from(prefix).width())
        .unwrap_or_default();
    u16::try_from(cells).unwrap_or(u16::MAX)
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
                    .fg(theme::BG)
                    .bg(theme::ACTION)
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
    let (text, style) = if let Some(Gesture::Move {
        id,
        dragging: true,
        target,
        ..
    }) = &app.layout_gesture
    {
        let text = if !app.layout.can_move_view(*id, ContainerId::Secondary) {
            " Primary sidebar must keep one view | Esc cancel"
        } else if app.layout.secondary.is_empty() {
            if target.is_some_and(|target| target.container == ContainerId::Secondary) {
                " Release to open secondary sidebar | Esc cancel"
            } else if app.terminal_size.width
                < crate::workbench::SIDE_MIN * 2 + crate::workbench::OUTPUT_MIN
            {
                " Not enough width to open secondary sidebar | Esc cancel"
            } else {
                " Drag to right edge to open secondary sidebar | Esc cancel"
            }
        } else {
            " Drag title to move view | Release to dock | Esc cancel"
        };
        (text, Style::default().fg(theme::ACTION))
    } else if !app.toast.is_empty() {
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
    } else if app.layout.focus == ViewId::Subagents {
        (
            " ↑/↓ select agent | Enter view transcript | main returns to main | Ctrl+←/→ view",
            Style::default().fg(theme::TEXT_HINT),
        )
    } else if app.worker_active {
        (
            " Running — Ctrl+C abort | Tab mode | ↑/↓ scroll | Ctrl+Y copy view",
            Style::default().fg(theme::TEXT_HINT),
        )
    } else {
        (
            " Tab mode | Shift+Tab safeguard | Ctrl+P/N history | Ctrl+←/→ view | ↑/↓ scroll | Ctrl+T thinking | F5 chain | Ctrl+S save | Ctrl+R restore | Ctrl+Y copy view | Ctrl+C exit",
            Style::default().fg(theme::TEXT_HINT),
        )
    };
    frame.render_widget(
        Paragraph::new(Span::styled(text, style)).style(Style::default().bg(theme::CHROME)),
        area,
    );
}
