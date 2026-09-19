use crate::workbench::{self, Gesture, ViewId};
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Position;

use crate::app::{App, LlmSettings};

pub fn handle_key(app: &mut App, key: KeyEvent) {
    // crossterm emits a Press and a Release (and sometimes Repeat) event for a
    // single physical keypress. Only act on Press, otherwise every character is
    // handled twice. Mirrors CodeWhale's `if key.kind != KeyEventKind::Press`.
    if key.kind != KeyEventKind::Press {
        return;
    }

    // A transient toast (e.g. "Copied …") lives until the next key press.
    app.toast.clear();

    // Execution approval modal is safety-critical and swallows every key:
    // Y approves, N/Esc denies (default deny), anything else is ignored so
    // injected content can never smuggle keystrokes into the composer.
    if app.pending_execution.is_some() {
        app.cancel_layout_gesture();
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.resolve_pending_execution(true),
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                app.resolve_pending_execution(false)
            }
            KeyCode::Up => app.scroll_pending_execution(false, false),
            KeyCode::Down => app.scroll_pending_execution(true, false),
            KeyCode::PageUp => app.scroll_pending_execution(false, true),
            KeyCode::PageDown => app.scroll_pending_execution(true, true),
            _ => {}
        }
        return;
    }

    if app.pending_task.is_some() {
        app.cancel_layout_gesture();
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_task(),
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => app.dismiss_task(),
            _ => {}
        }
        return;
    }

    // The LLM settings screen is a blocking overlay: it owns every key while
    // open, so its bindings below are deliberately self-contained.
    if app.llm_settings.is_some() {
        app.cancel_layout_gesture();
        handle_llm_settings_key(app, key);
        return;
    }

    if app.layout_gesture.is_some() {
        // Esc abandons a captured pointer gesture; any other key completes it
        // before applying the keyboard action.
        app.cancel_layout_gesture();
        if key.code == KeyCode::Esc {
            return;
        }
    }
    if app.show_attack_chain {
        match (key.code, key.modifiers) {
            (KeyCode::F(5) | KeyCode::Esc, _) => app.show_attack_chain = false,
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                if app.worker_active {
                    app.stop_worker();
                } else {
                    app.running = false;
                }
            }
            _ => {}
        }
        return;
    }
    if app.geometry(app.terminal_size).too_small && app.terminal_size.width != 0 {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            if app.worker_active {
                app.stop_worker();
            } else {
                app.running = false;
            }
        }
        return;
    }

    match (key.code, key.modifiers) {
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            if app.worker_active {
                app.stop_worker();
            } else {
                app.running = false;
            }
        }
        (KeyCode::Char('s'), KeyModifiers::CONTROL) => app.save_session(),
        (KeyCode::Char('r'), KeyModifiers::CONTROL) => app.restore_session(),
        (KeyCode::Char('t'), KeyModifiers::CONTROL) => app.show_reasoning = !app.show_reasoning,
        (KeyCode::Char('p'), KeyModifiers::CONTROL) => app.recall_history(true),
        (KeyCode::Char('n'), KeyModifiers::CONTROL) => app.recall_history(false),
        (KeyCode::Char('y'), KeyModifiers::CONTROL) => app.copy_active_view(),
        (KeyCode::Left, modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            app.cycle_active_view(true)
        }
        (KeyCode::Right, modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            app.cycle_active_view(false)
        }
        (KeyCode::F(5), _) => app.show_attack_chain = !app.show_attack_chain,
        (KeyCode::Tab, _) => app.cycle_mode(),
        (KeyCode::BackTab, _) => app.cycle_permission(),
        (KeyCode::Up, _) if app.layout.focus == ViewId::Subagents => {
            app.move_subagent_selection(false)
        }
        (KeyCode::Down, _) if app.layout.focus == ViewId::Subagents => {
            app.move_subagent_selection(true)
        }
        (KeyCode::Enter, _) if app.layout.focus == ViewId::Subagents => {
            app.open_selected_subagent()
        }
        (KeyCode::Up, _) if app.palette_visible() => app.select_next_command(false),
        (KeyCode::Down, _) if app.palette_visible() => app.select_next_command(true),
        // The Findings view owns the arrow keys while it is focused: they move
        // the row selection and the view follows, instead of scrolling raw.
        (KeyCode::Up, _) if app.layout.focus == workbench::ViewId::Findings => {
            app.move_findings_selection(false);
            app.reveal_selected_finding();
        }
        (KeyCode::Down, _) if app.layout.focus == workbench::ViewId::Findings => {
            app.move_findings_selection(true);
            app.reveal_selected_finding();
        }
        (KeyCode::Up, _) => app.scroll_active_view(false),
        (KeyCode::Down, _) => app.scroll_active_view(true),
        (KeyCode::PageUp, _) => app.scroll_active_view(false),
        (KeyCode::PageDown, _) => app.scroll_active_view(true),
        (KeyCode::Esc, _) => app.clear_composer(),
        (KeyCode::Enter, _)
            if app.layout.focus == workbench::ViewId::Findings && app.input.is_empty() =>
        {
            app.toggle_selected_finding();
        }
        (KeyCode::Enter, _) if app.palette_visible() && app.should_complete_selected_command() => {
            app.accept_selected_command();
        }
        (KeyCode::Enter, _) => app.submit(),
        (KeyCode::Backspace, _) => app.delete_input(),
        (KeyCode::Delete, _) => app.delete_forward_input(),
        (KeyCode::Left, _) => app.move_input_cursor(false),
        (KeyCode::Right, _) => app.move_input_cursor(true),
        (KeyCode::Home, _) => app.move_input_cursor_to_edge(false),
        (KeyCode::End, _) => app.move_input_cursor_to_edge(true),
        (KeyCode::Char(character), modifiers) if !modifiers.contains(KeyModifiers::CONTROL) => {
            app.append_input(character)
        }
        _ => {}
    }
}

/// Bindings for the open LLM settings screen.
///
/// The screen swallows every key, so this must cover closing, saving, moving
/// between rows, and editing text — nothing falls through to the composer.
fn handle_llm_settings_key(app: &mut App, key: KeyEvent) {
    let (list_open, editing) = app
        .llm_settings
        .as_ref()
        .map_or((false, false), |settings| {
            (settings.template_list_open, settings.editing)
        });
    match (key.code, key.modifiers) {
        // Esc unwinds one level at a time: the template list, then the open
        // row, and only then the screen itself.
        (KeyCode::Esc, _) => {
            if list_open {
                app.close_llm_template_list();
            } else if editing {
                app.cancel_llm_edit();
            } else {
                app.close_llm_settings();
            }
        }
        (KeyCode::Char('s'), KeyModifiers::CONTROL) => app.save_llm_settings(),
        // Enter is the confirmation both ways: it opens the focused row, and a
        // second press closes it.
        (KeyCode::Enter, _) => {
            if list_open {
                app.commit_llm_template_list();
            } else if editing {
                app.commit_llm_edit();
            } else {
                app.begin_llm_edit();
            }
        }
        // While a row is open these walk its suggestions, never the rows, so an
        // unconfirmed edit cannot be abandoned by moving away.
        (KeyCode::Up, _) => {
            if list_open {
                app.move_llm_template_list(false);
            } else if editing {
                app.move_llm_suggestion(false);
            } else {
                app.move_llm_focus(false);
            }
        }
        (KeyCode::Down, _) => {
            if list_open {
                app.move_llm_template_list(true);
            } else if editing {
                app.move_llm_suggestion(true);
            } else {
                app.move_llm_focus(true);
            }
        }
        (KeyCode::Tab, _) if !list_open && !editing => app.move_llm_focus(true),
        (KeyCode::BackTab, _) if !list_open && !editing => app.move_llm_focus(false),
        (KeyCode::Backspace, _) if editing => edit_llm_settings(app, |s| s.delete_backward()),
        (KeyCode::Delete, _) if editing => edit_llm_settings(app, |s| s.delete_forward()),
        (KeyCode::Left, _) if editing => edit_llm_settings(app, |s| s.move_cursor(false)),
        (KeyCode::Right, _) if editing => edit_llm_settings(app, |s| s.move_cursor(true)),
        (KeyCode::Home, _) if editing => edit_llm_settings(app, |s| s.move_cursor_to_edge(false)),
        (KeyCode::End, _) if editing => edit_llm_settings(app, |s| s.move_cursor_to_edge(true)),
        (KeyCode::Char(character), modifiers)
            if editing && !modifiers.contains(KeyModifiers::CONTROL) =>
        {
            edit_llm_settings(app, |s| s.insert_char(character));
        }
        _ => {}
    }
}

/// Apply *edit* to the open settings screen; a no-op when it is closed.
fn edit_llm_settings(app: &mut App, edit: impl FnOnce(&mut LlmSettings)) {
    if let Some(settings) = app.llm_settings.as_mut() {
        edit(settings);
    }
}

pub fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    let point = Position::new(mouse.column, mouse.row);
    if app.pending_execution.is_some() {
        app.cancel_layout_gesture();
        if crate::ui::layout::approval_body_area(app.terminal_size).contains(point) {
            match mouse.kind {
                MouseEventKind::ScrollUp => app.scroll_pending_execution(false, false),
                MouseEventKind::ScrollDown => app.scroll_pending_execution(true, false),
                _ => {}
            }
        }
        return;
    }
    if app.pending_task.is_some() || app.show_attack_chain || app.llm_settings.is_some() {
        app.cancel_layout_gesture();
        return;
    }
    if matches!(mouse.kind, MouseEventKind::Down(_)) {
        app.cancel_layout_gesture();
    }
    let geometry = app.geometry(app.terminal_size);
    if geometry.too_small {
        app.cancel_layout_gesture();
        return;
    }
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(sash) = geometry
                .sashes
                .iter()
                .find(|sash| sash.enabled && sash.rect.contains(point))
            {
                app.layout_gesture = Some(Gesture::Resize {
                    sash: sash.id,
                    origin: point,
                    original: Box::new(app.layout.clone()),
                    geometry: Box::new(geometry.clone()),
                });
                return;
            }
            if let Some(region) = geometry.views.iter().find(|view| view.rect.contains(point)) {
                app.layout.focus = region.id;
                if region.id == workbench::ViewId::Findings && region.content.contains(point) {
                    let scroll = usize::from(app.layout.view(region.id).scroll);
                    let row = usize::from(point.y.saturating_sub(region.content.y)) + scroll;
                    if let Some(index) = crate::ui::findings::finding_at_row(app, row) {
                        app.select_finding(index);
                        app.toggle_selected_finding();
                        return;
                    }
                }
                if region.id.movable() && region.title.contains(point) {
                    if point.x == region.title.x + 1 {
                        app.layout.toggle_collapsed(region.id, &geometry);
                        app.save_layout();
                    } else {
                        app.layout_gesture = Some(Gesture::Move {
                            id: region.id,
                            origin: point,
                            dragging: false,
                            target: None,
                        });
                    }
                }
            }
        }
        MouseEventKind::Drag(MouseButton::Left) | MouseEventKind::Up(MouseButton::Left) => {
            let release = mouse.kind == MouseEventKind::Up(MouseButton::Left);
            let Some(mut gesture) = app.layout_gesture.take() else {
                return;
            };
            if let Gesture::Resize { sash, origin, .. } = &gesture {
                let unchanged = match sash {
                    workbench::SashId::Primary | workbench::SashId::Secondary => {
                        point.x == origin.x
                    }
                    _ => point.y == origin.y,
                };
                if unchanged {
                    app.restore_layout(&gesture);
                    if !release {
                        app.layout_gesture = Some(gesture);
                    }
                    return;
                }
            }
            match &mut gesture {
                Gesture::Move {
                    id,
                    origin,
                    dragging,
                    target,
                } => {
                    *dragging |= point != *origin;
                    *target = if *dragging {
                        (*target)
                            .filter(|target| {
                                (release
                                    || (target.container == workbench::ContainerId::Secondary
                                        && app.layout.secondary.is_empty()))
                                    && target.indicator.contains(point)
                            })
                            .or_else(|| geometry.drop_target(point))
                            .filter(|target| app.layout.can_move_view(*id, target.container))
                            .and_then(|mut target| {
                                let mut preview = app.layout.clone();
                                preview.move_view(*id, target, &geometry);
                                let preview = workbench::LayoutGeometry::compute(
                                    app.terminal_size,
                                    &preview,
                                    app.required_input_height(),
                                );
                                target.indicator = preview.view(*id)?.rect;
                                Some(target)
                            })
                    } else {
                        None
                    };
                    if release && *dragging {
                        if let Some(target) = target {
                            if app.layout.move_view(*id, *target, &geometry) {
                                app.save_layout();
                            }
                        }
                    }
                }
                Gesture::Resize {
                    sash,
                    origin,
                    original,
                    geometry: start_geometry,
                } => {
                    workbench::resize(
                        &mut app.layout,
                        start_geometry,
                        *sash,
                        i32::from(point.x) - i32::from(origin.x),
                        i32::from(point.y) - i32::from(origin.y),
                    );
                    if release {
                        let before =
                            serde_json::to_value(original.as_ref()).expect("layout serializes");
                        let after = serde_json::to_value(&app.layout).expect("layout serializes");
                        if before != after {
                            app.save_layout();
                        }
                    }
                }
            }
            if !release {
                app.layout_gesture = Some(gesture);
            }
        }
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown if app.layout_gesture.is_none() => {
            if let Some(region) = geometry
                .views
                .iter()
                .find(|view| view.content.contains(point))
            {
                app.scroll_view(region.id, mouse.kind == MouseEventKind::ScrollDown);
            }
        }
        _ => {}
    }
}

pub fn handle_paste(app: &mut App, text: &str) {
    app.cancel_layout_gesture();
    if app.pending_execution.is_some() || app.pending_task.is_some() || app.show_attack_chain {
        return;
    }
    // A paste into the settings screen belongs to its focused row; letting it
    // through to the composer would type a credential into the wrong place.
    if app.llm_settings.is_some() {
        edit_llm_settings(app, |settings| settings.insert_text(text));
        return;
    }
    if !app.geometry(app.terminal_size).too_small {
        app.insert_text(text);
    }
}
