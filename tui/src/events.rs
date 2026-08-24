use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::App;

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
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.resolve_pending_execution(true),
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                app.resolve_pending_execution(false)
            }
            _ => {}
        }
        return;
    }

    if app.pending_task.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_task(),
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => app.dismiss_task(),
            _ => {}
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
        (KeyCode::Char('y'), KeyModifiers::CONTROL) => app.copy_active_pane(),
        (KeyCode::Left, modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            app.cycle_active_pane(true)
        }
        (KeyCode::Right, modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            app.cycle_active_pane(false)
        }
        (KeyCode::F(5), _) => app.show_attack_chain = !app.show_attack_chain,
        (KeyCode::Tab, _) => app.cycle_mode(),
        (KeyCode::BackTab, _) => app.cycle_permission(),
        (KeyCode::Up, _) if app.palette_visible() => app.select_next_command(false),
        (KeyCode::Down, _) if app.palette_visible() => app.select_next_command(true),
        (KeyCode::Up, _) => app.scroll_active_pane(false),
        (KeyCode::Down, _) => app.scroll_active_pane(true),
        // Keyboard page scrolling — compensates for disabling mouse capture
        // (which we turned off so users can select/copy text from the terminal).
        (KeyCode::PageUp, _) => app.scroll_active_pane(false),
        (KeyCode::PageDown, _) => app.scroll_active_pane(true),
        (KeyCode::Esc, _) => app.clear_composer(),
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
