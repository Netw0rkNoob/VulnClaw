use std::sync::mpsc;
use std::time::Instant;

use ratatui::{backend::TestBackend, Terminal};

use vulnclaw_tui::{
    app::{App, PendingExecution},
    ui::layout::render,
};

fn pending_execution(command: String) -> PendingExecution {
    PendingExecution {
        request_hash: "a".repeat(64),
        kind: "shell".into(),
        command,
        cwd: "/tmp".into(),
        detail: "operator review required".into(),
        expires_at: String::new(),
        expires_in_secs: 300,
        received_at: Instant::now(),
        risk: "not sandboxed".into(),
        scroll_offset: 0,
    }
}

fn rendered_text(terminal: &Terminal<TestBackend>) -> String {
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>()
}

#[test]
fn renders_a_composer_centered_security_workbench() {
    let (sender, _) = mpsc::channel();
    let app = App::new_disconnected(sender);
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Session transcript"));
    assert!(rendered.contains("Findings inspector (0)"));
    assert!(rendered.contains("Status"));
    assert!(rendered.contains("Subagents"));
    assert!(rendered.contains("Type / for commands"));
    assert!(rendered.contains("Tab mode"));
    assert!(rendered.contains("ready"));
    assert!(!rendered.contains("[Skills] [Findings] [Output]"));
}

#[test]
fn collapsed_secondary_previews_docking_until_release_and_escape_cancels() {
    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use ratatui::layout::Rect;
    use vulnclaw_tui::{
        events::{handle_key, handle_mouse},
        workbench::{ContainerId, Gesture, ViewId},
    };
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = Rect::new(0, 0, 120, 30);
    app.layout.primary.append(&mut app.layout.secondary);
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
    let geometry = app.geometry(app.terminal_size);
    let title = geometry.view(ViewId::Findings).unwrap().title;
    let send = |app: &mut App, kind, column, row| {
        handle_mouse(
            app,
            MouseEvent {
                kind,
                column,
                row,
                modifiers: KeyModifiers::NONE,
            },
        )
    };
    send(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        title.x + 3,
        title.y,
    );
    send(&mut app, MouseEventKind::Drag(MouseButton::Left), 60, 10);
    terminal.draw(|frame| render(frame, &app)).unwrap();
    assert!(rendered_text(&terminal).contains("Drag to right edge"));
    send(&mut app, MouseEventKind::Drag(MouseButton::Left), 119, 10);
    let Some(Gesture::Move {
        target: Some(target),
        ..
    }) = app.layout_gesture
    else {
        panic!("edge must offer a docking preview");
    };
    assert_eq!(target.container, ContainerId::Secondary);
    assert!(app.layout.secondary.is_empty());
    assert_eq!(
        app.geometry(app.terminal_size)
            .container(ContainerId::Center),
        geometry.container(ContainerId::Center)
    );
    terminal.draw(|frame| render(frame, &app)).unwrap();
    assert_eq!(
        terminal.backend().buffer()[(target.indicator.x + 1, target.indicator.y + 1)].bg,
        vulnclaw_tui::theme::DOCK_PREVIEW
    );
    // The visible preview remains a drop target when the pointer moves off the edge.
    send(
        &mut app,
        MouseEventKind::Drag(MouseButton::Left),
        target.indicator.x + 2,
        10,
    );
    assert!(matches!(
        app.layout_gesture,
        Some(Gesture::Move {
            target: Some(_),
            ..
        })
    ));
    handle_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.layout.secondary.is_empty());
    assert!(app.layout_gesture.is_none());
    assert_eq!(
        app.geometry(app.terminal_size)
            .container(ContainerId::Center),
        geometry.container(ContainerId::Center)
    );
    send(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        title.x + 3,
        title.y,
    );
    send(&mut app, MouseEventKind::Drag(MouseButton::Left), 119, 10);
    send(
        &mut app,
        MouseEventKind::Up(MouseButton::Left),
        target.indicator.x + 2,
        10,
    );
    assert_eq!(app.layout.secondary[0].id, ViewId::Findings);
    assert_eq!(app.layout.focus, ViewId::Findings);
    assert_eq!(
        app.geometry(app.terminal_size)
            .container(ContainerId::Secondary),
        target.indicator
    );
}

#[test]
fn module_drag_previews_match_cross_sidebar_and_reordered_placements() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::layout::Rect;
    use vulnclaw_tui::{
        events::handle_mouse,
        theme,
        workbench::{ContainerId, Gesture, ViewId},
    };

    for (id, destination, at_top, collapsed) in [
        (ViewId::Status, ContainerId::Secondary, false, false),
        (ViewId::Findings, ContainerId::Primary, false, false),
        (ViewId::Capabilities, ContainerId::Primary, true, false),
        (ViewId::Findings, ContainerId::Secondary, false, false),
        (ViewId::Findings, ContainerId::Primary, true, true),
    ] {
        let (sender, _) = mpsc::channel();
        let mut app = App::new_disconnected(sender);
        app.terminal_size = Rect::new(0, 0, 120, 30);
        app.layout.view_mut(id).collapsed = collapsed;
        app.layout.view_mut(id).scroll = 7;
        let original = serde_json::to_value(&app.layout).unwrap();
        let geometry = app.geometry(app.terminal_size);
        let title = geometry.view(id).unwrap().title;
        let container = geometry.container(destination);
        let send = |app: &mut App, kind, column, row| {
            handle_mouse(
                app,
                MouseEvent {
                    kind,
                    column,
                    row,
                    modifiers: KeyModifiers::NONE,
                },
            );
        };
        send(
            &mut app,
            MouseEventKind::Down(MouseButton::Left),
            title.x + 3,
            title.y,
        );
        let top = container.y;
        let bottom = container.bottom() - 1;
        send(
            &mut app,
            MouseEventKind::Drag(MouseButton::Left),
            container.x + 4,
            if at_top { bottom } else { top },
        );
        let Some(Gesture::Move {
            target: Some(first),
            ..
        }) = app.layout_gesture
        else {
            panic!("initial destination must offer a preview");
        };
        send(
            &mut app,
            MouseEventKind::Drag(MouseButton::Left),
            container.x + 4,
            if at_top { top } else { bottom },
        );
        let Some(Gesture::Move {
            target: Some(target),
            ..
        }) = app.layout_gesture
        else {
            panic!("destination must offer a preview");
        };
        assert_eq!(target.container, destination);
        assert_ne!(
            first.index, target.index,
            "drag must allow changing insertion position"
        );
        assert_eq!(serde_json::to_value(&app.layout).unwrap(), original);
        assert_eq!(target.indicator.height == 1, collapsed);
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        let gesture = app.layout_gesture.take();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let underneath = terminal.backend().buffer().clone();
        app.layout_gesture = gesture;
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let border_x = if collapsed {
            target.indicator.right() - 1
        } else {
            target.indicator.x
        };
        let corner = &terminal.backend().buffer()[(border_x, target.indicator.y)];
        assert_eq!(corner.fg, theme::ACTION);
        assert_eq!(corner.bg, theme::DOCK_PREVIEW);
        assert_eq!(corner.symbol(), if collapsed { "━" } else { "┏" });
        for y in target.indicator.y + 1..target.indicator.bottom().saturating_sub(1) {
            for x in target.indicator.x + 1..target.indicator.right() - 1 {
                let cell = &terminal.backend().buffer()[(x, y)];
                assert_eq!(cell.symbol(), underneath[(x, y)].symbol());
                assert_eq!(cell.fg, underneath[(x, y)].fg);
                assert_eq!(cell.bg, theme::DOCK_PREVIEW);
            }
        }
        // Releasing inside the displayed preview commits that placement.
        send(
            &mut app,
            MouseEventKind::Up(MouseButton::Left),
            target.indicator.x + 3,
            target.indicator.bottom() - 1,
        );
        assert!(app.layout_gesture.is_none());
        assert_eq!(app.layout.focus, id);
        let views = app.layout.views(destination);
        assert_eq!(
            if at_top { views.first() } else { views.last() }
                .unwrap()
                .id,
            id
        );
        assert_eq!(app.layout.view(id).scroll, 7);
        assert_eq!(app.layout.view(id).collapsed, collapsed);
        assert_eq!(
            app.geometry(app.terminal_size).view(id).unwrap().rect,
            target.indicator
        );
    }
}

fn app_with_provider(provider: Option<&str>, model: Option<&str>, config_ready: bool) -> App {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.config_ready = Some(config_ready);
    app.provider = provider.map(str::to_owned);
    app.model = model.map(str::to_owned);
    app
}

fn row_text(terminal: &Terminal<TestBackend>, y: u16) -> String {
    let buffer = terminal.backend().buffer();
    (0..buffer.area.width)
        .map(|x| buffer[(x, y)].symbol())
        .collect()
}

#[test]
fn header_boxes_the_brand_and_provider_without_duplicating_the_status_view() {
    let app = app_with_provider(Some("DeepSeek"), Some("deepseek-chat"), true);
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    // Rows 0 and 2 are the header box; the content sits on row 1.
    assert!(row_text(&terminal, 0).starts_with('┌'));
    assert!(row_text(&terminal, 2).starts_with('└'));
    let header = row_text(&terminal, 1);
    assert!(header.contains("VulnClaw"));
    assert!(header.contains("provider: DeepSeek"));
    // Nothing here repeats the composer status line or the Status view.
    assert!(
        !header.contains("Agent"),
        "mode lives on the composer status line"
    );
    assert!(
        !header.contains("Ask"),
        "guard lives on the composer status line"
    );
    assert!(
        !header.contains("idle"),
        "worker state lives in the Status view"
    );
    assert!(
        !header.contains("deepseek-chat"),
        "the model is not shown here"
    );
}

#[test]
fn composer_is_framed_and_followed_by_the_mode_guard_model_line() {
    let app = app_with_provider(Some("DeepSeek"), Some("deepseek-chat"), true);
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let buffer = terminal.backend().buffer();
    let input_row = (1..buffer.area.height)
        .find(|&y| row_text(&terminal, y).contains("Type / for commands"))
        .expect("composer placeholder must render");

    assert!(
        row_text(&terminal, input_row - 1).contains('─'),
        "the input must be framed above"
    );
    assert!(
        row_text(&terminal, input_row + 1).contains('─'),
        "the input must be framed below"
    );
    let status = row_text(&terminal, input_row + 2);
    assert!(status.contains("Agent"), "mode belongs under the frame");
    assert!(status.contains("Ask"), "guard belongs under the frame");
    // The marker is an ambiguous-width glyph, so the rendered row may pad it by
    // a cell; assert on order rather than on an exact adjacency.
    let marker = status.find('◈').expect("the model marker must render");
    let name = status.find("deepseek-chat").expect("the model must render");
    assert!(marker < name, "the marker precedes the model name");
    assert!(
        status.trim_end().ends_with("deepseek-chat"),
        "the model is right-aligned"
    );
}

#[test]
fn header_badge_falls_back_to_a_placeholder_without_credentials() {
    let app = app_with_provider(Some("DeepSeek"), Some("deepseek-chat"), false);
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = rendered_text(&terminal);
    assert!(rendered.contains("provider: not configured"));
    assert!(!rendered.contains("deepseek-chat"));
}

#[test]
fn header_badge_is_absent_before_the_backend_reports() {
    let app = app_with_provider(None, None, true);
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = rendered_text(&terminal);
    assert!(!rendered.contains("provider:"));
    assert!(rendered.contains("VulnClaw"));
}

#[test]
fn header_drops_the_badge_before_truncating_the_left_cluster() {
    let app = app_with_provider(Some("DeepSeek"), Some("deepseek-chat"), true);
    // Wide enough for the left cluster plus the badge minimum, but not both.
    let mut terminal = Terminal::new(TestBackend::new(40, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = rendered_text(&terminal);
    assert!(!rendered.contains("provider:"));
    assert!(rendered.contains("VulnClaw"));
}

#[test]
fn approval_modal_stays_inside_a_small_terminal() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.pending_execution = Some(pending_execution("whoami".into()));
    for (width, height) in [(1, 1), (10, 3), (30, 8)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        if width == 30 {
            let rendered = rendered_text(&terminal);
            assert!(rendered.contains("[Y]"));
            assert!(rendered.contains("[N/Esc]"));
        }
    }
}

#[test]
fn approval_modal_scrolls_full_code_with_fixed_footer() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.terminal_size = ratatui::layout::Rect::new(0, 0, 60, 18);
    let mut rows = vec!["FIRST-LINE".to_string()];
    rows.extend((1..29).map(|index| format!("middle-{index:02}")));
    rows.push("LAST-LINE".to_string());
    app.pending_execution = Some(pending_execution(rows.join("\n")));
    let mut terminal = Terminal::new(TestBackend::new(60, 18)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();
    let first = rendered_text(&terminal);
    assert!(first.contains("FIRST-LINE"));
    assert!(!first.contains("LAST-LINE"));
    assert!(first.contains("[Y]"));

    for _ in 0..10 {
        app.scroll_pending_execution(true, true);
    }
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let last = rendered_text(&terminal);
    assert!(last.contains("LAST-LINE"));
    assert!(last.contains("[Y]"));
    assert!(last.contains("[N/Esc]"));
}

#[test]
fn slash_input_renders_the_command_palette() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.backend_commands = vec!["scan".into()];
    app.insert_text("/");
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Commands"));
    assert!(rendered.contains("/scan "));
}

#[test]
fn composer_cursor_advances_by_display_cells_not_characters() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    app.insert_text("ab");
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let ascii = terminal.get_cursor_position().unwrap();

    // A CJK glyph is one character but two terminal cells. Counting characters
    // would advance the caret by one and leave it trailing the text.
    app.insert_text("中");
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let wide = terminal.get_cursor_position().unwrap();
    assert_eq!(
        wide.x - ascii.x,
        2,
        "one CJK glyph must advance the caret by two cells"
    );

    app.insert_text("文");
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let wider = terminal.get_cursor_position().unwrap();
    assert_eq!(wider.x - ascii.x, 4, "two CJK glyphs advance four cells");
}

#[test]
fn composer_placeholder_renders_on_a_single_row() {
    let (sender, _) = mpsc::channel();
    let app = App::new_disconnected(sender); // empty input -> placeholder path
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let buf = terminal.backend().buffer();
    let mut rows_with_placeholder = 0;
    for y in 0..24u16 {
        let line: String = (0..80u16)
            .map(|x| {
                buf.cell((x, y))
                    .map(|c| c.symbol().to_string())
                    .unwrap_or_default()
            })
            .collect();
        if line.contains("Type / for commands") {
            rows_with_placeholder += 1;
        }
    }
    assert_eq!(
        rows_with_placeholder, 1,
        "the composer placeholder must render on exactly one row"
    );
}

#[test]
fn task_confirmation_replaces_the_composer() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.pending_task = Some("/run target.test".into());
    let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("Task confirmation required"));
    assert!(rendered.contains("Y confirm"));
}

#[test]
fn a_collapsed_view_renders_as_a_rule_with_its_title_set_in() {
    use ratatui::layout::Rect;
    use vulnclaw_tui::workbench::ViewId;

    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.layout.view_mut(ViewId::Findings).collapsed = true;
    let area = Rect::new(0, 0, 120, 24);
    let rect = app.geometry(area).view(ViewId::Findings).unwrap().rect;
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let row = row_text(&terminal, rect.y);
    let cell: String = row
        .chars()
        .skip(usize::from(rect.x))
        .take(usize::from(rect.width))
        .collect();
    assert!(cell.starts_with("─▶ Findings inspector"), "got {cell:?}");
    // A collapsed view is a bare rule: no box corners and no side rails.
    assert!(!cell.contains('┌'), "got {cell:?}");
    assert!(!cell.contains('┐'), "got {cell:?}");
    assert!(!cell.contains('│'), "got {cell:?}");
}

#[test]
fn header_centres_the_live_cluster_between_brand_and_badge() {
    let mut app = app_with_provider(Some("DeepSeek"), Some("deepseek-chat"), true);
    app.worker_active = true;
    app.worker_started_at = Some(Instant::now());
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();

    terminal.draw(|frame| render(frame, &app)).unwrap();

    let header = row_text(&terminal, 1);
    assert!(header.contains("running"), "got {header:?}");
    assert!(header.contains('⏱'), "the elapsed readout must be back");

    // Centred in the gap between the brand and the badge.
    let brand_end = header.find("VulnClaw").expect("brand") + "VulnClaw".len();
    let badge_start = header.find("provider:").expect("badge");
    let cluster_start = header.find("running").expect("cluster");
    let cluster_end = header.find("00:").expect("elapsed") + 5;
    let cluster_mid = (cluster_start + cluster_end) / 2;
    let gap_mid = (brand_end + badge_start) / 2;
    assert!(
        cluster_mid.abs_diff(gap_mid) <= 4,
        "cluster mid {cluster_mid} should sit near {gap_mid}: {header:?}"
    );

    // An idle header carries no cluster and no idle placeholder.
    app.worker_active = false;
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let idle = row_text(&terminal, 1);
    assert!(!idle.contains("running"), "got {idle:?}");
    assert!(!idle.contains("idle"), "got {idle:?}");
    assert!(idle.contains("VulnClaw"));
    assert!(idle.contains("provider: DeepSeek"));
}

fn settings_screen() -> vulnclaw_tui::app::LlmSettings {
    use vulnclaw_tui::app::{LlmField, LlmSettings, ProviderEntry};

    LlmSettings {
        provider: "deepseek".into(),
        website_url: "https://www.deepseek.com/".into(),
        base_url: "https://api.deepseek.com".into(),
        api_key: String::new(),
        api_key_set: true,
        model: "deepseek-v4-pro".into(),
        providers: vec![
            ProviderEntry {
                id: "deepseek".into(),
                label: "DeepSeek".into(),
                website_url: "https://www.deepseek.com/".into(),
                base_url: "https://api.deepseek.com".into(),
                default_model: "deepseek-v4-pro".into(),
            },
            ProviderEntry {
                id: "custom".into(),
                label: "自定义".into(),
                website_url: String::new(),
                base_url: String::new(),
                default_model: String::new(),
            },
        ],
        focus: LlmField::Provider,
        ..LlmSettings::default()
    }
}

#[test]
fn settings_modal_renders_every_row_and_never_leaks_the_api_key() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.llm_settings = Some(settings_screen());
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = rendered_text(&terminal);
    for label in [
        "Template",
        "Website URL",
        "API request URL",
        "API key",
        "Model",
    ] {
        assert!(rendered.contains(label), "missing row: {label}");
    }
    assert!(rendered.contains("https://api.deepseek.com"));
    assert!(rendered.contains("deepseek-v4-pro"));
    // A stored key is shown as presence only — the value never reaches the UI.
    assert!(rendered.contains("(saved)"));
    // Idle hints advertise the confirm step, not a fetch shortcut.
    assert!(rendered.contains("Enter edit"));
}

#[test]
fn settings_modal_shows_the_open_template_list_under_its_row() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    let mut settings = settings_screen();
    settings.template_list_open = true;
    app.llm_settings = Some(settings);

    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = rendered_text(&terminal);
    assert!(rendered.contains("▾"));
    // Both templates are offered under the focused row.
    assert!(rendered.contains("DeepSeek"));
    // The CJK label is measured in cells, so TestBackend pads its second
    // column; match the glyph rather than the contiguous string.
    assert!(rendered.contains('自'));
    assert!(rendered.contains("choose template"));
}

#[test]
fn settings_modal_suggests_models_while_the_model_row_is_open() {
    use vulnclaw_tui::app::LlmField;

    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    let mut settings = settings_screen();
    settings.focus_field(LlmField::Model);
    settings.begin_edit();
    settings.models = vec![
        "deepseek-chat".into(),
        "deepseek-v4-pro".into(),
        "unrelated-model".into(),
    ];
    settings.model = "deepseek".into();
    settings.move_cursor_to_edge(true);
    app.llm_settings = Some(settings);

    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = rendered_text(&terminal);
    // The open row is marked, and only the matching models are suggested.
    assert!(rendered.contains('✎'));
    assert!(rendered.contains("deepseek-chat"));
    assert!(!rendered.contains("unrelated-model"));
    assert!(rendered.contains("pick suggestion"));

    // ↓ highlights the first suggestion row; before that nothing is picked out.
    let suggestion_style = |terminal: &Terminal<TestBackend>| {
        let buffer = terminal.backend().buffer();
        for y in 0..buffer.area.height {
            let row: String = (0..buffer.area.width)
                .map(|x| buffer.cell((x, y)).unwrap().symbol())
                .collect();
            if let Some(start) = row.find("deepseek-chat") {
                let x = u16::try_from(start).unwrap();
                return buffer.cell((x, y)).unwrap().style();
            }
        }
        panic!("suggestion row not rendered");
    };
    // Unselected rows inherit the modal's own background.
    assert_eq!(
        suggestion_style(&terminal).bg,
        Some(vulnclaw_tui::theme::PANEL)
    );

    let mut settings = app.llm_settings.take().unwrap();
    settings.move_suggestion(true);
    app.llm_settings = Some(settings);
    terminal.draw(|frame| render(frame, &app)).unwrap();
    assert_eq!(
        suggestion_style(&terminal).bg,
        Some(vulnclaw_tui::theme::GOLD)
    );
}

#[test]
fn settings_modal_hides_a_rows_text_until_enter_opens_it() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    let mut settings = settings_screen();
    settings.focus_field(vulnclaw_tui::app::LlmField::BaseUrl);
    app.llm_settings = Some(settings);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    // No caret is placed while the row is only selected, so whichever cursor
    // the frame reports is not the settings screen's.
    assert!(rendered_text(&terminal).contains("› API request URL"));
    let unopened = terminal.get_cursor_position().unwrap();

    let mut settings = app.llm_settings.take().unwrap();
    settings.begin_edit();
    app.llm_settings = Some(settings);
    terminal.draw(|frame| render(frame, &app)).unwrap();

    assert!(rendered_text(&terminal).contains("✎ API request URL"));
    let opened = terminal.get_cursor_position().unwrap();
    assert_eq!(opened.y, 8);
    assert_ne!(unopened.y, opened.y);
}

#[test]
fn settings_modal_stays_inside_a_small_terminal() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    app.llm_settings = Some(settings_screen());
    for (width, height) in [(1, 1), (10, 3), (30, 8), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        // Rendering must never panic, however little room it is given.
        terminal.draw(|frame| render(frame, &app)).unwrap();
    }
}

#[test]
fn settings_modal_places_the_caret_on_the_focused_row() {
    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    let mut settings = settings_screen();
    settings.focus_field(vulnclaw_tui::app::LlmField::BaseUrl);
    settings.begin_edit();
    app.llm_settings = Some(settings);

    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    // The modal draws after the composer and claims the frame's single cursor.
    // Geometry: 100-wide terminal -> 92-wide modal at x=4, border -> inner.x=5,
    // then the 2-column marker and the 18-column label before the value.
    let position = terminal.get_cursor_position().unwrap();
    assert_eq!(position.y, 8);
    assert_eq!(
        usize::from(position.x),
        5 + 2 + 18 + "https://api.deepseek.com".len()
    );
}

/// Draws the settings screen with `count` models and `selected` highlighted.
fn settings_terminal(count: usize, selected: usize) -> Terminal<TestBackend> {
    use vulnclaw_tui::app::LlmField;

    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    let mut settings = settings_screen();
    settings.focus_field(LlmField::Model);
    settings.begin_edit();
    settings.models = (0..count).map(|i| format!("model-{i:02}")).collect();
    settings.model = String::new();
    settings.move_cursor_to_edge(true);
    settings.suggestion = Some(selected);
    app.llm_settings = Some(settings);

    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();
    terminal
}

/// Reports every suggestion row the modal actually painted: the visible label
/// and whether the row is the highlighted one.
fn render_suggestions(count: usize, selected: usize) -> Vec<(String, bool)> {
    let terminal = settings_terminal(count, selected);
    let buffer = terminal.backend().buffer();
    let mut rows = Vec::new();
    for y in 0..buffer.area.height {
        let row: String = (0..buffer.area.width)
            .map(|x| buffer.cell((x, y)).unwrap().symbol())
            .collect();
        if let Some(start) = row.find("model-") {
            // Column, not byte offset: the modal draws box-drawing glyphs, which
            // are multi-byte, to the left of every row.
            let label = row[start..start + 8].to_owned();
            let highlighted = (0..buffer.area.width).any(|x| {
                buffer.cell((x, y)).unwrap().style().bg == Some(vulnclaw_tui::theme::GOLD)
            });
            rows.push((label, highlighted));
        }
    }
    rows
}

#[test]
fn a_long_suggestion_list_scrolls_without_growing_the_window() {
    // The window is the same height whatever the selection...
    let top = render_suggestions(20, 0);
    assert_eq!(top.len(), 6, "the window keeps its six rows");
    assert_eq!(top[0].0, "model-00");
    assert_eq!(top[5].0, "model-05");

    // ...and it scrolls to follow the highlight instead of capping the list.
    let scrolled = render_suggestions(20, 9);
    assert_eq!(scrolled.len(), 6, "still six rows after scrolling");
    assert_eq!(scrolled[0].0, "model-04");
    assert_eq!(scrolled[5].0, "model-09");

    // The highlight travels with the selection, on whichever row it lands.
    assert!(
        top[0].1,
        "the first entry is highlighted at the top of the list"
    );
    assert!(scrolled[5].1, "the highlight followed the window down");
    assert!(!scrolled[0].1);

    // The very last entry is reachable and sits at the bottom of the window.
    let end = render_suggestions(20, 19);
    assert_eq!(end.len(), 6);
    assert_eq!(end[0].0, "model-14");
    assert_eq!(end[5].0, "model-19");
    assert!(end[5].1);
}

#[test]
fn a_long_template_list_scrolls_too() {
    use vulnclaw_tui::app::ProviderEntry;

    let (sender, _) = mpsc::channel();
    let mut app = App::new_disconnected(sender);
    let mut settings = settings_screen();
    settings.providers = (0..20)
        .map(|i| ProviderEntry {
            id: format!("p{i:02}"),
            label: format!("provider-{i:02}"),
            ..ProviderEntry::default()
        })
        .collect();
    settings.template_list_open = true;
    settings.list_index = 19;
    app.llm_settings = Some(settings);

    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered = rendered_text(&terminal);
    // The selection sits at the end of a list longer than the window, so the
    // window must have scrolled to it — an unwindowed render would have capped
    // the list at the first entries and made the tail unreachable.
    assert!(
        rendered.contains("provider-19"),
        "the selection must be visible"
    );
    assert!(
        !rendered.contains("provider-00"),
        "the window must have scrolled past the head"
    );
}

#[test]
fn a_window_that_hides_models_says_how_many_remain_below() {
    let terminal = settings_terminal(20, 0);
    assert_eq!(
        render_suggestions(20, 0).len(),
        6,
        "the window keeps six rows"
    );

    // The hint closes the window rather than taking one of its rows.
    let rendered = rendered_text(&terminal);
    assert!(rendered.contains("… 14 more"), "{rendered}");

    let last_row = (0..28u16)
        .find(|&y| row_text(&terminal, y).contains("model-05"))
        .expect("the last suggestion row must render");
    let hint_row = row_text(&terminal, last_row + 1);
    assert!(hint_row.contains("… 14 more"), "{hint_row:?}");
    assert!(!hint_row.contains("model-"), "the hint is not a list row");

    // A provider-sized catalogue reports its real remainder.
    assert!(rendered_text(&settings_terminal(445, 0)).contains("… 439 more"));
}

#[test]
fn the_remainder_counts_down_as_the_selection_scrolls() {
    fn hint(selected: usize) -> Option<String> {
        rendered_text(&settings_terminal(20, selected))
            .split('…')
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next().map(str::to_owned))
    }

    // Each window reports only what is still below it, so the number shrinks as
    // the highlight moves down instead of sticking at the size of the list.
    assert_eq!(hint(0).as_deref(), Some("14"));
    assert_eq!(hint(5).as_deref(), Some("14"), "still the first window");
    assert_eq!(hint(6).as_deref(), Some("13"), "the window scrolled by one");
    assert_eq!(hint(13).as_deref(), Some("6"));
    assert_eq!(hint(18).as_deref(), Some("1"));
    assert_eq!(
        hint(19).as_deref(),
        None,
        "the last entry leaves nothing below"
    );
}

#[test]
fn the_remainder_hint_disappears_at_the_last_entry() {
    // Only the final entry pulls the window all the way to the end of the list.
    let rendered = rendered_text(&settings_terminal(20, 19));
    assert!(!rendered.contains('…'), "{rendered}");
    assert!(rendered.contains("model-19"), "the selection stays visible");

    // A provider-sized catalogue behaves the same way at its end.
    assert!(!rendered_text(&settings_terminal(445, 444)).contains('…'));
}

#[test]
fn a_list_that_fits_its_window_shows_no_remainder_hint() {
    for count in [1usize, 5, 6] {
        let rendered = rendered_text(&settings_terminal(count, 0));
        assert!(
            !rendered.contains('…'),
            "a {count}-entry list fits its window and needs no hint"
        );
    }
}
