use std::io::{self, stdout};
use std::sync::mpsc;
use std::time::Duration;

use crossterm::{
    event::{self, Event, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
// Bracketed paste is parsed by crossterm *only* on Unix (sys/unix/parse.rs). On
// Windows, enabling it makes the terminal wrap pastes in ESC sequences that we
// would misinterpret — notably the trailing ESC clears the composer — so paste
// silently does nothing. Only enable it where it actually helps.
#[cfg(unix)]
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use ratatui::{backend::CrosstermBackend, layout::Rect, Terminal};
use vulnclaw_tui::{events, ui, App, AppEvent};

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut terminal_stdout = stdout();
    execute!(terminal_stdout, EnterAlternateScreen)?;
    #[cfg(unix)]
    execute!(terminal_stdout, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(terminal_stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run(&mut terminal);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    #[cfg(unix)]
    execute!(terminal.backend_mut(), DisableBracketedPaste)?;
    terminal.show_cursor()?;
    result
}

fn run(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> io::Result<()> {
    let (sender, receiver) = mpsc::channel::<AppEvent>();
    let mut app = App::new(sender);
    while app.running {
        let mut drawn_area = Rect::default();
        // Pin the Session transcript to the newest output before each paint,
        // unless the user has scrolled up to read history (which clears follow).
        app.autoscroll_transcript();
        terminal.draw(|frame| {
            drawn_area = frame.area();
            ui::draw(frame, &app);
        })?;
        app.terminal_size = drawn_area;
        while let Ok(event) = receiver.try_recv() {
            app.apply_event(event);
        }
        if event::poll(Duration::from_millis(75))? {
            match event::read()? {
                Event::Key(key) => events::handle_key(&mut app, key),
                Event::Paste(text) => app.insert_text(&text),
                Event::Mouse(mouse) => match mouse.kind {
                    MouseEventKind::ScrollUp => app.scroll_active_pane(false),
                    MouseEventKind::ScrollDown => app.scroll_active_pane(true),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    // Gracefully stop and reap the one session backend. Task cancellation never
    // tears this process down; only leaving the TUI does.
    app.shutdown_backend();
    Ok(())
}
