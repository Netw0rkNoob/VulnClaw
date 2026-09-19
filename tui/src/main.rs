use std::io::{self, stdout};
use std::sync::mpsc;
use std::time::Duration;

use crossterm::{
    cursor::Show,
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
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
    let result = (|| {
        let mut terminal_stdout = stdout();
        execute!(terminal_stdout, EnterAlternateScreen, EnableMouseCapture)?;
        #[cfg(unix)]
        execute!(terminal_stdout, EnableBracketedPaste)?;
        let backend = CrosstermBackend::new(terminal_stdout);
        let mut terminal = Terminal::new(backend)?;
        run(&mut terminal)
    })();
    let raw_result = disable_raw_mode();
    let screen_result = execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen, Show);
    #[cfg(unix)]
    let result = result.and(execute!(stdout(), DisableBracketedPaste));
    result.and(raw_result).and(screen_result)
}

fn run(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> io::Result<()> {
    let (sender, receiver) = mpsc::channel::<AppEvent>();
    let mut app = App::new(sender);
    app.load_layout(vulnclaw_tui::sessions::client_dir().join("layout.json"));
    while app.running {
        while let Ok(event) = receiver.try_recv() {
            app.apply_event(event);
        }
        let size = terminal.size()?;
        let area = Rect::new(0, 0, size.width, size.height);
        if area != app.terminal_size
            || app.pending_execution.is_some()
            || app.pending_task.is_some()
            || app.llm_settings.is_some()
        {
            app.cancel_layout_gesture();
        }
        app.terminal_size = area;
        app.refresh_view_scrolls();
        terminal.draw(|frame| ui::draw(frame, &app))?;
        if event::poll(Duration::from_millis(75))? {
            match event::read()? {
                Event::Key(key) => events::handle_key(&mut app, key),
                Event::Paste(text) => events::handle_paste(&mut app, &text),
                Event::Mouse(mouse) => events::handle_mouse(&mut app, mouse),
                Event::Resize(width, height) => {
                    app.cancel_layout_gesture();
                    app.terminal_size = Rect::new(0, 0, width, height);
                }
                _ => {}
            }
        }
    }
    // Gracefully stop and reap the one session backend. Task cancellation never
    // tears this process down; only leaving the TUI does.
    app.shutdown_backend();
    Ok(())
}
