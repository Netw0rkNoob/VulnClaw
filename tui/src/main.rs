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
    install_panic_hook();
    let setup = enable_raw_mode();
    let result = match setup {
        Ok(()) => (|| {
            let mut terminal_stdout = stdout();
            execute!(terminal_stdout, EnterAlternateScreen, EnableMouseCapture)?;
            #[cfg(unix)]
            execute!(terminal_stdout, EnableBracketedPaste)?;
            let backend = CrosstermBackend::new(terminal_stdout);
            let mut terminal = Terminal::new(backend)?;
            let run_result = run(&mut terminal);
            if run_result.is_err() {
                // Fatal-console path (#298): ratatui's `Terminal` Drop calls
                // eprintln! when it fails to restore the cursor, and on the
                // already-severed console pipe that print panics inside std
                // itself and aborts the process (the stdio.rs:1166 panic
                // captured in the panic log). The process is exiting anyway,
                // so skip Drop entirely and let main's own exit path report.
                std::mem::forget(terminal);
            }
            run_result
        })(),
        Err(error) => Err(error),
    };
    let raw_result = disable_raw_mode();
    let screen_result = execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen, Show);
    #[cfg(unix)]
    let result = result.and(execute!(stdout(), DisableBracketedPaste));
    // Never hand an error back to the runtime: when the console pipe is
    // already severed (the #298 crash path), the runtime's error report is
    // itself a stderr write that fails inside the runtime and aborts the
    // process with the window still flashing closed. Persist the reason to
    // the panic log instead and exit cleanly.
    if let Err(error) = result.and(raw_result).and(screen_result) {
        append_panic_log(&format!("fatal: {error}"));
        std::process::exit(1);
    }
    Ok(())
}

fn run(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> io::Result<()> {
    let (sender, receiver) = mpsc::channel::<AppEvent>();
    let mut app = App::new(sender);
    app.load_layout(vulnclaw_tui::sessions::client_dir().join("layout.json"));
    // Windows recreates the console buffer when the window toggles between
    // maximized/restored or enters/leaves fullscreen. During that moment a
    // size query, console write, or event read can fail exactly once; with a
    // full transcript each frame writes far more bytes, so the race window
    // against the recreation widens and a propagated error was killing the
    // whole TUI with no message (#298). Treat transient I/O failures as
    // retryable instead of fatal, with a cap so a permanently broken console
    // still terminates.
    const MAX_CONSECUTIVE_FAILURES: u32 = 40; // ~3s at the 75ms frame budget
    let mut consecutive_failures = 0u32;
    while app.running {
        while let Ok(event) = receiver.try_recv() {
            app.apply_event(event);
        }
        // Size first: on a resize race the freshly queried size is the one
        // the console can actually accept for this frame.
        let size = match terminal.size() {
            Ok(size) => size,
            Err(error) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(75));
                continue;
            }
        };
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
        // A panic inside one frame's draw (a rare layout geometry edge case
        // under resize) must not take the process down: skip the frame and
        // keep running. The alternate screen hides stderr, so the payload is
        // persisted to %TEMP%\vulnclaw-tui-panic.log by the hook; the panic
        // loop is bounded by the same consecutive-failure cap.
        let draw_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Map to () inside the closure: CompletedFrame borrows the
            // terminal's buffer and cannot escape the FnMut body.
            terminal.draw(|frame| ui::draw(frame, &app)).map(|_| ())
        }));
        match draw_result {
            Ok(Ok(())) => consecutive_failures = 0,
            Ok(Err(error)) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(75));
                continue;
            }
            Err(_payload) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    return Err(io::Error::other("draw panicked repeatedly during resize"));
                }
                std::thread::sleep(Duration::from_millis(75));
                continue;
            }
        }
        // poll/read share the transient-error treatment: a ConPTY pipe can be
        // momentarily severed during the fullscreen/maximize transition, and a
        // propagated read error used to unwind the whole process (the very
        // crash path caught by the panic log in #298: poll fails -> run()
        // returns Err -> the runtime prints the error to the same broken
        // stderr pipe -> that print fails inside the runtime -> abort).
        match event::poll(Duration::from_millis(75)) {
            Ok(true) => match event::read() {
                Ok(event) => match event {
                    Event::Key(key) => events::handle_key(&mut app, key),
                    Event::Paste(text) => events::handle_paste(&mut app, &text),
                    Event::Mouse(mouse) => events::handle_mouse(&mut app, mouse),
                    Event::Resize(width, height) => {
                        app.cancel_layout_gesture();
                        app.terminal_size = Rect::new(0, 0, width, height);
                        // When the hosting console resizes between maximized
                        // and windowed/fullscreen, the console host itself is
                        // reflowing the entire scrollback buffer at the same
                        // moment we would be pushing a full repaint into it.
                        // Backing off one frame keeps our heaviest writes
                        // (large transcripts) out of that window and away
                        // from the conhost reflow path (#298 event-log
                        // evidence: conhost itself crashes with 0xc0000409
                        // during these transitions; we cannot fix conhost,
                        // but we can stop racing it).
                        std::thread::sleep(Duration::from_millis(75));
                    }
                    _ => {}
                },
                Err(error) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(75));
                    continue;
                }
            },
            Ok(false) => {}
            Err(error) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(75));
                continue;
            }
        }
    }
    // Gracefully stop and reap the one session backend. Task cancellation never
    // tears this process down; only leaving the TUI does.
    app.shutdown_backend();
    Ok(())
}

/// Persist panics where the user can find them after the alternate screen is
/// gone. The default hook prints to stderr, which the alternate screen and
/// the hidden window both swallow; the log keeps the payload diagnosable
/// (#298). Writing must never go through stderr: during the console-pipe
/// severing that triggers these panics, a failed stderr write inside the
/// panic handler would itself abort the process.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        let location = info
            .location()
            .map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        append_panic_log(&format!("panic{location}: {message}"));
    }));
}

/// Append one line to %TEMP%\vulnclaw-tui-panic.log. Failure to write is
/// silently ignored: this runs on panic/exit paths where there is nothing
/// left to report to.
fn append_panic_log(message: &str) {
    let line = format!(
        "[unix:{:?}] {message}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let path = std::env::temp_dir().join("vulnclaw-tui-panic.log");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(line.as_bytes())
        });
}
