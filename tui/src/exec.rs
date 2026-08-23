use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::{parse_backend_line, validate_protocol_value, AppEvent, ClientRequest};

#[derive(Clone)]
pub struct BackendHandle {
    child: Arc<Mutex<Option<Child>>>,
    stdin: Arc<Mutex<ChildStdin>>,
}

impl BackendHandle {
    pub fn send(&self, request: &ClientRequest) -> std::io::Result<()> {
        let mut input = self
            .stdin
            .lock()
            .map_err(|_| std::io::Error::other("backend stdin lock poisoned"))?;
        let value = serde_json::to_value(request).map_err(std::io::Error::other)?;
        validate_protocol_value(&value).map_err(std::io::Error::other)?;
        serde_json::to_writer(&mut *input, &value).map_err(std::io::Error::other)?;
        input.write_all(b"\n")?;
        input.flush()
    }

    /// Wait briefly for a graceful protocol shutdown, then force-reap the child.
    pub fn wait_or_kill(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let exited = {
                let mut guard = match self.child.lock() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };
                match guard.as_mut() {
                    Some(child) => matches!(child.try_wait(), Ok(Some(_))),
                    None => true,
                }
            };
            if exited || Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                if matches!(child.try_wait(), Ok(None)) {
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
        }
    }
}

#[cfg_attr(test, allow(dead_code))]
pub fn spawn_backend(sender: Sender<AppEvent>) -> std::io::Result<BackendHandle> {
    let python = std::env::var("VULNCLAW_PYTHON").unwrap_or_else(|_| "python".to_owned());
    let mut command = if cfg!(windows) && python == "python" {
        let mut command = Command::new("py");
        command.arg("-3");
        command
    } else {
        Command::new(python)
    };
    command.arg("-m").arg("vulnclaw.tui_backend");
    spawn_backend_command(command, sender)
}

/// Spawn a backend from a caller-supplied command.
///
/// This is the transport injection seam used by embedders and integration
/// tests; production callers normally use [`spawn_backend`].
pub fn spawn_backend_command(
    mut command: Command,
    sender: Sender<AppEvent>,
) -> std::io::Result<BackendHandle> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdin = child.stdin.take().expect("stdin is piped");
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let child_handle = Arc::new(Mutex::new(Some(child)));
    let handle = BackendHandle {
        child: child_handle.clone(),
        stdin: Arc::new(Mutex::new(stdin)),
    };

    let output_sender = sender.clone();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            match parse_backend_line(&line) {
                Ok(event) => {
                    let _ = output_sender.send(AppEvent::backend(event));
                }
                Err(error) => {
                    let _ = output_sender.send(AppEvent::BackendDiagnostic(format!(
                        "invalid backend protocol line ({error}): {line}"
                    )));
                }
            }
        }
    });

    let diagnostic_sender = sender.clone();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = diagnostic_sender.send(AppEvent::BackendDiagnostic(line));
        }
    });

    thread::spawn(move || loop {
        let next = {
            let mut guard = match child_handle.lock() {
                Ok(guard) => guard,
                Err(_) => break,
            };
            match guard.as_mut() {
                Some(child) => child.try_wait(),
                None => break,
            }
        };
        match next {
            Ok(Some(status)) => {
                let _ = sender.send(AppEvent::BackendExited(status.success()));
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(error) => {
                let _ = sender.send(AppEvent::BackendDiagnostic(format!(
                    "could not wait for VulnClaw backend: {error}"
                )));
                break;
            }
        }
    });

    Ok(handle)
}
