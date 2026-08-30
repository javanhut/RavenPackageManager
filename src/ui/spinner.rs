//! Animated stage indicators.
//!
//! A spinner owns one terminal line on stderr and repaints it from a
//! background thread. Nothing else may write to stderr while one is live, so
//! every spinner must be finished before further output — the `Ui` facade
//! enforces this by consuming the handle.
//!
//! A stage that has to talk to the user mid-flight — asking whether to review
//! a PKGBUILD, say — cannot settle the spinner and start a new one without
//! littering the transcript. [`Spinner::suspend`] lends the terminal out for
//! the duration instead: the painter stops, the line is cleared and the cursor
//! restored, and the animation resumes when the closure returns.

use super::theme::{Color, Style};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Wingbeat: braille frames that read as a bird's wings rising and falling.
pub const WINGBEAT: &[&str] = &["⢎ ", "⠎⠁", "⠊⠑", "⠈⠱", " ⡱", "⢀⡰", "⢄⡠", "⢆⡀"];

/// A plain orbit, used when the terminal cannot render braille.
pub const ASCII_SPIN: &[&str] = &["-", "\\", "|", "/"];

const FRAME_MS: u64 = 90;

struct Shared {
    message: Mutex<String>,
    frame: AtomicUsize,
    running: AtomicBool,
}

/// A live spinner. Call [`Spinner::succeed`] or [`Spinner::fail`] to settle it.
pub struct Spinner {
    shared: Arc<Shared>,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
    style: Style,
    started: Instant,
}

impl Spinner {
    pub(super) fn start(style: Style, message: &str) -> Spinner {
        let shared = Arc::new(Shared {
            message: Mutex::new(message.to_string()),
            frame: AtomicUsize::new(0),
            running: AtomicBool::new(true),
        });

        // Non-interactive output gets a single static line instead of an
        // animation, so logs and CI transcripts stay readable.
        if !style.interactive {
            if style.json {
                super::json::emit("stage", serde_json::json!({ "message": message }));
            } else {
                let mut err = std::io::stderr();
                let _ = writeln!(err, "  {} {}", style.glyphs.bullet, message);
            }
            return Spinner {
                shared,
                handle: Mutex::new(None),
                style,
                started: Instant::now(),
            };
        }

        let spinner = Spinner {
            shared,
            handle: Mutex::new(None),
            style,
            started: Instant::now(),
        };
        spinner.paint();
        spinner
    }

    /// Starts the painter thread. A no-op when one is already running or the
    /// session is not interactive.
    fn paint(&self) {
        if !self.style.interactive {
            return;
        }
        let mut handle = match self.handle.lock() {
            Ok(handle) => handle,
            Err(_) => return,
        };
        if handle.is_some() {
            return;
        }

        self.shared.running.store(true, Ordering::Relaxed);
        let frames: &'static [&'static str] = if self.style.unicode {
            WINGBEAT
        } else {
            ASCII_SPIN
        };
        let thread_shared = Arc::clone(&self.shared);
        let thread_style = self.style;

        *handle = Some(thread::spawn(move || {
            let mut err = std::io::stderr();
            let _ = write!(err, "\x1b[?25l"); // Hide the cursor while animating.
            let _ = err.flush();

            while thread_shared.running.load(Ordering::Relaxed) {
                let idx = thread_shared.frame.fetch_add(1, Ordering::Relaxed);
                let frame = frames[idx % frames.len()];
                let message = thread_shared
                    .message
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default();

                let painted = thread_style.paint(Color::Violet, frame);
                let line = format!("  {painted}  {message}");
                let _ = write!(err, "\r\x1b[2K{line}");
                let _ = err.flush();

                thread::sleep(Duration::from_millis(FRAME_MS));
            }

            // Clear the line and restore the cursor for whoever writes next.
            let _ = write!(err, "\r\x1b[2K\x1b[?25h");
            let _ = err.flush();
        }));
    }

    /// Updates the text without interrupting the animation.
    pub fn set_message(&self, message: &str) {
        if let Ok(mut current) = self.shared.message.lock() {
            *current = message.to_string();
        }
        if self.style.json {
            super::json::emit("stage", serde_json::json!({ "message": message }));
        } else if !self.style.interactive {
            let mut err = std::io::stderr();
            let _ = writeln!(err, "  {} {}", self.style.glyphs.bullet, message);
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn stop(&self) {
        self.shared.running.store(false, Ordering::Relaxed);
        let taken = self.handle.lock().ok().and_then(|mut h| h.take());
        // Joining guarantees the painter has cleared its line and restored the
        // cursor before anything else touches the terminal.
        if let Some(handle) = taken {
            let _ = handle.join();
        }
    }

    /// Lends the terminal to `body`, which may print and read from stdin.
    ///
    /// A prompt written underneath a live spinner is erased by the very next
    /// repaint, leaving the user staring at an animation that is silently
    /// waiting on an answer. Pausing the painter first is what makes such a
    /// question visible at all.
    pub fn suspend<T>(&self, body: impl FnOnce() -> T) -> T {
        self.stop();
        let result = body();
        self.paint();
        result
    }

    /// Settles the line with a success mark. Consumes the spinner so no
    /// further output can race the animation thread.
    pub fn succeed(self, message: &str) {
        self.stop();
        if self.style.json {
            return super::json::emit(
                "stage_done",
                serde_json::json!({ "message": message, "ok": true, "ms": self.started.elapsed().as_millis() as u64 }),
            );
        }
        let glyph = self.style.paint(Color::Green, self.style.glyphs.ok);
        let took = self.style.dim(&format!("({})", super::theme::duration(self.started.elapsed())));
        let mut err = std::io::stderr();
        let _ = writeln!(err, "  {glyph}  {message} {took}");
    }

    /// Settles the line with a failure mark.
    pub fn fail(self, message: &str) {
        self.stop();
        if self.style.json {
            return super::json::emit(
                "stage_done",
                serde_json::json!({ "message": message, "ok": false, "ms": self.started.elapsed().as_millis() as u64 }),
            );
        }
        let glyph = self.style.paint(Color::Red, self.style.glyphs.fail);
        let mut err = std::io::stderr();
        let _ = writeln!(err, "  {glyph}  {message}");
    }

    /// Settles the line without any verdict glyph.
    pub fn clear(self) {
        self.stop();
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        // A spinner dropped on an error path must not leave the cursor hidden.
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_sets_are_non_empty_and_uniform_width() {
        assert!(!WINGBEAT.is_empty());
        // Every frame must be the same display width or the line jitters.
        let width = WINGBEAT[0].chars().count();
        assert!(WINGBEAT.iter().all(|f| f.chars().count() == width));
        assert!(ASCII_SPIN.iter().all(|f| f.chars().count() == 1));
    }

    #[test]
    fn non_interactive_spinner_does_not_spawn_a_thread() {
        let spinner = Spinner::start(Style::plain(), "resolving");
        assert!(spinner.handle.lock().unwrap().is_none());
        spinner.succeed("resolved");
    }

    /// An interactive style without touching the real terminal capabilities,
    /// so the painter thread actually spawns under test.
    fn animated() -> Style {
        Style {
            color: false,
            unicode: false,
            interactive: true,
            glyphs: super::super::theme::ASCII,
            json: false,
        }
    }

    #[test]
    fn suspend_stops_the_painter_and_restarts_it() {
        let spinner = Spinner::start(animated(), "building");
        assert!(spinner.handle.lock().unwrap().is_some());

        // Whoever holds the terminal during the closure must have it to
        // themselves: a prompt printed here would otherwise be repainted over.
        let answer = spinner.suspend(|| {
            assert!(spinner.handle.lock().unwrap().is_none());
            "yes"
        });

        assert_eq!(answer, "yes");
        assert!(spinner.handle.lock().unwrap().is_some());
        spinner.clear();
    }

    #[test]
    fn suspend_is_a_no_op_without_a_terminal() {
        let spinner = Spinner::start(Style::plain(), "building");
        assert_eq!(spinner.suspend(|| 7), 7);
        assert!(spinner.handle.lock().unwrap().is_none());
        spinner.clear();
    }

    #[test]
    fn message_can_be_updated_and_settled() {
        let spinner = Spinner::start(Style::plain(), "starting");
        spinner.set_message("still going");
        assert_eq!(*spinner.shared.message.lock().unwrap(), "still going");
        spinner.clear();
    }
}
