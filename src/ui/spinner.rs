//! Animated stage indicators.
//!
//! A spinner owns one terminal line on stderr and repaints it from a
//! background thread. Nothing else may write to stderr while one is live, so
//! every spinner must be finished before further output — the `Ui` facade
//! enforces this by consuming the handle.

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
    handle: Option<thread::JoinHandle<()>>,
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
            let mut err = std::io::stderr();
            let _ = writeln!(err, "  {} {}", style.glyphs.bullet, message);
            return Spinner {
                shared,
                handle: None,
                style,
                started: Instant::now(),
            };
        }

        let frames: &'static [&'static str] = if style.unicode { WINGBEAT } else { ASCII_SPIN };
        let thread_shared = Arc::clone(&shared);
        let thread_style = style;

        let handle = thread::spawn(move || {
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
        });

        Spinner {
            shared,
            handle: Some(handle),
            style,
            started: Instant::now(),
        }
    }

    /// Updates the text without interrupting the animation.
    pub fn set_message(&self, message: &str) {
        if let Ok(mut current) = self.shared.message.lock() {
            *current = message.to_string();
        }
        if !self.style.interactive {
            let mut err = std::io::stderr();
            let _ = writeln!(err, "  {} {}", self.style.glyphs.bullet, message);
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn stop(&mut self) {
        self.shared.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Settles the line with a success mark. Consumes the spinner so no
    /// further output can race the animation thread.
    pub fn succeed(mut self, message: &str) {
        self.stop();
        let glyph = self.style.paint(Color::Green, self.style.glyphs.ok);
        let took = self.style.dim(&format!("({})", super::theme::duration(self.started.elapsed())));
        let mut err = std::io::stderr();
        let _ = writeln!(err, "  {glyph}  {message} {took}");
    }

    /// Settles the line with a failure mark.
    pub fn fail(mut self, message: &str) {
        self.stop();
        let glyph = self.style.paint(Color::Red, self.style.glyphs.fail);
        let mut err = std::io::stderr();
        let _ = writeln!(err, "  {glyph}  {message}");
    }

    /// Settles the line without any verdict glyph.
    pub fn clear(mut self) {
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
        assert!(spinner.handle.is_none());
        spinner.succeed("resolved");
    }

    #[test]
    fn message_can_be_updated_and_settled() {
        let spinner = Spinner::start(Style::plain(), "starting");
        spinner.set_message("still going");
        assert_eq!(*spinner.shared.message.lock().unwrap(), "still going");
        spinner.clear();
    }
}
