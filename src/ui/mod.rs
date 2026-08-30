//! rvn's terminal interface.
//!
//! All interface output goes to stderr so that machine-readable results on
//! stdout stay pipeable.

pub mod json;
pub mod progress;
pub mod spinner;
pub mod theme;

use progress::{Progress, Unit};
use spinner::Spinner;
use std::io::{BufRead, Write};
use theme::{Color, Style};

pub struct Ui {
    pub style: Style,
}

impl Ui {
    pub fn new() -> Ui {
        Ui {
            style: Style::detect(),
        }
    }

    pub fn plain() -> Ui {
        Ui {
            style: Style::plain(),
        }
    }

    /// A UI that emits JSON events on stdout for a graphical front-end. It is
    /// never interactive: prompts take their defaults, so callers pass `-y`.
    pub fn json() -> Ui {
        Ui {
            style: Style {
                json: true,
                ..Style::plain()
            },
        }
    }

    /// Whether output is the machine-readable event stream.
    pub fn is_json(&self) -> bool {
        self.style.json
    }

    /// Emits a structured event in JSON mode; a no-op otherwise. Operations
    /// use this to hand a front-end the data behind what they print.
    pub fn emit(&self, event: &str, payload: serde_json::Value) {
        if self.style.json {
            json::emit(event, payload);
        }
    }

    /// The masthead shown at the start of an operation.
    pub fn banner(&self, subtitle: &str) {
        if self.style.json {
            return json::emit("banner", serde_json::json!({ "version": subtitle }));
        }
        let s = &self.style;
        let mark = s.paint(Color::Violet, if s.unicode { "𝗿𝘃𝗻" } else { "rvn" });
        let name = s.bold(&s.paint(Color::White, "raven"));
        let mut err = std::io::stderr();
        let _ = writeln!(err, "\n {mark}  {name} {}", s.dim(subtitle));
    }

    /// Starts an animated stage. The returned handle must be settled.
    pub fn stage(&self, message: &str) -> Spinner {
        Spinner::start(self.style, message)
    }

    /// A progress bar measured in bytes, reporting throughput.
    pub fn progress(&self, label: &str, total: u64) -> Progress {
        Progress::new(self.style, label, total)
    }

    /// A progress bar measured in a plain count of `noun`.
    pub fn counter(&self, label: &str, total: u64, noun: &'static str) -> Progress {
        Progress::with_unit(self.style, label, total, Unit::Count(noun))
    }

    fn line(&self, color: Color, glyph: &str, message: &str) {
        if self.style.json {
            let kind = match color {
                Color::Green => "ok",
                Color::Red => "err",
                Color::Amber => "warn",
                Color::Violet => "step",
                _ => "info",
            };
            return json::message(kind, message);
        }
        let mut err = std::io::stderr();
        let _ = writeln!(err, "  {}  {}", self.style.paint(color, glyph), message);
    }

    pub fn ok(&self, message: &str) {
        self.line(Color::Green, self.style.glyphs.ok, message);
    }

    pub fn err(&self, message: &str) {
        self.line(Color::Red, self.style.glyphs.fail, message);
    }

    pub fn warn(&self, message: &str) {
        self.line(Color::Amber, self.style.glyphs.warn, message);
    }

    pub fn info(&self, message: &str) {
        self.line(Color::Slate, self.style.glyphs.info, message);
    }

    pub fn step(&self, message: &str) {
        self.line(Color::Violet, self.style.glyphs.bullet, message);
    }

    /// A blank separator line.
    pub fn blank(&self) {
        if self.style.json {
            return;
        }
        let _ = writeln!(std::io::stderr());
    }

    /// An indented detail line under the most recent step.
    pub fn detail(&self, message: &str) {
        if self.style.json {
            return json::message("detail", message);
        }
        let mut err = std::io::stderr();
        let _ = writeln!(err, "     {}", self.style.dim(message));
    }

    /// Renders a tree of child lines beneath a heading.
    pub fn tree(&self, items: &[String]) {
        if self.style.json {
            return json::emit("tree", serde_json::json!({ "items": items }));
        }
        let g = self.style.glyphs;
        let mut err = std::io::stderr();
        for (i, item) in items.iter().enumerate() {
            let branch = if i + 1 == items.len() {
                g.tree_end
            } else {
                g.tree_mid
            };
            let _ = writeln!(err, "     {} {}", self.style.dim(branch), item);
        }
    }

    /// Asks for free-text input. Returns an empty string when there is no
    /// terminal to ask.
    pub fn prompt(&self, question: &str) -> String {
        if !self.style.interactive {
            return String::new();
        }

        let mut err = std::io::stderr();
        let _ = write!(
            err,
            "  {}  {} ",
            self.style.paint(Color::Violet, self.style.glyphs.bullet),
            question
        );
        let _ = err.flush();

        let mut answer = String::new();
        if std::io::stdin().lock().read_line(&mut answer).is_err() {
            return String::new();
        }
        answer.trim().to_string()
    }

    /// Asks a yes/no question. Non-interactive sessions take `default`
    /// without blocking, so scripted use never hangs.
    pub fn confirm(&self, question: &str, default: bool) -> bool {
        if !self.style.interactive {
            return default;
        }

        let hint = if default { "[Y/n]" } else { "[y/N]" };
        let mut err = std::io::stderr();
        let _ = write!(
            err,
            "  {}  {} {} ",
            self.style.paint(Color::Violet, self.style.glyphs.bullet),
            question,
            self.style.dim(hint)
        );
        let _ = err.flush();

        let mut answer = String::new();
        if std::io::stdin().lock().read_line(&mut answer).is_err() {
            return default;
        }

        match answer.trim().to_lowercase().as_str() {
            "" => default,
            "y" | "yes" => true,
            _ => false,
        }
    }
}

impl Default for Ui {
    fn default() -> Self {
        Ui::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_interactive_confirm_returns_default_without_blocking() {
        let ui = Ui::plain();
        assert!(ui.confirm("proceed?", true));
        assert!(!ui.confirm("proceed?", false));
    }

    #[test]
    fn json_ui_is_never_interactive() {
        let ui = Ui::json();
        assert!(ui.is_json());
        assert!(!ui.style.interactive);
        // Prompts must fall through to their defaults rather than block.
        assert!(ui.confirm("proceed?", true));
        assert_eq!(ui.prompt("which?"), "");
    }

    #[test]
    fn output_helpers_do_not_panic_without_a_terminal() {
        let ui = Ui::plain();
        ui.banner("v0.1.0");
        ui.ok("done");
        ui.warn("careful");
        ui.err("broken");
        ui.info("fyi");
        ui.step("working");
        ui.detail("extra");
        ui.tree(&["one".into(), "two".into()]);
        ui.blank();
    }
}
