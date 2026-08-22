//! Colour and glyph palette for rvn's output.
//!
//! Everything degrades: colour is dropped when stderr is not a terminal or
//! `NO_COLOR` is set, and the glyph set falls back to ASCII when the terminal
//! is unlikely to render box-drawing and braille characters.

use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Raven,
    Violet,
    Slate,
    Dim,
    Green,
    Red,
    Amber,
    Cyan,
    White,
}

impl Color {
    fn code(self) -> &'static str {
        // 256-colour codes: a violet-forward palette to match Raven's identity.
        match self {
            Color::Raven => "\x1b[38;5;99m",
            Color::Violet => "\x1b[38;5;141m",
            Color::Slate => "\x1b[38;5;245m",
            Color::Dim => "\x1b[38;5;240m",
            Color::Green => "\x1b[38;5;114m",
            Color::Red => "\x1b[38;5;203m",
            Color::Amber => "\x1b[38;5;179m",
            Color::Cyan => "\x1b[38;5;80m",
            Color::White => "\x1b[38;5;255m",
        }
    }
}

/// Glyphs used across the interface, with an ASCII fallback set.
#[derive(Debug, Clone, Copy)]
pub struct Glyphs {
    pub ok: &'static str,
    pub fail: &'static str,
    pub warn: &'static str,
    pub info: &'static str,
    pub bullet: &'static str,
    pub arrow: &'static str,
    pub bar_full: &'static str,
    pub bar_empty: &'static str,
    pub tree_mid: &'static str,
    pub tree_end: &'static str,
}

pub const UNICODE: Glyphs = Glyphs {
    ok: "✔",
    fail: "✖",
    warn: "▲",
    info: "•",
    bullet: "▸",
    arrow: "→",
    bar_full: "█",
    bar_empty: "░",
    tree_mid: "├─",
    tree_end: "└─",
};

pub const ASCII: Glyphs = Glyphs {
    ok: "+",
    fail: "x",
    warn: "!",
    info: "*",
    bullet: ">",
    arrow: "->",
    bar_full: "#",
    bar_empty: "-",
    tree_mid: "|-",
    tree_end: "`-",
};

#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub color: bool,
    pub unicode: bool,
    pub interactive: bool,
    pub glyphs: Glyphs,
}

impl Style {
    /// Detects capabilities from the environment.
    pub fn detect() -> Style {
        let interactive = std::io::stderr().is_terminal();
        let term = std::env::var("TERM").unwrap_or_default();

        let color = interactive
            && std::env::var_os("NO_COLOR").is_none()
            && term != "dumb";

        // Assume UTF-8 output unless the locale clearly says otherwise.
        let lang = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_CTYPE"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default()
            .to_lowercase();
        let unicode = term != "dumb" && (lang.is_empty() || lang.contains("utf"));

        Style {
            color,
            unicode,
            interactive,
            glyphs: if unicode { UNICODE } else { ASCII },
        }
    }

    /// A style with every effect disabled, for piped output and tests.
    pub fn plain() -> Style {
        Style {
            color: false,
            unicode: false,
            interactive: false,
            glyphs: ASCII,
        }
    }

    pub fn paint(&self, color: Color, text: &str) -> String {
        if self.color {
            format!("{}{}\x1b[0m", color.code(), text)
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        if self.color {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint(Color::Dim, text)
    }

    /// Usable terminal width, clamped to something sane for narrow windows.
    pub fn width(&self) -> usize {
        terminal_size::terminal_size()
            .map(|(terminal_size::Width(w), _)| w as usize)
            .unwrap_or(80)
            .clamp(40, 200)
    }
}

/// Formats a byte count for humans: `8.1 MB`, `972 KB`, `14 B`.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{:.0} {}", value, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

/// Formats a signed byte delta, keeping the sign visible.
pub fn bytes_signed(n: i64) -> String {
    if n < 0 {
        format!("-{}", bytes(n.unsigned_abs()))
    } else {
        bytes(n as u64)
    }
}

/// Formats a duration compactly: `0.4s`, `12s`, `3m 05s`.
pub fn duration(d: std::time::Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 10.0 {
        format!("{secs:.1}s")
    } else if secs < 60.0 {
        format!("{secs:.0}s")
    } else {
        format!("{}m {:02.0}s", (secs / 60.0) as u64, secs % 60.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1024), "1.0 KB");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(1024 * 1024), "1.0 MB");
        // Three-digit values drop the decimal so columns stay narrow.
        assert_eq!(bytes(150 * 1024 * 1024), "150 MB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn formats_signed_bytes() {
        assert_eq!(bytes_signed(1024), "1.0 KB");
        assert_eq!(bytes_signed(-1024), "-1.0 KB");
        assert_eq!(bytes_signed(0), "0 B");
    }

    #[test]
    fn formats_durations() {
        use std::time::Duration;
        assert_eq!(duration(Duration::from_millis(400)), "400ms");
        assert_eq!(duration(Duration::from_secs_f64(1.25)), "1.2s");
        assert_eq!(duration(Duration::from_secs(42)), "42s");
        assert_eq!(duration(Duration::from_secs(125)), "2m 05s");
    }

    #[test]
    fn plain_style_emits_no_escapes() {
        let s = Style::plain();
        assert_eq!(s.paint(Color::Red, "boom"), "boom");
        assert_eq!(s.bold("loud"), "loud");
        assert!(!s.unicode);
    }

    #[test]
    fn colored_style_wraps_and_resets() {
        let s = Style {
            color: true,
            ..Style::plain()
        };
        let out = s.paint(Color::Green, "ok");
        assert!(out.starts_with("\x1b["));
        assert!(out.ends_with("\x1b[0m"));
        assert!(out.contains("ok"));
    }
}
