//! Progress bars for downloads and long extractions.

use super::theme::{Color, Style, bytes, duration};
use std::io::Write;
use std::time::{Duration, Instant};

/// What the numbers on a bar represent, which changes how they are formatted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Bytes,
    /// A plain count, with `noun` naming what is counted.
    Count(&'static str),
}

impl Unit {
    fn format(self, n: u64) -> String {
        match self {
            Unit::Bytes => bytes(n),
            Unit::Count(noun) => format!("{n} {noun}"),
        }
    }

    /// A per-second figure, only meaningful for byte throughput.
    fn rate(self, per_second: f64) -> Option<String> {
        match self {
            Unit::Bytes => Some(format!("{}/s", bytes(per_second as u64))),
            Unit::Count(_) => None,
        }
    }
}

/// A single-line progress bar that reports throughput.
pub struct Progress {
    style: Style,
    label: String,
    total: u64,
    done: u64,
    started: Instant,
    last_paint: Instant,
    /// Extra context shown after the rate, e.g. `3/12 packages`.
    detail: String,
    unit: Unit,
}

impl Progress {
    pub(super) fn new(style: Style, label: &str, total: u64) -> Progress {
        Progress::with_unit(style, label, total, Unit::Bytes)
    }

    pub(super) fn with_unit(style: Style, label: &str, total: u64, unit: Unit) -> Progress {
        Progress {
            style,
            label: label.to_string(),
            total,
            done: 0,
            started: Instant::now(),
            // Back-date so the first update paints immediately.
            last_paint: Instant::now() - Duration::from_secs(1),
            detail: String::new(),
            unit,
        }
    }

    pub fn set_detail(&mut self, detail: &str) {
        self.detail = detail.to_string();
    }

    /// Records absolute progress and repaints if enough time has passed.
    pub fn set(&mut self, done: u64) {
        self.done = done.min(self.total.max(done));
        self.maybe_paint();
    }

    /// Records incremental progress.
    pub fn advance(&mut self, delta: u64) {
        self.done = self.done.saturating_add(delta);
        self.maybe_paint();
    }

    fn fraction(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.done as f64 / self.total as f64).clamp(0.0, 1.0)
        }
    }

    fn rate(&self) -> f64 {
        let secs = self.started.elapsed().as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.done as f64 / secs
        }
    }

    fn maybe_paint(&mut self) {
        if !self.style.interactive {
            return;
        }
        // ~20fps is smooth without burning cycles on escape sequences.
        if self.last_paint.elapsed() < Duration::from_millis(50) && self.done < self.total {
            return;
        }
        self.last_paint = Instant::now();
        let line = self.render();
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[2K{line}");
        let _ = err.flush();
    }

    /// Builds the bar line. Kept pure so it can be tested without a terminal.
    pub fn render(&self) -> String {
        let g = self.style.glyphs;
        let pct = self.fraction();

        // Reserve room for label, percentage, rate and detail; the bar takes
        // what is left, so narrow terminals shrink the bar rather than wrap.
        let rate = self.unit.rate(self.rate()).unwrap_or_default();
        let counts = format!(
            "{}/{}",
            self.unit.format(self.done),
            self.unit.format(self.total)
        );
        let fixed =
            self.label.chars().count() + rate.len() + counts.len() + self.detail.chars().count() + 18;
        let bar_width = self.style.width().saturating_sub(fixed).clamp(8, 40);

        let filled = (pct * bar_width as f64).round() as usize;
        let bar = format!(
            "{}{}",
            self.style.paint(Color::Violet, &g.bar_full.repeat(filled)),
            self.style
                .paint(Color::Dim, &g.bar_empty.repeat(bar_width - filled))
        );

        let mut line = format!(
            "  {}  {}  {}  {:>3.0}%",
            self.style.paint(Color::Violet, g.bullet),
            self.label,
            bar,
            pct * 100.0,
        );
        if !rate.is_empty() {
            line.push_str(&format!("  {}", self.style.paint(Color::Cyan, &rate)));
        }
        line.push_str(&format!("  {}", self.style.dim(&counts)));
        if !self.detail.is_empty() {
            line.push_str(&format!("  {}", self.style.dim(&self.detail)));
        }
        line
    }

    /// Clears the bar and prints a settled summary line.
    pub fn finish(self, message: &str) {
        let mut err = std::io::stderr();
        if self.style.interactive {
            let _ = write!(err, "\r\x1b[2K");
        }
        let glyph = self.style.paint(Color::Green, self.style.glyphs.ok);
        let summary = self.style.dim(&format!(
            "({} in {})",
            self.unit.format(self.done),
            duration(self.started.elapsed())
        ));
        let _ = writeln!(err, "  {glyph}  {message} {summary}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(total: u64) -> Progress {
        Progress::new(Style::plain(), "fetching", total)
    }

    #[test]
    fn fraction_tracks_progress() {
        let mut p = progress(1000);
        assert_eq!(p.fraction(), 0.0);
        p.set(250);
        assert_eq!(p.fraction(), 0.25);
        p.set(1000);
        assert_eq!(p.fraction(), 1.0);
    }

    #[test]
    fn zero_total_does_not_divide_by_zero() {
        let p = progress(0);
        assert_eq!(p.fraction(), 0.0);
        // Rendering must still succeed rather than panic.
        assert!(p.render().contains("fetching"));
    }

    #[test]
    fn overshoot_is_clamped_for_display() {
        let mut p = progress(100);
        p.advance(500);
        assert_eq!(p.fraction(), 1.0);
        assert!(p.render().contains("100%"));
    }

    #[test]
    fn bar_fills_proportionally() {
        let mut p = progress(100);
        p.set(50);
        let rendered = p.render();
        // With the ASCII glyph set the bar is '#' filled and '-' empty.
        let filled = rendered.matches('#').count();
        let empty = rendered.matches('-').count();
        assert!(filled > 0 && empty > 0);
        assert!(
            (filled as i64 - empty as i64).abs() <= 1,
            "half progress should split the bar evenly: {rendered}"
        );
    }

    #[test]
    fn count_unit_formats_as_a_noun_not_bytes() {
        let mut p = Progress::with_unit(Style::plain(), "installing", 5, Unit::Count("files"));
        p.set(3);
        let rendered = p.render();
        assert!(rendered.contains("3 files/5 files"), "got {rendered}");
        // A per-second figure is meaningless for a file count.
        assert!(!rendered.contains("/s"));
    }

    #[test]
    fn byte_unit_still_reports_a_rate() {
        let mut p = progress(1000);
        p.set(500);
        assert!(p.render().contains("/s"));
    }

    #[test]
    fn detail_is_appended() {
        let mut p = progress(100);
        p.set_detail("3/12 packages");
        p.set(10);
        assert!(p.render().contains("3/12 packages"));
    }
}
