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
    /// Set by `finish`, so the `Drop` guard knows the line has already been
    /// settled and must not be wiped.
    finished: bool,
    /// How many times the bar has actually been written. Only tests read it,
    /// to assert that a detail change repaints rather than waiting for the
    /// next `advance` -- the difference is invisible from the rendered line.
    paints: u64,
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
            finished: false,
            paints: 0,
        }
    }

    /// Changes the trailing context, repainting immediately.
    ///
    /// The repaint deliberately bypasses the frame throttle. Detail changes
    /// once per package rather than per file, so it costs nothing -- and
    /// leaving it for the next `advance` means a package that fails before
    /// its first file is still labelled with the *previous* package's name.
    pub fn set_detail(&mut self, detail: &str) {
        if self.detail == detail {
            return;
        }
        self.detail = detail.to_string();
        self.paint();
    }

    /// Records absolute progress and repaints if enough time has passed.
    ///
    /// Overshoot is kept as-is rather than clamped: the displayed fraction is
    /// bounded separately, and silently discarding the real count would hide
    /// a caller reporting more work than it declared.
    pub fn set(&mut self, done: u64) {
        self.done = done;
        self.maybe_paint();
    }

    /// Takes back progress that turned out not to count, such as bytes from a
    /// mirror that failed partway through.
    pub fn rewind(&mut self, delta: u64) {
        self.done = self.done.saturating_sub(delta);
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
        // ~20fps is smooth without burning cycles on escape sequences.
        if self.last_paint.elapsed() < Duration::from_millis(50) && self.done < self.total {
            return;
        }
        self.paint();
    }

    /// The event a front-end receives instead of a painted bar.
    fn emit_json(&self) {
        let unit = match self.unit {
            Unit::Bytes => "bytes",
            Unit::Count(noun) => noun,
        };
        super::json::emit(
            "progress",
            serde_json::json!({
                "label": self.label,
                "done": self.done,
                "total": self.total,
                "unit": unit,
                "detail": self.detail,
            }),
        );
    }

    /// Repaints now, ignoring the frame throttle.
    fn paint(&mut self) {
        if self.style.json {
            self.paints += 1;
            self.last_paint = Instant::now();
            return self.emit_json();
        }
        if !self.style.interactive {
            return;
        }
        self.paints += 1;
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

    /// Whether dropping now would leave a half-drawn bar on screen.
    fn needs_clear(&self) -> bool {
        !self.finished && self.style.interactive
    }

    /// Clears the bar and prints a settled summary line.
    pub fn finish(mut self, message: &str) {
        self.finished = true;
        if self.style.json {
            return super::json::emit(
                "progress_done",
                serde_json::json!({ "label": self.label, "message": message, "done": self.done, "ms": self.started.elapsed().as_millis() as u64 }),
            );
        }
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

/// Wipes an abandoned bar.
///
/// A transaction that fails mid-extraction drops its `Progress` without ever
/// reaching `finish`, and the bar is only ever terminated by a carriage
/// return -- so the error the caller prints next lands *on top of* it, which
/// is how `installing 14% ... tzdata` and `error: filesystem: File exists`
/// ended up sharing one line.
impl Drop for Progress {
    fn drop(&mut self) {
        if !self.needs_clear() {
            return;
        }
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[2K");
        let _ = err.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(total: u64) -> Progress {
        Progress::new(Style::plain(), "fetching", total)
    }

    /// A style that claims a terminal, so painting is not short-circuited.
    fn interactive() -> Style {
        Style {
            interactive: true,
            ..Style::plain()
        }
    }

    fn installing(total: u64) -> Progress {
        Progress::with_unit(interactive(), "installing", total, Unit::Count("files"))
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
    fn rewinding_takes_back_failed_progress() {
        let mut p = progress(1000);
        p.advance(400);
        assert_eq!(p.fraction(), 0.4);

        // A mirror that failed after 400 bytes must not leave them counted.
        p.rewind(400);
        assert_eq!(p.fraction(), 0.0);

        // Rewinding past zero must not underflow.
        p.rewind(999_999);
        assert_eq!(p.fraction(), 0.0);
    }

    /// The bug this guards: `installing ... tzdata` stayed on screen while the
    /// failure came from `filesystem`. The package label had been set, but
    /// nothing repainted, because the package died before its first file and
    /// so never called `advance`.
    #[test]
    fn changing_the_detail_repaints_immediately() {
        let mut p = installing(100);
        p.set_detail("tzdata");
        p.advance(10);
        let before = p.paints;

        p.set_detail("filesystem");
        assert_eq!(p.paints, before + 1, "a new package label must repaint");
        assert!(p.render().contains("filesystem"));
        assert!(!p.render().contains("tzdata"));
    }

    #[test]
    fn repeating_the_same_detail_does_not_repaint() {
        let mut p = installing(100);
        p.set_detail("filesystem");
        let after_first = p.paints;
        p.set_detail("filesystem");
        assert_eq!(p.paints, after_first);
    }

    /// A transaction that fails mid-extraction drops the bar without calling
    /// `finish`; the line must be wiped or the error prints on top of it.
    #[test]
    fn an_abandoned_bar_is_cleared_and_a_finished_one_is_not() {
        let mut p = installing(100);
        p.advance(10);
        assert!(p.needs_clear());

        p.finished = true;
        assert!(!p.needs_clear());
    }

    #[test]
    fn detail_is_appended() {
        let mut p = progress(100);
        p.set_detail("3/12 packages");
        p.set(10);
        assert!(p.render().contains("3/12 packages"));
    }
}
