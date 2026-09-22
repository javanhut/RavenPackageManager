//! What asked for root, and what it was told.
//!
//! `/var/log/pacman.log` records what was installed. Every package manager
//! keeps that file and it is not the question this one answers. The question
//! after something has gone wrong on a machine where a socket grants root to
//! a whole group is *what asked for it*: you, at a terminal, or the browser
//! you left open, or a build script in a dependency you installed last week.
//! Nothing in rvn recorded that, so nothing could answer it.
//!
//! One line per privileged request, appended to
//! `/var/log/raven/rvnd-audit.log`,
//! including -- especially including -- the ones that were refused. A refusal
//! is the more interesting half of an audit log: an allow is what usually
//! happens, and a run of refusals at four in the morning is the thing that
//! makes somebody look.
//!
//! ```text
//! [2026-09-21T13:04:11+0000] [RVND] allowed op=install class=aur rule=auth \
//!   auth=prompt uid=1000 user=javanstorm gid=1000 pid=4242 session=1200 \
//!   exe="/usr/bin/rvn" packages=brave-bin
//! ```
//!
//! `key=value`, space separated, one line, values quoted only where they can
//! contain a space. Not JSON, because the first thing anybody does with this
//! file is `grep refused` at a console on a machine that is not well, and
//! because pacman.log next door is already line-oriented text and an
//! administrator should not need two habits. Values that could carry a space,
//! a quote or a newline -- the exe path, a refusal's reason -- are quoted and
//! escaped, so a hostile path cannot forge a second log line.
//!
//! The timestamp format is pacman.log's, for the same reason.
//!
//! # What is not in here
//!
//! The exe path is recorded and never trusted. It is read from
//! `/proc/<pid>/exe` after the fact, by which time the process may have
//! exec'd something else or exited and had its pid handed to somebody new,
//! and a path is not an identity in any case. It is a lead for a human, not
//! an input to a decision -- see `auth::exe_of`.
//!
//! # When the log cannot be written
//!
//! A warning on rvnd's own stderr, and the transaction goes ahead. Losing the
//! ability to install packages because `/var` is full is a worse failure than
//! losing the record of it, and this is not a machine with an auditor's
//! requirements on it -- it is somebody's desktop. The warning is the thing
//! to alert on.

use std::io::Write;
use std::path::Path;

/// One decision, as the log records it.
///
/// Every field has a sensible empty form, so a caller fills in what it knows
/// and the line simply does not carry the rest. A request refused before its
/// peer could be identified still gets a line; it just has less in it, and
/// that absence is itself worth seeing.
#[derive(Debug, Default)]
pub struct Event<'a> {
    /// `allowed` or `refused`.
    pub decision: &'a str,
    /// The operation asked for: install, uninstall, update, sync.
    pub op: &'a str,
    /// How `policy` classified it: query, repo, aur.
    pub class: &'a str,
    /// The rule that class has: allow, auth, deny.
    pub rule: &'a str,
    /// How the decision was reached -- `not-required`, `cached`, `prompt`,
    /// `denied`, `unavailable`, `root`, `policy`, `group`. This is the field
    /// to grep for: `auth=unavailable` is every request that went through
    /// because nothing could be asked.
    pub auth: &'a str,
    pub uid: Option<u32>,
    pub user: Option<&'a str>,
    pub gid: Option<u32>,
    pub pid: Option<i32>,
    /// The session leader's pid; see `auth::Session`.
    pub session: Option<i32>,
    pub exe: Option<&'a str>,
    pub packages: &'a [String],
    /// Why, for a refusal or an unusual allow.
    pub reason: Option<&'a str>,
}

/// The log line for an event, without the timestamp.
///
/// Separated from writing it so the format can be tested without a file, and
/// so the daemon can put the same text on its own stderr.
pub fn line(event: &Event) -> String {
    // The decision first, so `grep '] refused'` finds refusals and nothing
    // else -- a reason that happens to mention the word does not start a
    // line.
    let mut out = String::from(event.decision);

    push(&mut out, "op", bare(event.op));
    push(&mut out, "class", bare(event.class));
    push(&mut out, "rule", bare(event.rule));
    push(&mut out, "auth", bare(event.auth));
    push(
        &mut out,
        "uid",
        event.uid.map_or("-".into(), |uid| uid.to_string()),
    );
    push(&mut out, "user", bare(event.user.unwrap_or("-")));
    push(
        &mut out,
        "gid",
        event.gid.map_or("-".into(), |gid| gid.to_string()),
    );
    push(
        &mut out,
        "pid",
        event.pid.map_or("-".into(), |pid| pid.to_string()),
    );
    push(
        &mut out,
        "session",
        event.session.map_or("-".into(), |sid| sid.to_string()),
    );
    push(&mut out, "exe", quote(event.exe.unwrap_or("-")));
    push(
        &mut out,
        "packages",
        if event.packages.is_empty() {
            "-".to_string()
        } else {
            bare(&event.packages.join(","))
        },
    );
    if let Some(reason) = event.reason {
        push(&mut out, "reason", quote(reason));
    }
    out
}

/// One `key=value` onto the line being built.
fn push(out: &mut String, key: &str, value: String) {
    out.push(' ');
    out.push_str(key);
    out.push('=');
    out.push_str(&value);
}

/// Append one event to the log, creating the directory and the file.
///
/// The file is 0640 and the directory 0750: an audit log says which accounts
/// on this machine have been asking for root and what they asked to install,
/// which is a map of the machine drawn for whoever reads it. rvnd is root and
/// nobody else needs to write here.
pub fn record(log: &Path, event: &Event, when: u64) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(dir) = log.parent() {
        // Only on a directory this call created. `create_dir_all` returns Ok
        // whether or not it made anything, so the question has to be asked
        // before it runs: the parent here is /var/log/raven, which the
        // distribution ships at 0755 and raven-init writes its service logs
        // into. Tightening it on every audit write took the directory away
        // from `raven-rc logs` for everyone but root, and undid a deliberate
        // local chmod every time a package was installed, with nothing in any
        // log to say what had done it.
        let existed = dir.symlink_metadata().is_ok();
        std::fs::create_dir_all(dir)?;
        if !existed {
            std::fs::set_permissions(dir, PermissionsExt::from_mode(0o750)).ok();
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(log)?;
    writeln!(file, "[{}] [RVND] {}", timestamp(when), line(event))
}

/// A value with nothing in it that could be read as structure.
///
/// Package names are already checked against `daemon::valid_package_name` and
/// the fixed words are fixed, so in practice nothing here is ever replaced.
/// It exists so that the guarantee does not depend on that staying true.
fn bare(value: &str) -> String {
    if value.is_empty() {
        return "-".to_string();
    }
    value
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A value that may legitimately contain spaces, in quotes.
///
/// A path from `/proc/<pid>/exe` is whatever the person who made the file
/// called it, which can be `a" packages=vim exe="b` if they were trying. The
/// escaping is what stops that forging a field, and the newline case is what
/// stops it forging a whole line.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Seconds since the epoch, or 0 if the clock is before it.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seconds since the epoch as pacman.log's `YYYY-MM-DDTHH:MM:SS+0000`, in UTC.
///
/// Every line rvn writes to a log wears this format, so this is the one copy
/// of the calendar: the rvnd audit log here, the removal lines `ops::remove`
/// appends to pacman.log, and the scriptlet lines `scriptlet` appends beside
/// them all call it. There were three identical civil_from_days conversions
/// before -- one per module -- because each landed in a change that was not
/// allowed to touch the other's file, and three hand-rolled calendars is
/// three chances to disagree about a leap day in the one format an
/// administrator greps across.
///
/// It lives in `audit` rather than somewhere more neutral because this module
/// has no other business: depending on it costs a caller nothing, where
/// depending on `ops::remove` would drag in the removal pipeline.
pub fn timestamp(secs: u64) -> String {
    // Civil date from a day count: Howard Hinnant's civil_from_days.
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let secs_of_day = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}+0000",
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_says_who_asked_for_what_and_what_they_were_told() {
        let packages = vec!["brave-bin".to_string(), "localsend".to_string()];
        let line = line(&Event {
            decision: "allowed",
            op: "install",
            class: "aur",
            rule: "auth",
            auth: "prompt",
            uid: Some(1000),
            user: Some("javanstorm"),
            gid: Some(1000),
            pid: Some(4242),
            session: Some(1200),
            exe: Some("/usr/bin/rvn"),
            packages: &packages,
            reason: None,
        });
        assert_eq!(
            line,
            "allowed op=install class=aur rule=auth auth=prompt uid=1000 user=javanstorm \
             gid=1000 pid=4242 session=1200 exe=\"/usr/bin/rvn\" packages=brave-bin,localsend"
        );
    }

    #[test]
    fn what_is_not_known_is_a_dash_rather_than_a_missing_field() {
        let line = line(&Event {
            decision: "refused",
            op: "install",
            reason: Some("rvnd cannot identify the peer"),
            ..Event::default()
        });
        assert!(
            line.starts_with("refused op=install class=- rule=- auth=-"),
            "{line}"
        );
        assert!(
            line.contains("uid=- user=- gid=- pid=- session=- exe=\"-\" packages=-"),
            "{line}"
        );
        assert!(
            line.ends_with("reason=\"rvnd cannot identify the peer\""),
            "{line}"
        );
    }

    /// A path is whatever somebody called a file, so it has to be unable to
    /// write a field of its own or a line of its own.
    #[test]
    fn a_hostile_exe_path_cannot_forge_a_field_or_a_line() {
        let line = line(&Event {
            decision: "allowed",
            exe: Some("/tmp/a\" packages=vim\n[fake] [RVND] allowed"),
            ..Event::default()
        });
        assert_eq!(line.lines().count(), 1, "{line}");
        assert!(
            line.contains(r#"exe="/tmp/a\" packages=vim\n[fake] [RVND] allowed""#),
            "{line}"
        );
        // The forged field did not become a real one: there is exactly one.
        assert_eq!(line.matches("packages=").count(), 2, "{line}");
    }

    #[test]
    fn a_package_name_cannot_carry_structure_either() {
        let packages = vec!["a b".to_string()];
        let line = line(&Event {
            decision: "refused",
            packages: &packages,
            ..Event::default()
        });
        assert!(line.contains("packages=a_b"), "{line}");
    }

    #[test]
    fn the_timestamp_is_pacman_logs() {
        // 2026-09-21T13:04:11Z
        assert_eq!(timestamp(1_789_995_851), "2026-09-21T13:04:11+0000");
        assert_eq!(timestamp(0), "1970-01-01T00:00:00+0000");
        // A leap day, which is where a hand-rolled calendar goes wrong. This
        // case came from `ops::remove`'s copy of the function and is kept
        // here now that there is only one copy left to test.
        assert_eq!(timestamp(951_782_400), "2000-02-29T00:00:00+0000");
        assert_eq!(timestamp(1_789_504_157), "2026-09-15T20:29:17+0000");
    }

    /// The audit log's parent is /var/log/raven, which the distribution ships
    /// at 0755 and raven-init writes service logs into. rvnd used to chmod it
    /// to 0750 on every privileged request, which broke `raven-rc logs` for
    /// every non-root caller and silently reverted any local chmod.
    #[test]
    fn a_directory_that_was_already_there_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("rvnd-audit-mode-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).unwrap();

        let log = dir.join("rvnd.log");
        for _ in 0..2 {
            record(&log, &Event::default(), 0).expect("writes");
        }

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "the shipped directory was re-tightened to {mode:o}");
        // The log file itself is still the audit trail, so it stays closed.
        let file_mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o640, "{file_mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A directory rvnd makes for itself is nobody else's business, so that
    /// one does get the tight mode the comment promises.
    #[test]
    fn a_directory_it_creates_is_closed_to_everyone_else() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("rvnd-audit-new-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();

        record(&dir.join("rvnd.log"), &Event::default(), 0).expect("writes");

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "{mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn records_append_rather_than_replace() {
        let dir = std::env::temp_dir().join(format!("rvnd-audit-test-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let log = dir.join("rvnd.log");
        for op in ["install", "uninstall"] {
            record(
                &log,
                &Event {
                    decision: "allowed",
                    op,
                    ..Event::default()
                },
                0,
            )
            .expect("writes");
        }
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.contains("op=install"), "{text}");
        assert!(text.contains("op=uninstall"), "{text}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
