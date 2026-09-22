//! What rvnd will do without asking, and what it will not.
//!
//! For most of this daemon's life it had no authorization in it at all. The
//! socket was mode 0660 and owned by `wheel`, the kernel refused everybody
//! else's `connect`, and that was the entire story -- `daemon`'s own module
//! comment said so in as many words. The peer's uid was read from
//! `SO_PEERCRED` and used to write a log line and to set `SUDO_USER`, and
//! never once compared against anything.
//!
//! On a desktop where the one human is in `wheel`, that is not a privilege
//! boundary. Every process running as that human could install any package
//! from the AUR, whose PKGBUILD is a shell script from a stranger and whose
//! scriptlets run as root: a compromised browser tab, a postinstall script in
//! a node package, a pasted one-liner. No prompt, no password, and nothing
//! written down afterwards to say it had happened.
//!
//! This module is the policy half of the answer and `auth` is the mechanism
//! half. It reads `/etc/raven/rvnd.toml`, which is shipped heavily commented
//! -- that file is the security documentation for this daemon and is worth
//! reading before this code. It classifies each request into one of three
//! classes and gives back one of three rules:
//!
//! ```text
//!   query    sync, which writes only signed data           allow
//!   repo     packages the distribution signed              auth
//!   aur      anything that may build a stranger's script   auth
//!   service  starting or stopping a daemon this machine    auth
//!            already ships a definition for
//! ```
//!
//! The classification is taken from the request's own fields and never from
//! anything the client asserts about itself, and an `install` that was not
//! asked for `--repo-only` is `aur` whether or not it turns out to need the
//! AUR. Which packages a request resolves to is not known when the request
//! arrives, so a classification that waited to find out would be one an
//! attacker gets a say in.
//!
//! The shipped file is compiled into the binary with `include_str!` and the
//! test at the bottom parses it and asserts that it describes exactly the
//! defaults in this file. A comment that says 300 seconds beside a constant
//! that says 600 is worse than no comment, and `rvnd --print-policy` hands an
//! administrator the same text to start from.
//!
//! A file that is present and does not parse is a hard error that stops rvnd
//! starting. That is `login.toml`'s stated rule for ravend and `txhooks`'
//! rule for hook files, and the reason is the same each time: falling back to
//! a default would quietly ignore a policy somebody wrote down and believed.

use std::path::{Path, PathBuf};

use crate::toml::Document;

/// Where the policy lives unless `rvnd --policy` says otherwise.
pub const DEFAULT_PATH: &str = "/etc/raven/rvnd.toml";

/// Where ravend is expected to listen for authorization prompts. See `auth`
/// for why the lock screen's verify socket cannot be used instead.
pub const DEFAULT_AUTH_SOCKET: &str = "/run/raven-login/authorize.sock";

/// Where every privileged request is recorded, refused ones included.
///
/// Deliberately not `/var/log/raven/rvnd.log`, which is already taken:
/// raven-init captures each service's console output to `<name>.log` in that
/// directory, so `rvnd.log` is where rvnd's own stderr already goes. Writing
/// the audit trail into the same file would interleave structured records
/// with free-form daemon chatter -- including this daemon's warnings about
/// not being able to write the audit trail -- and make both harder to read
/// than either is alone.
pub const DEFAULT_AUDIT_LOG: &str = "/var/log/raven/rvnd-audit.log";

/// The shipped file, compiled in so `--print-policy` can hand it over on a
/// machine that never had a copy, and so the test below can prove that what
/// it documents is what this module does.
pub const DEFAULT_FILE: &str = include_str!("../etc/raven/rvnd.toml");

/// What an operation takes before rvnd will run it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Run it, record it, ask nobody.
    Allow,
    /// Ask the human who owns the session it came from.
    Auth,
    /// Refuse it, always.
    Deny,
}

impl Rule {
    fn parse(word: &str) -> Option<Rule> {
        match word {
            "allow" => Some(Rule::Allow),
            "auth" => Some(Rule::Auth),
            "deny" => Some(Rule::Deny),
            _ => None,
        }
    }

    /// The word this rule is written as, for the audit log and for messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::Allow => "allow",
            Rule::Auth => "auth",
            Rule::Deny => "deny",
        }
    }
}

/// What to do when an operation needs a human and there is nobody to ask.
///
/// Separated from `Rule` because it is not a rule about an operation, it is
/// what happens when the mechanism behind `Rule::Auth` is missing -- and
/// because the honest default for it points the opposite way from everything
/// else here. See the long comment in the shipped file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Run it, warn loudly, and record it as unauthenticated.
    Allow,
    /// Refuse it.
    Deny,
}

impl Unavailable {
    fn parse(word: &str) -> Option<Unavailable> {
        match word {
            "allow" => Some(Unavailable::Allow),
            "deny" => Some(Unavailable::Deny),
            _ => None,
        }
    }
}

/// Which kind of thing a request is, as far as policy cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Query,
    Repo,
    Aur,
    /// Starting, stopping or enabling one of the daemons this machine ships a
    /// service definition for.
    ///
    /// Its own class rather than a corner of `repo` because what it can reach
    /// is bounded by something no package operation is bounded by: the set of
    /// files under /usr/share/raven/services, which are root-owned, arrive
    /// with a signed package, and each name one fixed `exec`. An install runs
    /// arbitrary scriptlets as root; this runs a daemon the machine already
    /// agreed to ship, and would have run at boot had the definition been
    /// read in time. An administrator who wants the store to install without
    /// a prompt and the biometrics switch to ask for a password -- or the
    /// reverse -- needs two keys to say so.
    Service,
}

impl Class {
    /// The class of a request.
    ///
    /// `repo_only` and `dry_run` are the client's flags, and trusting them
    /// here is safe in the one direction that matters: each can only move a
    /// request towards the class that can do less, and each is passed
    /// straight through to rvn's argv, so a request that claimed one and then
    /// did the other thing anyway would need rvn itself to be wrong rather
    /// than this daemon.
    ///
    /// A dry run is a query however dangerous the operation it is a dry run
    /// of. It resolves, reports and writes nothing -- and putting a prompt in
    /// front of it would mean two prompts for one install, because the
    /// terminal client runs every transaction twice: once with `--dry-run` to
    /// show the plan, and again for real once the human has said yes. The
    /// prompt belongs on the half that does something, where the person
    /// answering it has just read the plan it is about.
    pub fn of(op: crate::daemon::Op, repo_only: bool, dry_run: bool) -> Class {
        use crate::daemon::Op;
        if dry_run {
            return Class::Query;
        }
        match op {
            // Downloading and verifying the repository databases installs
            // nothing and removes nothing. It writes as root, but only files
            // that are checked against the keyring and are never executed --
            // and it is what the desktop's store does on a timer, so putting
            // a password prompt in front of it would teach people to answer
            // password prompts they did not ask for.
            Op::Sync => Class::Query,
            // A removal runs the package's pre- and post-remove scriptlets as
            // root, so it is every bit as privileged as an install; it just
            // cannot reach the AUR, which is the only distinction these two
            // classes draw.
            Op::Uninstall => Class::Repo,
            // A rollback installs an archive that is already on this machine
            // and was verified under the repository's SigLevel when it was
            // downloaded. Nothing is fetched and nothing is built, so it can
            // never reach the AUR however the request is spelled -- which is
            // the whole of the difference between `repo` and `aur`. It is not
            // `query`: it runs the package's scriptlets as root, exactly as
            // the install it is undoing did.
            Op::Rollback => Class::Repo,
            Op::Install | Op::Update => {
                if repo_only {
                    Class::Repo
                } else {
                    Class::Aur
                }
            }
            // Every service verb, including the ones that switch something
            // off. `query` was considered for those and is wrong: a class
            // named for operations that change nothing must not contain one
            // that stops a daemon. One key covers the switch in both
            // directions, which is also the only way an administrator reading
            // the file can tell what it does.
            Op::Service => Class::Service,
        }
    }

    /// The word this class is written as, in the file and in the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Query => "query",
            Class::Repo => "repo",
            Class::Aur => "aur",
            Class::Service => "service",
        }
    }
}

/// The whole of `/etc/raven/rvnd.toml`, or the defaults for a machine that
/// has no such file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub query: Rule,
    pub repo: Rule,
    pub aur: Rule,
    pub service: Rule,
    /// How long an answered prompt counts for. 0 asks every time.
    pub auth_cache_seconds: u64,
    pub on_auth_unavailable: Unavailable,
    /// Where ravend listens for authorization prompts.
    pub auth_socket: PathBuf,
    /// How long to wait for the human before treating the prompt as refused.
    pub auth_timeout_seconds: u64,
    /// The audit log.
    pub audit_log: PathBuf,
    /// The file this came from, so a message can name it. Not part of the
    /// policy proper, which is why `PartialEq` on two policies loaded from
    /// different paths still compares the values -- see `same_values`.
    pub source: PathBuf,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            query: Rule::Allow,
            repo: Rule::Auth,
            aur: Rule::Auth,
            // Asked for, like the two above it. Turning a fingerprint reader
            // or a camera on is a change to how the machine can be unlocked,
            // and the person at the keyboard is exactly who should be asked
            // -- the prompt is ravend's, on their own screen, and answering
            // it is the whole of what this replaces `sudo raven-rc` with.
            service: Rule::Auth,
            auth_cache_seconds: 300,
            on_auth_unavailable: Unavailable::Allow,
            auth_socket: PathBuf::from(DEFAULT_AUTH_SOCKET),
            auth_timeout_seconds: 120,
            audit_log: PathBuf::from(DEFAULT_AUDIT_LOG),
            source: PathBuf::from(DEFAULT_PATH),
        }
    }
}

/// The sections the file may have, and the keys in each.
///
/// Listed so an unrecognised one can be refused by name rather than ignored.
/// A key that is silently dropped is the worst outcome available to a file
/// like this one: the administrator believes every AUR build asks them first,
/// and it does not, and nothing anywhere says so.
const POLICY_KEYS: &[&str] = &[
    "query",
    "repo",
    "aur",
    "service",
    "auth_cache_seconds",
    "on_auth_unavailable",
];
const AUTH_KEYS: &[&str] = &["socket", "timeout_seconds"];
const AUDIT_KEYS: &[&str] = &["file"];

impl Policy {
    /// Read `path`, or the defaults if there is no file there.
    ///
    /// Absent is not an error: the shipped file exists to be read, not to be
    /// required, and a machine that has never been configured should still
    /// start its package daemon. Present and unreadable *is* an error, since
    /// that is a policy somebody wrote that we cannot see.
    pub fn load(path: &Path) -> Result<Policy, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Policy {
                    source: path.to_path_buf(),
                    ..Policy::default()
                });
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Policy::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The policy `text` describes, starting from the defaults for anything
    /// it does not mention.
    pub fn parse(text: &str) -> Result<Policy, String> {
        let document = Document::parse(text).map_err(|e| e.to_string())?;
        let mut policy = Policy::default();

        for section in document.sections() {
            let known = match section.name.as_str() {
                "policy" => POLICY_KEYS,
                "auth" => AUTH_KEYS,
                "audit" => AUDIT_KEYS,
                // A file of nothing but comments parses to one empty unnamed
                // section, which is the shape of a file somebody commented
                // every line of to go back to the defaults.
                "" if section.is_empty() => continue,
                "" => {
                    return Err(format!(
                        "line {}: rvnd's settings belong under [policy], [auth] or [audit]",
                        section.line_of(section.keys().next().unwrap_or_default())
                    ));
                }
                other => {
                    return Err(format!(
                        "line {}: [{other}] is not a section of rvnd's policy; it has [policy], [auth] and [audit]",
                        section.line
                    ));
                }
            };
            if let Some(unknown) = section.keys().find(|key| !known.contains(key)) {
                return Err(format!(
                    "line {}: `{unknown}` is not a key of [{}]; it takes {}",
                    section.line_of(unknown),
                    section.name,
                    known.join(", ")
                ));
            }
        }

        if let Some(section) = document.section("policy") {
            for (key, slot) in [
                ("query", &mut policy.query),
                ("repo", &mut policy.repo),
                ("aur", &mut policy.aur),
                ("service", &mut policy.service),
            ] {
                if let Some(value) = section.get(key) {
                    *slot = value.as_str().and_then(Rule::parse).ok_or_else(|| {
                        format!(
                            "line {}: `{key}` is \"allow\", \"auth\" or \"deny\"",
                            section.line_of(key)
                        )
                    })?;
                }
            }
            if let Some(value) = section.get("auth_cache_seconds") {
                policy.auth_cache_seconds = seconds(
                    value,
                    section.line_of("auth_cache_seconds"),
                    "auth_cache_seconds",
                )?;
            }
            if let Some(value) = section.get("on_auth_unavailable") {
                policy.on_auth_unavailable =
                    value.as_str().and_then(Unavailable::parse).ok_or_else(|| {
                        format!(
                            "line {}: `on_auth_unavailable` is \"allow\" or \"deny\"",
                            section.line_of("on_auth_unavailable")
                        )
                    })?;
            }
        }

        if let Some(section) = document.section("auth") {
            if let Some(value) = section.get("socket") {
                policy.auth_socket = absolute(value, section.line_of("socket"), "socket")?;
            }
            if let Some(value) = section.get("timeout_seconds") {
                policy.auth_timeout_seconds =
                    seconds(value, section.line_of("timeout_seconds"), "timeout_seconds")?;
                if policy.auth_timeout_seconds == 0 {
                    return Err(format!(
                        "line {}: `timeout_seconds` cannot be 0; a prompt with no time to answer it is a prompt that always refuses",
                        section.line_of("timeout_seconds")
                    ));
                }
            }
        }

        if let Some(section) = document.section("audit")
            && let Some(value) = section.get("file")
        {
            policy.audit_log = absolute(value, section.line_of("file"), "file")?;
        }

        Ok(policy)
    }

    /// The rule for a class of operation.
    pub fn rule(&self, class: Class) -> Rule {
        match class {
            Class::Query => self.query,
            Class::Repo => self.repo,
            Class::Service => self.service,
            Class::Aur => self.aur,
        }
    }

    /// Whether two policies say the same thing, ignoring which file each was
    /// read from. Only the test below needs this, and it needs it because the
    /// shipped file's `source` is a path in the source tree rather than
    /// `/etc`.
    #[cfg(test)]
    fn same_values(&self, other: &Policy) -> bool {
        Policy {
            source: PathBuf::new(),
            ..self.clone()
        } == Policy {
            source: PathBuf::new(),
            ..other.clone()
        }
    }
}

/// A whole non-negative number of seconds.
///
/// Refused rather than clamped when it is negative: `auth_cache_seconds = -1`
/// is somebody reaching for "never expire", and silently turning it into 0 --
/// "always ask" -- would be the exact opposite of what they meant.
fn seconds(value: &crate::toml::Value, line: usize, key: &str) -> Result<u64, String> {
    match value.as_integer() {
        Some(number) if number >= 0 => Ok(number as u64),
        Some(_) => Err(format!("line {line}: `{key}` cannot be negative")),
        None => Err(format!(
            "line {line}: `{key}` is a whole number of seconds, not {}",
            value.kind()
        )),
    }
}

/// An absolute path.
///
/// rvnd starts with no working directory worth speaking of and a relative
/// path here would resolve somewhere nobody intended, so it is refused where
/// it is written rather than at the moment the file cannot be opened.
fn absolute(value: &crate::toml::Value, line: usize, key: &str) -> Result<PathBuf, String> {
    let text = value.as_str().ok_or_else(|| {
        format!(
            "line {line}: `{key}` is a path in quotes, not {}",
            value.kind()
        )
    })?;
    if !text.starts_with('/') {
        return Err(format!("line {line}: `{key}` must be an absolute path"));
    }
    Ok(PathBuf::from(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped file is the documentation, so it has to be true. If this
    /// fails, either a default moved and the file was not updated, or the
    /// file was edited into something that no longer parses -- and in both
    /// cases an administrator reading `/etc/raven/rvnd.toml` would be reading
    /// a description of a daemon that does not exist.
    #[test]
    fn the_shipped_file_describes_the_defaults() {
        let parsed = Policy::parse(DEFAULT_FILE).expect("the shipped file parses");
        assert!(
            parsed.same_values(&Policy::default()),
            "etc/raven/rvnd.toml no longer matches Policy::default():\n{parsed:#?}"
        );
    }

    #[test]
    fn a_missing_file_is_the_defaults_and_not_an_error() {
        let path = std::env::temp_dir().join("rvnd-policy-that-is-not-there.toml");
        std::fs::remove_file(&path).ok();
        let policy = Policy::load(&path).expect("absent is fine");
        assert!(policy.same_values(&Policy::default()));
        assert_eq!(policy.source, path);
    }

    #[test]
    fn every_rule_word_is_understood_and_nothing_else_is() {
        let policy = Policy::parse(
            "[policy]\nquery = \"deny\"\nrepo = \"allow\"\naur = \"auth\"\nauth_cache_seconds = 0\n",
        )
        .unwrap();
        assert_eq!(policy.rule(Class::Query), Rule::Deny);
        assert_eq!(policy.rule(Class::Repo), Rule::Allow);
        assert_eq!(policy.rule(Class::Aur), Rule::Auth);
        assert_eq!(policy.auth_cache_seconds, 0);

        let e = Policy::parse("[policy]\nrepo = \"ask\"\n").unwrap_err();
        assert!(e.contains("\"allow\", \"auth\" or \"deny\""), "{e}");
    }

    #[test]
    fn a_key_that_is_not_understood_is_refused_by_name() {
        let e = Policy::parse("[policy]\nrepo_only = \"auth\"\n").unwrap_err();
        assert!(e.contains("`repo_only` is not a key of [policy]"), "{e}");
        let e = Policy::parse("[policies]\nrepo = \"auth\"\n").unwrap_err();
        assert!(e.contains("[policies] is not a section"), "{e}");
        let e = Policy::parse("repo = \"auth\"\n").unwrap_err();
        assert!(e.contains("belong under [policy]"), "{e}");
    }

    #[test]
    fn numbers_and_paths_are_checked_where_they_are_written() {
        let e = Policy::parse("[policy]\nauth_cache_seconds = \"300\"\n").unwrap_err();
        assert!(e.contains("whole number of seconds"), "{e}");
        let e = Policy::parse("[policy]\nauth_cache_seconds = -1\n").unwrap_err();
        assert!(e.contains("cannot be negative"), "{e}");
        let e = Policy::parse("[auth]\ntimeout_seconds = 0\n").unwrap_err();
        assert!(e.contains("always refuses"), "{e}");
        let e = Policy::parse("[audit]\nfile = \"rvnd.log\"\n").unwrap_err();
        assert!(e.contains("absolute path"), "{e}");
    }

    /// The classification is the security-relevant half of this module, and
    /// the case worth pinning down is that an install which did not promise
    /// `--repo-only` is treated as capable of building.
    #[test]
    fn an_install_that_may_build_is_classified_as_aur() {
        use crate::daemon::Op;
        assert_eq!(Class::of(Op::Install, false, false), Class::Aur);
        assert_eq!(Class::of(Op::Install, true, false), Class::Repo);
        assert_eq!(Class::of(Op::Update, false, false), Class::Aur);
        assert_eq!(Class::of(Op::Update, true, false), Class::Repo);
        // A removal cannot reach the AUR however it was asked for.
        assert_eq!(Class::of(Op::Uninstall, false, false), Class::Repo);
        assert_eq!(Class::of(Op::Sync, false, false), Class::Query);
        // Nor can a rollback: the archive it installs is already on the
        // machine, so `--repo-only` makes no difference to what it can do.
        assert_eq!(Class::of(Op::Rollback, false, false), Class::Repo);
        assert_eq!(Class::of(Op::Rollback, true, false), Class::Repo);
    }

    /// The client shows a plan before it asks the human anything, and it gets
    /// that plan by running the whole transaction with `--dry-run`. If that
    /// phase prompted, every install would ask twice.
    #[test]
    fn a_dry_run_is_a_query_whatever_it_is_a_dry_run_of() {
        use crate::daemon::Op;
        assert_eq!(Class::of(Op::Install, false, true), Class::Query);
        assert_eq!(Class::of(Op::Uninstall, false, true), Class::Query);
        assert_eq!(Class::of(Op::Update, false, true), Class::Query);
        assert_eq!(Class::of(Op::Rollback, false, true), Class::Query);
    }
}
