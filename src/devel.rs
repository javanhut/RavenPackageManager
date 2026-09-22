//! Tracking for VCS ("devel") packages such as `-git`, `-hg` and `-svn`.
//!
//! A `-git` package's version is computed by `pkgver()` at build time, so its
//! recorded version never changes on its own — an ordinary version comparison
//! will never report an update no matter how far upstream moves. The only way
//! to know a rebuild is due is to ask the upstream repository what its head
//! commit is now and compare it with the commit that was built.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Suffixes that mark a package as tracking a moving upstream.
const DEVEL_SUFFIXES: &[&str] = &["-git", "-hg", "-svn", "-bzr", "-cvs", "-darcs"];

/// Whether a package name looks like a VCS package.
pub fn is_devel(name: &str) -> bool {
    DEVEL_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tracked {
    /// The upstream repository, with any VCS prefix and fragment removed.
    pub url: String,
    /// The commit that was built.
    pub commit: String,
}

/// The recorded upstream state of every devel package rvn has built.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    packages: HashMap<String, Tracked>,
}

impl Registry {
    fn path(db_path: &Path) -> PathBuf {
        // Kept beside, not inside, pacman's own database so nothing here can
        // confuse pacman.
        db_path.join("rvn").join("devel.json")
    }

    pub fn load(db_path: &Path) -> Registry {
        std::fs::read_to_string(Registry::path(db_path))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, db_path: &Path) -> std::io::Result<()> {
        let path = Registry::path(db_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, text)
    }

    pub fn get(&self, name: &str) -> Option<&Tracked> {
        self.packages.get(name)
    }

    pub fn record(&mut self, name: &str, tracked: Tracked) {
        self.packages.insert(name.to_string(), tracked);
    }

    pub fn forget(&mut self, name: &str) {
        self.packages.remove(name);
    }

    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.packages.keys().cloned().collect();
        names.sort();
        names
    }
}

/// Strips makepkg's VCS decorations from a source entry.
///
/// Sources look like `name::git+https://host/repo.git#branch=main`; only the
/// bare URL is useful for querying the remote.
pub fn clean_source_url(source: &str) -> Option<String> {
    // Drop a `name::` prefix.
    let source = source.split_once("::").map(|(_, rest)| rest).unwrap_or(source);

    // Only VCS sources move under us; a tarball is pinned by its checksum.
    let (vcs, rest) = source.split_once('+')?;
    if !matches!(vcs, "git" | "hg" | "svn" | "bzr") {
        return None;
    }

    // Drop a `#branch=`/`#commit=` fragment.
    let url = rest.split('#').next().unwrap_or(rest);
    if is_fetchable_url(url) {
        Some(url.to_string())
    } else {
        None
    }
}

/// Whether a URL is one rvn will let git dial.
///
/// A source line is whatever the AUR package says it is, and `.SRCINFO` is not
/// checked against the PKGBUILD that was actually built -- so a package that
/// builds harmlessly under `raven-build` can still name anything it likes
/// here, and what it names is stored and re-dialled on every update check.
/// Git's URL space is wider than a URL: `ext::<command>` makes git *run* the
/// command as a transport, and the `vcs+` and `name::` decorations this module
/// strips are exactly what would hide a second `::` from a casual reading.
///
/// So the allowed shapes are listed rather than the forbidden ones, and any
/// remaining `::` is refused outright. Git's scp-style `user@host:path` is not
/// on the list: it is rare in a PKGBUILD, and the cost of leaving it out is
/// only that such a package is never reported as needing a rebuild, which is
/// the same thing that happens to every package whose remote is unreachable.
fn is_fetchable_url(url: &str) -> bool {
    const FETCH_ONLY_SCHEMES: &[&str] = &[
        "https://", "http://", "git://", "ssh://", "ftps://", "ftp://",
    ];

    !url.contains("::") && FETCH_ONLY_SCHEMES.iter().any(|scheme| url.starts_with(scheme))
}

/// The first VCS source in a `.SRCINFO` source list.
pub fn vcs_source(sources: &[String]) -> Option<String> {
    sources.iter().find_map(|s| clean_source_url(s))
}

/// How long a remote gets to answer before rvn stops waiting for it.
///
/// Every one of these calls happens while rvnd holds the single transaction
/// lock, so a remote that accepts the connection and then says nothing used to
/// wedge every package operation on the machine until rvnd was restarted. The
/// length is generous enough for a slow link and short enough that a whole
/// registry of devel packages cannot add up to an afternoon.
const REMOTE_TIMEOUT: Duration = Duration::from_secs(20);

/// The most of a remote's answer that is ever read.
///
/// A head commit is forty characters; anything past this is a remote trying to
/// fill rvn's memory rather than answer the question.
const REMOTE_MAX_OUTPUT: u64 = 64 * 1024;

/// Asks a remote git repository for its current head commit.
///
/// The URL comes from a package's `.SRCINFO`, which makes this a step derived
/// from a PKGBUILD, and every other such step drops to the build account. This
/// one used to be the exception: plain `git ls-remote` as root, driven by a
/// file a stranger wrote, reachable from `rvn update --dry-run`, which the
/// policy classes as a query anybody may make. So it drops too -- and when rvn
/// is root and there is no account to drop to, it does not ask at all. Nothing
/// is lost by refusing: an unanswerable remote already means "no rebuild is
/// known to be due", which is the safe direction.
pub fn remote_head(url: &str) -> Option<String> {
    // Checked here as well as in `clean_source_url`, because a `devel.json`
    // written by an older rvn can still hold a URL that never went through it.
    if !is_fetchable_url(url) {
        return None;
    }

    let mut command = git_query_command()?;
    command
        // A URL is data, so it is passed as data: `--` ends the options, and
        // `protocol.ext.allow=never` refuses the transport that runs a command
        // whatever a system or global gitconfig on this machine says.
        .arg("-c")
        .arg("protocol.ext.allow=never")
        .arg("ls-remote")
        .arg("--")
        .arg(url)
        .arg("HEAD");

    let stdout = run_bounded(command, REMOTE_TIMEOUT)?;

    String::from_utf8_lossy(&stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
        .filter(|commit| !commit.is_empty())
}

/// A `git` that runs as the build account when rvn is root.
///
/// The environment is cleared and rebuilt for the same reason a build's is
/// (see [`crate::ops::install::BUILD_PATH`]): what a query does should not
/// depend on who happened to be holding the terminal. `GIT_TERMINAL_PROMPT=0`
/// is what stops a remote that asks for credentials from sitting on the prompt
/// until the timeout, and the working directory is `/` so that git never finds
/// a repository it was not asked about and never has an opinion about who owns
/// the directory rvn was started in.
fn git_query_command() -> Option<Command> {
    let mut command = if crate::ops::is_root() {
        let (uid, gid) = crate::ops::install::build_user_ids()?;
        let mut command = Command::new("setpriv");
        command
            .arg(format!("--reuid={uid}"))
            .arg(format!("--regid={gid}"))
            .arg("--clear-groups")
            .arg("git");
        command
    } else {
        Command::new("git")
    };

    command
        .current_dir("/")
        .env_clear()
        .env("PATH", crate::ops::install::BUILD_PATH)
        .env("HOME", "/")
        .env("LANG", "C.UTF-8")
        .env("GIT_TERMINAL_PROMPT", "0");

    Some(command)
}

/// Runs a command, giving up on it after `timeout` and reading only so much.
///
/// `Command::output` waits for as long as the child cares to take, which is a
/// decision a remote host should not get to make for a package manager holding
/// a lock. The output is read on a thread so that the wait can be bounded: a
/// child that outlives the timeout is killed, and one that says more than the
/// cap allows has the pipe closed under it rather than being left blocked on a
/// full pipe with rvn waiting for it to finish.
///
/// A grandchild that inherited the pipe -- ssh, say -- can keep the reading
/// thread alive after the kill. That thread holds nothing but the pipe and
/// ends when the last writer does, which is the price of not having a process
/// group to signal; it never keeps rvn itself waiting.
fn run_bounded(mut command: Command, timeout: Duration) -> Option<Vec<u8>> {
    use std::io::Read;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(REMOTE_MAX_OUTPUT).read_to_end(&mut buf);
        // Closed before the answer is sent, not after: a child with more to
        // say is blocked writing into a full pipe, and the wait below would
        // wait for it forever.
        drop(stdout);
        let _ = tx.send(buf);
    });

    match rx.recv_timeout(timeout) {
        Ok(buf) => child.wait().ok()?.success().then_some(buf),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

/// Names whose upstream has moved since they were built.
///
/// A package whose remote cannot be reached is left alone rather than being
/// reported as out of date.
pub fn outdated(registry: &Registry, names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            let Some(tracked) = registry.get(name) else {
                return false;
            };
            match remote_head(&tracked.url) {
                Some(head) => head != tracked.commit,
                None => false,
            }
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_vcs_package_names() {
        assert!(is_devel("neovim-git"));
        assert!(is_devel("foo-svn"));
        assert!(is_devel("bar-hg"));
        assert!(!is_devel("neovim"));
        // The suffix must be at the end, not merely present.
        assert!(!is_devel("git-lfs"));
    }

    #[test]
    fn cleans_source_urls() {
        assert_eq!(
            clean_source_url("git+https://github.com/user/repo.git"),
            Some("https://github.com/user/repo.git".into())
        );
        // A `name::` prefix and a fragment must both be stripped.
        assert_eq!(
            clean_source_url("myrepo::git+https://host/r.git#branch=main"),
            Some("https://host/r.git".into())
        );
        assert_eq!(
            clean_source_url("hg+https://host/repo"),
            Some("https://host/repo".into())
        );
    }

    #[test]
    fn ignores_non_vcs_sources() {
        // A tarball is pinned by checksum, so it cannot drift.
        assert_eq!(clean_source_url("https://host/file-1.0.tar.gz"), None);
        assert_eq!(clean_source_url("local-patch.diff"), None);
    }

    #[test]
    fn finds_the_vcs_source_among_others() {
        let sources = vec![
            "patch.diff".to_string(),
            "https://host/extra.tar.gz".to_string(),
            "git+https://host/repo.git".to_string(),
        ];
        assert_eq!(
            vcs_source(&sources),
            Some("https://host/repo.git".to_string())
        );
        assert_eq!(vcs_source(&["only.tar.gz".to_string()]), None);
    }

    /// `.SRCINFO` is not checked against the PKGBUILD that was built, so a
    /// source line is attacker-controlled text that ends up stored and
    /// re-dialled on every update check. `ext::` is a git transport that runs
    /// the rest of the line as a command, and the `name::`/`vcs+` decorations
    /// this module strips are what would hide the second `::` from a reader.
    #[test]
    fn a_transport_that_runs_a_command_is_not_a_url() {
        assert_eq!(clean_source_url("x::git+ext::/tmp/payload"), None);
        assert_eq!(clean_source_url("git+ext::sh -c id"), None);
        assert!(!is_fetchable_url("ext::sh -c id"));
        // A local path is not a remote, and `file://` is git's own way of
        // saying "somewhere on this machine" -- neither is a thing to dial.
        assert_eq!(clean_source_url("git+file:///tmp/repo"), None);
        assert_eq!(clean_source_url("git+/tmp/repo"), None);
        assert_eq!(clean_source_url("git+"), None);

        // The ordinary shapes still pass, or nothing would ever be tracked.
        assert!(is_fetchable_url("https://github.com/user/repo.git"));
        assert!(is_fetchable_url("git://host/repo"));
        assert!(is_fetchable_url("ssh://git@host/repo.git"));

        // And a URL that only reaches the registry through an older rvn is
        // refused at the point of use as well as at the parse.
        assert_eq!(remote_head("ext::sh -c id"), None);
    }

    /// Every one of these calls happens while rvnd holds the transaction lock,
    /// so a remote that accepts the connection and then says nothing must not
    /// be able to hold it. `Command::output` had no way to stop waiting.
    #[test]
    fn a_remote_that_never_answers_is_abandoned() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 30");

        let started = std::time::Instant::now();
        assert_eq!(run_bounded(command, Duration::from_millis(300)), None);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited {:?} for a command that was never going to answer",
            started.elapsed()
        );
    }

    /// The other half of the same guarantee: a remote that says more than the
    /// cap allows has the pipe closed under it instead of being left blocked
    /// on a full pipe with rvn waiting for it to exit.
    #[test]
    fn a_remote_that_will_not_stop_talking_does_not_hang_rvn() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("yes");

        let started = std::time::Instant::now();
        // It is killed by the closed pipe rather than exiting cleanly, so
        // there is no answer -- the point is that there is an ending.
        assert_eq!(run_bounded(command, Duration::from_secs(30)), None);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "waited {:?} for a command with nothing to read it",
            started.elapsed()
        );
    }

    #[test]
    fn the_answer_is_read_when_it_arrives() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("printf 'abc123\\tHEAD\\n'");
        let out = run_bounded(command, Duration::from_secs(10)).expect("it answered");
        assert_eq!(String::from_utf8_lossy(&out), "abc123\tHEAD\n");
    }

    /// Unprivileged, there is nothing to drop and git runs as the caller. The
    /// root branch cannot be exercised from a test suite that is not root;
    /// what it does is checked by reading it, and by the fact that there is no
    /// path through [`git_query_command`] that reaches `Command::new("git")`
    /// while `is_root()`.
    #[test]
    fn a_query_runs_as_the_caller_when_there_is_nothing_to_drop() {
        if crate::ops::is_root() {
            return;
        }
        let command = git_query_command().expect("an unprivileged caller always gets one");
        assert_eq!(command.get_program(), "git");
        let home = command
            .get_envs()
            .find(|(key, _)| *key == "HOME")
            .and_then(|(_, value)| value);
        assert_eq!(home, Some(std::ffi::OsStr::new("/")));
    }

    #[test]
    fn registry_round_trips() {
        let dir = std::env::temp_dir().join("rvn-devel-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut registry = Registry::default();
        registry.record(
            "demo-git",
            Tracked {
                url: "https://host/r.git".into(),
                commit: "abc123".into(),
            },
        );
        registry.save(&dir).unwrap();

        let reloaded = Registry::load(&dir);
        assert_eq!(reloaded.get("demo-git").unwrap().commit, "abc123");
        assert_eq!(reloaded.names(), vec!["demo-git"]);

        // A missing registry is empty rather than an error.
        assert!(Registry::load(Path::new("/nonexistent/rvn")).names().is_empty());
    }

    #[test]
    fn forgetting_removes_the_entry() {
        let dir = std::env::temp_dir().join("rvn-devel-forget");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut registry = Registry::default();
        registry.record(
            "gone-git",
            Tracked {
                url: "https://host/r.git".into(),
                commit: "abc".into(),
            },
        );
        registry.forget("gone-git");
        registry.save(&dir).unwrap();

        // An uninstalled package must not leave tracking behind.
        assert!(Registry::load(&dir).get("gone-git").is_none());
        // Forgetting something absent is harmless.
        registry.forget("never-there");
    }

    #[test]
    fn only_moved_upstreams_are_reported() {
        let mut registry = Registry::default();
        registry.record(
            "unreachable-git",
            Tracked {
                // An unresolvable host stands in for an unreachable remote.
                url: "https://invalid.invalid/nope.git".into(),
                commit: "abc".into(),
            },
        );

        // An unreachable remote must not be reported as out of date, or every
        // offline update would propose rebuilding the world.
        let names = vec!["unreachable-git".to_string()];
        assert!(outdated(&registry, &names).is_empty());

        // A package with no recorded state is likewise not reported.
        assert!(outdated(&registry, &["untracked-git".to_string()]).is_empty());
    }
}
