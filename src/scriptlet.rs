//! Package install scriptlets (`.INSTALL`).
//!
//! A scriptlet is a bash file defining optional hook functions that run around
//! a transaction. rvn stores it alongside the package record — exactly where
//! pacman keeps it — so removal hooks still work long after installation.
//!
//! A failing scriptlet warns rather than aborting: pacman behaves the same way,
//! and rolling a half-applied transaction back over a failed `post_install`
//! would be worse than continuing.
//!
//! A scriptlet is the most privileged thing a package gets to do: arbitrary
//! bash, as root, against the real system. Two things follow from that and both
//! live in this module. The file is staged in a directory only its owner can
//! open, because between writing the script and handing it to bash there is a
//! window in which whoever can rewrite the file chooses what root executes; and
//! every run is appended to the package log, because a root shell that leaves
//! no trace is the one nobody can account for afterwards.

// The log line wears pacman.log's timestamp, which is `audit`'s to compute --
// see the note on `audit::timestamp` for why one module owns the calendar.
use crate::audit::{now_unix, timestamp};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    PreInstall,
    PostInstall,
    PreUpgrade,
    PostUpgrade,
    PreRemove,
    PostRemove,
}

impl Hook {
    /// The bash function pacman looks for.
    pub fn function(self) -> &'static str {
        match self {
            Hook::PreInstall => "pre_install",
            Hook::PostInstall => "post_install",
            Hook::PreUpgrade => "pre_upgrade",
            Hook::PostUpgrade => "post_upgrade",
            Hook::PreRemove => "pre_remove",
            Hook::PostRemove => "post_remove",
        }
    }

    /// Whether this hook runs before the filesystem is touched.
    pub fn is_pre(self) -> bool {
        matches!(self, Hook::PreInstall | Hook::PreUpgrade | Hook::PreRemove)
    }

    /// The install-time hook for a transaction, which differs for an upgrade.
    pub fn for_install(upgrading: bool, pre: bool) -> Hook {
        match (upgrading, pre) {
            (true, true) => Hook::PreUpgrade,
            (true, false) => Hook::PostUpgrade,
            (false, true) => Hook::PreInstall,
            (false, false) => Hook::PostInstall,
        }
    }
}

/// Whether a scriptlet defines a given hook.
///
/// Checked before spawning bash: most scriptlets define only one or two hooks,
/// and starting a shell for a function that does not exist is pure overhead.
pub fn defines(script: &str, hook: Hook) -> bool {
    let name = hook.function();
    script.lines().map(str::trim).any(|line| {
        // Matches `post_install() {`, `post_install ()`, and `function post_install`.
        line.strip_prefix("function ")
            .unwrap_or(line)
            .trim_start()
            .strip_prefix(name)
            .map(|rest| rest.trim_start().starts_with('('))
            .unwrap_or(false)
    })
}

/// Candidate staging directories, inside the install root, best first.
///
/// A scriptlet has to live inside the root for `chroot` to reach it, so the
/// choice is between directories of the target system. It used to be staged at
/// `<root>/tmp/rvn-scriptlet-<package>`: a name anybody could predict, in a
/// directory anybody can write to, for a file root is about to execute. The
/// script is written and then handed to bash as a path, so between those two
/// moments an unprivileged process that wins the race replaces the file and
/// chooses what root runs. Unlinking it afterwards does nothing about that.
///
/// `/run` is preferred because its parent is root-owned and mode 0755, so no
/// unprivileged process can create anything there in the first place, and
/// because it is a tmpfs: a machine that loses power mid-transaction does not
/// come back with a stale scriptlet on disk. `/tmp` remains as a fallback for
/// the case where /run is not writable -- an install root that is not a running
/// system, and rvn's own tests -- and is safe there only because of what
/// [`staging_dir`] insists on below: the directory must be ours and mode 0700,
/// which is exactly the guarantee `mktemp -d` gives and the old path did not.
const STAGING_DIRS: &[&str] = &["run/rvn/scriptlet", "tmp/rvn-scriptlet"];

/// Prepares the private directory a scriptlet is staged in.
///
/// The returned directory is owned by this process's effective user and
/// readable by nobody else. An existing directory is reused -- rvn runs several
/// scriptlets per transaction and there is no reason to churn it -- but only
/// after it has been proved to still be a directory rather than a symlink
/// somebody swapped in, and its mode is re-asserted rather than trusted, so a
/// directory left behind by an older rvn that created it 0755 is tightened
/// before anything is written into it.
fn staging_dir(root: &Path) -> std::io::Result<PathBuf> {
    let mut last = None;
    for candidate in STAGING_DIRS {
        // The fallback carries the uid so two accounts on one machine cannot
        // collide on it; the /run path is root's alone in practice, but the
        // suffix costs nothing and keeps the two spellings the same shape.
        let dir = root.join(format!("{candidate}.{}", euid()));
        match prepare_staging_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no staging directory was configured",
        )
    }))
}

fn prepare_staging_dir(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Created 0700 in one step, so there is never an instant in which the
    // directory exists and anyone else can open it.
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(dir)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(e);
    }

    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if meta.uid() != euid() {
        // Somebody else got there first. On /tmp that is the attack this
        // directory exists to prevent; refusing sends us to the next candidate
        // and, if there is none, fails the scriptlet rather than running a
        // script out of a directory a stranger controls.
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} belongs to another user", dir.display()),
        ));
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Where one package's scriptlet is staged within that directory.
///
/// The directory is the whole of the protection, so the file name only has to
/// be unique and legible: the package it belongs to, and the pid, so two rvn
/// processes running as the same user do not write over each other.
fn staging_path(dir: &Path, package: &str) -> PathBuf {
    dir.join(format!("{package}.{}", std::process::id()))
}

/// The effective uid, to check that a staging directory is ours.
///
/// Declared here rather than taken from a crate: this codebase has no `libc`
/// dependency and hand-rolls the handful of calls it needs, the same way
/// `ops::is_root` does for the very same function.
fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc_geteuid() }
}

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Builds the command that runs one hook.
///
/// When the install root is not `/`, the scriptlet is executed inside it with
/// `chroot`, so a package's own post-install work lands in the target system
/// rather than the host.
pub fn command(
    root: &Path,
    script_in_root: &Path,
    hook: Hook,
    new_version: &str,
    old_version: Option<&str>,
) -> Command {
    // `source` then call: the scriptlet is a library of functions, not a
    // program with a main body.
    let script_arg = format!("/{}", script_in_root.display());
    let mut inline = format!(". {script_arg}; {}", hook.function());
    if let Some(old) = old_version {
        inline.push_str(&format!(" '{new_version}' '{old}'"));
    } else {
        inline.push_str(&format!(" '{new_version}'"));
    }

    if root == Path::new("/") {
        let mut command = Command::new("bash");
        command.arg("-c").arg(inline);
        command
    } else {
        let mut command = Command::new("chroot");
        command.arg(root).arg("bash").arg("-c").arg(inline);
        command
    }
}

/// Writes the scriptlet out, readable and writable by its owner and nobody
/// else.
///
/// The mode is part of the `open` rather than a `set_permissions` afterwards:
/// a file created at the process umask and then tightened is world-readable
/// for as long as those two calls take, and the contents of a scriptlet are
/// the one thing worth reading before deciding what to replace it with.
///
/// Anything already at the path is unlinked first, because a mode given to
/// `open` applies only when `open` creates the file. A run killed between
/// staging and unlinking leaves one behind, and writing through to it would
/// keep whatever mode and whatever hard links that file already had --
/// inheriting exactly the state this function exists to avoid. Truncation
/// stays as well, so a shorter script can never end up with a longer one's
/// tail still attached.
fn stage(path: &Path, script: &[u8]) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(script)
}

#[derive(Debug)]
pub enum Outcome {
    /// The hook ran successfully.
    Ran,
    /// The scriptlet does not define this hook.
    NotDefined,
    /// The hook ran and failed; the message is what it reported.
    Failed(String),
}

/// Runs one hook from a scriptlet.
pub fn run(
    root: &Path,
    package: &str,
    script: &[u8],
    hook: Hook,
    new_version: &str,
    old_version: Option<&str>,
) -> Outcome {
    let text = String::from_utf8_lossy(script);
    if !defines(&text, hook) {
        return Outcome::NotDefined;
    }

    // The scriptlet has to live inside the root for chroot to reach it.
    let dir = match staging_dir(root) {
        Ok(dir) => dir,
        Err(e) => return Outcome::Failed(format!("could not stage the scriptlet: {e}")),
    };
    let staged = staging_path(&dir, package);
    if let Err(e) = stage(&staged, script) {
        return Outcome::Failed(format!("could not stage the scriptlet: {e}"));
    }

    let relative = staged.strip_prefix(root).unwrap_or(&staged);
    let result = command(root, relative, hook, new_version, old_version).output();
    let _ = std::fs::remove_file(&staged);

    match result {
        Ok(output) if output.status.success() => Outcome::Ran,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("scriptlet failed")
                .trim()
                .to_string();
            Outcome::Failed(message)
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// Appends one scriptlet execution to `log`.
///
/// Every other privileged thing rvn does leaves a record: a package that is
/// installed is in the local database, a package that is removed is a line in
/// this same file (`ops::remove::log_removed` writes it). A scriptlet was the
/// exception, and it is the part with the most authority -- arbitrary bash as
/// root, which runs whether or not anybody was watching the terminal, and which
/// through `rvnd` runs with no terminal at all. Afterwards there was nothing on
/// disk to say it had happened, so "what did that update actually run on this
/// machine" had no answer.
///
/// The line says who ran, which hook, and how it ended; the layout is
/// pacman.log's `[timestamp] [RVN] ...` so that whatever already reads that
/// file reads these too. What the scriptlet *printed* is deliberately not
/// recorded: a chatty `post_install` would then decide how much of the log it
/// gets, and an unbounded write into /var/log driven by package content is its
/// own problem. A failure's last stderr line is kept, because that is the
/// sentence someone reading the log afterwards needs.
///
/// Nothing is written for a `--user` install, because nothing runs:
/// `ops::install::run_scriptlet` skips scriptlets under a per-user prefix,
/// which has no root. There is no root shell to account for, and a log of
/// things that did not happen, written into a file an unprivileged install
/// cannot open anyway, would be two mistakes rather than none.
pub fn log_execution(log: &Path, package: &str, hook: Hook, result: &str) -> std::io::Result<()> {
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    writeln!(
        file,
        "[{}] [RVN] scriptlet {package}: {} {result}",
        timestamp(now_unix()),
        hook.function()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = r#"
post_install() {
    echo "installed $1"
}

function pre_remove () {
    echo "removing $1"
}

post_upgrade() {
  echo "upgraded $1 from $2"
}
"#;

    #[test]
    fn detects_defined_hooks() {
        assert!(defines(SCRIPT, Hook::PostInstall));
        assert!(defines(SCRIPT, Hook::PostUpgrade));
        // Declared with the `function` keyword and a space before `()`.
        assert!(defines(SCRIPT, Hook::PreRemove));

        assert!(!defines(SCRIPT, Hook::PreInstall));
        assert!(!defines(SCRIPT, Hook::PreUpgrade));
        assert!(!defines(SCRIPT, Hook::PostRemove));
    }

    #[test]
    fn does_not_match_a_mere_mention() {
        // A call or comment must not count as a definition.
        let script = "# post_install is intentionally omitted\npre_install() { post_install; }\n";
        assert!(!defines(script, Hook::PostInstall));
        assert!(defines(script, Hook::PreInstall));
    }

    #[test]
    fn picks_the_right_hook_for_the_transaction() {
        assert_eq!(Hook::for_install(false, true), Hook::PreInstall);
        assert_eq!(Hook::for_install(false, false), Hook::PostInstall);
        assert_eq!(Hook::for_install(true, true), Hook::PreUpgrade);
        assert_eq!(Hook::for_install(true, false), Hook::PostUpgrade);
        assert!(Hook::PreInstall.is_pre());
        assert!(!Hook::PostInstall.is_pre());
    }

    #[test]
    fn install_command_passes_only_the_new_version() {
        let command = command(
            Path::new("/"),
            Path::new("tmp/s"),
            Hook::PostInstall,
            "1.2-1",
            None,
        );
        assert_eq!(command.get_program(), "bash");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let inline = args.last().unwrap();
        assert!(inline.contains("post_install '1.2-1'"), "{inline}");
        assert!(!inline.contains("''"), "no empty second argument: {inline}");
    }

    #[test]
    fn upgrade_command_passes_both_versions() {
        let command = command(
            Path::new("/"),
            Path::new("tmp/s"),
            Hook::PostUpgrade,
            "2.0-1",
            Some("1.0-1"),
        );
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let inline = args.last().unwrap();
        // pacman's order is new then old.
        assert!(inline.contains("post_upgrade '2.0-1' '1.0-1'"), "{inline}");
    }

    #[test]
    fn a_non_root_install_runs_inside_a_chroot() {
        let command = command(
            Path::new("/mnt/target"),
            Path::new("tmp/s"),
            Hook::PostInstall,
            "1.0-1",
            None,
        );
        assert_eq!(command.get_program(), "chroot");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(args[0], "/mnt/target");
        assert_eq!(args[1], "bash");
    }

    #[test]
    fn undefined_hook_is_skipped_without_running_anything() {
        let root = std::env::temp_dir().join("rvn-scriptlet-skip");
        std::fs::create_dir_all(&root).unwrap();
        let outcome = run(
            &root,
            "demo",
            b"post_install() { exit 1; }",
            Hook::PreRemove,
            "1.0-1",
            None,
        );
        assert!(matches!(outcome, Outcome::NotDefined));
    }

    #[test]
    fn a_defined_hook_runs_and_reports_failure() {
        // Executes for real against `/`, so keep the hooks trivial.
        let root = Path::new("/");

        let ok = run(
            root,
            "rvn-selftest-ok",
            b"post_install() { true; }",
            Hook::PostInstall,
            "1.0-1",
            None,
        );
        assert!(matches!(ok, Outcome::Ran), "{ok:?}");

        let bad = run(
            root,
            "rvn-selftest-bad",
            b"post_install() { echo 'boom' >&2; false; }",
            Hook::PostInstall,
            "1.0-1",
            None,
        );
        match bad {
            Outcome::Failed(message) => assert!(message.contains("boom"), "{message}"),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn the_staging_directory_is_private_and_so_is_the_script() {
        let root = std::env::temp_dir().join("rvn-scriptlet-private");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let dir = staging_dir(&root).unwrap();
        // /run is not writable by a test, so the fallback is what is exercised
        // here -- and the fallback is only safe if it is 0700.
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "{}",
            dir.display()
        );

        let staged = staging_path(&dir, "demo");
        stage(&staged, b"post_install() { true; }").unwrap();
        assert_eq!(
            std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
            0o600,
            "a script root is about to run must not be readable by anyone else"
        );
        // Not the old predictable name in the shared directory.
        assert!(!root.join("tmp/rvn-scriptlet-demo").exists());
    }

    #[test]
    fn a_staging_directory_owned_by_somebody_else_is_refused() {
        if euid() == 0 {
            // The whole point is a directory this process does not own, and
            // root owns everything.
            return;
        }
        // Stands in for a directory planted by another account before rvn got
        // there: /proc is root's and no test can come to own it.
        let err = prepare_staging_dir(Path::new("/proc")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }

    #[test]
    fn a_relaxed_directory_left_by_an_older_rvn_is_tightened() {
        let dir = std::env::temp_dir().join("rvn-scriptlet-relaxed");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        prepare_staging_dir(&dir).unwrap();

        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn every_execution_leaves_a_line_in_the_log() {
        let log = std::env::temp_dir().join("rvn-scriptlet-log/pacman.log");
        let _ = std::fs::remove_dir_all(log.parent().unwrap());

        log_execution(&log, "linux", Hook::PostInstall, "ran").unwrap();
        log_execution(&log, "shadow", Hook::PostUpgrade, "failed: boom").unwrap();

        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(
            lines[0].contains("[RVN] scriptlet linux: post_install ran"),
            "{text}"
        );
        assert!(
            lines[1].contains("[RVN] scriptlet shadow: post_upgrade failed: boom"),
            "{text}"
        );
        // pacman.log's own layout, so whatever reads that file reads these.
        assert!(lines[0].starts_with('['), "{text}");
        assert!(lines[0].contains("+0000]"), "{text}");
    }

    #[test]
    fn the_new_version_reaches_the_hook() {
        let marker = std::env::temp_dir().join("rvn-scriptlet-version");
        let _ = std::fs::remove_file(&marker);
        let script = format!(
            "post_install() {{ printf '%s' \"$1\" > {}; }}",
            marker.display()
        );
        let outcome = run(
            Path::new("/"),
            "rvn-selftest-version",
            script.as_bytes(),
            Hook::PostInstall,
            "3.1-4",
            None,
        );
        assert!(matches!(outcome, Outcome::Ran), "{outcome:?}");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "3.1-4");
    }
}
