//! What the distribution runs around a transaction, before and after.
//!
//! The `hooks` module next door is about what a *package* asks the system to
//! do -- its sysusers.d and tmpfiles.d declarations, applied one package at a
//! time as each is unpacked. This is the other kind of hook, the one pacman
//! means by the word: something the machine's administrator, or a component
//! of Raven itself, wants run once around the transaction as a whole.
//!
//! It exists because of rollback. rvn cannot undo an install: a file the
//! payload overwrites is gone the moment it is written and nothing keeps a
//! copy, which `extract::unpack` says in as many words. The only honest
//! answer is a snapshot taken before the first file is written, and taking
//! one is not the package manager's business -- it depends on whether the
//! machine is on btrfs, or zfs, or neither, and on where the administrator
//! wants the snapshots kept. So rvn does not take a snapshot. It provides the
//! moment: a hook that runs after the plan is approved and before anything is
//! fetched, whose failure can still stop the transaction because stopping it
//! costs nothing yet.
//!
//! A hook is one TOML file in
//!
//!   usr/share/rvn/hooks.d/   shipped by a component
//!   etc/rvn/hooks.d/         written by the machine's administrator
//!
//! read in file-name order across both directories, the same two-tier layout
//! `provides` already uses. A file in etc replaces a shipped file of the same
//! name, so a component's hook can be changed without editing a file the next
//! upgrade will overwrite; a file with nothing in it replaces a shipped hook
//! with nothing, which is how one is switched off.
//!
//! ```text
//! # /etc/rvn/hooks.d/50-snapshot.toml
//!
//! [trigger]
//! when = "pre-transaction"
//! operations = ["install", "update", "remove"]
//! paths = ["etc/**", "usr/**"]
//!
//! [run]
//! description = "snapshotting the root subvolume"
//! exec = "/usr/lib/rvn/snapshot"
//! args = ["--label", "before-rvn"]
//! abort_on_fail = true
//! ```
//!
//! Failure is deliberately asymmetric, because the two moments are not alike.
//! A pre-transaction hook that fails with `abort_on_fail` stops the
//! transaction before a single file has been written, and that is a real
//! promise worth making: a snapshot that did not happen is an excellent
//! reason not to upgrade. A post-transaction hook that fails is a warning and
//! nothing more. By then the packages are on disk and registered, and
//! reporting the transaction as failed because something after it went wrong
//! would be a lie that the next `rvn update` -- which would find everything
//! already installed -- immediately contradicts.
//!
//! Hooks run as whatever rvn is, which for any transaction that touches `/`
//! is root. The environment is cleared and rebuilt with the same three
//! variables rvnd hands rvn (see `daemon`), so a hook behaves identically
//! whether the install was started from a terminal, through `sudo`, or by the
//! desktop's package store over rvnd's socket -- an ambient environment is
//! the difference between those three, and a hook that behaves differently
//! depending on who started the install is a bug nobody will find. What the
//! hook needs to know it is told outright: `RVN_HOOK_WHEN`,
//! `RVN_HOOK_OPERATIONS` and `RVN_HOOK_ROOT`.
//!
//! `rvn --user` runs none of this. These files are system policy: they live
//! under /etc, they are written expecting root, and a per-user prefix has
//! neither root nor the system's root directory -- a snapshot hook pointed at
//! `/` would be actively wrong there, and one pointed at the prefix would not
//! be the hook anybody wrote. Scriptlets and sysusers.d are already skipped
//! for a per-user prefix for the same reason; this says so once rather than
//! failing per hook.

use crate::toml::{Document, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Directories holding hook files, relative to the install root, in the order
/// they are read: a file in the second replaces one of the same name in the
/// first.
pub const DIRS: &[&str] = &["usr/share/rvn/hooks.d", "etc/rvn/hooks.d"];

/// Which side of the transaction a hook runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    Pre,
    Post,
}

impl When {
    /// The spelling used in the file and in the event stream.
    pub fn as_str(self) -> &'static str {
        match self {
            When::Pre => "pre-transaction",
            When::Post => "post-transaction",
        }
    }

    fn parse(text: &str) -> Option<When> {
        match text {
            "pre-transaction" => Some(When::Pre),
            "post-transaction" => Some(When::Post),
            _ => None,
        }
    }
}

/// What a transaction is doing, from a hook's point of view.
///
/// A transaction can be more than one of these at once and usually is: a
/// system upgrade that pulls in a new dependency installs something *and*
/// updates something. Both are reported, and a hook fires if it asked for any
/// of them, so a hook that only cares about upgrades is not silently skipped
/// the one time an upgrade also brought something new.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Install,
    Remove,
    Update,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Operation::Install => "install",
            Operation::Remove => "remove",
            Operation::Update => "update",
        }
    }

    fn parse(text: &str) -> Option<Operation> {
        match text {
            "install" => Some(Operation::Install),
            "remove" => Some(Operation::Remove),
            "update" => Some(Operation::Update),
            _ => None,
        }
    }
}

/// What a transaction is about to do, or has just done.
///
/// The file list is what `paths` triggers are matched against, and how much
/// of it rvn can honestly offer differs by moment. Before an install it is
/// the files the transaction's packages own *now* -- which for an upgrade is
/// what is about to be replaced, and for a package the machine has never seen
/// is nothing at all, because the archive that would answer the question has
/// not been downloaded yet and downloading it is the thing the hook may be
/// about to veto. After an install it is what those packages own now that
/// they are registered, which is exact. Before a removal it is exact too: the
/// records are still there and they list precisely what is about to be
/// deleted.
///
/// A hook that must see the files a not-yet-fetched package will ship is
/// therefore a post-transaction hook, and the module documentation says so.
#[derive(Debug)]
pub struct Transaction {
    operations: Vec<Operation>,
    packages: Vec<String>,
    files: Vec<String>,
}

impl Transaction {
    pub fn new(
        operations: Vec<Operation>,
        packages: Vec<String>,
        files: Vec<String>,
    ) -> Transaction {
        Transaction {
            operations,
            packages,
            files,
        }
    }

    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn packages(&self) -> &[String] {
        &self.packages
    }
}

/// One hook file.
#[derive(Debug)]
pub struct Hook {
    /// The file name, which is what the user is told when it fails: file-name
    /// order is the run order, so the name is the thing they can act on.
    pub name: String,
    pub source: PathBuf,
    pub when: When,
    pub operations: Vec<Operation>,
    /// Package-name globs. Empty, together with `paths`, means every
    /// transaction of the right kind.
    pub packages: Vec<String>,
    /// Root-relative path globs, matched against the transaction's file list.
    pub paths: Vec<String>,
    pub description: Option<String>,
    pub exec: PathBuf,
    pub args: Vec<String>,
    /// Whether a failure stops the transaction. Only a pre-transaction hook
    /// may set it; see the module documentation for why.
    pub abort_on_fail: bool,
}

impl Hook {
    /// What to show while it runs: the description if it has one, because
    /// "snapshotting the root subvolume" tells somebody staring at a stalled
    /// terminal what is happening and "50-snapshot.toml" does not.
    pub fn label(&self) -> &str {
        self.description.as_deref().unwrap_or(&self.name)
    }

    /// Whether this hook wants to run for `transaction`.
    ///
    /// A hook with neither `packages` nor `paths` matches every transaction of
    /// the right kind, which is what a snapshot hook wants. Given both, either
    /// one matching is enough: they are two ways of describing the same
    /// interest, not two conditions to satisfy at once.
    pub fn matches(&self, transaction: &Transaction) -> bool {
        if !self
            .operations
            .iter()
            .any(|op| transaction.operations.contains(op))
        {
            return false;
        }
        if self.packages.is_empty() && self.paths.is_empty() {
            return true;
        }
        let by_name = self.packages.iter().any(|pattern| {
            transaction
                .packages
                .iter()
                .any(|name| glob_matches(pattern, name))
        });
        let by_path = self.paths.iter().any(|pattern| {
            transaction
                .files
                .iter()
                .any(|file| glob_matches(trim_root(pattern), trim_root(file)))
        });
        by_name || by_path
    }

    /// Runs the hook to completion, returning what to tell the user if it
    /// failed.
    ///
    /// The hook's own output is captured and then discarded unless it failed,
    /// in which case the last thing it said on stderr becomes part of the
    /// message. A stage is animating the terminal while this runs, and
    /// letting a hook paint over it would make both unreadable; `scriptlet`
    /// discards scriptlet output for the same reason.
    pub fn run(&self, root: &Path, transaction: &Transaction) -> Result<(), String> {
        let operations: Vec<&str> = transaction
            .operations
            .iter()
            .map(|op| op.as_str())
            .collect();

        let mut command = Command::new(&self.exec);
        command
            .args(&self.args)
            // Never rvn's own working directory: it may be anywhere, it may
            // have been deleted, and a hook that resolves a relative path
            // against it would do something different every run.
            .current_dir(if root.is_dir() { root } else { Path::new("/") })
            .stdin(Stdio::null())
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", "/root")
            .env("LANG", "C.UTF-8")
            .env("RVN_HOOK_WHEN", self.when.as_str())
            .env("RVN_HOOK_OPERATIONS", operations.join(" "))
            .env("RVN_HOOK_ROOT", root);

        let output = command
            .output()
            .map_err(|e| format!("could not run {}: {e}", self.exec.display()))?;
        if output.status.success() {
            return Ok(());
        }

        let status = match output.status.code() {
            Some(code) => format!("exited {code}"),
            None => "was killed by a signal".to_string(),
        };
        let stderr = String::from_utf8_lossy(&output.stderr);
        match stderr.lines().rev().find(|line| !line.trim().is_empty()) {
            Some(last) => Err(format!("{status}: {}", last.trim())),
            None => Err(status),
        }
    }
}

/// Every hook on the machine, in the order they run.
#[derive(Debug, Default)]
pub struct Set {
    hooks: Vec<Hook>,
}

impl Set {
    /// Reads every hook file under `root`.
    ///
    /// A missing directory is not an error -- a machine with no hooks is the
    /// normal case, and the common one for a long time yet. A file that is
    /// *there* and does not parse is a hard error, and the caller turns it
    /// into a refused transaction: a hook file is policy somebody wrote down,
    /// and running an upgrade while quietly ignoring the thing meant to
    /// snapshot it first is the one behaviour this module must not have.
    pub fn load(root: &Path) -> Result<Set, String> {
        // Keyed by file name so etc/ replaces a shipped file of the same
        // name, and sorted by it so the order a person reads in the directory
        // listing is the order things run in.
        let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
        for dir in DIRS {
            let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // Followed rather than checked with `file_type`, so a hook
                // symlinked in from somewhere else is a hook. It also means a
                // symlink to /dev/null is not a regular file and so is not
                // read at all, which is how pacman's hooks are switched off
                // and costs nothing to keep working here.
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if name.starts_with('.') || !name.ends_with(".toml") {
                    continue;
                }
                files.insert(name.to_string(), path.clone());
            }
        }

        let mut hooks = Vec::new();
        for (name, path) in files {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let document =
                Document::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            // A hook file with nothing in it is a hook deliberately switched
            // off, not a broken one: it is how an administrator disables a
            // shipped hook without deleting a file the next upgrade restores.
            if document.is_empty() {
                continue;
            }
            hooks.push(
                parse_hook(&document, name, &path)
                    .map_err(|e| format!("{}: {e}", path.display()))?,
            );
        }

        Ok(Set { hooks })
    }

    /// Whether the machine has any hook files at all, without reading them.
    ///
    /// Used only to decide whether a per-user install should mention that it
    /// is skipping them. It must not parse: a file with a typo in it is a
    /// reason to refuse a system transaction, and no reason at all to refuse
    /// an unprivileged install into somebody's home directory.
    pub fn present(root: &Path) -> bool {
        DIRS.iter().any(|dir| {
            std::fs::read_dir(root.join(dir)).is_ok_and(|mut entries| {
                entries.any(|entry| {
                    entry.is_ok_and(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|n| !n.starts_with('.') && n.ends_with(".toml"))
                    })
                })
            })
        })
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Whether any hook for this moment triggers on paths.
    ///
    /// Building the file list means reading a `files` record per package,
    /// which for a full system upgrade is a thousand small reads for nothing
    /// if no hook asked. The caller checks this first and passes an empty
    /// list when the answer is no.
    pub fn wants_paths(&self, when: When) -> bool {
        self.hooks
            .iter()
            .any(|hook| hook.when == when && !hook.paths.is_empty())
    }

    /// The hooks to run for this moment, in file-name order.
    pub fn matching(&self, when: When, transaction: &Transaction) -> Vec<&Hook> {
        self.hooks
            .iter()
            .filter(|hook| hook.when == when && hook.matches(transaction))
            .collect()
    }
}

/// The sections a hook file may have, and the keys in each.
///
/// Listed so an unrecognised one can be refused by name. A key that is
/// silently ignored is the worst outcome available here: the administrator
/// believes the machine is snapshotting before every upgrade, and it is not.
const TRIGGER_KEYS: &[&str] = &["when", "operations", "packages", "paths"];
const RUN_KEYS: &[&str] = &["description", "exec", "args", "abort_on_fail"];

fn parse_hook(document: &Document, name: String, path: &Path) -> Result<Hook, String> {
    for section in document.sections() {
        let known = match section.name.as_str() {
            "trigger" => TRIGGER_KEYS,
            "run" => RUN_KEYS,
            "" if section.is_empty() => continue,
            "" => {
                return Err(format!(
                    "line {}: a hook's keys belong under [trigger] or [run]",
                    section.line_of(section.keys().next().unwrap_or_default())
                ));
            }
            other => {
                return Err(format!(
                    "line {}: [{other}] is not a section of a hook file; it has [trigger] and [run]",
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

    let trigger = document
        .section("trigger")
        .ok_or("a hook needs a [trigger] section saying when it runs")?;
    let run = document
        .section("run")
        .ok_or("a hook needs a [run] section saying what to run")?;

    let when_value = trigger
        .get("when")
        .ok_or("[trigger] needs `when`: \"pre-transaction\" or \"post-transaction\"")?;
    let when = when_value.as_str().and_then(When::parse).ok_or_else(|| {
        format!(
            "line {}: `when` is \"pre-transaction\" or \"post-transaction\"",
            trigger.line_of("when")
        )
    })?;

    // Every operation by default. A hook that names none is asking to run
    // around any transaction, which is what a snapshot hook means.
    let operations = match trigger.get("operations") {
        None => vec![Operation::Install, Operation::Remove, Operation::Update],
        Some(value) => {
            let names = strings(value, trigger.line_of("operations"), "operations")?;
            if names.is_empty() {
                return Err(format!(
                    "line {}: `operations` with nothing in it would never run; leave the key out to run for every operation",
                    trigger.line_of("operations")
                ));
            }
            let mut operations = Vec::new();
            for name in names {
                let operation = Operation::parse(&name).ok_or_else(|| {
                    format!(
                        "line {}: `{name}` is not an operation; they are install, remove and update",
                        trigger.line_of("operations")
                    )
                })?;
                operations.push(operation);
            }
            operations
        }
    };

    let packages = match trigger.get("packages") {
        None => Vec::new(),
        Some(value) => strings(value, trigger.line_of("packages"), "packages")?,
    };
    let paths = match trigger.get("paths") {
        None => Vec::new(),
        Some(value) => strings(value, trigger.line_of("paths"), "paths")?,
    };

    let exec = run
        .get("exec")
        .ok_or("[run] needs `exec`: the absolute path of the program to run")?;
    let exec = exec.as_str().ok_or_else(|| {
        format!(
            "line {}: `exec` is a path, found {}",
            run.line_of("exec"),
            exec.kind()
        )
    })?;
    if !exec.starts_with('/') {
        // Hooks run with an environment rvn built, not an inherited one, so
        // what is on the PATH here is rvn's decision rather than the
        // administrator's. Naming the program outright removes the question.
        return Err(format!(
            "line {}: `exec` is an absolute path -- a hook runs with an environment rvn built, so a bare name would resolve against a PATH nobody wrote",
            run.line_of("exec")
        ));
    }

    let args = match run.get("args") {
        None => Vec::new(),
        Some(value) => strings(value, run.line_of("args"), "args")?,
    };

    let description = match run.get("description") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| {
                    format!(
                        "line {}: `description` is a string",
                        run.line_of("description")
                    )
                })?
                .to_string(),
        ),
    };

    let abort_on_fail = match run.get("abort_on_fail") {
        None => false,
        Some(value) => value.as_bool().ok_or_else(|| {
            format!(
                "line {}: `abort_on_fail` is true or false, found {}",
                run.line_of("abort_on_fail"),
                value.kind()
            )
        })?,
    };
    if abort_on_fail && when == When::Post {
        // Refused rather than ignored. Somebody writing this believes a
        // failure here will undo something, and there is nothing left to
        // undo: the packages are installed and registered by the time a
        // post-transaction hook runs. Saying so now beats finding out during
        // the upgrade it was supposed to protect.
        return Err(format!(
            "line {}: `abort_on_fail` has nothing to abort in a post-transaction hook -- the packages are already installed. Move the hook to \"pre-transaction\", or drop the key",
            run.line_of("abort_on_fail")
        ));
    }

    Ok(Hook {
        name,
        source: path.to_path_buf(),
        when,
        operations,
        packages,
        paths,
        description,
        exec: PathBuf::from(exec),
        args,
        abort_on_fail,
    })
}

/// A list-of-strings key, refusing a list with a number in it by name.
fn strings(value: &Value, line: usize, key: &str) -> Result<Vec<String>, String> {
    value.as_strings().ok_or_else(|| {
        format!(
            "line {line}: `{key}` is a list of strings, found {}",
            value.kind()
        )
    })
}

/// A path written with or without its leading slash, so `/etc/**` and
/// `etc/**` mean the same thing.
///
/// The database records paths root-relative and without one; a person writing
/// a hook file writes the path as they would type it into a shell. Both are
/// obviously intended to mean the same file, so both do.
fn trim_root(path: &str) -> &str {
    path.trim_start_matches('/')
}

/// Whether `text` matches the glob `pattern`.
///
/// `?` is a single character, `*` is any run of characters within one path
/// component, and `**` is any run at all including `/`. So `etc/*` is the
/// files directly in /etc, `etc/**` is everything below it, and `linux-*`
/// catches `linux-headers` but a package name has no slashes in it for the
/// distinction to matter.
///
/// There are no character classes and no brace expansion. Hook triggers are
/// written once and read often; the day somebody needs `[a-z]` to express
/// which packages they care about, the answer is two hooks.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    matches_from(&pattern, &text)
}

fn matches_from(pattern: &[char], text: &[char]) -> bool {
    match pattern.first() {
        None => text.is_empty(),
        Some('*') => {
            let stars = pattern.iter().take_while(|c| **c == '*').count();
            let rest = &pattern[stars..];
            // One star stops at a path separator; two or more cross it.
            let crosses = stars > 1;
            for taken in 0..=text.len() {
                if !crosses && text[..taken].contains(&'/') {
                    break;
                }
                if matches_from(rest, &text[taken..]) {
                    return true;
                }
            }
            false
        }
        Some('?') => !text.is_empty() && text[0] != '/' && matches_from(&pattern[1..], &text[1..]),
        Some(c) => !text.is_empty() && text[0] == *c && matches_from(&pattern[1..], &text[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root with the given hook files in it, as `(directory, name, text)`.
    fn root(tag: &str, files: &[(&str, &str, &str)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rvn-txhooks-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (dir, name, text) in files {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join(name), text).unwrap();
        }
        root
    }

    fn hook_text(when: &str, extra: &str) -> String {
        format!("[trigger]\nwhen = \"{when}\"\n{extra}\n[run]\nexec = \"/bin/true\"\n")
    }

    fn transaction(operations: Vec<Operation>, packages: &[&str], files: &[&str]) -> Transaction {
        Transaction::new(
            operations,
            packages.iter().map(|s| s.to_string()).collect(),
            files.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn hooks_run_in_file_name_order_and_etc_replaces_what_a_package_shipped() {
        let root = root(
            "order",
            &[
                (
                    "usr/share/rvn/hooks.d",
                    "10-first.toml",
                    &hook_text("pre-transaction", ""),
                ),
                (
                    "usr/share/rvn/hooks.d",
                    "50-shipped.toml",
                    &hook_text("pre-transaction", ""),
                ),
                (
                    "etc/rvn/hooks.d",
                    "50-shipped.toml",
                    "[trigger]\nwhen = \"pre-transaction\"\n[run]\nexec = \"/bin/false\"\n",
                ),
                (
                    "etc/rvn/hooks.d",
                    "20-second.toml",
                    &hook_text("pre-transaction", ""),
                ),
                // Neither of these is a hook file.
                (
                    "etc/rvn/hooks.d",
                    ".hidden.toml",
                    "nonsense that would not parse",
                ),
                (
                    "etc/rvn/hooks.d",
                    "notes.txt",
                    "nonsense that would not parse",
                ),
                // An empty file with a shipped file's name switches it off.
                (
                    "usr/share/rvn/hooks.d",
                    "90-off.toml",
                    &hook_text("pre-transaction", ""),
                ),
                ("etc/rvn/hooks.d", "90-off.toml", "# switched off locally\n"),
            ],
        );

        let set = Set::load(&root).expect("these hooks should load");
        let names: Vec<&str> = set.hooks.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(
            names,
            ["10-first.toml", "20-second.toml", "50-shipped.toml"]
        );
        assert_eq!(
            set.hooks[2].exec,
            PathBuf::from("/bin/false"),
            "the administrator's copy replaces the shipped one"
        );
        assert!(Set::present(&root));
        assert!(Set::load(&root.join("nowhere")).unwrap().is_empty());
        assert!(!Set::present(&root.join("nowhere")));
    }

    #[test]
    fn a_hook_file_that_does_not_parse_refuses_the_transaction_by_name() {
        for (text, says) in [
            (
                "[trigger]\nwhen = \"whenever\"\n[run]\nexec = \"/bin/true\"\n",
                "pre-transaction",
            ),
            ("[run]\nexec = \"/bin/true\"\n", "[trigger]"),
            ("[trigger]\nwhen = \"pre-transaction\"\n", "[run]"),
            (
                "[trigger]\nwhen = \"pre-transaction\"\n[run]\nexec = \"snapshot\"\n",
                "absolute path",
            ),
            (
                "[trigger]\nwhen = \"pre-transaction\"\nwhere = \"x\"\n[run]\nexec = \"/bin/true\"\n",
                "`where` is not a key",
            ),
            (
                "[trigger]\nwhen = \"pre-transaction\"\n[cleanup]\nx = 1\n",
                "[cleanup] is not a section",
            ),
            (
                "when = \"pre-transaction\"\n",
                "belong under [trigger] or [run]",
            ),
            (
                "[trigger]\nwhen = \"pre-transaction\"\noperations = [\"upgrade\"]\n[run]\nexec = \"/bin/true\"\n",
                "not an operation",
            ),
            (
                "[trigger]\nwhen = \"pre-transaction\"\noperations = []\n[run]\nexec = \"/bin/true\"\n",
                "would never run",
            ),
            // The one a person is most likely to write and most likely to
            // believe: an abort that could not abort anything.
            (
                "[trigger]\nwhen = \"post-transaction\"\n[run]\nexec = \"/bin/true\"\nabort_on_fail = true\n",
                "nothing to abort",
            ),
        ] {
            let root = root("broken", &[("etc/rvn/hooks.d", "50-broken.toml", text)]);
            let error = Set::load(&root).expect_err("this hook file should be refused");
            assert!(error.contains(says), "{text:?} -> {error}");
            assert!(error.contains("50-broken.toml"), "{error}");
        }
    }

    #[test]
    fn a_hook_with_no_triggers_runs_for_every_transaction_of_its_kind() {
        let root = root(
            "any",
            &[(
                "etc/rvn/hooks.d",
                "50-snapshot.toml",
                &hook_text("pre-transaction", ""),
            )],
        );
        let set = Set::load(&root).unwrap();

        let install = transaction(vec![Operation::Install], &["ripgrep"], &[]);
        assert_eq!(set.matching(When::Pre, &install).len(), 1);
        assert_eq!(
            set.matching(When::Post, &install).len(),
            0,
            "a pre hook is not a post hook"
        );
        let removal = transaction(vec![Operation::Remove], &["ripgrep"], &[]);
        assert_eq!(set.matching(When::Pre, &removal).len(), 1);
        assert!(
            !set.wants_paths(When::Pre),
            "no paths to match, so no file list is built"
        );
    }

    #[test]
    fn names_and_paths_are_two_ways_to_ask_for_the_same_transaction() {
        let root = root(
            "triggers",
            &[(
                "etc/rvn/hooks.d",
                "50-kernel.toml",
                &hook_text(
                    "post-transaction",
                    "operations = [\"install\", \"update\"]\npackages = [\"linux\", \"linux-*\"]\npaths = [\"/usr/lib/modules/**\"]\n",
                ),
            )],
        );
        let set = Set::load(&root).unwrap();
        assert!(set.wants_paths(When::Post));

        let by_name = transaction(vec![Operation::Update], &["linux-headers"], &[]);
        assert_eq!(set.matching(When::Post, &by_name).len(), 1);

        let by_path = transaction(
            vec![Operation::Install],
            &["nvidia-dkms"],
            &["usr/lib/modules/6.17/extra/nvidia.ko"],
        );
        assert_eq!(
            set.matching(When::Post, &by_path).len(),
            1,
            "the path trigger alone is enough"
        );

        let neither = transaction(vec![Operation::Install], &["ripgrep"], &["usr/bin/rg"]);
        assert!(set.matching(When::Post, &neither).is_empty());

        // The right packages, the wrong operation.
        let removal = transaction(vec![Operation::Remove], &["linux"], &[]);
        assert!(set.matching(When::Post, &removal).is_empty());
    }

    #[test]
    fn one_star_stays_inside_a_path_component_and_two_cross_it() {
        assert!(glob_matches("etc/*", "etc/fstab"));
        assert!(!glob_matches("etc/*", "etc/pam.d/sudo"));
        assert!(glob_matches("etc/**", "etc/pam.d/sudo"));
        assert!(glob_matches("etc/**", "etc/fstab"));
        assert!(!glob_matches("etc/**", "etcetera"));
        assert!(glob_matches("*", "linux"));
        assert!(glob_matches("linux-*", "linux-headers"));
        assert!(!glob_matches("linux-*", "linux"));
        assert!(glob_matches("?inux", "linux"));
        assert!(!glob_matches("?", "a/b"));
        assert!(glob_matches("**/*.conf", "usr/lib/sysusers.d/dbus.conf"));
        // A pattern with no wildcards is an exact path.
        assert!(glob_matches("etc/sudoers", "etc/sudoers"));
        assert!(!glob_matches("etc/sudoers", "etc/sudoers.d/wheel"));
    }

    #[test]
    fn a_leading_slash_is_the_same_path_either_way() {
        let root = root(
            "slash",
            &[(
                "etc/rvn/hooks.d",
                "50-etc.toml",
                &hook_text("pre-transaction", "paths = [\"/etc/**\"]"),
            )],
        );
        let set = Set::load(&root).unwrap();
        let tx = transaction(vec![Operation::Update], &["sudo"], &["etc/sudoers"]);
        assert_eq!(set.matching(When::Pre, &tx).len(), 1);
    }

    #[test]
    fn a_hook_runs_with_an_environment_rvn_built_and_explains_its_own_failure() {
        let root = root(
            "run",
            &[(
                "etc/rvn/hooks.d",
                "50-check.toml",
                // Proves three things at once: the program and its arguments
                // are what the file said, the RVN_HOOK_* variables are set,
                // and env_clear did not take them with it.
                "[trigger]\nwhen = \"pre-transaction\"\n\
                 [run]\nexec = \"/bin/sh\"\n\
                 args = [\"-c\", \"test \\\"$RVN_HOOK_WHEN $RVN_HOOK_OPERATIONS\\\" = 'pre-transaction install update'\"]\n",
            )],
        );
        let set = Set::load(&root).unwrap();
        let tx = transaction(vec![Operation::Install, Operation::Update], &["sudo"], &[]);
        assert_eq!(set.hooks[0].run(&root, &tx), Ok(()));

        // The last thing a failing hook said is what the user is told.
        let noisy = Hook {
            name: "50-noisy.toml".into(),
            source: PathBuf::new(),
            when: When::Pre,
            operations: vec![Operation::Install],
            packages: Vec::new(),
            paths: Vec::new(),
            description: None,
            exec: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".into(),
                "echo ignored >&2; echo 'no space left on device' >&2; exit 4".into(),
            ],
            abort_on_fail: true,
        };
        let message = noisy.run(&root, &tx).expect_err("this hook fails");
        assert!(message.contains("exited 4"), "{message}");
        assert!(message.contains("no space left on device"), "{message}");

        let missing = Hook {
            exec: PathBuf::from("/usr/lib/rvn/no-such-hook"),
            args: Vec::new(),
            ..noisy
        };
        assert!(
            missing
                .run(&root, &tx)
                .expect_err("there is no such program")
                .contains("could not run"),
        );
    }
}
