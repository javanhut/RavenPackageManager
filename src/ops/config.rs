//! `rvn config`: the review desk for configuration files an upgrade spared.
//!
//! When a package ships a new version of a file it declared as `backup` and
//! the copy on disk has been edited, the install keeps what is on disk and
//! writes the package's version beside it with a `.pacnew` suffix. That is the
//! right call -- an upgrade must never silently discard an administrator's
//! work -- but it is only half a decision. Something still has to reconcile
//! the two, and until this module existed nothing in rvn helped, or even
//! reliably said it had happened: the one warning was printed from inside the
//! install loop, onto the line the progress bar was repainting.
//!
//! The machine this was written on had thirty-nine of them waiting in /etc,
//! including sudoers, shadow, group and fstab, some of them years old, and
//! its owner had never seen a single one. Every one of those is a security
//! fix or a format change that was published, downloaded, written to disk and
//! then quietly ignored.
//!
//! So: `list` says what is waiting and how long it has waited, `diff` shows
//! what actually changed, and `merge`, `accept` and `keep` settle it. Each of
//! those three destroys one of the two copies, so each asks first, each keeps
//! a backup of anything it overwrites, and `accept` refuses outright on the
//! files that carry live account state -- a package's /etc/shadow cannot know
//! the passwords on this machine, and taking it would lock everyone out.

use super::Context;
use crate::db::local::LocalDb;
use crate::ui::theme::Color;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// The suffix an install gives the package's copy of a spared file.
const SUFFIX: &str = ".pacnew";

/// Where the file that is on disk goes before anything replaces it.
///
/// pacman's own name for the same thing. An administrator who has met one of
/// these before already knows what it is, which is worth more than a name of
/// rvn's own devising that nobody would recognise at three in the morning.
const ORIGINAL: &str = ".pacorig";

/// Files `accept` refuses to take the package's version of, whatever the
/// person at the keyboard says.
///
/// These are not configuration in the sense the rest of this module means.
/// They are live state that only this machine holds: which accounts exist,
/// what their password hashes are, which groups they are in, and which uid
/// ranges have been delegated to them. A package's copy is a build-time
/// default -- Arch's `filesystem` ships a one-line /etc/passwd, a one-line
/// /etc/group and a root-only /etc/shadow -- and it cannot know any of it.
///
/// Accepting one empties the machine of accounts in a single rename: no uid
/// for the graphical session to run as, no `dbus` user for the system bus, no
/// `video` group for seatd, and no password hash for root. The install path
/// already refuses to let a payload replace these (see `NEVER_REPLACED` in
/// [`super::install`]); this is the same refusal held one step later, because
/// a `.pacnew` for one of them is exactly what that refusal produces, and the
/// obvious next thing to do with a `.pacnew` is accept it.
///
/// `etc/subuid` and `etc/subgid` are on the list for the same reason as the
/// four account files: they record delegations made on this machine, and a
/// package's copy is empty. `merge` and `keep` remain available for all of
/// them -- the refusal is only against taking the package's version whole.
const ACCOUNT_STATE: &[(&str, &str)] = &[
    (
        "etc/passwd",
        "every account on this machine, including the one you log in as",
    ),
    (
        "etc/shadow",
        "the password hash of every account, including root's",
    ),
    ("etc/group", "every group membership on this machine"),
    ("etc/gshadow", "every group's administrators and password"),
    (
        "etc/subuid",
        "the uid ranges delegated to each user for containers",
    ),
    ("etc/subgid", "the gid ranges delegated to each user"),
];

/// What `rvn config` was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    List,
    Diff,
    Merge,
    Accept,
    Keep,
}

impl Action {
    /// The verb as the command line spells it, or `None` for anything else.
    pub fn parse(verb: &str) -> Option<Action> {
        match verb {
            "list" => Some(Action::List),
            "diff" => Some(Action::Diff),
            "merge" => Some(Action::Merge),
            "accept" => Some(Action::Accept),
            "keep" => Some(Action::Keep),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::List => "list",
            Action::Diff => "diff",
            Action::Merge => "merge",
            Action::Accept => "accept",
            Action::Keep => "keep",
        }
    }

    /// Whether this action changes anything on disk. `list` and `diff` never
    /// do, which is what lets them run without root and without the daemon.
    fn writes(self) -> bool {
        matches!(self, Action::Merge | Action::Accept | Action::Keep)
    }
}

/// One configuration file waiting to be reconciled.
#[derive(Debug, Clone)]
pub struct Pending {
    /// The file, relative to the install root: `etc/sudoers`.
    pub path: String,
    /// The copy on disk, which the install kept.
    pub live: PathBuf,
    /// The package's copy, written beside it.
    pub pacnew: PathBuf,
    /// The package that shipped it, where one still declares it as a backup
    /// file. `None` for a `.pacnew` whose package has since been removed or
    /// renamed, which is a real state and not an error.
    pub package: Option<String>,
    /// When the package's copy was written, where the filesystem knows.
    pub written: Option<SystemTime>,
}

impl Pending {
    /// How long the file has been waiting, in seconds.
    fn waited(&self) -> Option<u64> {
        self.written
            .and_then(|written| written.elapsed().ok())
            .map(|age| age.as_secs())
    }

    fn owner(&self) -> &str {
        self.package.as_deref().unwrap_or("no installed package")
    }

    fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.path,
            "package": self.package,
            "pacnew": self.pacnew.display().to_string(),
            "age_seconds": self.waited(),
        })
    }
}

/// Runs one `rvn config` verb over the files it names, or over all of them.
pub fn run(ctx: &mut Context, action: Action, paths: &[String]) -> Result<(), String> {
    let mut pending = discover(&ctx.config.root_dir, &owners(&ctx.local));
    pending.sort_by(|a, b| a.path.cmp(&b.path));

    if !paths.is_empty() {
        let wanted: Vec<String> = paths
            .iter()
            .map(|p| relative_to(p, &ctx.config.root_dir))
            .collect();
        let unknown: Vec<String> = wanted
            .iter()
            .filter(|w| !pending.iter().any(|p| p.path == **w))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(format!(
                "nothing is waiting for {} — `rvn config list` shows what is",
                unknown.join(", ")
            ));
        }
        pending.retain(|p| wanted.contains(&p.path));
    }

    if action.writes() {
        // Asked once, before anything is touched, rather than per file: a run
        // that cannot possibly say yes should say so instead of walking a list
        // declining every question in turn.
        if !ctx.assume_yes && !ctx.ui.style.interactive {
            return Err(format!(
                "`rvn config {}` changes files and there is no terminal to confirm on — pass --yes if that is what you meant",
                action.as_str()
            ));
        }
        if let Some(blocked) = unwritable(&pending) {
            return Err(format!(
                "cannot write to {} — `rvn config {}` needs root, so run it with sudo",
                blocked.display(),
                action.as_str()
            ));
        }
    }

    match action {
        Action::List => {
            list(ctx, &pending);
            Ok(())
        }
        Action::Diff => diff(ctx, &pending),
        Action::Merge | Action::Accept | Action::Keep => {
            let refused = settle(ctx, action, &pending)?;
            // A sweep over everything waiting is allowed to step over the
            // account files and still count as having done its job -- that is
            // the whole point of the refusal. Naming one of them outright is a
            // different matter: the command was asked to do exactly one thing,
            // it did not do it, and exiting successfully would tell a script
            // otherwise.
            if !refused.is_empty() && !paths.is_empty() {
                return Err(format!(
                    "refused to accept {}, for the reason above; `rvn config keep {}` discards the package's copy instead",
                    refused.join(", "),
                    refused.join(" ")
                ));
            }
            Ok(())
        }
    }
}

// ---- finding them ------------------------------------------------------

/// Every `.pacnew` under the install root, with the package that brought it.
///
/// Two passes, because neither alone is complete. The local database knows
/// every path an installed package declares as configuration, wherever it
/// lives, and is the only source that can name the package -- but it cannot
/// see a file left behind by a package that has since been removed. A walk of
/// `/etc` catches those, and is where all but a handful of backup files live.
///
/// What is deliberately not done is a walk of the whole root: a `.pacnew` can
/// only ever appear beside a file some package declared, and walking /home,
/// /proc and a few terabytes of media to look for one would cost far more
/// than it could ever find.
pub fn discover(root: &Path, owners: &HashMap<String, String>) -> Vec<Pending> {
    let mut found: HashMap<String, Pending> = HashMap::new();

    let mut record = |relative: String| {
        let live = root.join(&relative);
        let pacnew = with_suffix(&live, SUFFIX);
        if !pacnew.is_file() {
            return;
        }
        let written = pacnew.metadata().and_then(|m| m.modified()).ok();
        found.entry(relative.clone()).or_insert(Pending {
            package: owners.get(&relative).cloned(),
            path: relative,
            live,
            pacnew,
            written,
        });
    };

    for path in owners.keys() {
        record(path.clone());
    }
    for relative in walk_for_pacnew(root, Path::new("etc")) {
        record(relative);
    }

    found.into_values().collect()
}

/// Which package declares each backup path, keyed by the path.
///
/// Two packages declaring the same path would be a file conflict the install
/// refuses, so the first answer is the only answer.
pub fn owners(local: &LocalDb) -> HashMap<String, String> {
    let mut owners = HashMap::new();
    for pkg in local.packages.values() {
        for backup in &pkg.backup {
            owners
                .entry(backup.path.clone())
                .or_insert_with(|| pkg.name.clone());
        }
    }
    owners
}

/// Walks `root/relative` for files ending in `.pacnew`, returning their paths
/// relative to `root` with the suffix stripped.
///
/// Symlinked directories are stepped over rather than followed: `DirEntry`
/// reports the link itself, and /etc is full of them pointing at /usr, /run
/// and, on some machines, at each other.
fn walk_for_pacnew(root: &Path, relative: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root.join(relative)) else {
        return found;
    };

    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let child = relative.join(entry.file_name());
        if kind.is_dir() {
            found.extend(walk_for_pacnew(root, &child));
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        let name = child.to_string_lossy().to_string();
        if let Some(stripped) = name.strip_suffix(SUFFIX) {
            found.push(stripped.to_string());
        }
    }

    found
}

/// Turns whatever the user typed into the root-relative spelling the records
/// use, so `/etc/sudoers`, `etc/sudoers` and `/etc/sudoers.pacnew` all name
/// the same waiting file. Typing the `.pacnew` path is what tab-completion
/// produces, so it has to work.
fn relative_to(argument: &str, root: &Path) -> String {
    let trimmed = argument.strip_suffix(SUFFIX).unwrap_or(argument);
    let path = Path::new(trimmed);
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .to_string_lossy()
        .trim_start_matches('/')
        .to_string()
}

/// Appends a suffix to a path's file name without going through a `String`,
/// so a path this process cannot round-trip as UTF-8 is still named exactly.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

/// The first directory in the list that cannot be written to.
///
/// Permission bits alone do not settle it -- a read-only mount and a
/// restrictive ACL both pass that check and fail the write -- so this creates
/// a file and removes it again, the same probe `ops::sync` uses before it
/// starts downloading.
fn unwritable(pending: &[Pending]) -> Option<PathBuf> {
    let mut probed: Vec<&Path> = Vec::new();
    for file in pending {
        let Some(dir) = file.live.parent() else {
            continue;
        };
        // One probe per directory, not one per file: a sweep of /etc would
        // otherwise create and remove the same file thirty-nine times.
        if probed.contains(&dir) {
            continue;
        }
        probed.push(dir);
        let probe = dir.join(".rvn-config-probe");
        match std::fs::File::create(&probe) {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe);
            }
            Err(_) => return Some(dir.to_path_buf()),
        }
    }
    None
}

// ---- list --------------------------------------------------------------

fn list(ctx: &Context, pending: &[Pending]) {
    if ctx.ui.is_json() {
        return ctx.ui.emit("pacnew", payload(pending));
    }

    if pending.is_empty() {
        return ctx
            .ui
            .ok("no configuration files are waiting to be reviewed");
    }

    let s = &ctx.ui.style;
    let count = pending.len();
    ctx.ui.info(&format!(
        "{count} config file{} {} not replaced:",
        if count == 1 { "" } else { "s" },
        if count == 1 { "was" } else { "were" }
    ));
    ctx.ui.tree(
        &pending
            .iter()
            .map(|p| {
                format!(
                    "{}  {}  {}",
                    s.bold(&p.path),
                    s.paint(Color::Cyan, p.owner()),
                    s.dim(&waited(p.waited()))
                )
            })
            .collect::<Vec<_>>(),
    );
    ctx.ui
        .detail("`rvn config diff <path>` shows what changed; accept, keep or merge settles it");
}

fn payload(pending: &[Pending]) -> serde_json::Value {
    serde_json::json!({
        "count": pending.len(),
        "files": pending.iter().map(Pending::as_json).collect::<Vec<_>>(),
    })
}

/// How long a file has been waiting, in the units a person would use.
///
/// Not [`crate::ui::theme::duration`], which measures how long an operation
/// took and tops out at minutes: these are routinely months old, and "64800m
/// 00s" tells nobody anything. The point of the number is to make a file that
/// has been ignored since the machine was built look as bad as it is.
fn waited(seconds: Option<u64>) -> String {
    let Some(seconds) = seconds else {
        return "waiting".to_string();
    };
    let plural = |n: u64, unit: &str| {
        format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
    };
    match seconds {
        s if s < 60 => "just now".to_string(),
        s if s < 3600 => plural(s / 60, "minute"),
        s if s < 86_400 => plural(s / 3600, "hour"),
        s if s < 86_400 * 365 => plural(s / 86_400, "day"),
        s => plural(s / (86_400 * 365), "year"),
    }
}

// ---- diff --------------------------------------------------------------

/// Shows what the package would change, painted the way a diff is expected to
/// look.
///
/// The colouring is rvn's own rather than `diff --color`, so it obeys the same
/// `NO_COLOR` and not-a-terminal rules as every other line rvn prints: the
/// style was already decided once, in [`crate::ui::theme::Style::detect`], and
/// a second opinion from a child process would contradict it.
fn diff(ctx: &Context, pending: &[Pending]) -> Result<(), String> {
    if pending.is_empty() {
        ctx.ui
            .ok("no configuration files are waiting to be reviewed");
        return Ok(());
    }

    for file in pending {
        // A missing live file still has a diff worth seeing: everything the
        // package would add.
        let live: &Path = if file.live.exists() {
            &file.live
        } else {
            Path::new("/dev/null")
        };

        let output = Command::new("diff")
            .arg("-u")
            .arg("--label")
            .arg(&file.path)
            .arg("--label")
            .arg(format!("{}{SUFFIX}", file.path))
            .arg(live)
            .arg(&file.pacnew)
            .output();

        let output = match output {
            Ok(output) => output,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(
                    "diff is not installed, so there is nothing to compare with — `rvn install diffutils`"
                        .into(),
                );
            }
            Err(e) => return Err(format!("could not run diff: {e}")),
        };

        // diff exits 0 for identical, 1 for different and 2 for trouble, so a
        // non-zero status is not by itself a failure.
        if output.status.code() == Some(2) {
            let reason = String::from_utf8_lossy(&output.stderr);
            let reason = reason.lines().last().unwrap_or("diff failed").trim();
            ctx.ui.warn(&format!(
                "{}: {reason}{}",
                file.path,
                if reason.contains("ermission") {
                    " — reading this one needs root, so try sudo"
                } else {
                    ""
                }
            ));
            continue;
        }

        let text = String::from_utf8_lossy(&output.stdout);
        if ctx.ui.is_json() {
            ctx.ui.emit(
                "pacnew_diff",
                serde_json::json!({
                    "path": file.path,
                    "package": file.package,
                    "diff": text,
                }),
            );
            continue;
        }

        ctx.ui.blank();
        ctx.ui.step(&format!(
            "{} — from {}, {}",
            ctx.ui.style.bold(&file.path),
            file.owner(),
            waited(file.waited())
        ));
        if text.trim().is_empty() {
            ctx.ui
                .detail("identical; `rvn config keep` will clear it away");
            continue;
        }
        paint_diff(ctx, &text);
    }

    Ok(())
}

/// Writes a unified diff to stderr, one colour per kind of line.
///
/// stderr, like everything else a person reads, so that `rvn --json` keeps
/// stdout to itself and a diff can be piped somewhere without the events
/// getting mixed into it.
fn paint_diff(ctx: &Context, text: &str) {
    use std::io::Write;
    let s = &ctx.ui.style;
    let mut err = std::io::stderr().lock();

    for line in text.lines() {
        let painted = if line.starts_with("+++") || line.starts_with("---") {
            s.bold(line)
        } else if line.starts_with("@@") {
            s.paint(Color::Cyan, line)
        } else if line.starts_with('+') {
            s.paint(Color::Green, line)
        } else if line.starts_with('-') {
            s.paint(Color::Red, line)
        } else {
            line.to_string()
        };
        let _ = writeln!(err, "     {painted}");
    }
}

// ---- settling it -------------------------------------------------------

/// Works through the list, returning the files that were refused outright as
/// opposed to merely declined at the prompt.
fn settle(ctx: &mut Context, action: Action, pending: &[Pending]) -> Result<Vec<String>, String> {
    if pending.is_empty() {
        ctx.ui
            .ok("no configuration files are waiting to be reviewed");
        return Ok(Vec::new());
    }

    let mut settled = 0usize;
    let mut refused = Vec::new();
    for file in pending {
        let outcome = match action {
            Action::Accept => accept(ctx, file)?,
            Action::Keep => keep(ctx, file)?,
            Action::Merge => merge(ctx, file)?,
            Action::List | Action::Diff => Settled::Declined,
        };
        match outcome {
            Settled::Done => settled += 1,
            Settled::Refused => refused.push(file.path.clone()),
            Settled::Declined => {}
        }
    }

    ctx.ui.blank();
    let left = pending.len() - settled;
    ctx.ui
        .ok(&format!("{settled} settled, {left} still waiting"));
    Ok(refused)
}

/// What became of one file.
///
/// `Declined` and `Refused` both leave the file alone, and the difference
/// matters: declined is the answer to a question rvn asked, refused is rvn
/// saying no to the answer.
enum Settled {
    Done,
    Declined,
    Refused,
}

/// Asks, unless `--yes` already answered.
///
/// The default is no. A question about destroying one of two copies of a
/// configuration file is not one to answer by pressing return, and the
/// non-interactive case is refused before we ever get here.
fn agreed(ctx: &Context, question: &str) -> bool {
    ctx.assume_yes || ctx.ui.confirm(question, false)
}

/// Takes the package's version, keeping the current one.
fn accept(ctx: &mut Context, file: &Pending) -> Result<Settled, String> {
    if let Some(holds) = account_state(&file.path) {
        let message = format!(
            "{} holds {} — a package's copy is a build-time default that cannot know any of it, and taking it would lock this machine's accounts out. Compare them with `rvn config diff {}` and move across anything genuinely new by hand, or discard the package's copy with `rvn config keep {}`.",
            file.path, holds, file.path, file.path
        );
        ctx.ui.warn(&message);
        ctx.ui.emit(
            "pacnew_refused",
            serde_json::json!({
                "path": file.path,
                "package": file.package,
                "action": "accept",
                "reason": message,
            }),
        );
        return Ok(Settled::Refused);
    }

    if !agreed(
        ctx,
        &format!(
            "replace {} with the version from {}?",
            file.path,
            file.owner()
        ),
    ) {
        return Ok(Settled::Declined);
    }

    record_shipped_hash(ctx, file);
    let saved = save_original(&file.live)
        .map_err(|e| format!("{}: could not save the current file: {e}", file.path))?;
    // A rename rather than a copy: the package's copy is already beside the
    // file, on the same filesystem, so this either happens completely or does
    // not happen at all. Its mode and ownership come across with it, which is
    // the point -- taking the package's version means taking all of it.
    std::fs::rename(&file.pacnew, &file.live)
        .map_err(|e| format!("{}: could not install the package's version: {e}", file.path))?;

    match &saved {
        Some(saved) => ctx.ui.ok(&format!(
            "{} is now the package's version; what was there is at {}",
            file.path,
            saved.display()
        )),
        None => ctx.ui.ok(&format!(
            "{} is now the package's version; there was nothing on disk to save",
            file.path
        )),
    }
    resolved(ctx, file, "accept", saved.as_deref());
    Ok(Settled::Done)
}

/// Discards the package's version and keeps what is on disk.
fn keep(ctx: &mut Context, file: &Pending) -> Result<Settled, String> {
    if !agreed(
        ctx,
        &format!("discard {}'s version of {}?", file.owner(), file.path),
    ) {
        return Ok(Settled::Declined);
    }

    record_shipped_hash(ctx, file);
    std::fs::remove_file(&file.pacnew)
        .map_err(|e| format!("{}: could not remove {SUFFIX}: {e}", file.path))?;

    ctx.ui.ok(&format!(
        "{} left exactly as it is; the package's version is gone",
        file.path
    ));
    resolved(ctx, file, "keep", None);
    Ok(Settled::Done)
}

/// Hands both files to an editor and clears the `.pacnew` once the person
/// says the merge is done.
fn merge(ctx: &mut Context, file: &Pending) -> Result<Settled, String> {
    // --yes cannot drive an editor, and a front-end reading JSON has no
    // terminal to give it. Both are refused here rather than launching vim
    // into a pipe and hanging.
    if !ctx.ui.style.interactive {
        return Err(format!(
            "merging {} needs a terminal to run the editor in; `rvn config diff` and `rvn config accept` work without one",
            file.path
        ));
    }

    if !agreed(ctx, &format!("merge {} by hand?", file.path)) {
        return Ok(Settled::Declined);
    }

    // Before the editor, not after: the copy that has to survive a slip of the
    // fingers is the one that exists right now.
    let saved = save_original(&file.live)
        .map_err(|e| format!("{}: could not save the current file: {e}", file.path))?;
    if let Some(saved) = &saved {
        ctx.ui
            .info(&format!("the file as it stands is saved at {}", saved.display()));
    }

    let mut command = editor(&chosen_editor(), &file.live, &file.pacnew);
    let status = command
        .status()
        .map_err(|e| format!("could not run {:?}: {e}", command.get_program()))?;
    if !status.success() {
        ctx.ui.warn(&format!(
            "the editor exited with {status}; {} was left in place",
            file.pacnew.display()
        ));
        return Ok(Settled::Declined);
    }

    if !agreed(
        ctx,
        &format!(
            "is {} finished? the package's version will be discarded",
            file.path
        ),
    ) {
        ctx.ui.info(&format!(
            "left for later; {} is still there",
            file.pacnew.display()
        ));
        return Ok(Settled::Declined);
    }

    record_shipped_hash(ctx, file);
    std::fs::remove_file(&file.pacnew)
        .map_err(|e| format!("{}: could not remove {SUFFIX}: {e}", file.path))?;

    ctx.ui.ok(&format!("{} merged", file.path));
    resolved(ctx, file, "merge", saved.as_deref());
    Ok(Settled::Done)
}

/// The editor to hand the two files to.
///
/// `$VISUAL` before `$EDITOR`, as every other tool does, and `vimdiff` when
/// neither is set because a three-way comparison is the whole job here. A
/// value with arguments in it -- `code --wait`, `emacsclient -nw` -- is split
/// on whitespace, because a bare `Command::new` of the whole string looks for
/// a program with a space in its name and fails in a way nobody can read.
fn chosen_editor() -> String {
    std::env::var("VISUAL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| std::env::var("EDITOR").ok().filter(|v| !v.trim().is_empty()))
        .unwrap_or_else(|| "vimdiff".to_string())
}

/// Builds the command from an already-chosen editor, kept separate from
/// [`chosen_editor`] so what it does with the string can be tested without a
/// test reaching into the process environment every other test shares.
fn editor(chosen: &str, live: &Path, pacnew: &Path) -> Command {
    let mut words = chosen.split_whitespace();
    let program = words.next().unwrap_or("vimdiff");
    let mut command = Command::new(program);
    command.args(words);
    command.arg(live).arg(pacnew);
    command
}

/// Copies a file aside before anything replaces it, returning where it went.
///
/// Nothing here ever writes over the only copy of a configuration file. This
/// command will be pointed at /etc/sudoers and /etc/fstab by people who are
/// tired, and the cost of a spare copy is a few kilobytes against a machine
/// that will not boot or will not let anyone become root.
///
/// A file that is not there yet is not an error -- the package is adding it --
/// and an existing `.pacorig` is never overwritten, because it is the record
/// of an earlier decision and may be the older, better copy.
fn save_original(live: &Path) -> std::io::Result<Option<PathBuf>> {
    if !live.exists() {
        return Ok(None);
    }

    let mut target = with_suffix(live, ORIGINAL);
    let mut attempt = 1;
    while target.exists() {
        target = with_suffix(live, &format!("{ORIGINAL}.{attempt}"));
        attempt += 1;
        if attempt > 1000 {
            return Err(std::io::Error::other(format!(
                "{} already has a thousand saved copies beside it",
                live.display()
            )));
        }
    }

    std::fs::copy(live, &target)?;
    Ok(Some(target))
}

/// Records the checksum of the bytes the package shipped, before the only
/// copy of them is destroyed.
///
/// `%BACKUP%` holds what the *package* installed, never what is on disk. That
/// is what lets a later removal tell an administrator's edits (rename to
/// `.pacsave`) from untouched package content (delete) -- see `was_modified`
/// in [`super::remove`]. While a `.pacnew` exists those shipped bytes are
/// sitting right there and the record is usually already correct; every verb
/// here is about to delete or move them, so this is the last moment it can be
/// made correct, and for a `.pacnew` written by pacman or by an rvn old enough
/// not to have recorded one it may never have been.
///
/// Failing is a warning rather than an error, and the direction of the failure
/// is the safe one: a missing or stale checksum makes `was_modified` answer
/// "modified", which preserves the file. The bytes on disk are what matter,
/// and they are already where the user asked for them.
fn record_shipped_hash(ctx: &mut Context, file: &Pending) {
    let Some(package) = file.package.clone() else {
        return;
    };
    let Ok(shipped) = crate::verify::sha256_file(&file.pacnew) else {
        return;
    };
    let recorded = ctx
        .local
        .get(&package)
        .and_then(|pkg| pkg.backup_hash(&file.path))
        .map(str::to_string);
    if recorded.as_deref() == Some(shipped.as_str()) {
        return;
    }
    if let Err(e) = ctx.local.set_backup_hash(&package, &file.path, &shipped) {
        ctx.ui.warn(&format!(
            "{}: could not record what {package} shipped, so a later removal will err towards keeping this file: {e}",
            file.path
        ));
    }
}

/// The `--json` event for a file that has been settled, so Raven Store can
/// show the review being worked through rather than polling for what is left.
fn resolved(ctx: &Context, file: &Pending, action: &str, saved: Option<&Path>) {
    ctx.ui.emit(
        "pacnew_resolved",
        serde_json::json!({
            "path": file.path,
            "package": file.package,
            "action": action,
            "saved": saved.map(|p| p.display().to_string()),
        }),
    );
}

/// What a file holds that a package's copy of it cannot know, or `None` when
/// the package's version is a legitimate thing to accept.
fn account_state(path: &str) -> Option<&'static str> {
    ACCOUNT_STATE
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, holds)| *holds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-config-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        dir
    }

    /// A live file and the package's version of it, waiting to be reconciled.
    fn waiting(root: &Path, relative: &str, live: &str, shipped: &str) -> Pending {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, live).unwrap();
        std::fs::write(with_suffix(&path, SUFFIX), shipped).unwrap();
        Pending {
            path: relative.to_string(),
            live: path.clone(),
            pacnew: with_suffix(&path, SUFFIX),
            package: None,
            written: None,
        }
    }

    #[test]
    fn a_pacnew_is_found_and_attributed_to_its_package() {
        let root = temp_root("discover");
        waiting(&root, "etc/sudoers", "root ALL=(ALL) ALL\n", "shipped\n");

        let owners = HashMap::from([("etc/sudoers".to_string(), "sudo".to_string())]);
        let found = discover(&root, &owners);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "etc/sudoers");
        assert_eq!(found[0].package.as_deref(), Some("sudo"));
    }

    // A package that has been removed leaves its .pacnew behind, and that is
    // exactly the file nobody will ever notice on their own.
    #[test]
    fn a_pacnew_no_package_claims_is_still_found() {
        let root = temp_root("orphan");
        waiting(&root, "etc/orphan.conf", "mine\n", "theirs\n");
        std::fs::create_dir_all(root.join("etc/deep/nested")).unwrap();
        waiting(&root, "etc/deep/nested/thing.conf", "mine\n", "theirs\n");

        let found = discover(&root, &HashMap::new());
        let mut paths: Vec<&str> = found.iter().map(|p| p.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(paths, vec!["etc/deep/nested/thing.conf", "etc/orphan.conf"]);
        assert!(found.iter().all(|p| p.package.is_none()));
    }

    // Declared backup files can live outside /etc, where the walk never goes.
    #[test]
    fn a_declared_backup_outside_etc_is_found() {
        let root = temp_root("outside-etc");
        waiting(&root, "usr/share/demo/demo.conf", "mine\n", "theirs\n");

        let owners = HashMap::from([(
            "usr/share/demo/demo.conf".to_string(),
            "demo".to_string(),
        )]);
        let found = discover(&root, &owners);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].package.as_deref(), Some("demo"));
    }

    // A backup file with no .pacnew beside it has nothing to reconcile.
    #[test]
    fn a_config_file_with_no_pacnew_is_not_waiting() {
        let root = temp_root("settled");
        std::fs::write(root.join("etc/settled.conf"), "fine\n").unwrap();

        let owners = HashMap::from([("etc/settled.conf".to_string(), "demo".to_string())]);
        assert!(discover(&root, &owners).is_empty());
    }

    #[test]
    fn paths_are_accepted_however_they_are_spelled() {
        let root = Path::new("/");
        assert_eq!(relative_to("/etc/sudoers", root), "etc/sudoers");
        assert_eq!(relative_to("etc/sudoers", root), "etc/sudoers");
        assert_eq!(relative_to("/etc/sudoers.pacnew", root), "etc/sudoers");

        let chroot = Path::new("/mnt/target");
        assert_eq!(relative_to("/mnt/target/etc/fstab", chroot), "etc/fstab");
    }

    #[test]
    fn the_current_file_is_saved_before_anything_replaces_it() {
        let root = temp_root("save");
        let file = waiting(&root, "etc/demo.conf", "mine\n", "theirs\n");

        let first = save_original(&file.live).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "mine\n");
        assert!(first.to_string_lossy().ends_with(".pacorig"));

        // An earlier save is the record of an earlier decision and is never
        // written over.
        std::fs::write(&file.live, "edited again\n").unwrap();
        let second = save_original(&file.live).unwrap().unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "mine\n");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "edited again\n");
    }

    #[test]
    fn a_file_that_does_not_exist_yet_has_nothing_to_save() {
        let root = temp_root("save-absent");
        assert!(save_original(&root.join("etc/absent.conf")).unwrap().is_none());
    }

    // The four files the account database lives in, plus the two that record
    // delegated id ranges. Accepting a package's copy of any of them locks
    // this machine's accounts out.
    #[test]
    fn account_state_is_never_accepted() {
        for path in [
            "etc/passwd",
            "etc/shadow",
            "etc/group",
            "etc/gshadow",
            "etc/subuid",
            "etc/subgid",
        ] {
            assert!(account_state(path).is_some(), "{path} must be refused");
        }
        // Ordinary configuration is still the user's call.
        assert!(account_state("etc/sudoers").is_none());
        assert!(account_state("etc/fstab").is_none());
    }

    // Paths are matched as the backup records spell them: relative, no leading
    // slash. An absolute spelling here would silently never match.
    #[test]
    fn refused_paths_are_relative() {
        for (path, _) in ACCOUNT_STATE {
            assert!(!path.starts_with('/'), "{path} must not be absolute");
        }
    }

    #[test]
    fn ages_are_reported_in_units_a_person_uses() {
        assert_eq!(waited(Some(5)), "just now");
        assert_eq!(waited(Some(60)), "1 minute ago");
        assert_eq!(waited(Some(3 * 3600)), "3 hours ago");
        assert_eq!(waited(Some(86_400)), "1 day ago");
        assert_eq!(waited(Some(86_400 * 400)), "1 year ago");
        assert_eq!(waited(None), "waiting");
    }

    // $EDITOR with flags in it is ordinary -- `code --wait`, `emacsclient
    // -nw` -- and a Command::new of the whole string looks for a program with
    // a space in its name.
    #[test]
    fn an_editor_with_arguments_is_split_into_them() {
        let command = editor(
            "code --wait",
            Path::new("/etc/sudoers"),
            Path::new("/etc/sudoers.pacnew"),
        );
        assert_eq!(command.get_program(), "code");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            args,
            vec!["--wait", "/etc/sudoers", "/etc/sudoers.pacnew"]
        );
    }

    // Both files, in that order, so a side-by-side editor puts what is on
    // disk on the left and what the package shipped on the right.
    #[test]
    fn the_editor_is_given_the_live_file_first() {
        let command = editor(
            "vimdiff",
            Path::new("/etc/fstab"),
            Path::new("/etc/fstab.pacnew"),
        );
        assert_eq!(command.get_program(), "vimdiff");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(args, vec!["/etc/fstab", "/etc/fstab.pacnew"]);
    }

    #[test]
    fn verbs_know_whether_they_write() {
        assert_eq!(Action::parse("list"), Some(Action::List));
        assert_eq!(Action::parse("accept"), Some(Action::Accept));
        assert_eq!(Action::parse("install"), None);
        assert!(!Action::List.writes());
        assert!(!Action::Diff.writes());
        for action in [Action::Merge, Action::Accept, Action::Keep] {
            assert!(action.writes(), "{} changes files", action.as_str());
        }
    }
}
