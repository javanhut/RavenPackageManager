//! `rvn uninstall`: removing installed packages.

use super::Context;
// The removal line wears pacman.log's timestamp, which is `audit`'s to
// compute -- see the note on `audit::timestamp` for why one module owns the
// calendar.
use crate::audit::{now_unix, timestamp};
use crate::remove::{self, Options, RemovalPlan};
use crate::txhooks;
use crate::ui::theme::{Color, bytes};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct Outcome {
    pub removed: Vec<String>,
    /// Configuration files preserved rather than deleted.
    pub preserved: Vec<String>,
}

/// Runs `rvn uninstall`, including the masthead.
pub fn run(ctx: &mut Context, targets: &[String], options: Options) -> Result<Outcome, String> {
    ctx.ui.banner(&format!("v{}", env!("CARGO_PKG_VERSION")));
    execute(ctx, targets, options)
}

/// The removal pipeline without the masthead.
pub fn execute(
    ctx: &mut Context,
    targets: &[String],
    options: Options,
) -> Result<Outcome, String> {
    let plan = {
        let spinner = ctx.ui.stage(&format!("checking {}", targets.join(", ")));
        let plan = remove::plan_with(&ctx.local, &ctx.system, targets, options);
        if plan.blocked.is_empty() {
            spinner.succeed(&format!(
                "{} package{} to remove",
                plan.remove.len(),
                if plan.remove.len() == 1 { "" } else { "s" }
            ));
        } else {
            spinner.fail("removal is not safe as requested");
        }
        plan
    };

    // Pacman refuses the whole transaction when a target is not installed,
    // rather than silently doing part of what was asked.
    if !plan.not_installed.is_empty() {
        ctx.ui.err("not installed:");
        ctx.ui.tree(&plan.not_installed);
        return Err(format!(
            "no package named {}",
            plan.not_installed.join(", ")
        ));
    }

    if !plan.blocked.is_empty() {
        ctx.ui.err("removal would break installed packages:");
        let mut lines = Vec::new();
        for blocked in &plan.blocked {
            for (dependent, dep) in &blocked.required_by {
                lines.push(format!(
                    "{} is required by {} (needs {})",
                    ctx.ui.style.bold(&blocked.package),
                    ctx.ui.style.bold(dependent),
                    dep
                ));
            }
        }
        ctx.ui.tree(&lines);
        ctx.ui
            .info("use --cascade to remove the dependents too, or --nodeps to force");
        return Err("removal blocked by reverse dependencies".into());
    }

    if plan.is_empty() {
        ctx.ui.info("nothing to remove");
        return Ok(Outcome {
            removed: Vec::new(),
            preserved: Vec::new(),
        });
    }

    ctx.ui.emit(
        "removal_plan",
        serde_json::json!({
            "remove": plan.remove.iter().map(crate::ui::json::package).collect::<Vec<_>>(),
            "orphaned": plan.orphaned,
            "cascaded": plan.cascaded,
        }),
    );
    show_plan(ctx, &plan);

    // Held packages -- essential to Raven, or named by HoldPkg -- are never
    // taken as a side effect of removing something else. Named outright, a
    // person at a terminal may still confirm it, as pacman lets them; `--yes`
    // and rvnd would answer that question without anyone reading it.
    let (held_targets, held_side): (Vec<String>, Vec<String>) =
        remove::held(&plan, &ctx.config.hold_pkg)
            .into_iter()
            .partition(|name| targets.contains(name));
    if !held_side.is_empty() {
        ctx.ui
            .err("removal would take held packages that were not named:");
        ctx.ui.tree(&held_side);
        if held_side.iter().any(|name| plan.orphaned.contains(name)) {
            ctx.ui
                .info("use --keep-orphans to leave orphaned dependencies behind");
        }
        if held_side.iter().any(|name| plan.cascaded.contains(name)) {
            ctx.ui
                .info("drop --cascade, or remove the dependents by name first");
        }
        return Err("removal includes held packages".into());
    }
    if !held_targets.is_empty() {
        ctx.ui.warn(&format!(
            "held: {} (essential, or listed in HoldPkg)",
            held_targets.join(", ")
        ));
        if !ctx.dry_run {
            if ctx.assume_yes || !ctx.ui.style.interactive {
                return Err(
                    "held packages are only removed with confirmation at a terminal, never with --yes"
                        .into(),
                );
            }
            if !ctx.ui.confirm("remove held packages anyway?", false) {
                return Err("cancelled".into());
            }
        }
    }

    if ctx.dry_run {
        ctx.ui.info("dry run — nothing was changed");
        return Ok(Outcome {
            removed: Vec::new(),
            preserved: Vec::new(),
        });
    }

    // An orphan sweep removes packages nobody named. Under `--yes` nobody
    // reads the plan either, so the caller has to have asked for it.
    if ctx.assume_yes && !plan.orphaned.is_empty() && !options.remove_orphans {
        ctx.ui
            .err("removal would also take orphaned dependencies, and --yes skips the review:");
        ctx.ui.tree(&plan.orphaned);
        ctx.ui.info(
            "check with --dry-run, then pass --remove-orphans to take them or --keep-orphans to leave them",
        );
        return Err("orphan removal under --yes needs --remove-orphans".into());
    }

    if !ctx.assume_yes && !ctx.ui.confirm("proceed with removal?", false) {
        return Err("cancelled".into());
    }

    // ---- transaction hooks ---------------------------------------------
    //
    // Both sides are driven from here rather than from `apply`, because
    // `apply` is also how an install retires a package something replaced —
    // and that is one install transaction, not an install with a removal
    // nested inside it. A snapshot hook firing twice in the middle of an
    // upgrade is exactly the confusion that would cause.
    //
    // The file list is taken now, before anything is deleted: it is read out
    // of the very records `apply` is about to unregister, and it is the same
    // list for both moments because what a removal did is what it was going
    // to do. `apply` either removes every package in the plan or returns an
    // error, so the planned set is also the removed set.
    let hooks = super::install::load_transaction_hooks(ctx)?;
    let targets: Vec<String> = plan.remove.iter().map(|p| p.name.clone()).collect();
    let files = if hooks.wants_paths(txhooks::When::Pre) || hooks.wants_paths(txhooks::When::Post) {
        targets
            .iter()
            .filter_map(|name| ctx.local.files_or_empty(name).ok())
            .flatten()
            .collect()
    } else {
        Vec::new()
    };
    let transaction = txhooks::Transaction::new(vec![txhooks::Operation::Remove], targets, files);
    super::install::run_transaction_hooks(ctx, &hooks, txhooks::When::Pre, &transaction)?;

    let outcome = apply(ctx, &plan)?;

    super::install::run_transaction_hooks(ctx, &hooks, txhooks::When::Post, &transaction)?;

    Ok(outcome)
}

/// Deletes the files of an already-approved plan and updates the database.
pub fn apply(ctx: &mut Context, plan: &RemovalPlan) -> Result<Outcome, String> {
    let removing: HashSet<String> = plan.remove.iter().map(|p| p.name.clone()).collect();
    let total_files: u64 = plan
        .remove
        .iter()
        .map(|p| ctx.local.files(&p.name).map(|f| f.len()).unwrap_or(0) as u64)
        .sum();

    let mut progress = ctx.ui.counter("removing", total_files, "files");
    let mut removed = Vec::new();
    let mut preserved = Vec::new();
    let mut log_failed = false;
    let mut touched_dirs: HashSet<PathBuf> = HashSet::new();
    let mut stale_caches = crate::caches::Stale::default();

    for pkg in &plan.remove {
        progress.set_detail(&pkg.name);

        // Captured before the record is unregistered, and run before any file
        // disappears so the hook can still use the package it belongs to.
        let script = ctx.local.install_script(&pkg.name);
        super::install::run_scriptlet(
            ctx,
            &pkg.name,
            script.as_deref(),
            crate::scriptlet::Hook::PreRemove,
            &pkg.version,
            None,
        );

        let files = remove::deletable_files(&ctx.local, pkg, &removing)
            .map_err(|e| format!("{}: could not determine which files to delete: {e}", pkg.name))?;
        // A per-user prefix is not what the system caches index.
        if ctx.user_prefix.is_none() {
            stale_caches.note(&files);
        }

        for file in &files {
            // Directory entries are pruned after every file is gone.
            if let Some(dir) = file.strip_suffix('/') {
                touched_dirs.insert(ctx.config.root_dir.join(dir));
                progress.advance(1);
                continue;
            }

            let path = ctx.config.root_dir.join(file);

            if retire_file(pkg, file, &path) == Retirement::Preserved {
                preserved.push(file.clone());
            }

            if let Some(parent) = path.parent() {
                touched_dirs.insert(parent.to_path_buf());
            }
            progress.advance(1);
        }

        ctx.local
            .unregister(&pkg.name)
            .map_err(|e| format!("{}: could not update the local database: {e}", pkg.name))?;

        super::install::run_scriptlet(
            ctx,
            &pkg.name,
            script.as_deref(),
            crate::scriptlet::Hook::PostRemove,
            &pkg.version,
            None,
        );

        // Upstream tracking outlives the package otherwise, leaving stale
        // entries that would be consulted if it were ever reinstalled.
        ctx.devel.forget(&pkg.name);

        removed.push(pkg.name.clone());

        // Logged as each package goes, so a removal that fails part-way still
        // leaves a record of what it had already taken.
        if let Err(e) = log_removed(&ctx.config.log_file, &pkg.name, &pkg.version, now_unix()) {
            if !log_failed {
                ctx.ui.warn(&format!(
                    "could not record removals in {}: {e}",
                    ctx.config.log_file.display()
                ));
            }
            log_failed = true;
        }
    }

    progress.finish(&format!(
        "removed {} package{}",
        removed.len(),
        if removed.len() == 1 { "" } else { "s" }
    ));

    if let Err(e) = ctx.devel.save(&ctx.config.db_path) {
        ctx.ui
            .warn(&format!("could not update upstream tracking: {e}"));
    }

    // ---- prune empty directories ---------------------------------------
    let spinner = ctx.ui.stage("pruning empty directories");
    let pruned = prune_dirs(&ctx.config.root_dir, touched_dirs);
    spinner.succeed(&format!(
        "pruned {pruned} empty director{}",
        if pruned == 1 { "y" } else { "ies" }
    ));

    // A removed browser must stop being the handler for its links.
    crate::caches::refresh(&ctx.config.root_dir, stale_caches, &mut |w| ctx.ui.warn(w));

    // ---- summary -------------------------------------------------------
    ctx.ui.blank();
    ctx.ui.ok(&format!(
        "{} package{} removed, {} freed",
        ctx.ui.style.bold(&removed.len().to_string()),
        if removed.len() == 1 { "" } else { "s" },
        ctx.ui.style.bold(&bytes(plan.freed_size()))
    ));

    if !preserved.is_empty() {
        ctx.ui.blank();
        ctx.ui
            .info("configuration files kept with a .pacsave suffix:");
        ctx.ui.tree(&preserved);
    }

    Ok(Outcome { removed, preserved })
}

/// What became of a file a package owned and no longer should.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Retirement {
    /// Unlinked: it was package content, and package content goes with the
    /// package.
    Deleted,
    /// Renamed to `.pacsave`: an edited configuration file, which is the
    /// administrator's work and not the package's.
    Preserved,
    /// Neither happened. The file was already gone, or the rename failed and
    /// leaving it where the administrator put it beats deleting it.
    Left,
}

/// Retires one file a package owned, preserving an edited configuration file
/// as `.pacsave` and unlinking anything else.
///
/// Two callers have to make this decision: the uninstall loop above, and
/// `install::prune_stale`, which deletes the paths the previous version owned
/// and the new one no longer ships. Both are the same situation — a file is
/// about to stop being owned — and an edit the administrator made is just as
/// lost either way, so the policy lives here once. `prune_stale` used to
/// unlink unconditionally, which is how a config file that a new upstream
/// version merely *relocated* took the administrator's edits with it.
pub(crate) fn retire_file(
    pkg: &crate::pkg::Package,
    file: &str,
    path: &Path,
) -> Retirement {
    if pkg.is_backup(file) && path.exists() && was_modified(pkg, file, path) {
        // An edited configuration file is never destroyed; it is set aside so
        // an administrator can recover or discard it. One still matching what
        // was installed is just package content.
        if std::fs::rename(path, pacsave_path(path)).is_ok() {
            return Retirement::Preserved;
        }
        // The rename failed, so the edited file is still exactly where it was.
        // Unlinking it now would be the loss this branch exists to prevent.
        return Retirement::Left;
    }
    // A file already gone is not an error — the goal is its absence.
    match std::fs::remove_file(path) {
        Ok(()) => Retirement::Deleted,
        Err(_) => Retirement::Left,
    }
}

/// Where a preserved configuration file goes: the path with `.pacsave`
/// appended after whatever extension it already had, so `foo.conf` becomes
/// `foo.conf.pacsave` and a plain `sudo` becomes `sudo.pacsave`.
pub(crate) fn pacsave_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}pacsave",
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| format!("{e}."))
            .unwrap_or_default()
    ))
}

/// Whether a backup file differs from what the package installed.
///
/// Without a recorded checksum the file cannot be proven untouched, so it is
/// treated as modified — losing an edit is far worse than leaving a stray
/// `.pacsave` behind.
fn was_modified(pkg: &crate::pkg::Package, file: &str, path: &Path) -> bool {
    // A `.pacnew` beside it means the install found this file already there
    // and kept it. Older records hashed that kept file rather than the
    // package's copy, so the checksum would call it untouched.
    let pacnew = path.with_file_name(format!(
        "{}.pacnew",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default()
    ));
    if pacnew.exists() {
        return true;
    }
    let Some(original) = pkg.backup_hash(file) else {
        return true;
    };
    match crate::verify::sha256_file(path) {
        Ok(current) => !current.eq_ignore_ascii_case(original),
        Err(_) => true,
    }
}

/// Appends one removal to `LogFile`, in pacman.log's layout so whatever reads
/// that file reads this too. Nothing else records what an uninstall took, and
/// without it the only way to learn what an orphan sweep removed was to
/// reconstruct it from the package cache.
fn log_removed(log: &Path, name: &str, version: &str, when: u64) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    writeln!(
        file,
        "[{}] [RVN] removed {name} ({version})",
        timestamp(when)
    )
}

/// Removes directories that the removal emptied, deepest first so parents
/// become empty before they are tried.
fn prune_dirs(root: &Path, dirs: HashSet<PathBuf>) -> usize {
    let mut candidates: Vec<PathBuf> = dirs.into_iter().collect();
    candidates.sort_by_key(|d| std::cmp::Reverse(d.components().count()));

    let mut pruned = 0;
    for dir in candidates {
        let mut current = dir.as_path();
        // Walk upward, stopping at the install root or the first non-empty
        // directory.
        while current.starts_with(root) && current != root {
            if std::fs::remove_dir(current).is_ok() {
                pruned += 1;
            } else {
                break;
            }
            match current.parent() {
                Some(parent) => current = parent,
                None => break,
            }
        }
    }
    pruned
}

fn show_plan(ctx: &Context, plan: &RemovalPlan) {
    let s = &ctx.ui.style;
    ctx.ui.blank();

    let lines: Vec<String> = plan
        .remove
        .iter()
        .map(|pkg| {
            let mut line = format!(
                "{} {}",
                s.bold(&pkg.name),
                s.paint(Color::Green, &pkg.version)
            );
            if plan.orphaned.contains(&pkg.name) {
                line.push_str(&format!(" {}", s.dim("(orphaned)")));
            } else if plan.cascaded.contains(&pkg.name) {
                line.push_str(&format!(" {}", s.paint(Color::Amber, "(depends on a target)")));
            }
            line
        })
        .collect();

    ctx.ui.step(&format!("packages to remove ({})", lines.len()));
    ctx.ui.tree(&lines);

    ctx.ui.blank();
    ctx.ui.info(&format!(
        "freeing {}",
        s.bold(&bytes(plan.freed_size()))
    ));
    ctx.ui.blank();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmodified_config_is_not_preserved_but_edited_config_is() {
        use crate::pkg::{BackupFile, Package};

        let dir = std::env::temp_dir().join("rvn-backup-check");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("demo.conf");
        std::fs::write(&path, b"original").unwrap();

        let hash = crate::verify::sha256_file(&path).unwrap();
        let pkg = Package {
            backup: vec![BackupFile {
                path: "etc/demo.conf".into(),
                hash: Some(hash),
            }],
            ..Default::default()
        };

        // Untouched: safe to delete.
        assert!(!was_modified(&pkg, "etc/demo.conf", &path));

        // Edited: must be kept.
        std::fs::write(&path, b"original\n# my change").unwrap();
        assert!(was_modified(&pkg, "etc/demo.conf", &path));

        // No recorded checksum means it cannot be proven untouched.
        let hashless = Package {
            backup: vec![BackupFile::parse("etc/demo.conf")],
            ..Default::default()
        };
        assert!(was_modified(&hashless, "etc/demo.conf", &path));
    }

    #[test]
    fn a_config_kept_beside_a_pacnew_is_preserved_despite_its_hash() {
        use crate::pkg::{BackupFile, Package};

        let dir = std::env::temp_dir().join("rvn-backup-pacnew");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sudo");
        std::fs::write(&path, b"raven's own stack").unwrap();

        // What an older rvn recorded: the hash of the file it kept, which
        // makes that file look like untouched package content.
        let pkg = Package {
            backup: vec![BackupFile {
                path: "etc/pam.d/sudo".into(),
                hash: Some(crate::verify::sha256_file(&path).unwrap()),
            }],
            ..Default::default()
        };
        assert!(!was_modified(&pkg, "etc/pam.d/sudo", &path));

        std::fs::write(dir.join("sudo.pacnew"), b"arch's stack").unwrap();
        assert!(was_modified(&pkg, "etc/pam.d/sudo", &path));
    }

    #[test]
    fn removals_are_appended_to_the_log() {
        let dir = std::env::temp_dir().join("rvn-remove-log");
        let _ = std::fs::remove_dir_all(&dir);
        let log = dir.join("log/pacman.log");

        log_removed(&log, "mako", "1.9.0-1", 0).unwrap();
        log_removed(&log, "libfoo", "2-1", 60).unwrap();

        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "[1970-01-01T00:00:00+0000] [RVN] removed mako (1.9.0-1)\n\
             [1970-01-01T00:01:00+0000] [RVN] removed libfoo (2-1)\n"
        );
    }

    #[test]
    fn prunes_nested_empty_directories_up_to_the_root() {
        let root = std::env::temp_dir().join("rvn-prune-test");
        let _ = std::fs::remove_dir_all(&root);
        let deep = root.join("usr/share/doc/demo");
        std::fs::create_dir_all(&deep).unwrap();

        let dirs: HashSet<PathBuf> = [deep.clone()].into_iter().collect();
        let pruned = prune_dirs(&root, dirs);

        // usr, usr/share, usr/share/doc, usr/share/doc/demo.
        assert_eq!(pruned, 4);
        assert!(!root.join("usr").exists());
        // The install root itself must survive.
        assert!(root.exists());
    }

    #[test]
    fn stops_at_a_non_empty_directory() {
        let root = std::env::temp_dir().join("rvn-prune-keep");
        let _ = std::fs::remove_dir_all(&root);
        let deep = root.join("usr/bin/sub");
        std::fs::create_dir_all(&deep).unwrap();
        // A sibling file keeps usr/bin alive.
        std::fs::write(root.join("usr/bin/other"), b"x").unwrap();

        let dirs: HashSet<PathBuf> = [deep].into_iter().collect();
        let pruned = prune_dirs(&root, dirs);

        assert_eq!(pruned, 1, "only the empty leaf may be pruned");
        assert!(root.join("usr/bin").exists());
        assert!(root.join("usr/bin/other").exists());
    }
}
