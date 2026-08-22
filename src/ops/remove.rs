//! `rvn uninstall`: removing installed packages.

use super::Context;
use crate::remove::{self, Options, RemovalPlan};
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
        let plan = remove::plan(&ctx.local, targets, options);
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

    show_plan(ctx, &plan);

    if ctx.dry_run {
        ctx.ui.info("dry run — nothing was changed");
        return Ok(Outcome {
            removed: Vec::new(),
            preserved: Vec::new(),
        });
    }

    if !ctx.assume_yes && !ctx.ui.confirm("proceed with removal?", false) {
        return Err("cancelled".into());
    }

    apply(ctx, &plan)
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
    let mut touched_dirs: HashSet<PathBuf> = HashSet::new();

    for pkg in &plan.remove {
        progress.set_detail(&pkg.name);
        let files = remove::deletable_files(&ctx.local, pkg, &removing);

        for file in &files {
            // Directory entries are pruned after every file is gone.
            if let Some(dir) = file.strip_suffix('/') {
                touched_dirs.insert(ctx.config.root_dir.join(dir));
                progress.advance(1);
                continue;
            }

            let path = ctx.config.root_dir.join(file);

            if pkg.is_backup(file) && path.exists() && was_modified(pkg, file, &path) {
                // An edited configuration file is never destroyed; it is set
                // aside so an administrator can recover or discard it. One
                // still matching what was installed is just package content.
                let saved = path.with_extension(format!(
                    "{}pacsave",
                    path.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| format!("{e}."))
                        .unwrap_or_default()
                ));
                if std::fs::rename(&path, &saved).is_ok() {
                    preserved.push(file.clone());
                }
            } else {
                // A file already gone is not an error — the goal is its absence.
                let _ = std::fs::remove_file(&path);
            }

            if let Some(parent) = path.parent() {
                touched_dirs.insert(parent.to_path_buf());
            }
            progress.advance(1);
        }

        ctx.local
            .unregister(&pkg.name)
            .map_err(|e| format!("{}: could not update the local database: {e}", pkg.name))?;
        removed.push(pkg.name.clone());
    }

    progress.finish(&format!(
        "removed {} package{}",
        removed.len(),
        if removed.len() == 1 { "" } else { "s" }
    ));

    // ---- prune empty directories ---------------------------------------
    let spinner = ctx.ui.stage("pruning empty directories");
    let pruned = prune_dirs(&ctx.config.root_dir, touched_dirs);
    spinner.succeed(&format!(
        "pruned {pruned} empty director{}",
        if pruned == 1 { "y" } else { "ies" }
    ));

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

/// Whether a backup file differs from what the package installed.
///
/// Without a recorded checksum the file cannot be proven untouched, so it is
/// treated as modified — losing an edit is far worse than leaving a stray
/// `.pacsave` behind.
fn was_modified(pkg: &crate::pkg::Package, file: &str, path: &Path) -> bool {
    let Some(original) = pkg.backup_hash(file) else {
        return true;
    };
    match crate::verify::sha256_file(path) {
        Ok(current) => !current.eq_ignore_ascii_case(original),
        Err(_) => true,
    }
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
