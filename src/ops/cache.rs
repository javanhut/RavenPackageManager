//! `rvn cache`: what the package cache is holding, and what may go.
//!
//! The mechanism is [`crate::cache`] -- the walk, the retention rule and the
//! sweep all live there and have no idea a terminal exists. This module is the
//! command: it decides what to call things, which archives count as having
//! come from a repository and which were built here, which versions are
//! protected because they are installed, and how to say all of it once in
//! prose and once as an event.
//!
//! `status` is deliberately the default verb. The question anybody has when
//! they type `rvn cache` is "what is in there and why is it that big", and
//! answering it costs nothing and deletes nothing. `clean` is the verb that
//! removes things, and it never runs by being guessed at.
//!
//! `--user` is the one place where the answer is "the same thing, somewhere
//! else" rather than "skipped". Every other install-time step that needs root
//! -- scriptlets, sysusers and tmpfiles, the desktop caches -- is stepped over
//! for a per-user prefix, but a prefix has a cache of its own at
//! `$XDG_CACHE_HOME/rvn/pkg`, it fills up the same way, and the person who
//! owns it can write to it without asking anyone. So both verbs run, against
//! `ctx.config.cache_dirs` and `ctx.local` as the invocation defines them, and
//! report on the prefix rather than on the system.

use super::Context;
use crate::cache::{self, Inventory, Policy, Sweep};
use crate::ui::theme::bytes;
use std::collections::HashSet;

/// How many per-package lines a report prints before it stops and says how
/// many more there were.
///
/// A full system's cache has hundreds of names in it and a list that long is
/// not read, it is scrolled past. The lines are sorted by what they are
/// holding, so the twelve that are printed are the twelve that explain the
/// number at the top; `--json` carries all of them for anything that wants to
/// do its own arithmetic.
const LISTED: usize = 12;

/// What `rvn cache` was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Status,
    Clean,
}

impl Action {
    /// The verb as the command line spells it, or `None` for anything else.
    pub fn parse(verb: &str) -> Option<Action> {
        match verb {
            "status" => Some(Action::Status),
            "clean" => Some(Action::Clean),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Status => "status",
            Action::Clean => "clean",
        }
    }
}

/// How a clean was asked to behave.
pub struct Options {
    /// Versions of each package to keep; [`cache::DEFAULT_KEEP`] unless the
    /// caller said otherwise.
    pub keep: usize,
    /// Sweep the AUR build trees as well. Never implied by anything.
    pub builds: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            keep: cache::DEFAULT_KEEP,
            builds: false,
        }
    }
}

/// Runs `rvn cache <verb>`.
pub fn run(ctx: &mut Context, action: Action, options: &Options) -> Result<(), String> {
    let inventory = Inventory::scan(&ctx.config.cache_dirs);

    // Said once, up front, whichever verb follows: a report that silently
    // omits /var/cache/pacman/pkg because the caller is not root would put a
    // reassuring small number on the screen for the directory that is the
    // whole problem.
    for path in &inventory.unreadable {
        ctx.ui.warn(&format!(
            "cannot read {} — this is not the whole picture; try sudo",
            path.display()
        ));
    }

    match action {
        Action::Status => {
            status(ctx, &inventory);
            Ok(())
        }
        Action::Clean => clean(ctx, &inventory, options),
    }
}

/// The size of each thing in the cache, and which packages are holding more
/// than one version.
fn status(ctx: &Context, inventory: &Inventory) {
    let split = Split::of(ctx, inventory);
    let held = versions_held(ctx, inventory);
    let index = index_cache();

    if ctx.ui.is_json() {
        ctx.ui.emit(
            "cache",
            serde_json::json!({
                "directories": inventory
                    .roots
                    .iter()
                    .map(|r| r.display().to_string())
                    .collect::<Vec<_>>(),
                "total": inventory.total(),
                "repository": { "count": split.repo_count, "bytes": split.repo },
                "built": { "count": split.built_count, "bytes": split.built },
                "sources": { "count": inventory.builds.len(), "bytes": split.sources },
                "partial": { "count": inventory.partials.len(), "bytes": split.partial },
                "other": { "count": split.other_count, "bytes": split.other },
                "index": index.map(|(path, size)| serde_json::json!({
                    "path": path.display().to_string(),
                    "bytes": size,
                })),
                "packages": held
                    .iter()
                    .map(|p| serde_json::json!({
                        "name": p.name,
                        "versions": p.versions,
                        "bytes": p.size,
                        "reclaimable": p.reclaimable,
                        "built": p.built,
                    }))
                    .collect::<Vec<_>>(),
            }),
        );
        return;
    }

    let s = &ctx.ui.style;
    ctx.ui.info(&format!(
        "{} in {}",
        s.bold(&bytes(inventory.total())),
        inventory
            .roots
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));

    let mut lines = vec![
        format!(
            "{:>10}  {} package archives from repositories",
            bytes(split.repo),
            split.repo_count
        ),
        format!(
            "{:>10}  {} archives built here",
            bytes(split.built),
            split.built_count
        ),
        format!(
            "{:>10}  aur sources and git checkouts, for {} package{}",
            bytes(split.sources),
            inventory.builds.len(),
            if inventory.builds.len() == 1 { "" } else { "s" }
        ),
    ];
    if !inventory.partials.is_empty() {
        lines.push(format!(
            "{:>10}  {} interrupted download{}",
            bytes(split.partial),
            inventory.partials.len(),
            if inventory.partials.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
    }
    if split.other > 0 {
        lines.push(format!(
            "{:>10}  {} other file{} rvn does not recognise",
            bytes(split.other),
            split.other_count,
            if split.other_count == 1 { "" } else { "s" }
        ));
    }
    ctx.ui.tree(&lines);

    // The parse cache is not the package cache and is not cleaned by this
    // command -- it is a rebuildable index under the caller's own home, not
    // something an administrator has to manage. It is mentioned because it is
    // the other rvn directory that grows, and somebody chasing disk space
    // should not have to find it by accident.
    if let Some((path, size)) = index {
        ctx.ui.detail(&format!(
            "database parse cache: {} in {} (rebuilt on demand; delete it freely)",
            bytes(size),
            path.display()
        ));
    }

    let multiple: Vec<&Held> = held.iter().filter(|p| p.versions > 1).collect();
    if multiple.is_empty() {
        ctx.ui
            .detail("no package is holding more than one version; there is nothing for `rvn cache clean` to retire");
        return;
    }

    ctx.ui.blank();
    ctx.ui.info(&format!(
        "{} package{} holding more than one version:",
        multiple.len(),
        if multiple.len() == 1 { "" } else { "s" }
    ));
    let mut lines: Vec<String> = multiple
        .iter()
        .take(LISTED)
        .map(|p| {
            format!(
                "{} {} {}",
                s.bold(&p.name),
                s.dim(&format!("{} versions", p.versions)),
                bytes(p.size)
            )
        })
        .collect();
    if multiple.len() > LISTED {
        lines.push(s.dim(&format!("and {} more", multiple.len() - LISTED)));
    }
    ctx.ui.tree(&lines);

    let reclaimable: u64 = held.iter().map(|p| p.reclaimable).sum();
    if reclaimable > 0 {
        ctx.ui.detail(&format!(
            "`rvn cache clean` would reclaim {} and keep the {} most recent versions of each",
            bytes(reclaimable),
            cache::DEFAULT_KEEP
        ));
    }
}

/// Retires the versions the policy does not keep.
fn clean(ctx: &Context, inventory: &Inventory, options: &Options) -> Result<(), String> {
    let policy = Policy {
        keep: options.keep,
        builds: options.builds,
        // Everything installed right now, by exact version. This is the list
        // that makes the difference between a cache clean and a machine that
        // can no longer reinstall what it is running without the network.
        protected: ctx
            .local
            .packages
            .values()
            .map(|pkg| (pkg.name.clone(), pkg.version.clone()))
            .collect(),
    };
    let sweep = cache::plan(inventory, &policy);

    if options.builds && !confirm_builds(ctx, inventory)? {
        return Err("cancelled".into());
    }

    report_plan(ctx, &sweep, options);

    if sweep.is_empty() {
        ctx.ui.ok("nothing to clean");
        return Ok(());
    }

    if ctx.dry_run {
        ctx.ui.ok(&format!(
            "dry run — {} would be reclaimed, nothing was deleted",
            bytes(sweep.reclaimed)
        ));
        return Ok(());
    }

    let swept = cache::apply(&sweep);

    // Nothing at all came out and the reason was permissions: this is the
    // ordinary case of an unprivileged `rvn cache clean` against
    // /var/cache/pacman/pkg, and it deserves the one sentence that fixes it
    // rather than the same permission error printed once per archive.
    if swept.denied && swept.freed == 0 {
        return Err(format!(
            "cannot write to {} — `rvn cache clean` needs root, so run it with sudo",
            inventory
                .roots
                .first()
                .map(|r| r.display().to_string())
                .unwrap_or_else(|| "the cache".into())
        ));
    }

    for failure in &swept.failures {
        ctx.ui.warn(failure);
    }

    if swept.rescued > 0 {
        ctx.ui.info(&format!(
            "moved {} built package{} into the cache before removing their build trees",
            swept.rescued,
            if swept.rescued == 1 { "" } else { "s" }
        ));
    }

    ctx.ui.emit(
        "cache_clean",
        serde_json::json!({
            "keep": options.keep,
            "builds": options.builds,
            "freed": swept.freed,
            "archives": swept.archives,
            "partials": swept.partials,
            "trees": swept.trees,
            "rescued": swept.rescued,
            "kept": sweep.kept,
            "failures": swept.failures,
        }),
    );

    ctx.ui.ok(&format!(
        "reclaimed {} — {}",
        bytes(swept.freed),
        removed_summary(&swept)
    ));
    Ok(())
}

/// Asks before the one part of a clean that cannot be undone by downloading
/// something again.
fn confirm_builds(ctx: &Context, inventory: &Inventory) -> Result<bool, String> {
    if inventory.builds.is_empty() {
        return Ok(true);
    }

    let sources: u64 = inventory.builds.iter().map(|b| b.sources()).sum();
    ctx.ui.warn(&format!(
        "--builds deletes {} of AUR build trees: {}",
        bytes(sources),
        inventory
            .builds
            .iter()
            .map(|b| b.package.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    ctx.ui.detail(
        "that is the git checkout, any PKGBUILD edits in it and every source tarball the build downloaded; the next build re-clones and re-downloads all of it",
    );
    ctx.ui
        .detail("the built packages themselves are moved into the cache first and kept");

    if ctx.assume_yes {
        return Ok(true);
    }
    if !ctx.ui.style.interactive {
        return Err(
            "`rvn cache clean --builds` discards build trees and there is no terminal to confirm on — pass --yes if that is what you meant"
                .into(),
        );
    }
    Ok(ctx.ui.confirm("delete the build trees?", true))
}

/// The per-package lines a clean prints before it does anything.
fn report_plan(ctx: &Context, sweep: &Sweep, options: &Options) {
    let s = &ctx.ui.style;
    ctx.ui.info(&format!(
        "keeping the {} most recent version{} of each package, and whatever is installed",
        options.keep,
        if options.keep == 1 { "" } else { "s" }
    ));

    if sweep.retired.is_empty() {
        return;
    }

    let mut lines: Vec<String> = sweep
        .retired
        .iter()
        .take(LISTED)
        .map(|r| {
            format!(
                "{} {} {}",
                s.bold(&r.package),
                s.dim(&r.version),
                bytes(r.size())
            )
        })
        .collect();
    if sweep.retired.len() > LISTED {
        lines.push(s.dim(&format!("and {} more", sweep.retired.len() - LISTED)));
    }
    ctx.ui.tree(&lines);
}

/// "37 archives, 2 interrupted downloads and 1 build tree", without the empty
/// clauses.
fn removed_summary(swept: &cache::Swept) -> String {
    let mut parts = Vec::new();
    if swept.archives > 0 {
        parts.push(format!(
            "{} archive{}",
            swept.archives,
            if swept.archives == 1 { "" } else { "s" }
        ));
    }
    if swept.partials > 0 {
        parts.push(format!(
            "{} interrupted download{}",
            swept.partials,
            if swept.partials == 1 { "" } else { "s" }
        ));
    }
    if swept.trees > 0 {
        parts.push(format!(
            "{} build tree{}",
            swept.trees,
            if swept.trees == 1 { "" } else { "s" }
        ));
    }
    match parts.len() {
        0 => "nothing was removed".to_string(),
        1 => parts.remove(0),
        _ => {
            let last = parts.pop().unwrap_or_default();
            format!("{} and {last}", parts.join(", "))
        }
    }
}

/// The size of the cache broken down the way somebody looking for space
/// thinks about it.
///
/// The parts add up to [`Inventory::total`] exactly, which is the only reason
/// the numbers are worth printing together: a breakdown whose lines do not
/// sum to the headline just raises a second question.
struct Split {
    repo: u64,
    repo_count: usize,
    built: u64,
    built_count: usize,
    sources: u64,
    partial: u64,
    other: u64,
    other_count: usize,
}

impl Split {
    fn of(ctx: &Context, inventory: &Inventory) -> Split {
        let carried: HashSet<&str> = ctx
            .sync
            .iter()
            .flat_map(|db| db.packages.iter().map(|p| p.name.as_str()))
            .collect();

        // Two ways of knowing something was built here, and the second only
        // works when there are databases to check against. An archive inside a
        // build tree is unambiguous. One sitting in the cache directory proper
        // is a judgement: no configured repository carries a package by that
        // name, so either it was built here or the repository that had it is
        // gone -- and for the purpose of "where did my disk go" those are the
        // same answer. With no sync databases loaded at all (--repo-only on a
        // machine that has never synced, or a fresh install) every name would
        // fail that test, so the question is not asked.
        let judge = !carried.is_empty();
        let built_here = |archive: &cache::Archive| {
            archive.built || (judge && !carried.contains(archive.package.as_str()))
        };

        let mut split = Split {
            repo: 0,
            repo_count: 0,
            built: 0,
            built_count: 0,
            sources: 0,
            partial: inventory.partials.iter().map(|s| s.size).sum(),
            other: 0,
            other_count: 0,
        };

        let mut artifacts = 0;
        for archive in &inventory.archives {
            if archive.built {
                artifacts += archive.total();
            }
            if built_here(archive) {
                split.built += archive.total();
                split.built_count += 1;
            } else {
                split.repo += archive.total();
                split.repo_count += 1;
            }
        }

        // What is left of the build trees once their finished packages are
        // counted elsewhere. Anything in a tree that is neither -- a stray
        // signature, a half-written archive -- falls in here, which is where a
        // reader would expect it.
        let trees: u64 = inventory.builds.iter().map(|b| b.total).sum();
        split.sources = trees.saturating_sub(artifacts);

        for stray in inventory.other.iter() {
            if let Some(size) = stray_outside_a_build_tree(inventory, stray) {
                split.other += size;
                split.other_count += 1;
            }
        }

        split
    }
}

/// A stray's size, unless a build tree has already counted it.
fn stray_outside_a_build_tree(inventory: &Inventory, stray: &cache::Stray) -> Option<u64> {
    if inventory
        .builds
        .iter()
        .any(|tree| stray.path.starts_with(&tree.path))
    {
        return None;
    }
    Some(stray.size)
}

/// One package's occupancy of the cache.
struct Held {
    name: String,
    versions: usize,
    size: u64,
    /// What a clean at the default retention would take back from it.
    reclaimable: u64,
    built: bool,
}

/// How many versions of each package the cache holds, biggest first.
fn versions_held(ctx: &Context, inventory: &Inventory) -> Vec<Held> {
    let installed: HashSet<(&str, &str)> = ctx
        .local
        .packages
        .values()
        .map(|pkg| (pkg.name.as_str(), pkg.version.as_str()))
        .collect();

    let mut held: Vec<Held> = inventory
        .by_package()
        .into_iter()
        .map(|(name, archives)| Held {
            name: name.to_string(),
            versions: archives.len(),
            size: archives.iter().map(|a| a.total()).sum(),
            reclaimable: archives
                .iter()
                .enumerate()
                .filter(|(index, archive)| {
                    *index >= cache::DEFAULT_KEEP
                        && !installed
                            .contains(&(archive.package.as_str(), archive.version.as_str()))
                })
                .map(|(_, archive)| archive.total())
                .sum(),
            built: archives.iter().any(|a| a.built),
        })
        .collect();

    held.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
    held
}

/// The database parse cache, when there is one: see [`crate::db::index`].
fn index_cache() -> Option<(std::path::PathBuf, u64)> {
    let dir = crate::db::index::cache_home()?.join("rvn").join("index");
    let mut total = 0;
    for entry in std::fs::read_dir(&dir).ok()?.flatten() {
        if let Ok(meta) = entry.metadata() {
            total += meta.len();
        }
    }
    Some((dir, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verbs_are_the_two_the_command_line_offers() {
        assert_eq!(Action::parse("status"), Some(Action::Status));
        assert_eq!(Action::parse("clean"), Some(Action::Clean));
        assert_eq!(Action::parse("clear"), None);
        assert_eq!(Action::Clean.as_str(), "clean");
    }

    #[test]
    fn the_default_keeps_something() {
        // A default of zero would empty the cache and make `rvn rollback`
        // impossible before it is even written; the default exists to be
        // conservative.
        assert!(Options::default().keep >= 1);
        assert_eq!(Options::default().keep, cache::DEFAULT_KEEP);
        assert!(!Options::default().builds, "build trees are never implied");
    }

    #[test]
    fn a_summary_reads_as_a_sentence_whatever_was_removed() {
        let swept = |archives, partials, trees| cache::Swept {
            archives,
            partials,
            trees,
            ..Default::default()
        };
        assert_eq!(removed_summary(&swept(1, 0, 0)), "1 archive");
        assert_eq!(removed_summary(&swept(4, 0, 0)), "4 archives");
        assert_eq!(
            removed_summary(&swept(4, 1, 0)),
            "4 archives and 1 interrupted download"
        );
        assert_eq!(
            removed_summary(&swept(4, 2, 1)),
            "4 archives, 2 interrupted downloads and 1 build tree"
        );
        assert_eq!(removed_summary(&swept(0, 0, 0)), "nothing was removed");
    }
}
