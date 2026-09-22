//! `rvn rollback`.
//!
//! Bare, it reports what could be rolled back. Named, it puts one package
//! back to the previous version in the cache. What it cannot do, and why, is
//! written out in [`crate::rollback`]'s module documentation; the short
//! version is that rvn keeps no copy of the bytes an upgrade overwrote, so a
//! rollback is a downgrade rather than an undo, and this says so to the
//! person's face before it does anything.
//!
//! # `--user`
//!
//! A rollback under `--user` works, and it is not a special case. The
//! configuration a per-user prefix is built with already points
//! `cache_dirs` at the caller's own cache (see
//! [`crate::config::UserPrefix`]), so the archives found are the ones that
//! prefix installed, and the install underneath goes through the same
//! `install_archives` as any other, which already skips scriptlets and hooks
//! for a prefix. Nothing here needs to know about it -- but it was checked
//! rather than assumed, because every other install-time step in this crate
//! has had to answer the question.
//!
//! # The archive is not swept afterwards
//!
//! An ordinary transaction clears what it downloaded unless `--keep-cache`
//! was given. A rollback deliberately does not: the archive it just
//! installed from is the only copy of that version on the machine, and
//! deleting it would mean the next `rvn update` could take the package
//! forward with no way back. Nothing is added to the cache either, so
//! [`crate::cache`]'s retention rules still decide when it goes.

use super::Context;
use crate::cache::Inventory;
use crate::rollback::{self, Target};
use crate::ui::theme::bytes;

/// Reports what can be rolled back, or rolls one package back.
pub fn run(ctx: &mut Context, package: Option<&str>) -> Result<(), String> {
    let inventory = Inventory::scan(&ctx.config.cache_dirs);

    match package {
        None => report(ctx, &inventory),
        Some(package) => apply(ctx, &inventory, package),
    }
}

/// The bare command: what is available, and nothing changed.
fn report(ctx: &mut Context, inventory: &Inventory) -> Result<(), String> {
    let targets = rollback::available(inventory, &ctx.local);

    if ctx.ui.is_json() {
        ctx.ui.emit(
            "rollback_available",
            serde_json::json!({
                "count": targets.len(),
                "packages": targets.iter().map(payload).collect::<Vec<_>>(),
            }),
        );
        return Ok(());
    }

    if targets.is_empty() {
        ctx.ui.info(
            "nothing can be rolled back: the cache holds no earlier version of anything installed",
        );
        // The reason, not just the fact. This is the expected state on a
        // machine that has never kept its cache, and the fix is a setting
        // rather than anything to do with rollback.
        ctx.ui.detail(
            "the cache is cleared after every transaction unless `rvn install --keep-cache` is used",
        );
        ctx.ui
            .detail("`rvn cache status` shows what is being kept today");
        return Ok(());
    }

    let s = &ctx.ui.style;
    ctx.ui.info(&format!(
        "{} {} could be rolled back:",
        s.bold(&targets.len().to_string()),
        if targets.len() == 1 {
            "package"
        } else {
            "packages"
        }
    ));
    ctx.ui.tree(
        &targets
            .iter()
            .map(|t| {
                format!(
                    "{} {} {} {}",
                    s.bold(&t.package),
                    s.dim(&t.from),
                    s.dim("→"),
                    t.to
                )
            })
            .collect::<Vec<_>>(),
    );
    ctx.ui.blank();
    ctx.ui.detail("roll one back with `rvn rollback <package>`");
    Ok(())
}

/// Rolls one package back.
fn apply(ctx: &mut Context, inventory: &Inventory, package: &str) -> Result<(), String> {
    let target = rollback::find(inventory, &ctx.local, package).map_err(|e| e.to_string())?;

    ctx.ui.banner(&format!("v{}", env!("CARGO_PKG_VERSION")));
    ctx.ui
        .emit("rollback_plan", serde_json::json!(payload(&target)));

    ctx.ui.blank();
    // Scoped: `Style` is borrowed out of the UI, and the install below takes
    // the whole context mutably.
    {
        let s = &ctx.ui.style;
        ctx.ui.info(&format!(
            "{} {} {} {}",
            s.bold(&target.package),
            target.from,
            s.dim("→"),
            s.bold(&target.to)
        ));
    }
    ctx.ui.detail(&format!(
        "from {} ({})",
        target.archive.path.display(),
        bytes(target.archive.size)
    ));

    // Said before the confirmation, because it is the thing somebody
    // reaching for a rollback is most likely to be wrong about. rvn keeps no
    // copy of what an upgrade overwrote, so this puts the package's files
    // back and nothing else.
    ctx.ui.detail(
        "this reinstalls the package's files; anything the newer version changed outside them — migrated state, rewritten configuration — stays changed",
    );

    // Named rather than counted, because the answer decides whether the
    // rollback is safe: a package whose dependents wanted the newer version
    // will be broken by this, and rvn's resolver is not being asked, so the
    // person has to be.
    let dependents = dependents_wanting_more(ctx, &target);
    if !dependents.is_empty() {
        ctx.ui.blank();
        ctx.ui.warn(&format!(
            "{} installed {} require a newer {} than this:",
            dependents.len(),
            if dependents.len() == 1 {
                "package"
            } else {
                "packages"
            },
            target.package
        ));
        ctx.ui.tree(&dependents);
    }

    if ctx.dry_run {
        ctx.ui.blank();
        ctx.ui.info("dry run — nothing was changed");
        return Ok(());
    }

    if !ctx.assume_yes
        && !ctx.ui.confirm(
            &format!("roll {} back to {}?", target.package, target.to),
            // Defaults to no. Every other confirmation in rvn defaults to
            // yes because the person asked for the thing being confirmed;
            // this one is a downgrade, which is the direction that surprises
            // people, and the warning above may be the first they have heard
            // of the consequences.
            false,
        )
    {
        return Err("cancelled".to_string());
    }

    if !ctx.local.is_installed(&target.package) {
        return Err(format!("{} is no longer installed", target.package));
    }

    let outcome = super::install::install_from_cache(ctx, &target.package, &target.archive.path)?;

    ctx.ui.blank();
    if outcome.installed.is_empty() {
        return Err(format!("{} was not rolled back", target.package));
    }
    ctx.ui.ok(&format!(
        "{} is back at {}",
        ctx.ui.style.bold(&target.package),
        target.to
    ));
    ctx.ui.emit(
        "rollback_done",
        serde_json::json!({
            "package": target.package,
            "version": target.to,
        }),
    );

    // The rollback is undone by the next `rvn update`, which will find a
    // newer version in the repository and offer it. Saying so is the
    // difference between a rollback that holds and one that quietly comes
    // back in a week.
    ctx.ui.detail(&format!(
        "`rvn update` will offer {} again — add it to IgnorePkg in /etc/pacman.conf to hold it here",
        target.package
    ));

    Ok(())
}

/// Installed packages whose dependency on this one the older version would no
/// longer satisfy.
///
/// Read from the local database rather than resolved, because a resolver run
/// would answer a different question -- what the repositories offer -- and
/// this is about what is on the machine now.
fn dependents_wanting_more(ctx: &Context, target: &Target) -> Vec<String> {
    let s = &ctx.ui.style;
    let mut wanting = Vec::new();

    for package in ctx.local.packages.values() {
        for dep in &package.depends {
            if dep.name != target.package {
                continue;
            }
            // A dependency with no version constraint is satisfied by any
            // version, including the older one, so it is not a problem and
            // saying it was would bury the ones that are.
            if dep.satisfied_by(&target.to) {
                continue;
            }
            wanting.push(format!(
                "{} {}",
                s.bold(&package.name),
                s.dim(&format!("needs {}", dep))
            ));
        }
    }

    wanting.sort();
    wanting
}

fn payload(target: &Target) -> serde_json::Value {
    serde_json::json!({
        "package": target.package,
        "installed": target.from,
        "rollback_to": target.to,
        "archive": target.archive.path.display().to_string(),
        "size": target.archive.size,
    })
}
