//! Read-only queries: package details, what is installed, and file ownership.

use super::Context;
use crate::pkg::{InstallReason, Origin, Package};
use crate::resolve::Source;
use crate::ui::theme::{Color, bytes};

/// What `rvn list` should report.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListFilter {
    /// Only packages installed as dependencies that nothing needs any more.
    pub orphans: bool,
    /// Only packages no configured repository carries (AUR or hand-built).
    pub foreign: bool,
    /// Only packages the user asked for by name.
    pub explicit: bool,
}

/// Finds a package anywhere: installed first, then repositories, then the AUR.
pub fn locate(ctx: &Context, name: &str) -> Option<Package> {
    let installed = ctx.local.get(name);
    let repo = repo_entry(ctx, name);

    match (installed, repo) {
        // A repository entry carries fields the local database never stores —
        // optional dependencies, download size — so it is the better base,
        // with the installed version kept so the report is about what is
        // actually on the system.
        (Some(local), Some(repo)) => {
            let mut merged = repo.clone();
            merged.version = local.version.clone();
            merged.install_reason = local.install_reason;
            merged.backup = local.backup.clone();
            merged.validation = local.validation;
            Some(merged)
        }
        (Some(local), None) => Some(local.clone()),
        (None, Some(repo)) => Some(repo.clone()),
        (None, None) if ctx.repo_only => None,
        (None, None) => ctx.aur.get(name),
    }
}

/// The repository entry for a package, if any repository carries it.
fn repo_entry<'a>(ctx: &'a Context, name: &str) -> Option<&'a Package> {
    ctx.sync.iter().find_map(|db| db.get(name))
}

/// `rvn info`: everything known about a package.
pub fn info(ctx: &Context, names: &[String]) -> Result<(), String> {
    let s = &ctx.ui.style;
    let mut missing = Vec::new();

    for (index, name) in names.iter().enumerate() {
        let Some(pkg) = locate(ctx, name) else {
            missing.push(name.clone());
            continue;
        };

        if index > 0 {
            println!();
        }

        let installed = ctx.local.get(name);
        let repo = repo_entry(ctx, name);
        let origin = match (installed.is_some(), repo) {
            (_, Some(r)) => r.origin.clone(),
            (true, None) => Origin::Aur,
            (false, None) => pkg.origin.clone(),
        };

        let field = |label: &str, value: &str| {
            if !value.is_empty() {
                println!("{:<16} {}", s.dim(label), value);
            }
        };

        println!(
            "{}",
            s.bold(&format!("{}/{}", s.paint(Color::Violet, origin.label()), pkg.name))
        );
        field("Version", &s.paint(Color::Green, &pkg.version));
        field("Description", &pkg.description);
        field("URL", pkg.url.as_deref().unwrap_or(""));
        field("Licenses", &pkg.licenses.join("  "));
        field("Architecture", pkg.arch.as_deref().unwrap_or(""));

        let deps = |list: &[crate::pkg::Dep]| {
            list.iter().map(|d| d.to_string()).collect::<Vec<_>>().join("  ")
        };
        field("Provides", &deps(&pkg.provides));
        field("Depends On", &deps(&pkg.depends));
        field("Conflicts", &deps(&pkg.conflicts));
        field("Replaces", &deps(&pkg.replaces));

        if !pkg.optdepends.is_empty() {
            println!("{:<16}", s.dim("Optional Deps"));
            for dep in &pkg.optdepends {
                let mark = if ctx.local.is_installed(&dep.name) {
                    s.paint(Color::Green, "installed")
                } else {
                    s.dim("not installed")
                };
                match &dep.description {
                    Some(desc) => println!("    {} — {} [{mark}]", s.bold(&dep.name), s.dim(desc)),
                    None => println!("    {} [{mark}]", s.bold(&dep.name)),
                }
            }
        }

        if pkg.csize > 0 {
            field("Download Size", &bytes(pkg.csize));
        }
        if pkg.isize > 0 {
            field("Installed Size", &bytes(pkg.isize));
        }
        field("Packager", pkg.packager.as_deref().unwrap_or(""));

        if pkg.popularity > 0.0 {
            field("Popularity", &format!("{:.2}", pkg.popularity));
        }
        if pkg.out_of_date {
            field("Status", &s.paint(Color::Red, "flagged out of date"));
        }

        match installed {
            Some(local) => {
                field(
                    "Installed",
                    &s.paint(Color::Green, &format!("yes ({})", local.version)),
                );
                field(
                    "Install Reason",
                    match local.install_reason {
                        InstallReason::Explicit => "explicitly installed",
                        InstallReason::Dependency => "installed as a dependency",
                    },
                );
                let required: Vec<String> = ctx
                    .local
                    .packages
                    .values()
                    .filter(|p| p.depends.iter().any(|d| local.satisfies(d)))
                    .map(|p| p.name.clone())
                    .collect();
                field(
                    "Required By",
                    &if required.is_empty() {
                        "none".to_string()
                    } else {
                        required.join("  ")
                    },
                );
                if let Some(tracked) = ctx.devel.get(name) {
                    field("Upstream", &format!("{} @ {}", tracked.url, &tracked.commit[..tracked.commit.len().min(9)]));
                }
            }
            None => field("Installed", &s.dim("no")),
        }
    }

    if !missing.is_empty() {
        return Err(format!("no package named {}", missing.join(", ")));
    }
    Ok(())
}

/// Whether no configured repository carries an installed package.
pub fn is_foreign(ctx: &Context, pkg: &Package) -> bool {
    ctx.sync.iter().all(|db| db.get(&pkg.name).is_none())
}

/// The installed packages `rvn list` would show, sorted by name.
pub fn installed(ctx: &Context, filter: ListFilter) -> Vec<&Package> {
    let mut packages: Vec<&Package> = ctx.local.packages.values().collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));

    let is_foreign = |pkg: &Package| is_foreign(ctx, pkg);

    let selected: Vec<&Package> = packages
        .into_iter()
        .filter(|pkg| {
            if filter.explicit && pkg.install_reason != InstallReason::Explicit {
                return false;
            }
            if filter.foreign && !is_foreign(pkg) {
                return false;
            }
            if filter.orphans {
                if pkg.install_reason != InstallReason::Dependency {
                    return false;
                }
                // Nothing else may depend on it, directly or by provide.
                let needed = ctx.local.packages.values().any(|other| {
                    other.name != pkg.name && other.depends.iter().any(|d| pkg.satisfies(d))
                });
                if needed {
                    return false;
                }
            }
            true
        })
        .collect();
    selected
}

/// `rvn list`: installed packages, optionally filtered.
pub fn list(ctx: &Context, filter: ListFilter) -> Result<usize, String> {
    let s = &ctx.ui.style;
    let selected = installed(ctx, filter);
    let is_foreign = |pkg: &Package| is_foreign(ctx, pkg);

    for pkg in &selected {
        let tag = if is_foreign(pkg) {
            s.paint(Color::Cyan, "aur")
        } else {
            s.paint(Color::Violet, "repo")
        };
        let mut line = format!("{tag}/{} {}", s.bold(&pkg.name), s.paint(Color::Green, &pkg.version));
        if pkg.install_reason == InstallReason::Dependency {
            line.push_str(&format!(" {}", s.dim("(dependency)")));
        }
        println!("{line}");
    }

    Ok(selected.len())
}

/// `rvn owns`: which package owns a path.
pub fn owns(ctx: &Context, paths: &[String]) -> Result<(), String> {
    let s = &ctx.ui.style;
    let mut unowned = Vec::new();

    // One pass over the database builds an index; scanning per query would
    // re-read every file list.
    let mut index: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for name in ctx.local.packages.keys() {
        if let Ok(files) = ctx.local.files(name) {
            for file in files {
                index.insert(file, name.clone());
            }
        }
    }

    for query in paths {
        // Accept both absolute paths and database-relative ones.
        let relative = query
            .trim_start_matches('/')
            .to_string();

        match index.get(&relative) {
            Some(owner) => {
                let version = ctx
                    .local
                    .get(owner)
                    .map(|p| p.version.clone())
                    .unwrap_or_default();
                println!(
                    "{} is owned by {} {}",
                    query,
                    s.bold(owner),
                    s.paint(Color::Green, &version)
                );
            }
            None => unowned.push(query.clone()),
        }
    }

    if !unowned.is_empty() {
        return Err(format!("no package owns {}", unowned.join(", ")));
    }
    Ok(())
}

/// `rvn files`: the files an installed package owns.
pub fn files(ctx: &Context, names: &[String]) -> Result<(), String> {
    let mut missing = Vec::new();

    for name in names {
        if !ctx.local.is_installed(name) {
            missing.push(name.clone());
            continue;
        }
        for file in ctx.local.files(name).unwrap_or_default() {
            println!("{name} /{file}");
        }
    }

    if !missing.is_empty() {
        return Err(format!("not installed: {}", missing.join(", ")));
    }
    Ok(())
}
