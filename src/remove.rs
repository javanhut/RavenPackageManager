//! Removal planning: what can be uninstalled, and in what order.
//!
//! The hard part is not deleting files, it is deciding whether deleting them
//! breaks something. A package only blocks a removal if *every* installed
//! provider of a dependency is going away — otherwise something else still
//! satisfies it.

use crate::db::local::LocalDb;
use crate::pkg::{InstallReason, Package};
use crate::provides::SystemProvides;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Also remove packages that depend on the targets.
    pub cascade: bool,
    /// Also remove dependencies that become orphaned.
    pub recursive: bool,
    /// Remove regardless of what would break.
    pub nodeps: bool,
    /// The caller has seen the orphans and wants them gone. Required for an
    /// orphan sweep under `--yes`, where nobody is asked.
    pub remove_orphans: bool,
}

/// What Raven needs to log in, become root and install its way back, held
/// whatever `HoldPkg` says: an unset or trimmed `HoldPkg` must not be what
/// lets an uninstall take sudo or tar. rvn itself is statically linked with
/// its own certificates and decompressors, so it needs nothing more.
pub const ESSENTIAL: &[&str] = &[
    "filesystem",
    "glibc",
    "bash",
    "coreutils",
    "util-linux",
    "shadow",
    "pam",
    "sudo",
    "pacman",
    "tar",
];

/// Packages in `plan` that are held: essential, or named by `HoldPkg`.
pub fn held(plan: &RemovalPlan, hold_pkg: &[String]) -> Vec<String> {
    plan.remove
        .iter()
        .map(|pkg| pkg.name.clone())
        .filter(|name| ESSENTIAL.contains(&name.as_str()) || hold_pkg.contains(name))
        .collect()
}

/// A package that cannot be removed because something still needs it.
#[derive(Debug, Clone)]
pub struct Blocked {
    pub package: String,
    /// Installed packages that would be broken, with the dependency named.
    pub required_by: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct RemovalPlan {
    /// Packages to remove, dependents before their dependencies.
    pub remove: Vec<Package>,
    pub blocked: Vec<Blocked>,
    pub not_installed: Vec<String>,
    /// Packages added because they became orphaned.
    pub orphaned: Vec<String>,
    /// Packages added because they depended on a target.
    pub cascaded: Vec<String>,
}

impl RemovalPlan {
    pub fn is_empty(&self) -> bool {
        self.remove.is_empty()
    }

    /// Disk space that removal frees.
    pub fn freed_size(&self) -> u64 {
        self.remove.iter().map(|p| p.isize).sum()
    }
}

/// Every installed package outside `removing` that would lose a dependency,
/// paired with the dependency in question.
fn broken_by(
    local: &LocalDb,
    system: &SystemProvides,
    removing: &HashSet<String>,
) -> Vec<(String, String)> {
    let mut broken = Vec::new();

    for pkg in local.packages.values() {
        if removing.contains(&pkg.name) {
            continue;
        }

        for dep in &pkg.depends {
            // Only a dependency that is currently satisfied can be broken.
            if local.satisfier(dep).is_none() {
                continue;
            }
            // Something outside the removal set still satisfying it means no
            // breakage, even if one provider is going away.
            // The base system providing it counts too: removing an
            // `xdg-utils` rvn once installed breaks nothing while raven-open
            // stands in for it.
            let survives = system.satisfier(dep).is_some()
                || local
                    .packages
                    .values()
                    .any(|other| !removing.contains(&other.name) && other.satisfies(dep));
            if !survives {
                broken.push((pkg.name.clone(), dep.to_string()));
            }
        }
    }

    broken
}

/// Whether anything outside `removing` still needs `candidate`.
fn is_orphan(local: &LocalDb, candidate: &Package, removing: &HashSet<String>) -> bool {
    if candidate.install_reason != InstallReason::Dependency {
        return false;
    }
    !local.packages.values().any(|pkg| {
        !removing.contains(&pkg.name)
            && pkg.name != candidate.name
            && pkg.depends.iter().any(|dep| candidate.satisfies(dep))
    })
}

/// Orders a removal set so dependents come before what they depend on.
fn removal_order(local: &LocalDb, names: &HashSet<String>) -> Vec<Package> {
    let mut remaining: Vec<Package> = names
        .iter()
        .filter_map(|n| local.get(n).cloned())
        .collect();
    remaining.sort_by(|a, b| a.name.cmp(&b.name));

    let mut ordered = Vec::new();

    while !remaining.is_empty() {
        // A package is safe to remove once nothing left in the set depends
        // on it.
        let next = remaining.iter().position(|candidate| {
            !remaining.iter().any(|other| {
                other.name != candidate.name
                    && other.depends.iter().any(|dep| candidate.satisfies(dep))
            })
        });

        match next {
            Some(index) => ordered.push(remaining.remove(index)),
            // A cycle within the removal set: order cannot matter, so drain.
            None => {
                ordered.append(&mut remaining);
                break;
            }
        }
    }

    ordered
}

/// Builds a removal plan for `targets`.
pub fn plan(local: &LocalDb, targets: &[String], options: Options) -> RemovalPlan {
    plan_with(local, &SystemProvides::default(), targets, options)
}

/// [`plan`], counting what the base system provides as still satisfying
/// dependencies after the removal.
pub fn plan_with(
    local: &LocalDb,
    system: &SystemProvides,
    targets: &[String],
    options: Options,
) -> RemovalPlan {
    let mut plan = RemovalPlan::default();
    let mut removing: HashSet<String> = HashSet::new();

    for target in targets {
        if local.is_installed(target) {
            removing.insert(target.clone());
        } else {
            plan.not_installed.push(target.clone());
        }
    }

    if removing.is_empty() {
        return plan;
    }

    // Cascade first: pulling in dependents can itself orphan more packages.
    if options.cascade {
        loop {
            let broken = broken_by(local, system, &removing);
            let additions: Vec<String> = broken
                .iter()
                .map(|(name, _)| name.clone())
                .filter(|name| !removing.contains(name))
                .collect();
            if additions.is_empty() {
                break;
            }
            for name in additions {
                plan.cascaded.push(name.clone());
                removing.insert(name);
            }
        }
    }

    if options.recursive {
        loop {
            // Only what the removal set itself depends on can be orphaned by
            // it. A package that was already unneeded before this removal is
            // not this removal's to take: scanning the whole database is how
            // uninstalling a notification daemon swept away sudo, pacman and
            // tar, which an earlier AUR build had left recorded as
            // dependencies that nothing required.
            let wanted: Vec<&crate::pkg::Dep> = removing
                .iter()
                .filter_map(|name| local.get(name))
                .flat_map(|pkg| pkg.depends.iter())
                .collect();
            let additions: Vec<String> = local
                .packages
                .values()
                .filter(|pkg| !removing.contains(&pkg.name))
                .filter(|pkg| wanted.iter().any(|&dep| pkg.satisfies(dep)))
                .filter(|pkg| is_orphan(local, pkg, &removing))
                .map(|pkg| pkg.name.clone())
                .collect();
            if additions.is_empty() {
                break;
            }
            for name in additions {
                plan.orphaned.push(name.clone());
                removing.insert(name);
            }
        }
    }

    if !options.nodeps {
        let broken = broken_by(local, system, &removing);
        if !broken.is_empty() {
            // Report against the target that is actually disappearing.
            let mut blocked: Vec<Blocked> = Vec::new();
            for name in &removing {
                let culprits: Vec<(String, String)> = broken
                    .iter()
                    .filter(|(_, dep)| {
                        local
                            .get(name)
                            .map(|pkg| pkg.satisfies(&crate::pkg::Dep::parse(dep)))
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                if !culprits.is_empty() {
                    blocked.push(Blocked {
                        package: name.clone(),
                        required_by: culprits,
                    });
                }
            }
            blocked.sort_by(|a, b| a.package.cmp(&b.package));
            plan.blocked = blocked;
            return plan;
        }
    }

    plan.cascaded.sort();
    plan.orphaned.sort();
    plan.remove = removal_order(local, &removing);
    plan
}

/// Files that are safe to delete when removing `pkg`.
///
/// A file still owned by a package that survives must be left alone, which is
/// what makes removing one of two packages sharing a file safe.
pub fn deletable_files(
    local: &LocalDb,
    pkg: &Package,
    also_removing: &HashSet<String>,
) -> std::io::Result<Vec<String>> {
    let own_files = local.files_or_empty(&pkg.name)?;

    let mut kept: HashSet<String> = HashSet::new();
    for other in local.packages.values() {
        if other.name == pkg.name || also_removing.contains(&other.name) {
            continue;
        }
        // An unreadable file list must abort the removal. Skipping it would
        // leave that package's files looking unowned, and they would be
        // deleted along with the target's.
        kept.extend(local.files_or_empty(&other.name)?);
    }

    Ok(own_files
        .into_iter()
        .filter(|file| !kept.contains(file))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::Dep;
    use std::path::PathBuf;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-remove-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pkg(name: &str, depends: &[&str], reason: InstallReason) -> Package {
        Package {
            name: name.into(),
            version: "1.0-1".into(),
            depends: depends.iter().map(|d| Dep::parse(d)).collect(),
            install_reason: reason,
            isize: 1000,
            ..Default::default()
        }
    }

    /// Builds a local database with the given packages, each owning one file.
    fn db(tag: &str, packages: Vec<Package>) -> LocalDb {
        let root = temp_root(tag);
        let mut db = LocalDb::load(&root);
        for p in packages {
            let file = format!("usr/bin/{}", p.name);
            db.register(&p, &[file]).unwrap();
        }
        db
    }

    fn names(plan: &RemovalPlan) -> Vec<String> {
        plan.remove.iter().map(|p| p.name.clone()).collect()
    }

    #[test]
    fn removes_a_leaf_package() {
        let local = db(
            "leaf",
            vec![pkg("app", &[], InstallReason::Explicit)],
        );
        let plan = plan(&local, &["app".into()], Options::default());
        assert_eq!(names(&plan), vec!["app"]);
        assert!(plan.blocked.is_empty());
        assert_eq!(plan.freed_size(), 1000);
    }

    #[test]
    fn refuses_to_break_a_dependent() {
        let local = db(
            "blocked",
            vec![
                pkg("app", &["libfoo"], InstallReason::Explicit),
                pkg("libfoo", &[], InstallReason::Dependency),
            ],
        );
        let plan = plan(&local, &["libfoo".into()], Options::default());

        assert!(plan.remove.is_empty(), "must not remove a needed package");
        assert_eq!(plan.blocked.len(), 1);
        assert_eq!(plan.blocked[0].package, "libfoo");
        assert_eq!(plan.blocked[0].required_by[0].0, "app");
    }

    #[test]
    fn removing_what_the_system_also_provides_breaks_nothing() {
        // An xdg-utils rvn installed before raven-open existed: chromium
        // still needs *an* xdg-utils, and the system has one.
        let local = db(
            "system-provided",
            vec![
                pkg("chromium", &["xdg-utils"], InstallReason::Explicit),
                pkg("xdg-utils", &[], InstallReason::Dependency),
            ],
        );
        let system = SystemProvides::from(crate::provides::parse("xdg-utils=1.2.1", "raven-open"));
        let with = plan_with(&local, &system, &["xdg-utils".into()], Options::default());
        assert_eq!(names(&with), vec!["xdg-utils"]);
        assert!(with.blocked.is_empty());

        // Without the provision the same removal is still refused.
        let without = plan(&local, &["xdg-utils".into()], Options::default());
        assert_eq!(without.blocked.len(), 1);
    }

    #[test]
    fn nodeps_overrides_the_block() {
        let local = db(
            "nodeps",
            vec![
                pkg("app", &["libfoo"], InstallReason::Explicit),
                pkg("libfoo", &[], InstallReason::Dependency),
            ],
        );
        let plan = plan(
            &local,
            &["libfoo".into()],
            Options {
                nodeps: true,
                ..Default::default()
            },
        );
        assert_eq!(names(&plan), vec!["libfoo"]);
    }

    #[test]
    fn cascade_pulls_in_dependents() {
        let local = db(
            "cascade",
            vec![
                pkg("app", &["libfoo"], InstallReason::Explicit),
                pkg("libfoo", &[], InstallReason::Dependency),
            ],
        );
        let plan = plan(
            &local,
            &["libfoo".into()],
            Options {
                cascade: true,
                ..Default::default()
            },
        );

        assert_eq!(plan.cascaded, vec!["app"]);
        // The dependent must be removed before the dependency.
        assert_eq!(names(&plan), vec!["app", "libfoo"]);
    }

    #[test]
    fn recursive_collects_orphaned_dependencies() {
        let local = db(
            "recursive",
            vec![
                pkg("app", &["libfoo"], InstallReason::Explicit),
                pkg("libfoo", &["libbar"], InstallReason::Dependency),
                pkg("libbar", &[], InstallReason::Dependency),
            ],
        );
        let plan = plan(
            &local,
            &["app".into()],
            Options {
                recursive: true,
                ..Default::default()
            },
        );

        // Both dependencies become orphans once app is gone.
        assert_eq!(plan.orphaned, vec!["libbar", "libfoo"]);
        assert_eq!(names(&plan), vec!["app", "libfoo", "libbar"]);
    }

    #[test]
    fn explicitly_installed_packages_are_never_orphans() {
        let local = db(
            "explicit-orphan",
            vec![
                pkg("app", &["tool"], InstallReason::Explicit),
                // Installed on purpose, so it must survive even when unused.
                pkg("tool", &[], InstallReason::Explicit),
            ],
        );
        let plan = plan(
            &local,
            &["app".into()],
            Options {
                recursive: true,
                ..Default::default()
            },
        );
        assert!(plan.orphaned.is_empty());
        assert_eq!(names(&plan), vec!["app"]);
    }

    #[test]
    fn recursive_leaves_unrelated_orphans_alone() {
        let local = db(
            "unrelated-orphans",
            vec![
                pkg("mako", &["libfoo"], InstallReason::Explicit),
                pkg("libfoo", &[], InstallReason::Dependency),
                // Left behind by an AUR build: recorded as dependencies, and
                // required by nothing long before mako is removed.
                pkg("base-devel", &["sudo", "pacman"], InstallReason::Dependency),
                pkg("sudo", &[], InstallReason::Dependency),
                pkg("pacman", &[], InstallReason::Dependency),
            ],
        );
        let plan = plan(
            &local,
            &["mako".into()],
            Options {
                recursive: true,
                ..Default::default()
            },
        );

        assert_eq!(plan.orphaned, vec!["libfoo"]);
        assert_eq!(names(&plan), vec!["mako", "libfoo"]);
    }

    #[test]
    fn essential_packages_are_held_even_without_hold_pkg() {
        let local = db(
            "held",
            vec![
                pkg(
                    "base-devel",
                    &["sudo", "make", "glibc"],
                    InstallReason::Explicit,
                ),
                pkg("sudo", &[], InstallReason::Dependency),
                pkg("make", &[], InstallReason::Dependency),
                pkg("glibc", &[], InstallReason::Dependency),
            ],
        );
        let plan = plan(
            &local,
            &["base-devel".into()],
            Options {
                recursive: true,
                ..Default::default()
            },
        );
        // The plan still finds them; holding is what refuses it.
        assert_eq!(plan.orphaned, vec!["glibc", "make", "sudo"]);

        let mut held_names = held(&plan, &[]);
        held_names.sort();
        assert_eq!(held_names, vec!["glibc", "sudo"]);

        // HoldPkg adds to the essentials; it cannot take them away.
        let mut with_config = held(&plan, &["make".to_string()]);
        with_config.sort();
        assert_eq!(with_config, vec!["glibc", "make", "sudo"]);
    }

    #[test]
    fn recursive_keeps_a_dependency_something_else_needs() {
        let local = db(
            "shared-dep",
            vec![
                pkg("app", &["libfoo"], InstallReason::Explicit),
                pkg("other", &["libfoo"], InstallReason::Explicit),
                pkg("libfoo", &[], InstallReason::Dependency),
            ],
        );
        let plan = plan(
            &local,
            &["app".into()],
            Options {
                recursive: true,
                ..Default::default()
            },
        );
        assert!(plan.orphaned.is_empty());
        assert_eq!(names(&plan), vec!["app"]);
    }

    #[test]
    fn another_provider_prevents_a_block() {
        let mut alt = pkg("openjdk21", &[], InstallReason::Dependency);
        alt.provides = vec![Dep::parse("java-runtime=21")];
        let mut old = pkg("openjdk17", &[], InstallReason::Dependency);
        old.provides = vec![Dep::parse("java-runtime=17")];

        let local = db(
            "two-providers",
            vec![pkg("app", &["java-runtime"], InstallReason::Explicit), alt, old],
        );

        // Removing one provider is fine while the other still satisfies it.
        let plan = plan(&local, &["openjdk17".into()], Options::default());
        assert_eq!(names(&plan), vec!["openjdk17"]);
        assert!(plan.blocked.is_empty());
    }

    #[test]
    fn removing_every_provider_is_blocked() {
        let mut alt = pkg("openjdk21", &[], InstallReason::Dependency);
        alt.provides = vec![Dep::parse("java-runtime=21")];
        let mut old = pkg("openjdk17", &[], InstallReason::Dependency);
        old.provides = vec![Dep::parse("java-runtime=17")];

        let local = db(
            "all-providers",
            vec![pkg("app", &["java-runtime"], InstallReason::Explicit), alt, old],
        );

        let plan = plan(
            &local,
            &["openjdk17".into(), "openjdk21".into()],
            Options::default(),
        );
        assert!(plan.remove.is_empty());
        assert!(!plan.blocked.is_empty());
    }

    #[test]
    fn missing_targets_are_reported() {
        let local = db("missing", vec![pkg("app", &[], InstallReason::Explicit)]);
        let plan = plan(&local, &["ghost".into()], Options::default());
        assert_eq!(plan.not_installed, vec!["ghost"]);
        assert!(plan.remove.is_empty());
    }

    #[test]
    fn a_package_without_a_file_list_owns_nothing() {
        let root = temp_root("no-files");
        let mut local = LocalDb::load(&root);
        let meta = pkg("meta", &[], InstallReason::Explicit);
        local.register(&meta, &[]).unwrap();
        // Remove the record entirely, as a metapackage may have none.
        let _ = std::fs::remove_file(root.join("meta-1.0-1/files"));

        // Missing means "owns nothing", not an error.
        let files = deletable_files(&local, &meta, &HashSet::new()).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn shared_files_are_not_deleted() {
        let root = temp_root("shared");
        let mut local = LocalDb::load(&root);

        let a = pkg("a", &[], InstallReason::Explicit);
        let b = pkg("b", &[], InstallReason::Explicit);
        local
            .register(&a, &["usr/share/common".into(), "usr/bin/a".into()])
            .unwrap();
        local
            .register(&b, &["usr/share/common".into(), "usr/bin/b".into()])
            .unwrap();

        // Removing only `a` must leave the file `b` also owns.
        let files = deletable_files(&local, &a, &HashSet::new()).unwrap();
        assert_eq!(files, vec!["usr/bin/a"]);

        // Removing both frees the shared file.
        let both: HashSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
        let files = deletable_files(&local, &a, &both).unwrap();
        assert!(files.contains(&"usr/share/common".to_string()));
    }
}
