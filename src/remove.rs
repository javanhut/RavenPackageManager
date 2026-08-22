//! Removal planning: what can be uninstalled, and in what order.
//!
//! The hard part is not deleting files, it is deciding whether deleting them
//! breaks something. A package only blocks a removal if *every* installed
//! provider of a dependency is going away — otherwise something else still
//! satisfies it.

use crate::db::local::LocalDb;
use crate::pkg::{InstallReason, Package};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Also remove packages that depend on the targets.
    pub cascade: bool,
    /// Also remove dependencies that become orphaned.
    pub recursive: bool,
    /// Remove regardless of what would break.
    pub nodeps: bool,
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
fn broken_by(local: &LocalDb, removing: &HashSet<String>) -> Vec<(String, String)> {
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
            let survives = local
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
            let broken = broken_by(local, &removing);
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
            let additions: Vec<String> = local
                .packages
                .values()
                .filter(|pkg| !removing.contains(&pkg.name))
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
        let broken = broken_by(local, &removing);
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
) -> Vec<String> {
    let own_files = local.files(&pkg.name).unwrap_or_default();

    let mut kept: HashSet<String> = HashSet::new();
    for other in local.packages.values() {
        if other.name == pkg.name || also_removing.contains(&other.name) {
            continue;
        }
        if let Ok(files) = local.files(&other.name) {
            kept.extend(files);
        }
    }

    own_files
        .into_iter()
        .filter(|file| !kept.contains(file))
        .collect()
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
        let files = deletable_files(&local, &a, &HashSet::new());
        assert_eq!(files, vec!["usr/bin/a"]);

        // Removing both frees the shared file.
        let both: HashSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
        let files = deletable_files(&local, &a, &both);
        assert!(files.contains(&"usr/share/common".to_string()));
    }
}
