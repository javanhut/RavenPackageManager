//! Dependency resolution across sync repositories, the AUR, and the local
//! database.
//!
//! The resolver walks targets depth-first and emits packages in install order
//! (dependencies before dependents). It deliberately tolerates dependency
//! cycles — the AUR has them, and refusing to install is worse than picking an
//! order — recording each cycle so the caller can report it.

use crate::db::local::LocalDb;
use crate::db::sync::SyncDb;
use crate::pkg::{Dep, Package};
use crate::version::vercmp;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

/// A source of packages that is not a local sync database — in practice the
/// AUR. Abstracted so resolution is testable without network access.
pub trait Source {
    fn get(&self, name: &str) -> Option<Package>;
    /// A package providing `dep`, when no exact name match exists.
    fn provider(&self, _dep: &Dep) -> Option<Package> {
        None
    }
}

/// A no-op source, for resolving against official repos only.
pub struct NoSource;
impl Source for NoSource {
    fn get(&self, _name: &str) -> Option<Package> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Named directly on the command line.
    Explicit,
    /// Pulled in to satisfy another package.
    Dependency { of: String },
    /// Needed only to build an AUR package.
    MakeDependency { of: String },
}

impl Reason {
    pub fn is_explicit(&self) -> bool {
        matches!(self, Reason::Explicit)
    }
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub package: Package,
    pub reason: Reason,
    /// The version already installed, when this is an upgrade.
    pub replaces_version: Option<String>,
}

impl Resolved {
    pub fn is_upgrade(&self) -> bool {
        self.replaces_version.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct Conflict {
    pub package: String,
    pub conflicts_with: String,
}

#[derive(Debug, Default)]
pub struct Plan {
    /// Packages to install, dependencies first.
    pub install: Vec<Resolved>,
    /// Targets already installed at a satisfying version.
    pub already_satisfied: Vec<String>,
    /// Dependencies nothing could provide.
    pub missing: Vec<Missing>,
    pub conflicts: Vec<Conflict>,
    /// Dependency cycles that had to be broken, for reporting.
    pub cycles: Vec<Vec<String>>,
    /// Installed packages that an incoming package explicitly replaces, as
    /// (successor, replaced). These are retired rather than treated as
    /// conflicts, which is how a package rename is meant to work.
    pub replacing: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct Missing {
    pub dep: String,
    pub required_by: Option<String>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.install.is_empty()
    }

    pub fn download_size(&self) -> u64 {
        self.install.iter().map(|r| r.package.csize).sum()
    }

    /// Net change in installed size, accounting for packages being replaced.
    pub fn installed_size_delta(&self) -> i64 {
        self.install.iter().map(|r| r.package.isize as i64).sum()
    }

    pub fn aur_count(&self) -> usize {
        self.install
            .iter()
            .filter(|r| r.package.origin.is_aur())
            .count()
    }
}

pub struct Resolver<'a> {
    sync: &'a [SyncDb],
    local: &'a LocalDb,
    aur: &'a dyn Source,
    /// Skip these when resolving, per `IgnorePkg`.
    ignore: HashSet<String>,
    /// Rebuild these even when the installed version already satisfies the
    /// request. A VCS package's version does not change when upstream moves,
    /// so nothing else would ever schedule it.
    force: HashSet<String>,
}

impl<'a> Resolver<'a> {
    pub fn new(sync: &'a [SyncDb], local: &'a LocalDb, aur: &'a dyn Source) -> Resolver<'a> {
        Resolver {
            sync,
            local,
            aur,
            ignore: HashSet::new(),
            force: HashSet::new(),
        }
    }

    pub fn ignoring(mut self, names: &[String]) -> Self {
        self.ignore = names.iter().cloned().collect();
        self
    }

    /// Marks targets that must be reinstalled regardless of version.
    pub fn forcing(mut self, names: &[String]) -> Self {
        self.force = names.iter().cloned().collect();
        self
    }

    /// Looks up an exact name in the sync repos, preferring the earliest
    /// configured repo (pacman's ordering rule) and the highest version.
    fn sync_get(&self, name: &str) -> Option<&Package> {
        self.sync.iter().find_map(|db| db.get(name))
    }

    /// Every sync package satisfying `dep`: the exact name match first, then
    /// providers from best version down. Repo order breaks version ties.
    fn candidates(&self, dep: &Dep) -> Vec<&Package> {
        let mut out: Vec<&Package> = Vec::new();
        if let Some(pkg) = self.sync_get(&dep.name) {
            if dep.satisfied_by(&pkg.version) {
                out.push(pkg);
            }
        }
        let mut providers: Vec<&Package> = self
            .sync
            .iter()
            .flat_map(|db| db.packages.iter())
            .filter(|pkg| pkg.name != dep.name && pkg.satisfies(dep))
            .collect();
        // Stable sort keeps the earlier repo first among equal versions.
        providers.sort_by(|a, b| vercmp(&b.version, &a.version));
        out.extend(providers);
        out
    }

    /// Whether `pkg` can sit alongside every package already chosen.
    fn compatible_with_plan(pkg: &Package, chosen: &HashMap<String, Package>) -> bool {
        chosen.values().all(|other| {
            other.name == pkg.name || !Self::clash(pkg, other) && !Self::clash(other, pkg)
        })
    }

    /// Whether `a` declares a conflict that `b` satisfies.
    fn clash(a: &Package, b: &Package) -> bool {
        a.conflicts
            .iter()
            .any(|c| c.name != a.name && b.satisfies(c))
    }

    /// Whether `pkg` conflicts with something installed that it does not
    /// itself replace (a rename is expressed as conflicts + replaces).
    fn clashes_with_installed(&self, pkg: &Package) -> bool {
        pkg.conflicts.iter().any(|c| {
            if c.name == pkg.name {
                return false;
            }
            match self.local.satisfier(c) {
                Some(installed) => {
                    installed.name != pkg.name
                        && !pkg.replaces.iter().any(|r| installed.satisfies(r))
                }
                None => false,
            }
        })
    }

    /// Finds a package satisfying `dep` that fits the plan built so far.
    ///
    /// A virtual dependency such as `libz.so=1-32` can have several
    /// providers that conflict with one another (lib32-zlib and
    /// lib32-zlib-ng-compat, say). Picking purely by version would put both
    /// in the plan whenever another package names one of them directly, so
    /// providers that clash with a chosen package are skipped, and ones that
    /// clash with an installed package are used only as a last resort.
    /// Exact names still win when they fit, matching pacman.
    fn find(&self, dep: &Dep, chosen: &HashMap<String, Package>) -> Option<Package> {
        let candidates = self.candidates(dep);
        let pick = candidates
            .iter()
            .find(|p| Self::compatible_with_plan(p, chosen) && !self.clashes_with_installed(p))
            .or_else(|| {
                candidates
                    .iter()
                    .find(|p| Self::compatible_with_plan(p, chosen))
            })
            .or_else(|| candidates.first());
        if let Some(pkg) = pick {
            return Some((*pkg).clone());
        }

        // Fall back to the AUR only once the official repos have nothing.
        if let Some(pkg) = self.aur.get(&dep.name) {
            if dep.satisfied_by(&pkg.version) {
                return Some(pkg);
            }
        }
        self.aur.provider(dep)
    }

    /// Builds an install plan for the given target names.
    pub fn resolve(&self, targets: &[String]) -> Plan {
        let mut plan = Plan::default();
        // Packages chosen so far, keyed by name. Later lookups consult this
        // so one virtual dependency is never satisfied twice over.
        let mut seen: HashMap<String, Package> = HashMap::new();
        let mut stack: Vec<String> = Vec::new();

        for target in targets {
            let dep = Dep::parse(target);

            // An explicit target that is already installed and satisfying is
            // reported, not reinstalled.
            if let Some(installed) = self.local.get(&dep.name) {
                if dep.satisfied_by(&installed.version)
                    && self.upgrade_candidate(&dep.name).is_none()
                    && !self.force.contains(&dep.name)
                {
                    plan.already_satisfied.push(dep.name.clone());
                    continue;
                }
            }

            match self.find(&dep, &seen) {
                Some(pkg) => {
                    self.visit(pkg, Reason::Explicit, &mut plan, &mut seen, &mut stack);
                }
                None => plan.missing.push(Missing {
                    dep: target.clone(),
                    required_by: None,
                }),
            }
        }

        self.detect_conflicts(&mut plan);
        plan
    }

    /// A newer version of an installed package, from a sync repo or the AUR.
    ///
    /// A package carried by an official repository is never checked against
    /// the AUR, so a higher AUR version cannot hijack a repo package.
    pub fn upgrade_candidate(&self, name: &str) -> Option<Package> {
        let installed = self.local.get(name)?;

        if let Some(candidate) = self.sync_get(name) {
            return (vercmp(&candidate.version, &installed.version) == Ordering::Greater)
                .then(|| candidate.clone());
        }

        let candidate = self.aur.get(name)?;
        (vercmp(&candidate.version, &installed.version) == Ordering::Greater).then_some(candidate)
    }

    fn visit(
        &self,
        pkg: Package,
        reason: Reason,
        plan: &mut Plan,
        seen: &mut HashMap<String, Package>,
        stack: &mut Vec<String>,
    ) {
        // The cycle check must come before the `seen` check: a package caught
        // in a cycle is in both sets, and returning early on `seen` would hide
        // the cycle entirely.
        if stack.contains(&pkg.name) {
            let start = stack.iter().position(|n| *n == pkg.name).unwrap_or(0);
            let mut cycle = stack[start..].to_vec();
            cycle.push(pkg.name.clone());
            plan.cycles.push(cycle);
            return;
        }

        if seen.contains_key(&pkg.name) || self.ignore.contains(&pkg.name) {
            return;
        }

        seen.insert(pkg.name.clone(), pkg.clone());
        stack.push(pkg.name.clone());

        // Build-time dependencies only matter for packages rvn compiles.
        let build_deps: Vec<Dep> = if pkg.origin.is_aur() {
            pkg.makedepends.clone()
        } else {
            Vec::new()
        };

        for (dep, is_make) in pkg
            .depends
            .iter()
            .map(|d| (d, false))
            .chain(build_deps.iter().map(|d| (d, true)))
        {
            // Anything the system already provides needs no work.
            if self.local.satisfier(dep).is_some() {
                continue;
            }
            // Something already in the plan may satisfy this through a
            // provide; revisiting it records a cycle if there is one and
            // otherwise returns straight away.
            if let Some(existing) = seen.values().find(|p| p.satisfies(dep)).cloned() {
                self.visit(
                    existing,
                    Reason::Dependency {
                        of: pkg.name.clone(),
                    },
                    plan,
                    seen,
                    stack,
                );
                continue;
            }
            match self.find(dep, seen) {
                Some(child) => {
                    let child_reason = if is_make {
                        Reason::MakeDependency {
                            of: pkg.name.clone(),
                        }
                    } else {
                        Reason::Dependency {
                            of: pkg.name.clone(),
                        }
                    };
                    self.visit(child, child_reason, plan, seen, stack);
                }
                None => plan.missing.push(Missing {
                    dep: dep.to_string(),
                    required_by: Some(pkg.name.clone()),
                }),
            }
        }

        stack.pop();

        let replaces_version = self.local.get(&pkg.name).map(|p| p.version.clone());
        plan.install.push(Resolved {
            package: pkg,
            reason,
            replaces_version,
        });
    }

    /// Flags packages in the plan that conflict with each other or with
    /// something already installed.
    fn detect_conflicts(&self, plan: &mut Plan) {
        let incoming: Vec<&Package> = plan.install.iter().map(|r| &r.package).collect();

        for pkg in &incoming {
            for replaces in &pkg.replaces {
                let Some(installed) = self.local.satisfier(replaces) else {
                    continue;
                };
                if installed.name == pkg.name || incoming.iter().any(|p| p.name == installed.name) {
                    continue;
                }
                let entry = (pkg.name.clone(), installed.name.clone());
                if !plan.replacing.contains(&entry) {
                    plan.replacing.push(entry);
                }
            }

            for conflict in &pkg.conflicts {
                // Self-conflicts via provides are normal and not reported.
                if conflict.name == pkg.name {
                    continue;
                }

                // Declaring both `conflicts` and `replaces` for the same
                // package is how a rename is expressed. Treating it as a
                // conflict would block every renamed package.
                if let Some(installed) = self.local.satisfier(conflict) {
                    let is_replacement = pkg.replaces.iter().any(|r| installed.satisfies(r));
                    if is_replacement && !incoming.iter().any(|p| p.name == installed.name) {
                        let entry = (pkg.name.clone(), installed.name.clone());
                        if !plan.replacing.contains(&entry) {
                            plan.replacing.push(entry);
                        }
                        continue;
                    }
                }

                if let Some(other) = incoming.iter().find(|p| p.satisfies(conflict)) {
                    if other.name != pkg.name {
                        plan.conflicts.push(Conflict {
                            package: pkg.name.clone(),
                            conflicts_with: other.name.clone(),
                        });
                    }
                } else if let Some(installed) = self.local.satisfier(conflict) {
                    // An upgrade replacing itself is not a conflict.
                    if installed.name != pkg.name {
                        plan.conflicts.push(Conflict {
                            package: pkg.name.clone(),
                            conflicts_with: installed.name.clone(),
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sync::SyncDb;
    use crate::pkg::Origin;

    fn pkg(name: &str, version: &str, depends: &[&str]) -> Package {
        Package {
            name: name.into(),
            version: version.into(),
            depends: depends.iter().map(|d| Dep::parse(d)).collect(),
            origin: Origin::Repo("core".into()),
            csize: 100,
            isize: 1000,
            ..Default::default()
        }
    }

    fn sync_db(packages: Vec<Package>) -> Vec<SyncDb> {
        // Build via the tar path so the index is populated the same way it is
        // in production.
        let mut builder = tar::Builder::new(Vec::new());
        for p in &packages {
            let mut body = format!("%NAME%\n{}\n\n%VERSION%\n{}\n\n", p.name, p.version);
            if !p.depends.is_empty() {
                body.push_str("%DEPENDS%\n");
                for d in &p.depends {
                    body.push_str(&format!("{d}\n"));
                }
                body.push('\n');
            }
            if !p.provides.is_empty() {
                body.push_str("%PROVIDES%\n");
                for d in &p.provides {
                    body.push_str(&format!("{d}\n"));
                }
                body.push('\n');
            }
            if !p.conflicts.is_empty() {
                body.push_str("%CONFLICTS%\n");
                for d in &p.conflicts {
                    body.push_str(&format!("{d}\n"));
                }
                body.push('\n');
            }
            if !p.replaces.is_empty() {
                body.push_str("%REPLACES%\n");
                for d in &p.replaces {
                    body.push_str(&format!("{d}\n"));
                }
                body.push('\n');
            }
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    format!("{}-{}/desc", p.name, p.version),
                    body.as_bytes(),
                )
                .unwrap();
        }
        let tar = builder.into_inner().unwrap();
        vec![SyncDb::from_tar("core", &tar[..]).unwrap()]
    }

    fn empty_local() -> LocalDb {
        LocalDb::default()
    }

    fn names(plan: &Plan) -> Vec<String> {
        plan.install
            .iter()
            .map(|r| r.package.name.clone())
            .collect()
    }

    #[test]
    fn resolves_transitive_dependencies_in_install_order() {
        let dbs = sync_db(vec![
            pkg("app", "1.0-1", &["libfoo"]),
            pkg("libfoo", "2.0-1", &["glibc"]),
            pkg("glibc", "2.39-1", &[]),
        ]);
        let local = empty_local();
        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);

        assert!(plan.missing.is_empty(), "missing: {:?}", plan.missing);
        // Dependencies must precede the packages that need them.
        let order = names(&plan);
        assert_eq!(order, vec!["glibc", "libfoo", "app"]);
        assert!(plan.install.last().unwrap().reason.is_explicit());
    }

    #[test]
    fn skips_dependencies_already_installed() {
        let dbs = sync_db(vec![
            pkg("app", "1.0-1", &["libfoo"]),
            pkg("libfoo", "2.0-1", &[]),
        ]);
        let mut local = empty_local();
        local
            .packages
            .insert("libfoo".into(), pkg("libfoo", "2.0-1", &[]));

        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);
        assert_eq!(names(&plan), vec!["app"]);
    }

    #[test]
    fn already_installed_target_is_reported_not_reinstalled() {
        let dbs = sync_db(vec![pkg("app", "1.0-1", &[])]);
        let mut local = empty_local();
        local
            .packages
            .insert("app".into(), pkg("app", "1.0-1", &[]));

        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);
        assert!(plan.install.is_empty());
        assert_eq!(plan.already_satisfied, vec!["app"]);
    }

    #[test]
    fn forced_targets_are_reinstalled_at_the_same_version() {
        let dbs = sync_db(vec![pkg("app", "1.0-1", &[])]);
        let mut local = empty_local();
        local
            .packages
            .insert("app".into(), pkg("app", "1.0-1", &[]));

        // Without forcing, an identical version is left alone.
        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);
        assert!(plan.install.is_empty());

        // A VCS package's version never moves, so a rebuild has to be forced
        // or it would silently do nothing.
        let plan = Resolver::new(&dbs, &local, &NoSource)
            .forcing(&["app".to_string()])
            .resolve(&["app".into()]);
        assert_eq!(names(&plan), vec!["app"]);
        assert!(plan.already_satisfied.is_empty());
    }

    #[test]
    fn newer_sync_version_is_an_upgrade() {
        let dbs = sync_db(vec![pkg("app", "2.0-1", &[])]);
        let mut local = empty_local();
        local
            .packages
            .insert("app".into(), pkg("app", "1.0-1", &[]));

        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);
        assert_eq!(names(&plan), vec!["app"]);
        let resolved = &plan.install[0];
        assert!(resolved.is_upgrade());
        assert_eq!(resolved.replaces_version.as_deref(), Some("1.0-1"));
    }

    #[test]
    fn resolves_virtual_packages_through_provides() {
        let mut provider = pkg("openjdk21", "21.0.2-1", &[]);
        provider.provides = vec![Dep::parse("java-runtime=21")];
        let dbs = sync_db(vec![pkg("app", "1.0-1", &["java-runtime>=17"]), provider]);
        let local = empty_local();

        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);
        assert!(plan.missing.is_empty(), "missing: {:?}", plan.missing);
        assert_eq!(names(&plan), vec!["openjdk21", "app"]);
    }

    fn zlib_pair() -> (Package, Package) {
        let mut plain = pkg("lib32-zlib", "1.3.1-2", &[]);
        plain.provides = vec![Dep::parse("libz.so=1-32")];
        let mut ng = pkg("lib32-zlib-ng-compat", "2.2.4-1", &[]);
        ng.provides = vec![Dep::parse("lib32-zlib"), Dep::parse("libz.so=1-32")];
        ng.conflicts = vec![Dep::parse("lib32-zlib")];
        (plain, ng)
    }

    #[test]
    fn a_virtual_dependency_never_pulls_a_second_conflicting_provider() {
        // Steam's graph names lib32-zlib directly in one place and asks for
        // libz.so=1-32 in another; both providers must not end up in the plan.
        for deps in [
            &["lib32-zlib", "libz.so=1-32"][..],
            &["libz.so=1-32", "lib32-zlib"][..],
        ] {
            let (plain, ng) = zlib_pair();
            let dbs = sync_db(vec![pkg("app", "1.0-1", deps), plain, ng]);
            let local = empty_local();
            let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);

            assert!(plan.missing.is_empty(), "missing: {:?}", plan.missing);
            assert!(plan.conflicts.is_empty(), "conflicts: {:?}", plan.conflicts);
            let chosen = names(&plan);
            assert_eq!(chosen.len(), 2, "plan: {chosen:?}");
            assert_eq!(chosen[1], "app");
        }
    }

    #[test]
    fn an_exact_name_still_wins_over_a_newer_provider() {
        let (plain, ng) = zlib_pair();
        let dbs = sync_db(vec![pkg("app", "1.0-1", &["lib32-zlib"]), plain, ng]);
        let local = empty_local();
        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);
        assert_eq!(names(&plan), vec!["lib32-zlib", "app"]);
    }

    #[test]
    fn a_provider_clashing_with_an_installed_package_is_avoided() {
        let (plain, ng) = zlib_pair();
        let dbs = sync_db(vec![pkg("app", "1.0-1", &["libz.so=1-32"]), plain, ng]);
        // Not a satisfier of libz.so=1-32 itself, but something ng conflicts
        // with: an older lib32-zlib lacking the soname provide.
        let mut local = empty_local();
        let mut old = pkg("lib32-zlib", "1.2.0-1", &[]);
        old.origin = Origin::Local;
        local.packages.insert(old.name.clone(), old);
        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);

        assert!(plan.conflicts.is_empty(), "conflicts: {:?}", plan.conflicts);
        assert_eq!(names(&plan), vec!["lib32-zlib", "app"]);
    }

    #[test]
    fn unsatisfiable_version_constraint_is_missing() {
        let dbs = sync_db(vec![
            pkg("app", "1.0-1", &["libfoo>=5.0"]),
            pkg("libfoo", "2.0-1", &[]),
        ]);
        let local = empty_local();
        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["app".into()]);

        assert_eq!(plan.missing.len(), 1);
        assert_eq!(plan.missing[0].dep, "libfoo>=5.0");
        assert_eq!(plan.missing[0].required_by.as_deref(), Some("app"));
    }

    #[test]
    fn dependency_cycles_terminate_and_are_recorded() {
        let dbs = sync_db(vec![
            pkg("a", "1.0-1", &["b"]),
            pkg("b", "1.0-1", &["c"]),
            pkg("c", "1.0-1", &["a"]),
        ]);
        let local = empty_local();
        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["a".into()]);

        // All three still get installed, and the cycle is reported.
        assert_eq!(plan.install.len(), 3);
        assert_eq!(plan.cycles.len(), 1);
    }

    #[test]
    fn detects_conflicts_within_the_plan() {
        let mut a = pkg("nginx", "1.0-1", &[]);
        a.conflicts = vec![Dep::parse("apache")];
        let dbs = sync_db(vec![a, pkg("apache", "2.4-1", &[])]);
        let local = empty_local();

        let plan =
            Resolver::new(&dbs, &local, &NoSource).resolve(&["nginx".into(), "apache".into()]);
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].package, "nginx");
        assert_eq!(plan.conflicts[0].conflicts_with, "apache");
    }

    #[test]
    fn a_declared_replacement_is_not_a_conflict() {
        // The standard rename shape: the successor both conflicts with and
        // replaces the package it supersedes.
        let mut successor = pkg("newname", "2.0-1", &[]);
        successor.conflicts = vec![Dep::parse("oldname")];
        successor.replaces = vec![Dep::parse("oldname")];

        let dbs = sync_db(vec![successor]);
        let mut local = empty_local();
        local
            .packages
            .insert("oldname".into(), pkg("oldname", "1.0-1", &[]));

        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["newname".into()]);

        assert!(
            plan.conflicts.is_empty(),
            "a rename must not be blocked: {:?}",
            plan.conflicts
        );
        assert_eq!(names(&plan), vec!["newname"]);
        assert_eq!(
            plan.replacing,
            vec![("newname".to_string(), "oldname".to_string())]
        );
    }

    #[test]
    fn replacing_is_recorded_without_a_conflict_declaration() {
        let mut successor = pkg("newname", "2.0-1", &[]);
        successor.replaces = vec![Dep::parse("oldname")];

        let dbs = sync_db(vec![successor]);
        let mut local = empty_local();
        local
            .packages
            .insert("oldname".into(), pkg("oldname", "1.0-1", &[]));

        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["newname".into()]);
        assert_eq!(
            plan.replacing,
            vec![("newname".to_string(), "oldname".to_string())]
        );
    }

    #[test]
    fn a_genuine_conflict_is_still_reported() {
        // Conflicting without replacing is a real conflict.
        let mut a = pkg("nginx", "1.0-1", &[]);
        a.conflicts = vec![Dep::parse("apache")];
        let dbs = sync_db(vec![a]);
        let mut local = empty_local();
        local
            .packages
            .insert("apache".into(), pkg("apache", "2.4-1", &[]));

        let plan = Resolver::new(&dbs, &local, &NoSource).resolve(&["nginx".into()]);
        assert_eq!(plan.conflicts.len(), 1);
        assert!(plan.replacing.is_empty());
    }

    #[test]
    fn ignored_packages_are_skipped() {
        let dbs = sync_db(vec![
            pkg("app", "1.0-1", &["libfoo"]),
            pkg("libfoo", "2.0-1", &[]),
        ]);
        let local = empty_local();
        let plan = Resolver::new(&dbs, &local, &NoSource)
            .ignoring(&["libfoo".to_string()])
            .resolve(&["app".into()]);
        assert_eq!(names(&plan), vec!["app"]);
    }

    struct FakeAur(Vec<Package>);
    impl Source for FakeAur {
        fn get(&self, name: &str) -> Option<Package> {
            self.0.iter().find(|p| p.name == name).cloned()
        }
    }

    #[test]
    fn aur_packages_pull_repo_dependencies_and_makedepends() {
        let dbs = sync_db(vec![
            pkg("glibc", "2.39-1", &[]),
            pkg("rust", "1.80-1", &[]),
        ]);
        let local = empty_local();

        let aur_pkg = Package {
            name: "mytool".into(),
            version: "0.3.0-1".into(),
            depends: vec![Dep::parse("glibc")],
            makedepends: vec![Dep::parse("rust")],
            origin: Origin::Aur,
            ..Default::default()
        };
        let aur = FakeAur(vec![aur_pkg]);

        let plan = Resolver::new(&dbs, &local, &aur).resolve(&["mytool".into()]);
        assert!(plan.missing.is_empty(), "missing: {:?}", plan.missing);

        let order = names(&plan);
        assert_eq!(order.last().unwrap(), "mytool");
        assert!(order.contains(&"glibc".to_string()));
        // makedepends are only pulled in for packages rvn has to build.
        assert!(order.contains(&"rust".to_string()));
        assert_eq!(plan.aur_count(), 1);

        let rust = plan
            .install
            .iter()
            .find(|r| r.package.name == "rust")
            .unwrap();
        assert!(matches!(rust.reason, Reason::MakeDependency { .. }));
    }

    #[test]
    fn detects_an_aur_upgrade_for_a_package_not_in_any_repo() {
        let dbs = sync_db(vec![]);
        let mut local = empty_local();
        local
            .packages
            .insert("mytool".into(), pkg("mytool", "0.1.0-1", &[]));

        let aur = FakeAur(vec![Package {
            name: "mytool".into(),
            version: "0.2.0-1".into(),
            origin: Origin::Aur,
            ..Default::default()
        }]);

        let resolver = Resolver::new(&dbs, &local, &aur);
        let candidate = resolver.upgrade_candidate("mytool").expect("aur upgrade");
        assert_eq!(candidate.version, "0.2.0-1");

        // And the plan must schedule it rather than calling it satisfied.
        let plan = resolver.resolve(&["mytool".into()]);
        assert_eq!(names(&plan), vec!["mytool"]);
        assert!(plan.already_satisfied.is_empty());
    }

    #[test]
    fn a_repo_package_is_never_upgraded_from_the_aur() {
        let dbs = sync_db(vec![pkg("go", "1.22-1", &[])]);
        let mut local = empty_local();
        local.packages.insert("go".into(), pkg("go", "1.22-1", &[]));

        // The AUR claims a much newer version; it must be ignored.
        let aur = FakeAur(vec![Package {
            name: "go".into(),
            version: "99.0-1".into(),
            origin: Origin::Aur,
            ..Default::default()
        }]);

        let resolver = Resolver::new(&dbs, &local, &aur);
        assert!(resolver.upgrade_candidate("go").is_none());
    }

    #[test]
    fn official_repos_take_precedence_over_aur() {
        let dbs = sync_db(vec![pkg("go", "1.22-1", &[])]);
        let local = empty_local();
        let aur = FakeAur(vec![Package {
            name: "go".into(),
            version: "9.9-1".into(),
            origin: Origin::Aur,
            ..Default::default()
        }]);

        let plan = Resolver::new(&dbs, &local, &aur).resolve(&["go".into()]);
        assert_eq!(plan.install.len(), 1);
        assert_eq!(plan.install[0].package.origin.label(), "core");
        assert_eq!(plan.aur_count(), 0);
    }
}
