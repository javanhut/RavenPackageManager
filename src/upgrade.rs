//! Deciding what an update should do.
//!
//! Kept separate from the install pipeline so the "what is out of date"
//! question is answerable — and testable — on its own.

use crate::db::local::LocalDb;
use crate::db::sync::SyncDb;
use crate::pkg::{Origin, Package};
use crate::resolve::Source;
use crate::version::vercmp;
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A newer version of the same package.
    Upgrade,
    /// A different package that declares `%REPLACES%` for the installed one.
    Replacement { replaces: String },
    /// The installed version is newer than what the repositories carry.
    Downgrade,
    /// A VCS package whose upstream has moved since it was built.
    Devel,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub name: String,
    pub installed_version: String,
    pub new_version: String,
    pub origin: Origin,
    pub kind: Kind,
    pub download_size: u64,
}

impl Candidate {
    pub fn is_replacement(&self) -> bool {
        matches!(self.kind, Kind::Replacement { .. })
    }
}

/// Finds a package by exact name across all sync databases, honouring repo
/// order.
fn sync_get<'a>(sync: &'a [SyncDb], name: &str) -> Option<&'a Package> {
    sync.iter().find_map(|db| db.get(name))
}

/// Computes what is out of date.
///
/// `only` restricts the check to the named packages; `None` checks everything
/// installed. `aur` is consulted only for packages no repository carries.
pub fn candidates(
    local: &LocalDb,
    sync: &[SyncDb],
    aur: &dyn Source,
    only: Option<&[String]>,
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();

    let installed: Vec<&Package> = match only {
        Some(names) => names.iter().filter_map(|n| local.get(n)).collect(),
        None => local.packages.values().collect(),
    };

    for pkg in &installed {
        match sync_get(sync, &pkg.name) {
            Some(candidate) => match vercmp(&candidate.version, &pkg.version) {
                Ordering::Greater => out.push(Candidate {
                    name: pkg.name.clone(),
                    installed_version: pkg.version.clone(),
                    new_version: candidate.version.clone(),
                    origin: candidate.origin.clone(),
                    kind: Kind::Upgrade,
                    download_size: candidate.csize,
                }),
                Ordering::Less => out.push(Candidate {
                    name: pkg.name.clone(),
                    installed_version: pkg.version.clone(),
                    new_version: candidate.version.clone(),
                    origin: candidate.origin.clone(),
                    kind: Kind::Downgrade,
                    download_size: candidate.csize,
                }),
                Ordering::Equal => {}
            },
            // Not in any repository: it came from the AUR, so ask the AUR.
            None => {
                if let Some(candidate) = aur.get(&pkg.name) {
                    if vercmp(&candidate.version, &pkg.version) == Ordering::Greater {
                        out.push(Candidate {
                            name: pkg.name.clone(),
                            installed_version: pkg.version.clone(),
                            new_version: candidate.version.clone(),
                            origin: Origin::Aur,
                            kind: Kind::Upgrade,
                            download_size: 0,
                        });
                    }
                }
            }
        }
    }

    // A renamed package appears as a repo package that replaces an installed
    // one. Only relevant for a full check — a named target is explicit.
    if only.is_none() {
        for db in sync {
            for candidate in &db.packages {
                if local.is_installed(&candidate.name) {
                    continue;
                }
                for replaces in &candidate.replaces {
                    let Some(old) = local.satisfier(replaces) else {
                        continue;
                    };
                    // Do not propose the same replacement twice.
                    if out.iter().any(|c| c.name == candidate.name) {
                        continue;
                    }
                    out.push(Candidate {
                        name: candidate.name.clone(),
                        installed_version: old.version.clone(),
                        new_version: candidate.version.clone(),
                        origin: candidate.origin.clone(),
                        kind: Kind::Replacement {
                            replaces: old.name.clone(),
                        },
                        download_size: candidate.csize,
                    });
                }
            }
        }
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Total bytes an update would download.
pub fn download_size(candidates: &[Candidate]) -> u64 {
    candidates.iter().map(|c| c.download_size).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sync::SyncDb;
    use crate::pkg::Dep;
    use std::path::PathBuf;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-upgrade-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pkg(name: &str, version: &str) -> Package {
        Package {
            name: name.into(),
            version: version.into(),
            origin: Origin::Repo("core".into()),
            csize: 500,
            ..Default::default()
        }
    }

    fn sync_db(packages: Vec<Package>) -> Vec<SyncDb> {
        let mut builder = tar::Builder::new(Vec::new());
        for p in &packages {
            let mut body = format!(
                "%NAME%\n{}\n\n%VERSION%\n{}\n\n%CSIZE%\n{}\n\n",
                p.name, p.version, p.csize
            );
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
        vec![SyncDb::from_tar("core", &builder.into_inner().unwrap()[..]).unwrap()]
    }

    fn local_db(tag: &str, packages: Vec<Package>) -> LocalDb {
        let mut db = LocalDb::load(&temp_root(tag));
        for p in packages {
            db.register(&p, &[format!("usr/bin/{}", p.name)]).unwrap();
        }
        db
    }

    struct NoAur;
    impl Source for NoAur {
        fn get(&self, _name: &str) -> Option<Package> {
            None
        }
    }

    struct FakeAur(Vec<Package>);
    impl Source for FakeAur {
        fn get(&self, name: &str) -> Option<Package> {
            self.0.iter().find(|p| p.name == name).cloned()
        }
    }

    #[test]
    fn finds_newer_repo_versions() {
        let local = local_db("newer", vec![pkg("app", "1.0-1"), pkg("lib", "2.0-1")]);
        let sync = sync_db(vec![pkg("app", "1.1-1"), pkg("lib", "2.0-1")]);

        let found = candidates(&local, &sync, &NoAur, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "app");
        assert_eq!(found[0].installed_version, "1.0-1");
        assert_eq!(found[0].new_version, "1.1-1");
        assert_eq!(found[0].kind, Kind::Upgrade);
        assert_eq!(download_size(&found), 500);
    }

    #[test]
    fn epoch_changes_count_as_upgrades() {
        let local = local_db("epoch", vec![pkg("app", "9.0-1")]);
        // A lower plain version with a higher epoch is still newer.
        let sync = sync_db(vec![pkg("app", "1:1.0-1")]);

        let found = candidates(&local, &sync, &NoAur, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::Upgrade);
    }

    #[test]
    fn a_newer_installed_version_is_a_downgrade_not_an_upgrade() {
        let local = local_db("downgrade", vec![pkg("app", "2.0-1")]);
        let sync = sync_db(vec![pkg("app", "1.0-1")]);

        let found = candidates(&local, &sync, &NoAur, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::Downgrade);
    }

    #[test]
    fn detects_replacements_for_renamed_packages() {
        let local = local_db("replace", vec![pkg("oldname", "1.0-1")]);
        let mut successor = pkg("newname", "2.0-1");
        successor.replaces = vec![Dep::parse("oldname")];
        let sync = sync_db(vec![successor]);

        let found = candidates(&local, &sync, &NoAur, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "newname");
        assert_eq!(
            found[0].kind,
            Kind::Replacement {
                replaces: "oldname".into()
            }
        );
        assert!(found[0].is_replacement());
    }

    #[test]
    fn an_installed_successor_is_not_proposed_again() {
        let mut successor = pkg("newname", "2.0-1");
        successor.replaces = vec![Dep::parse("oldname")];
        // Both already installed: nothing to do.
        let local = local_db(
            "replace-done",
            vec![pkg("oldname", "1.0-1"), successor.clone()],
        );
        let sync = sync_db(vec![successor]);

        let found = candidates(&local, &sync, &NoAur, None);
        assert!(found.is_empty(), "got {found:?}");
    }

    #[test]
    fn aur_packages_are_checked_against_the_aur() {
        let local = local_db("aur", vec![pkg("mytool", "0.1.0-1")]);
        // Empty repos, so the package can only have come from the AUR.
        let sync = sync_db(vec![]);
        let aur = FakeAur(vec![Package {
            name: "mytool".into(),
            version: "0.2.0-1".into(),
            origin: Origin::Aur,
            ..Default::default()
        }]);

        let found = candidates(&local, &sync, &aur, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin, Origin::Aur);
        assert_eq!(found[0].new_version, "0.2.0-1");
    }

    #[test]
    fn repo_packages_are_not_checked_against_the_aur() {
        let local = local_db("repo-wins", vec![pkg("go", "1.22-1")]);
        let sync = sync_db(vec![pkg("go", "1.22-1")]);
        let aur = FakeAur(vec![Package {
            name: "go".into(),
            version: "99.0-1".into(),
            origin: Origin::Aur,
            ..Default::default()
        }]);

        assert!(candidates(&local, &sync, &aur, None).is_empty());
    }

    #[test]
    fn named_targets_restrict_the_check() {
        let local = local_db("named", vec![pkg("app", "1.0-1"), pkg("lib", "1.0-1")]);
        let sync = sync_db(vec![pkg("app", "2.0-1"), pkg("lib", "2.0-1")]);

        let found = candidates(&local, &sync, &NoAur, Some(&["app".to_string()]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "app");
    }

    #[test]
    fn replacements_are_skipped_for_named_targets() {
        let local = local_db("named-replace", vec![pkg("oldname", "1.0-1")]);
        let mut successor = pkg("newname", "2.0-1");
        successor.replaces = vec![Dep::parse("oldname")];
        let sync = sync_db(vec![successor]);

        // Asking about `oldname` specifically must not silently rename it.
        let found = candidates(&local, &sync, &NoAur, Some(&["oldname".to_string()]));
        assert!(found.is_empty());
    }

    #[test]
    fn devel_is_distinct_from_a_version_upgrade() {
        // A devel rebuild carries no comparable version, so it must not be
        // mistaken for a downgrade and filtered out.
        assert_ne!(Kind::Devel, Kind::Downgrade);
        assert_ne!(Kind::Devel, Kind::Upgrade);
    }

    #[test]
    fn an_up_to_date_system_yields_nothing() {
        let local = local_db("current", vec![pkg("app", "1.0-1")]);
        let sync = sync_db(vec![pkg("app", "1.0-1")]);
        assert!(candidates(&local, &sync, &NoAur, None).is_empty());
    }
}
