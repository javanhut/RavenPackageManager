//! Going back to the version that was installed before.
//!
//! # What this can and cannot be
//!
//! It would be good if `rvn rollback` undid the last transaction. It cannot,
//! and the reason is written down in [`crate::extract::unpack`]'s own doc
//! comment: extraction is not transactional, a file the package overwrites is
//! gone the moment it is written, and rvn keeps no copy to restore. Nothing
//! short of a filesystem snapshot changes that, and promising otherwise would
//! be a lie that only shows itself at the moment somebody is relying on it.
//!
//! So this is the honest version: find the previous version's archive in the
//! package cache and install it, which is the same operation as installing
//! any other package and has the same guarantees -- no more. A configuration
//! file the newer version rewrote stays rewritten unless the package marked
//! it `backup`. A database the newer version migrated stays migrated; that is
//! what a package's own `.INSTALL` scriptlet is for and rvn runs it. What
//! this recovers is a binary that stopped working, which is the case people
//! actually hit.
//!
//! The snapshot-based version has a place to live, and it is a pre-transaction
//! hook: [`crate::txhooks`]'s module documentation carries
//! `/etc/rvn/hooks.d/50-snapshot.toml` as its worked example precisely so
//! that a machine on btrfs or zfs can take a real snapshot before every
//! transaction. That composes with this rather than replacing it.
//!
//! # It only works if the archive is still there
//!
//! rvn clears the cache after a successful transaction by default, so on a
//! machine that has never used `--keep-cache` there is nothing to roll back
//! to and this says so rather than failing obscurely. [`crate::cache`]'s
//! retention rules are what keep the archives around -- `--keep 2` keeps the
//! version that was running before the last upgrade, which is exactly the one
//! this looks for. Saying "no cached copy" and explaining how to have one
//! next time is the only useful answer when the bytes are gone.

use crate::cache::{Archive, Inventory};
use crate::db::local::LocalDb;
use crate::version::vercmp;
use std::fmt;

/// A version that could be installed in place of the one that is.
#[derive(Debug, Clone)]
pub struct Target {
    pub package: String,
    /// The version installed now.
    pub from: String,
    /// The version in the cache that would replace it.
    pub to: String,
    pub archive: Archive,
}

/// Why a package cannot be rolled back.
#[derive(Debug)]
pub enum Reason {
    NotInstalled {
        package: String,
    },
    /// Nothing older is cached. `cached` is what *is* there, which is the
    /// difference between "the cache was cleared" and "you are already on the
    /// oldest copy".
    NoOlderVersion {
        package: String,
        installed: String,
        cached: Vec<String>,
    },
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::NotInstalled { package } => {
                write!(
                    f,
                    "{package} is not installed, so there is nothing to roll back"
                )
            }
            // The installed version is deliberately not mentioned here: when
            // the cache is empty the reason has nothing to do with which
            // version is on the machine, and naming it would invite the
            // reader to look for a version problem that is not there.
            Reason::NoOlderVersion {
                package,
                installed: _,
                cached,
            } if cached.is_empty() => write!(
                f,
                "no cached copy of an earlier {package} — the cache is cleared after every transaction unless `rvn install --keep-cache` is used, so there is nothing to go back to. \
                 `rvn cache status` shows what is kept"
            ),
            Reason::NoOlderVersion {
                package,
                installed,
                cached,
            } => write!(
                f,
                "{package} {installed} is the oldest version in the cache; the only copies there are {}",
                cached.join(", ")
            ),
        }
    }
}

/// The version to roll `package` back to.
///
/// The newest cached version that is strictly older than the installed one.
/// Newest rather than oldest because a rollback is a step back, not a journey
/// to the beginning: somebody upgrading from 1.2 to 1.4 through 1.3 and then
/// finding 1.4 broken wants 1.3, and can run the command again for 1.2.
///
/// Ordering is [`crate::version::vercmp`] throughout and never mtime. The
/// archive that was written most recently is the one that was downloaded most
/// recently, which during a downgrade is the *older* version -- ordering by
/// file time would offer to roll back to the version already installed.
pub fn find(inventory: &Inventory, local: &LocalDb, package: &str) -> Result<Target, Reason> {
    let Some(installed) = local.get(package) else {
        return Err(Reason::NotInstalled {
            package: package.to_string(),
        });
    };
    let installed_version = installed.version.clone();

    let mine: Vec<&Archive> = inventory
        .archives
        .iter()
        .filter(|archive| archive.package == package)
        .collect();

    let best = mine
        .iter()
        .filter(|archive| vercmp(&archive.version, &installed_version).is_lt())
        .max_by(|a, b| vercmp(&a.version, &b.version));

    match best {
        Some(archive) => Ok(Target {
            package: package.to_string(),
            from: installed_version,
            to: archive.version.clone(),
            archive: (*archive).clone(),
        }),
        None => {
            let mut cached: Vec<String> = mine.iter().map(|a| a.version.clone()).collect();
            cached.sort_by(|a, b| vercmp(a, b));
            cached.dedup();
            Err(Reason::NoOlderVersion {
                package: package.to_string(),
                installed: installed_version,
                cached,
            })
        }
    }
}

/// Every installed package that has an earlier version in the cache.
///
/// This is what a bare `rvn rollback` reports. It deliberately does not pick
/// one: rolling a package back is a decision about a specific thing that
/// broke, and "the last transaction" is not a set rvn can reconstruct -- it
/// keeps no transaction journal, and inferring one from install dates would
/// sweep in every package a single `rvn update` touched.
pub fn available(inventory: &Inventory, local: &LocalDb) -> Vec<Target> {
    let mut targets: Vec<Target> = local
        .packages
        .keys()
        .filter_map(|name| find(inventory, local, name).ok())
        .collect();
    targets.sort_by(|a, b| a.package.cmp(&b.package));
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Archive;
    use crate::pkg::Package;
    use std::path::PathBuf;

    fn archive(package: &str, version: &str) -> Archive {
        Archive {
            path: PathBuf::from(format!(
                "/var/cache/pacman/pkg/{package}-{version}-x86_64.pkg.tar.zst"
            )),
            package: package.to_string(),
            version: version.to_string(),
            size: 1024,
            signature: None,
            signature_size: 0,
            built: false,
            modified: None,
        }
    }

    fn inventory(archives: Vec<Archive>) -> Inventory {
        Inventory {
            archives,
            ..Default::default()
        }
    }

    fn installed(entries: &[(&str, &str)]) -> LocalDb {
        let mut db = LocalDb::default();
        for (name, version) in entries {
            db.packages.insert(
                name.to_string(),
                Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    ..Default::default()
                },
            );
        }
        db
    }

    #[test]
    fn the_newest_version_below_the_installed_one_is_the_target() {
        let local = installed(&[("huginn", "1.4.0-1")]);
        let inv = inventory(vec![
            archive("huginn", "1.2.0-1"),
            archive("huginn", "1.3.0-1"),
            // The installed version is in the cache too, as it will be right
            // after the upgrade that installed it, and must not be offered.
            archive("huginn", "1.4.0-1"),
            archive("roostbar", "0.9.0-1"),
        ]);

        let target = find(&inv, &local, "huginn").expect("1.3.0 should be found");
        assert_eq!(target.from, "1.4.0-1");
        assert_eq!(target.to, "1.3.0-1");
    }

    #[test]
    fn versions_are_compared_as_versions_and_never_as_text() {
        // The case that makes a string comparison wrong: 1.10 is newer than
        // 1.9, and sorts before it as text.
        let local = installed(&[("huginn", "1.11.0-1")]);
        let inv = inventory(vec![
            archive("huginn", "1.9.0-1"),
            archive("huginn", "1.10.0-1"),
        ]);
        assert_eq!(find(&inv, &local, "huginn").unwrap().to, "1.10.0-1");

        // And an epoch beats everything to its right, so an epoch-1 archive
        // is not an earlier version of an epoch-2 install by digit order.
        let local = installed(&[("huginn", "2:1.0.0-1")]);
        let inv = inventory(vec![archive("huginn", "1:9.9.9-1")]);
        assert_eq!(find(&inv, &local, "huginn").unwrap().to, "1:9.9.9-1");
    }

    #[test]
    fn an_empty_cache_says_why_rather_than_just_no() {
        let local = installed(&[("huginn", "1.4.0-1")]);
        let e = find(&inventory(Vec::new()), &local, "huginn").unwrap_err();
        // The useful part is the reason the archive is not there, which is a
        // policy rather than an accident.
        assert!(e.to_string().contains("--keep-cache"), "{e}");

        // Something cached, but nothing older: a different message, because
        // the advice about --keep-cache would be wrong.
        let inv = inventory(vec![archive("huginn", "1.4.0-1")]);
        let e = find(&inv, &local, "huginn").unwrap_err();
        assert!(e.to_string().contains("oldest version in the cache"), "{e}");

        let e = find(&inv, &local, "nothing").unwrap_err();
        assert!(e.to_string().contains("is not installed"), "{e}");
    }

    #[test]
    fn what_is_available_lists_only_packages_with_somewhere_to_go() {
        let local = installed(&[("huginn", "1.4.0-1"), ("roostbar", "0.9.0-1")]);
        let inv = inventory(vec![
            archive("huginn", "1.3.0-1"),
            // roostbar's only cached copy is the installed one, so it is not
            // a rollback candidate.
            archive("roostbar", "0.9.0-1"),
        ]);

        let available = available(&inv, &local);
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].package, "huginn");
        assert_eq!(available[0].to, "1.3.0-1");
    }
}
