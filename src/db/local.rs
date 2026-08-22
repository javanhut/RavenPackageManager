//! The local database at `$dbpath/local`, which records what is installed.
//!
//! Layout is one directory per package (`name-version/`) containing `desc`
//! (metadata) and `files` (the owned file list).

use crate::db::desc;
use crate::pkg::{InstallReason, Origin, Package};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct LocalDb {
    pub root: PathBuf,
    pub packages: HashMap<String, Package>,
}

impl LocalDb {
    /// Reads every installed package. A missing local database is treated as
    /// "nothing installed" rather than an error, so rvn works on a fresh root.
    pub fn load(path: &Path) -> LocalDb {
        let mut packages = HashMap::new();

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if !entry.path().is_dir() {
                    continue;
                }
                let desc_path = entry.path().join("desc");
                let Ok(text) = std::fs::read_to_string(&desc_path) else {
                    continue;
                };
                if let Some(pkg) = desc::parse_package(&text, Origin::Local) {
                    packages.insert(pkg.name.clone(), pkg);
                }
            }
        }

        LocalDb {
            root: path.to_path_buf(),
            packages,
        }
    }

    pub fn get(&self, name: &str) -> Option<&Package> {
        self.packages.get(name)
    }

    pub fn is_installed(&self, name: &str) -> bool {
        self.packages.contains_key(name)
    }

    /// Finds an installed package satisfying `dep`, including via provides.
    pub fn satisfier(&self, dep: &crate::pkg::Dep) -> Option<&Package> {
        self.packages.values().find(|p| p.satisfies(dep))
    }

    /// The files owned by an installed package, as recorded in its `files`.
    pub fn files(&self, name: &str) -> io::Result<Vec<String>> {
        let pkg = self
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not installed")))?;
        let dir = self.root.join(format!("{}-{}", pkg.name, pkg.version));
        let text = std::fs::read_to_string(dir.join("files"))?;
        Ok(desc::parse_fields(&text)
            .remove("FILES")
            .unwrap_or_default())
    }

    /// Installed packages that were pulled in as dependencies.
    pub fn dependencies(&self) -> impl Iterator<Item = &Package> {
        self.packages
            .values()
            .filter(|p| p.install_reason == InstallReason::Dependency)
    }

    /// Removes a package's entry from the database.
    pub fn unregister(&mut self, name: &str) -> io::Result<()> {
        let Some(pkg) = self.packages.remove(name) else {
            return Ok(());
        };
        let dir = self.root.join(format!("{}-{}", pkg.name, pkg.version));
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }

    /// Registers a freshly installed package by writing its `desc` and `files`.
    ///
    /// An entry for a previous version is removed first: the directory is
    /// named `name-version`, so an upgrade would otherwise leave a stale
    /// record behind and make the next load ambiguous.
    pub fn register(&mut self, pkg: &Package, files: &[String]) -> io::Result<()> {
        let dir = self.root.join(format!("{}-{}", pkg.name, pkg.version));

        if let Some(previous) = self.packages.get(&pkg.name) {
            if previous.version != pkg.version {
                let stale = self
                    .root
                    .join(format!("{}-{}", previous.name, previous.version));
                if stale != dir && stale.exists() {
                    std::fs::remove_dir_all(&stale)?;
                }
            }
        }

        std::fs::create_dir_all(&dir)?;

        let mut desc_out = String::new();
        let mut field = |key: &str, values: &[String]| {
            if values.is_empty() {
                return;
            }
            desc_out.push_str(&format!("%{key}%\n"));
            for v in values {
                desc_out.push_str(v);
                desc_out.push('\n');
            }
            desc_out.push('\n');
        };

        field("NAME", &[pkg.name.clone()]);
        field("VERSION", &[pkg.version.clone()]);
        field("DESC", &[pkg.description.clone()]);
        if let Some(url) = &pkg.url {
            field("URL", &[url.clone()]);
        }
        field("LICENSE", &pkg.licenses);
        field("GROUPS", &pkg.groups);
        field("ISIZE", &[pkg.isize.to_string()]);
        field("REASON", &[pkg.install_reason.as_code().to_string()]);
        field(
            "BACKUP",
            &pkg.backup.iter().map(|b| b.to_entry()).collect::<Vec<_>>(),
        );
        field(
            "PROVIDES",
            &pkg.provides.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        );
        field(
            "DEPENDS",
            &pkg.depends.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        );
        field(
            "CONFLICTS",
            &pkg.conflicts.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        );

        std::fs::write(dir.join("desc"), desc_out)?;

        let mut files_out = String::from("%FILES%\n");
        for f in files {
            files_out.push_str(f);
            files_out.push('\n');
        }
        std::fs::write(dir.join("files"), files_out)?;

        let mut stored = pkg.clone();
        stored.origin = Origin::Local;
        self.packages.insert(stored.name.clone(), stored);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::Dep;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-local-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_database_is_empty_not_an_error() {
        let db = LocalDb::load(Path::new("/nonexistent/rvn/local"));
        assert!(db.packages.is_empty());
        assert!(!db.is_installed("go"));
    }

    #[test]
    fn round_trips_a_registration() {
        let root = temp_root("roundtrip");
        let mut db = LocalDb::load(&root);

        let pkg = Package {
            name: "bash".into(),
            version: "5.2.26-1".into(),
            description: "The GNU Bourne Again shell".into(),
            provides: vec![Dep::parse("sh=5.2")],
            depends: vec![Dep::parse("glibc"), Dep::parse("readline>=8.0")],
            isize: 9_000_000,
            ..Default::default()
        };
        db.register(&pkg, &["usr/bin/bash".into(), "usr/share/man/bash.1".into()])
            .unwrap();

        // Re-read from disk to prove the on-disk format parses back.
        let reread = LocalDb::load(&root);
        let got = reread.get("bash").expect("bash registered");
        assert_eq!(got.version, "5.2.26-1");
        assert_eq!(got.depends.len(), 2);
        assert_eq!(got.isize, 9_000_000);

        let files = reread.files("bash").unwrap();
        assert_eq!(files, vec!["usr/bin/bash", "usr/share/man/bash.1"]);

        // A provide recorded on disk still satisfies a versioned dep.
        assert!(reread.satisfier(&Dep::parse("sh>=5.0")).is_some());
        assert!(reread.satisfier(&Dep::parse("zsh")).is_none());
    }

    #[test]
    fn install_reason_and_backup_survive_a_round_trip() {
        let root = temp_root("reason");
        let mut db = LocalDb::load(&root);

        let pkg = Package {
            name: "demo".into(),
            version: "1.0-1".into(),
            backup: vec![crate::pkg::BackupFile::parse("etc/demo.conf\tfeedface")],
            install_reason: InstallReason::Dependency,
            ..Default::default()
        };
        db.register(&pkg, &["etc/demo.conf".into()]).unwrap();

        let reread = LocalDb::load(&root);
        let got = reread.get("demo").unwrap();
        assert_eq!(got.install_reason, InstallReason::Dependency);
        assert!(got.is_backup("etc/demo.conf"));
        // The checksum must survive the round trip or removal cannot tell a
        // modified config from an untouched one.
        assert_eq!(got.backup_hash("etc/demo.conf"), Some("feedface"));
        assert_eq!(reread.dependencies().count(), 1);
    }

    #[test]
    fn upgrading_replaces_the_previous_entry() {
        let root = temp_root("upgrade");
        let mut db = LocalDb::load(&root);

        let old = Package {
            name: "app".into(),
            version: "1.0-1".into(),
            ..Default::default()
        };
        db.register(&old, &["usr/bin/app".into()]).unwrap();
        assert!(root.join("app-1.0-1").exists());

        let new = Package {
            name: "app".into(),
            version: "2.0-1".into(),
            ..Default::default()
        };
        db.register(&new, &["usr/bin/app".into()]).unwrap();

        // The stale directory must be gone, or a reload would be ambiguous.
        assert!(!root.join("app-1.0-1").exists());
        assert!(root.join("app-2.0-1").exists());

        let reread = LocalDb::load(&root);
        assert_eq!(reread.packages.len(), 1);
        assert_eq!(reread.get("app").unwrap().version, "2.0-1");
    }

    #[test]
    fn unregister_removes_the_entry_and_its_directory() {
        let root = temp_root("unregister");
        let mut db = LocalDb::load(&root);
        let pkg = Package {
            name: "demo".into(),
            version: "1.0-1".into(),
            ..Default::default()
        };
        db.register(&pkg, &["usr/bin/demo".into()]).unwrap();
        assert!(root.join("demo-1.0-1").exists());

        db.unregister("demo").unwrap();
        assert!(!db.is_installed("demo"));
        assert!(!root.join("demo-1.0-1").exists());
        // Removing something absent is not an error.
        assert!(db.unregister("ghost").is_ok());
    }
}
