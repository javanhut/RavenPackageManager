//! Sync databases: the `$repo.db` tarballs served by Arch mirrors.
//!
//! A `.db` is a gzipped tar whose entries are `pkgname-version/desc` records.
//! rvn downloads and parses these itself rather than delegating to pacman.

use crate::config::{Config, Repo};
use crate::db::desc;
use crate::pkg::{Origin, Package};
use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// An in-memory view of one repository's package list.
#[derive(Debug, Default)]
pub struct SyncDb {
    pub repo: String,
    pub packages: Vec<Package>,
    /// name -> index into `packages`, for O(1) exact lookups.
    by_name: HashMap<String, usize>,
}

impl SyncDb {
    pub fn get(&self, name: &str) -> Option<&Package> {
        self.by_name.get(name).map(|&i| &self.packages[i])
    }

    fn index(&mut self) {
        self.by_name = self
            .packages
            .iter()
            .enumerate()
            .map(|(i, p)| (p.name.clone(), i))
            .collect();
    }

    /// Parses a decompressed `.db` tar stream.
    ///
    /// Each package is a directory holding several members. `desc` carries the
    /// metadata, but dependency information lives in a separate `depends`
    /// member — reading only `desc` yields packages that appear to have no
    /// dependencies at all. Fields from every member are merged.
    pub fn from_tar<R: Read>(repo: &str, reader: R) -> io::Result<SyncDb> {
        let mut archive = tar::Archive::new(reader);
        // Package directory -> merged fields, insertion-ordered so the result
        // is stable across runs.
        let mut records: Vec<(String, HashMap<String, Vec<String>>)> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();

        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();

            let member = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // `files` holds the file list, which is only needed by `rvn find
            // --owns`; everything else describes the package.
            if !matches!(member, "desc" | "depends") {
                continue;
            }

            let Some(dir) = path.parent().and_then(|p| p.to_str()).map(str::to_string) else {
                continue;
            };

            let mut text = String::new();
            if entry.read_to_string(&mut text).is_err() {
                continue; // Non-UTF8 record: skip rather than abort the repo.
            }

            let fields = desc::parse_fields(&text);
            match index.get(&dir) {
                Some(&i) => {
                    for (key, values) in fields {
                        records[i].1.entry(key).or_default().extend(values);
                    }
                }
                None => {
                    index.insert(dir.clone(), records.len());
                    records.push((dir, fields));
                }
            }
        }

        let packages: Vec<Package> = records
            .into_iter()
            .filter_map(|(_, fields)| {
                desc::package_from_fields(&fields, Origin::Repo(repo.to_string()))
            })
            .collect();

        let mut db = SyncDb {
            repo: repo.to_string(),
            packages,
            by_name: HashMap::new(),
        };
        db.index();
        Ok(db)
    }

    /// Loads a `.db` from disk, transparently gunzipping it.
    pub fn from_file(repo: &str, path: &Path) -> io::Result<SyncDb> {
        let file = std::fs::File::open(path)?;
        SyncDb::from_tar(repo, GzDecoder::new(io::BufReader::new(file)))
    }
}

/// Where a repo's database is cached locally, mirroring pacman's layout.
pub fn db_file(cfg: &Config, repo: &str) -> PathBuf {
    cfg.sync_db_path().join(format!("{repo}.db"))
}

/// The URL a repo's database is fetched from, for a given mirror.
pub fn db_url(server: &str, repo: &str) -> String {
    format!("{}/{}.db", server.trim_end_matches('/'), repo)
}

/// Where a repo's database signature is cached.
pub fn db_sig_file(cfg: &Config, repo: &str) -> PathBuf {
    cfg.sync_db_path().join(format!("{repo}.db.sig"))
}

/// The URL a repo's database signature is fetched from.
pub fn db_sig_url(server: &str, repo: &str) -> String {
    format!("{}.sig", db_url(server, repo))
}

/// Loads every configured repo that has a cached database. Repos whose
/// database is missing are reported so the caller can offer to sync.
pub fn load_all(cfg: &Config) -> (Vec<SyncDb>, Vec<String>) {
    let mut loaded = Vec::new();
    let mut missing = Vec::new();

    for repo in &cfg.repos {
        let path = db_file(cfg, &repo.name);
        match SyncDb::from_file(&repo.name, &path) {
            Ok(db) => loaded.push(db),
            Err(_) => missing.push(repo.name.clone()),
        }
    }

    (loaded, missing)
}

/// Resolves the download URL for a package file across a repo's mirrors.
pub fn package_urls(repo: &Repo, filename: &str) -> Vec<String> {
    repo.servers
        .iter()
        .map(|s| format!("{}/{}", s.trim_end_matches('/'), filename))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an in-memory tar shaped like a real sync database.
    fn fake_db(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, body.as_bytes())
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn reads_desc_entries_and_skips_others() {
        let tar = fake_db(&[
            (
                "go-1.22.0-1/desc",
                "%NAME%\ngo\n\n%VERSION%\n1.22.0-1\n\n%DEPENDS%\nglibc\n",
            ),
            // `files` members must be ignored.
            ("go-1.22.0-1/files", "%FILES%\nusr/bin/go\n"),
            (
                "ripgrep-14.1.0-1/desc",
                "%NAME%\nripgrep\n\n%VERSION%\n14.1.0-1\n",
            ),
        ]);

        let db = SyncDb::from_tar("extra", &tar[..]).unwrap();
        assert_eq!(db.packages.len(), 2);
        assert_eq!(db.get("go").unwrap().version, "1.22.0-1");
        assert_eq!(db.get("ripgrep").unwrap().origin.label(), "extra");
        assert!(db.get("nope").is_none());
    }

    #[test]
    fn merges_the_separate_depends_member() {
        // Arch databases split metadata across `desc` and `depends`; reading
        // only `desc` would report every package as dependency-free.
        let tar = fake_db(&[
            (
                "ripgrep-15.2.0-1/desc",
                "%NAME%\nripgrep\n\n%VERSION%\n15.2.0-1\n",
            ),
            (
                "ripgrep-15.2.0-1/depends",
                "%DEPENDS%\nglibc\nlibgcc\npcre2\n\n%PROVIDES%\nrg=15.2.0\n",
            ),
            ("ripgrep-15.2.0-1/files", "%FILES%\nusr/bin/rg\n"),
        ]);

        let db = SyncDb::from_tar("extra", &tar[..]).unwrap();
        assert_eq!(db.packages.len(), 1, "members must merge into one package");

        let pkg = db.get("ripgrep").expect("ripgrep");
        assert_eq!(pkg.version, "15.2.0-1");
        assert_eq!(pkg.depends.len(), 3);
        assert_eq!(pkg.depends[2].name, "pcre2");
        assert_eq!(pkg.provides[0].to_string(), "rg=15.2.0");
    }

    #[test]
    fn handles_depends_appearing_before_desc() {
        // Tar member order is not guaranteed.
        let tar = fake_db(&[
            ("app-1.0-1/depends", "%DEPENDS%\nglibc\n"),
            ("app-1.0-1/desc", "%NAME%\napp\n\n%VERSION%\n1.0-1\n"),
        ]);
        let db = SyncDb::from_tar("core", &tar[..]).unwrap();
        assert_eq!(db.packages.len(), 1);
        assert_eq!(db.get("app").unwrap().depends[0].name, "glibc");
    }

    #[test]
    fn inline_depends_still_work() {
        // Some repositories merge everything into `desc`.
        let tar = fake_db(&[(
            "app-1.0-1/desc",
            "%NAME%\napp\n\n%VERSION%\n1.0-1\n\n%DEPENDS%\nglibc\n",
        )]);
        let db = SyncDb::from_tar("core", &tar[..]).unwrap();
        assert_eq!(db.get("app").unwrap().depends[0].name, "glibc");
    }

    #[test]
    fn builds_signature_urls_alongside_databases() {
        assert_eq!(
            db_sig_url("https://mirror/core/os/x86_64", "core"),
            "https://mirror/core/os/x86_64/core.db.sig"
        );
    }

    #[test]
    fn builds_urls() {
        assert_eq!(
            db_url("https://mirror/core/os/x86_64/", "core"),
            "https://mirror/core/os/x86_64/core.db"
        );
        let repo = Repo {
            name: "core".into(),
            servers: vec!["https://a/core/os/x86_64".into(), "https://b/core".into()],
            siglevel: crate::config::SigLevel::default_level(),
        };
        let urls = package_urls(&repo, "go-1.22.0-1-x86_64.pkg.tar.zst");
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://a/core/os/x86_64/go-1.22.0-1-x86_64.pkg.tar.zst");
    }
}
