//! Tracking for VCS ("devel") packages such as `-git`, `-hg` and `-svn`.
//!
//! A `-git` package's version is computed by `pkgver()` at build time, so its
//! recorded version never changes on its own — an ordinary version comparison
//! will never report an update no matter how far upstream moves. The only way
//! to know a rebuild is due is to ask the upstream repository what its head
//! commit is now and compare it with the commit that was built.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Suffixes that mark a package as tracking a moving upstream.
const DEVEL_SUFFIXES: &[&str] = &["-git", "-hg", "-svn", "-bzr", "-cvs", "-darcs"];

/// Whether a package name looks like a VCS package.
pub fn is_devel(name: &str) -> bool {
    DEVEL_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tracked {
    /// The upstream repository, with any VCS prefix and fragment removed.
    pub url: String,
    /// The commit that was built.
    pub commit: String,
}

/// The recorded upstream state of every devel package rvn has built.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    packages: HashMap<String, Tracked>,
}

impl Registry {
    fn path(db_path: &Path) -> PathBuf {
        // Kept beside, not inside, pacman's own database so nothing here can
        // confuse pacman.
        db_path.join("rvn").join("devel.json")
    }

    pub fn load(db_path: &Path) -> Registry {
        std::fs::read_to_string(Registry::path(db_path))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, db_path: &Path) -> std::io::Result<()> {
        let path = Registry::path(db_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, text)
    }

    pub fn get(&self, name: &str) -> Option<&Tracked> {
        self.packages.get(name)
    }

    pub fn record(&mut self, name: &str, tracked: Tracked) {
        self.packages.insert(name.to_string(), tracked);
    }

    pub fn forget(&mut self, name: &str) {
        self.packages.remove(name);
    }

    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.packages.keys().cloned().collect();
        names.sort();
        names
    }
}

/// Strips makepkg's VCS decorations from a source entry.
///
/// Sources look like `name::git+https://host/repo.git#branch=main`; only the
/// bare URL is useful for querying the remote.
pub fn clean_source_url(source: &str) -> Option<String> {
    // Drop a `name::` prefix.
    let source = source.split_once("::").map(|(_, rest)| rest).unwrap_or(source);

    // Only VCS sources move under us; a tarball is pinned by its checksum.
    let (vcs, rest) = source.split_once('+')?;
    if !matches!(vcs, "git" | "hg" | "svn" | "bzr") {
        return None;
    }

    // Drop a `#branch=`/`#commit=` fragment.
    let url = rest.split('#').next().unwrap_or(rest);
    if url.is_empty() {
        None
    } else {
        Some(url.to_string())
    }
}

/// The first VCS source in a `.SRCINFO` source list.
pub fn vcs_source(sources: &[String]) -> Option<String> {
    sources.iter().find_map(|s| clean_source_url(s))
}

/// Asks a remote git repository for its current head commit.
pub fn remote_head(url: &str) -> Option<String> {
    let output = Command::new("git")
        .arg("ls-remote")
        .arg(url)
        .arg("HEAD")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
        .filter(|commit| !commit.is_empty())
}

/// Names whose upstream has moved since they were built.
///
/// A package whose remote cannot be reached is left alone rather than being
/// reported as out of date.
pub fn outdated(registry: &Registry, names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            let Some(tracked) = registry.get(name) else {
                return false;
            };
            match remote_head(&tracked.url) {
                Some(head) => head != tracked.commit,
                None => false,
            }
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_vcs_package_names() {
        assert!(is_devel("neovim-git"));
        assert!(is_devel("foo-svn"));
        assert!(is_devel("bar-hg"));
        assert!(!is_devel("neovim"));
        // The suffix must be at the end, not merely present.
        assert!(!is_devel("git-lfs"));
    }

    #[test]
    fn cleans_source_urls() {
        assert_eq!(
            clean_source_url("git+https://github.com/user/repo.git"),
            Some("https://github.com/user/repo.git".into())
        );
        // A `name::` prefix and a fragment must both be stripped.
        assert_eq!(
            clean_source_url("myrepo::git+https://host/r.git#branch=main"),
            Some("https://host/r.git".into())
        );
        assert_eq!(
            clean_source_url("hg+https://host/repo"),
            Some("https://host/repo".into())
        );
    }

    #[test]
    fn ignores_non_vcs_sources() {
        // A tarball is pinned by checksum, so it cannot drift.
        assert_eq!(clean_source_url("https://host/file-1.0.tar.gz"), None);
        assert_eq!(clean_source_url("local-patch.diff"), None);
    }

    #[test]
    fn finds_the_vcs_source_among_others() {
        let sources = vec![
            "patch.diff".to_string(),
            "https://host/extra.tar.gz".to_string(),
            "git+https://host/repo.git".to_string(),
        ];
        assert_eq!(
            vcs_source(&sources),
            Some("https://host/repo.git".to_string())
        );
        assert_eq!(vcs_source(&["only.tar.gz".to_string()]), None);
    }

    #[test]
    fn registry_round_trips() {
        let dir = std::env::temp_dir().join("rvn-devel-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut registry = Registry::default();
        registry.record(
            "demo-git",
            Tracked {
                url: "https://host/r.git".into(),
                commit: "abc123".into(),
            },
        );
        registry.save(&dir).unwrap();

        let reloaded = Registry::load(&dir);
        assert_eq!(reloaded.get("demo-git").unwrap().commit, "abc123");
        assert_eq!(reloaded.names(), vec!["demo-git"]);

        // A missing registry is empty rather than an error.
        assert!(Registry::load(Path::new("/nonexistent/rvn")).names().is_empty());
    }

    #[test]
    fn forgetting_removes_the_entry() {
        let dir = std::env::temp_dir().join("rvn-devel-forget");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut registry = Registry::default();
        registry.record(
            "gone-git",
            Tracked {
                url: "https://host/r.git".into(),
                commit: "abc".into(),
            },
        );
        registry.forget("gone-git");
        registry.save(&dir).unwrap();

        // An uninstalled package must not leave tracking behind.
        assert!(Registry::load(&dir).get("gone-git").is_none());
        // Forgetting something absent is harmless.
        registry.forget("never-there");
    }

    #[test]
    fn only_moved_upstreams_are_reported() {
        let mut registry = Registry::default();
        registry.record(
            "unreachable-git",
            Tracked {
                // An unresolvable host stands in for an unreachable remote.
                url: "https://invalid.invalid/nope.git".into(),
                commit: "abc".into(),
            },
        );

        // An unreachable remote must not be reported as out of date, or every
        // offline update would propose rebuilding the world.
        let names = vec!["unreachable-git".to_string()];
        assert!(outdated(&registry, &names).is_empty());

        // A package with no recorded state is likewise not reported.
        assert!(outdated(&registry, &["untracked-git".to_string()]).is_empty());
    }
}
