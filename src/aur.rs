//! Arch User Repository client.
//!
//! rvn talks to the AUR RPC directly and builds packages itself, so `yay` (or
//! any other helper) never needs to be installed. Building still runs bash —
//! a PKGBUILD *is* a bash script — but rvn drives it rather than delegating to
//! another package manager.

use crate::fetch;
use crate::pkg::{Dep, Origin, Package};
use crate::resolve::Source;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const RPC_BASE: &str = "https://aur.archlinux.org/rpc/v5";
pub const GIT_BASE: &str = "https://aur.archlinux.org";

#[derive(Debug, Deserialize)]
struct RpcPackage {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(rename = "Maintainer")]
    maintainer: Option<String>,
    #[serde(rename = "Popularity", default)]
    popularity: f64,
    #[serde(rename = "OutOfDate")]
    out_of_date: Option<i64>,
    #[serde(rename = "License", default)]
    license: Vec<String>,
    #[serde(rename = "Depends", default)]
    depends: Vec<String>,
    #[serde(rename = "MakeDepends", default)]
    make_depends: Vec<String>,
    #[serde(rename = "OptDepends", default)]
    opt_depends: Vec<String>,
    #[serde(rename = "Conflicts", default)]
    conflicts: Vec<String>,
    #[serde(rename = "Provides", default)]
    provides: Vec<String>,
    #[serde(rename = "Replaces", default)]
    replaces: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(rename = "resultcount", default)]
    _result_count: usize,
    #[serde(rename = "results", default)]
    results: Vec<RpcPackage>,
    #[serde(rename = "error")]
    error: Option<String>,
}

fn deps(raw: &[String]) -> Vec<Dep> {
    raw.iter().map(|d| Dep::parse(d)).collect()
}

impl RpcPackage {
    fn into_package(self) -> Package {
        Package {
            name: self.name,
            version: self.version,
            description: self.description.unwrap_or_default(),
            url: self.url,
            packager: self.maintainer,
            licenses: self.license,
            groups: Vec::new(),
            provides: deps(&self.provides),
            depends: deps(&self.depends),
            makedepends: deps(&self.make_depends),
            optdepends: deps(&self.opt_depends),
            conflicts: deps(&self.conflicts),
            replaces: deps(&self.replaces),
            filename: None,
            csize: 0,
            isize: 0,
            sha256: None,
            has_sig: false,
            origin: Origin::Aur,
            popularity: self.popularity,
            out_of_date: self.out_of_date.is_some(),
            backup: Vec::new(),
            install_reason: crate::pkg::InstallReason::default(),
            arch: None,
            base: None,
            build_date: 0,
            validation: crate::pkg::Validation::default(),
        }
    }
}

/// Percent-encodes a query argument. The AUR rejects raw spaces and `+`.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Parses an RPC payload into packages.
pub fn parse_rpc(body: &str) -> Result<Vec<Package>, String> {
    let response: RpcResponse =
        serde_json::from_str(body).map_err(|e| format!("malformed AUR response: {e}"))?;
    if let Some(error) = response.error {
        return Err(error);
    }
    Ok(response
        .results
        .into_iter()
        .map(RpcPackage::into_package)
        .collect())
}

/// The AUR RPC, with a per-run cache so resolution does not re-request the
/// same package repeatedly.
pub struct Aur {
    cache: Mutex<HashMap<String, Option<Package>>>,
    offline: bool,
}

impl Aur {
    pub fn new() -> Aur {
        Aur {
            cache: Mutex::new(HashMap::new()),
            offline: false,
        }
    }

    /// An AUR client that never touches the network, for `--repo-only` runs.
    pub fn offline() -> Aur {
        Aur {
            cache: Mutex::new(HashMap::new()),
            offline: true,
        }
    }

    /// Full-text search across name and description.
    pub fn search(&self, term: &str) -> Result<Vec<Package>, String> {
        if self.offline {
            return Ok(Vec::new());
        }
        let url = format!("{RPC_BASE}/search/{}?by=name-desc", encode(term));
        let body = fetch::get_string(&url).map_err(|e| e.to_string())?;
        parse_rpc(&body)
    }

    /// Warms the cache for many packages in as few requests as possible.
    ///
    /// Resolution and update checks otherwise ask about one package per HTTP
    /// round trip, which on a system with many AUR packages dominates the
    /// runtime. The RPC accepts many `arg[]` values at once, so requests are
    /// batched — bounded only to keep the URL within server limits.
    pub fn prefetch(&self, names: &[String]) -> Result<usize, String> {
        if self.offline || names.is_empty() {
            return Ok(0);
        }

        const BATCH: usize = 100;
        let mut found = 0;

        for chunk in names.chunks(BATCH) {
            let packages = self.info(chunk)?;
            found += packages.len();
        }

        Ok(found)
    }

    /// Exact metadata for one or more package names.
    pub fn info(&self, names: &[String]) -> Result<Vec<Package>, String> {
        if self.offline || names.is_empty() {
            return Ok(Vec::new());
        }
        let query = names
            .iter()
            .map(|n| format!("arg[]={}", encode(n)))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{RPC_BASE}/info?{query}");
        let body = fetch::get_string(&url).map_err(|e| e.to_string())?;
        let packages = parse_rpc(&body)?;

        // Warm the cache, including negative results.
        if let Ok(mut cache) = self.cache.lock() {
            for name in names {
                let found = packages.iter().find(|p| p.name == *name).cloned();
                cache.insert(name.clone(), found);
            }
        }
        Ok(packages)
    }

    /// The git URL for a package's build files.
    pub fn git_url(name: &str) -> String {
        format!("{GIT_BASE}/{name}.git")
    }
}

impl Default for Aur {
    fn default() -> Self {
        Aur::new()
    }
}

impl Source for Aur {
    fn get(&self, name: &str) -> Option<Package> {
        if self.offline {
            return None;
        }
        if let Ok(cache) = self.cache.lock() {
            if let Some(hit) = cache.get(name) {
                return hit.clone();
            }
        }
        let found = self
            .info(&[name.to_string()])
            .ok()
            .and_then(|mut pkgs| pkgs.pop());
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(name.to_string(), found.clone());
        }
        found
    }
}

/// A parsed `.SRCINFO`, which is the authoritative dependency list for a
/// package's build files (the RPC can lag behind the repository).
#[derive(Debug, Default, Clone)]
pub struct SrcInfo {
    pub pkgbase: String,
    pub pkgver: String,
    pub pkgrel: String,
    pub epoch: Option<String>,
    pub pkgnames: Vec<String>,
    pub depends: Vec<Dep>,
    pub makedepends: Vec<Dep>,
    pub checkdepends: Vec<Dep>,
    pub provides: Vec<Dep>,
    pub conflicts: Vec<Dep>,
    pub sources: Vec<String>,
}

impl SrcInfo {
    /// The full `epoch:pkgver-pkgrel` version string.
    pub fn version(&self) -> String {
        match &self.epoch {
            Some(e) => format!("{}:{}-{}", e, self.pkgver, self.pkgrel),
            None => format!("{}-{}", self.pkgver, self.pkgrel),
        }
    }

    /// Parses the tab-indented `key = value` format written by makepkg, for
    /// the machine's own architecture.
    pub fn parse(text: &str) -> SrcInfo {
        SrcInfo::parse_for_arch(text, &crate::config::detect_arch())
    }

    /// Parses a `.SRCINFO`, honouring architecture-suffixed keys.
    ///
    /// A `.SRCINFO` lists `depends_x86_64` alongside `depends_aarch64`;
    /// folding every suffix into the base key would apply another
    /// architecture's dependencies to this machine.
    pub fn parse_for_arch(text: &str, arch: &str) -> SrcInfo {
        let mut info = SrcInfo::default();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() {
                continue;
            }

            match key {
                "pkgbase" => info.pkgbase = value.to_string(),
                "pkgname" => info.pkgnames.push(value.to_string()),
                "pkgver" => info.pkgver = value.to_string(),
                "pkgrel" => info.pkgrel = value.to_string(),
                "epoch" => info.epoch = Some(value.to_string()),
                "source" => info.sources.push(value.to_string()),
                _ => {
                    // `depends_aarch64` counts as `depends`, but only when the
                    // suffix names this machine.
                    let base = match key.split_once('_') {
                        Some((base, suffix)) if suffix == arch => base,
                        Some(_) => continue,
                        None => key,
                    };
                    match base {
                        "depends" => info.depends.push(Dep::parse(value)),
                        "makedepends" => info.makedepends.push(Dep::parse(value)),
                        "checkdepends" => info.checkdepends.push(Dep::parse(value)),
                        "provides" => info.provides.push(Dep::parse(value)),
                        "conflicts" => info.conflicts.push(Dep::parse(value)),
                        _ => {}
                    }
                }
            }
        }

        if info.pkgbase.is_empty() {
            info.pkgbase = info.pkgnames.first().cloned().unwrap_or_default();
        }
        info
    }

    pub fn read(dir: &Path) -> std::io::Result<SrcInfo> {
        Ok(SrcInfo::parse(&std::fs::read_to_string(
            dir.join(".SRCINFO"),
        )?))
    }
}

/// Where build files are checked out.
pub fn build_dir(cache_root: &Path, name: &str) -> PathBuf {
    cache_root.join("aur").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEARCH_BODY: &str = r#"{
        "resultcount": 2,
        "results": [
            {"Name":"spotify","Version":"1.2.31-1","Description":"A proprietary music streaming service",
             "URL":"https://spotify.com","Maintainer":"someone","Popularity":42.5,"OutOfDate":null,
             "License":["custom"],"Depends":["alsa-lib","gtk3"],"MakeDepends":["unzip"],
             "OptDepends":["ffmpeg: playback"],"Provides":["spotify-client"],"Conflicts":[]},
            {"Name":"spotifyd","Version":"0.3.5-2","Description":"An open source Spotify client daemon",
             "Popularity":8.0,"OutOfDate":1700000000,"Depends":["rust"]}
        ],
        "type": "search",
        "version": 5
    }"#;

    #[test]
    fn parses_search_results() {
        let pkgs = parse_rpc(SEARCH_BODY).unwrap();
        assert_eq!(pkgs.len(), 2);

        let spotify = &pkgs[0];
        assert_eq!(spotify.name, "spotify");
        assert_eq!(spotify.version, "1.2.31-1");
        assert_eq!(spotify.origin, Origin::Aur);
        assert_eq!(spotify.popularity, 42.5);
        assert!(!spotify.out_of_date);
        assert_eq!(spotify.depends.len(), 2);
        assert_eq!(spotify.optdepends[0].name, "ffmpeg");
        assert_eq!(spotify.provides[0].name, "spotify-client");

        // A non-null OutOfDate timestamp flags the package.
        assert!(pkgs[1].out_of_date);
        // Absent optional fields must default rather than fail the parse.
        assert_eq!(pkgs[1].description, "An open source Spotify client daemon");
        assert!(pkgs[1].url.is_none());
    }

    #[test]
    fn surfaces_rpc_errors() {
        let body = r#"{"error":"Too many package results.","resultcount":0,"results":[]}"#;
        assert_eq!(parse_rpc(body).unwrap_err(), "Too many package results.");
    }

    #[test]
    fn empty_results_are_not_an_error() {
        let body = r#"{"resultcount":0,"results":[],"type":"search","version":5}"#;
        assert!(parse_rpc(body).unwrap().is_empty());
    }

    #[test]
    fn encodes_query_arguments() {
        assert_eq!(encode("hello world"), "hello%20world");
        assert_eq!(encode("c++"), "c%2B%2B");
        assert_eq!(encode("gtk3"), "gtk3");
        assert_eq!(encode("lib-foo_bar.baz~1"), "lib-foo_bar.baz~1");
    }

    const SRCINFO: &str = "\
pkgbase = mytool
\tpkgdesc = A tool
\tpkgver = 1.4.0
\tpkgrel = 2
\tepoch = 1
\turl = https://example.com
\tarch = x86_64
\tdepends = glibc
\tdepends = openssl>=3.0
\tdepends_x86_64 = lib32-glibc
\tdepends_aarch64 = aarch64-only-lib
\tmakedepends = rust
\tcheckdepends = python-pytest
\tprovides = mytool-bin=1.4.0
\tsource = https://example.com/mytool-1.4.0.tar.gz

pkgname = mytool
pkgname = mytool-docs
";

    #[test]
    fn architecture_suffixed_keys_only_apply_to_that_architecture() {
        let x86 = SrcInfo::parse_for_arch(SRCINFO, "x86_64");
        let names: Vec<String> = x86.depends.iter().map(|d| d.name.clone()).collect();
        assert!(names.contains(&"lib32-glibc".to_string()), "{names:?}");
        assert!(
            !names.contains(&"aarch64-only-lib".to_string()),
            "another architecture's dependency must not apply: {names:?}"
        );

        let arm = SrcInfo::parse_for_arch(SRCINFO, "aarch64");
        let names: Vec<String> = arm.depends.iter().map(|d| d.name.clone()).collect();
        assert!(names.contains(&"aarch64-only-lib".to_string()), "{names:?}");
        assert!(!names.contains(&"lib32-glibc".to_string()), "{names:?}");

        // Unsuffixed dependencies apply everywhere.
        assert!(names.contains(&"glibc".to_string()));
    }

    #[test]
    fn parses_srcinfo() {
        let info = SrcInfo::parse_for_arch(SRCINFO, "x86_64");
        assert_eq!(info.pkgbase, "mytool");
        assert_eq!(info.pkgver, "1.4.0");
        assert_eq!(info.pkgrel, "2");
        // Epoch must be folded into the version string.
        assert_eq!(info.version(), "1:1.4.0-2");
        assert_eq!(info.pkgnames, vec!["mytool", "mytool-docs"]);

        // Architecture-suffixed keys fold into their base key.
        assert_eq!(info.depends.len(), 3);
        assert_eq!(info.depends[1].to_string(), "openssl>=3.0");
        assert_eq!(info.makedepends[0].name, "rust");
        assert_eq!(info.checkdepends[0].name, "python-pytest");
        assert_eq!(info.provides[0].to_string(), "mytool-bin=1.4.0");
        assert_eq!(info.sources.len(), 1);
    }

    #[test]
    fn srcinfo_without_epoch_omits_it() {
        let info = SrcInfo::parse("pkgbase = foo\n\tpkgver = 2.0\n\tpkgrel = 1\n");
        assert_eq!(info.version(), "2.0-1");
    }

    #[test]
    fn srcinfo_falls_back_to_first_pkgname() {
        let info = SrcInfo::parse("pkgname = solo\n\tpkgver = 1.0\n\tpkgrel = 1\n");
        assert_eq!(info.pkgbase, "solo");
    }

    #[test]
    fn offline_client_never_resolves() {
        let aur = Aur::offline();
        assert!(aur.get("anything").is_none());
        assert!(aur.search("anything").unwrap().is_empty());
    }

    #[test]
    fn builds_git_url() {
        assert_eq!(Aur::git_url("spotify"), "https://aur.archlinux.org/spotify.git");
    }
}
