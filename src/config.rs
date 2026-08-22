//! Parsing of `pacman.conf` and the mirrorlists it includes.
//!
//! rvn reads the same configuration pacman does so an existing Arch system
//! keeps working unchanged, but nothing here shells out to pacman.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Repo {
    pub name: String,
    /// Fully expanded mirror URLs, in the order they should be tried.
    pub servers: Vec<String>,
    pub siglevel: SigLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigLevel {
    Never,
    Optional,
    Required,
}

impl SigLevel {
    fn parse(values: &str, inherited: SigLevel) -> SigLevel {
        let mut level = inherited;
        for token in values.split_whitespace() {
            match token {
                "Never" | "PackageNever" => level = SigLevel::Never,
                "Optional" | "PackageOptional" => level = SigLevel::Optional,
                "Required" | "PackageRequired" => level = SigLevel::Required,
                // TrustedOnly / TrustAll affect which keys count, not whether
                // a signature is demanded.
                _ => {}
            }
        }
        level
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub root_dir: PathBuf,
    pub db_path: PathBuf,
    pub cache_dirs: Vec<PathBuf>,
    pub gpg_dir: PathBuf,
    pub arch: Vec<String>,
    pub repos: Vec<Repo>,
    pub ignore_pkg: Vec<String>,
    pub parallel_downloads: usize,
    pub color: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            root_dir: PathBuf::from("/"),
            db_path: PathBuf::from("/var/lib/pacman"),
            cache_dirs: vec![PathBuf::from("/var/cache/pacman/pkg")],
            gpg_dir: PathBuf::from("/etc/pacman.d/gnupg"),
            arch: vec![detect_arch()],
            repos: Vec::new(),
            ignore_pkg: Vec::new(),
            parallel_downloads: 5,
            color: true,
        }
    }
}

/// The machine architecture, matching what pacman substitutes for `$arch`.
pub fn detect_arch() -> String {
    if cfg!(target_arch = "x86_64") {
        "x86_64".to_string()
    } else if cfg!(target_arch = "aarch64") {
        "aarch64".to_string()
    } else {
        std::env::consts::ARCH.to_string()
    }
}

impl Config {
    pub fn sync_db_path(&self) -> PathBuf {
        self.db_path.join("sync")
    }

    pub fn local_db_path(&self) -> PathBuf {
        self.db_path.join("local")
    }

    pub fn repo(&self, name: &str) -> Option<&Repo> {
        self.repos.iter().find(|r| r.name == name)
    }

    /// Loads configuration from `path`, following `Include` directives.
    pub fn load(path: &Path) -> io::Result<Config> {
        let mut cfg = Config::default();
        let mut arch_from_file: Option<Vec<String>> = None;
        // Section name -> raw key/value pairs, preserving repeats.
        let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
        parse_into(path, &mut sections, 0)?;

        let mut global_siglevel = SigLevel::Required;

        for (section, entries) in &sections {
            if section == "options" {
                for (key, value) in entries {
                    match key.as_str() {
                        "RootDir" => cfg.root_dir = PathBuf::from(value),
                        "DBPath" => cfg.db_path = PathBuf::from(value),
                        "GPGDir" => cfg.gpg_dir = PathBuf::from(value),
                        "CacheDir" => {
                            let dirs: Vec<PathBuf> =
                                value.split_whitespace().map(PathBuf::from).collect();
                            if !dirs.is_empty() {
                                cfg.cache_dirs = dirs;
                            }
                        }
                        "Architecture" => {
                            arch_from_file = Some(
                                value
                                    .split_whitespace()
                                    .map(|a| {
                                        if a == "auto" {
                                            detect_arch()
                                        } else {
                                            a.to_string()
                                        }
                                    })
                                    .collect(),
                            );
                        }
                        "IgnorePkg" => cfg
                            .ignore_pkg
                            .extend(value.split_whitespace().map(str::to_string)),
                        "ParallelDownloads" => {
                            if let Ok(n) = value.trim().parse::<usize>() {
                                cfg.parallel_downloads = n.max(1);
                            }
                        }
                        "SigLevel" => global_siglevel = SigLevel::parse(value, global_siglevel),
                        "Color" => cfg.color = true,
                        _ => {}
                    }
                }
            }
        }

        if let Some(arch) = arch_from_file {
            if !arch.is_empty() {
                cfg.arch = arch;
            }
        }
        let primary_arch = cfg.arch.first().cloned().unwrap_or_else(detect_arch);

        for (section, entries) in &sections {
            if section == "options" {
                continue;
            }
            let mut servers = Vec::new();
            let mut siglevel = global_siglevel;

            for (key, value) in entries {
                match key.as_str() {
                    "Server" => servers.push(expand(value, section, &primary_arch)),
                    "SigLevel" => siglevel = SigLevel::parse(value, siglevel),
                    "Include" => {
                        // Mirrorlists are plain `Server = ...` lists.
                        if let Ok(text) = std::fs::read_to_string(value) {
                            for line in text.lines() {
                                let line = strip_comment(line);
                                if let Some((k, v)) = split_kv(line) {
                                    if k == "Server" {
                                        servers.push(expand(&v, section, &primary_arch));
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            cfg.repos.push(Repo {
                name: section.clone(),
                servers,
                siglevel,
            });
        }

        Ok(cfg)
    }
}

/// Substitutes `$repo` and `$arch` the way pacman does.
fn expand(server: &str, repo: &str, arch: &str) -> String {
    server.replace("$repo", repo).replace("$arch", arch)
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
    .trim()
}

fn split_kv(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim().to_string(), value.trim().to_string()))
}

/// Reads a config file into ordered sections, recursing through `Include`
/// directives in the `[options]`/repo body.
fn parse_into(
    path: &Path,
    sections: &mut Vec<(String, Vec<(String, String)>)>,
    depth: usize,
) -> io::Result<()> {
    if depth > 10 {
        return Ok(()); // Guard against Include cycles.
    }
    let text = std::fs::read_to_string(path)?;
    let mut current = String::from("options");

    for line in text.lines() {
        let line = strip_comment(line);
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim().to_string();
            if !sections.iter().any(|(name, _)| *name == current) {
                sections.push((current.clone(), Vec::new()));
            }
            continue;
        }

        let (key, value) = match split_kv(line) {
            Some(kv) => kv,
            // Bare directives such as `Color` or `ILoveCandy`.
            None => (line.to_string(), String::new()),
        };

        if sections.iter().all(|(name, _)| *name != current) {
            sections.push((current.clone(), Vec::new()));
        }
        let entry = sections
            .iter_mut()
            .find(|(name, _)| *name == current)
            .expect("section was just ensured to exist");
        entry.1.push((key, value));
    }

    Ok(())
}

/// Convenience for callers that only need a name -> repo map.
pub fn repo_map(cfg: &Config) -> HashMap<&str, &Repo> {
    cfg.repos.iter().map(|r| (r.name.as_str(), r)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rvn-test-{name}"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parses_options_and_repos() {
        let mirrorlist = write_temp(
            "mirrorlist",
            "# comment\nServer = https://mirror.one/$repo/os/$arch\nServer = https://mirror.two/$repo/os/$arch\n",
        );
        let conf = write_temp(
            "pacman.conf",
            &format!(
                "[options]\n\
                 RootDir = /\n\
                 DBPath  = /var/lib/pacman/\n\
                 Architecture = x86_64\n\
                 ParallelDownloads = 8\n\
                 IgnorePkg = linux nvidia\n\
                 SigLevel = Required DatabaseOptional\n\
                 \n\
                 [core]\n\
                 Include = {}\n\
                 \n\
                 [custom]\n\
                 SigLevel = Never\n\
                 Server = file:///opt/repo\n",
                mirrorlist.display()
            ),
        );

        let cfg = Config::load(&conf).unwrap();
        assert_eq!(cfg.db_path, PathBuf::from("/var/lib/pacman/"));
        assert_eq!(cfg.parallel_downloads, 8);
        assert_eq!(cfg.ignore_pkg, vec!["linux", "nvidia"]);
        assert_eq!(cfg.arch, vec!["x86_64"]);

        let core = cfg.repo("core").expect("core repo");
        assert_eq!(core.servers.len(), 2);
        // $repo and $arch must both be substituted.
        assert_eq!(core.servers[0], "https://mirror.one/core/os/x86_64");
        assert_eq!(core.siglevel, SigLevel::Required);

        let custom = cfg.repo("custom").expect("custom repo");
        assert_eq!(custom.siglevel, SigLevel::Never);
        assert_eq!(custom.servers, vec!["file:///opt/repo"]);
    }

    #[test]
    fn options_section_is_not_a_repo() {
        let conf = write_temp("only-options.conf", "[options]\nColor\nCheckSpace\n");
        let cfg = Config::load(&conf).unwrap();
        assert!(cfg.repos.is_empty(), "options must not become a repo");
    }

    #[test]
    fn architecture_auto_resolves() {
        let conf = write_temp("auto-arch.conf", "[options]\nArchitecture = auto\n");
        let cfg = Config::load(&conf).unwrap();
        assert_eq!(cfg.arch, vec![detect_arch()]);
    }
}
