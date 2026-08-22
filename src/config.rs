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

/// How strictly a signature is demanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Do not fetch or check signatures at all.
    Never,
    /// Check a signature when one is available; a bad one is still fatal.
    Optional,
    /// A valid signature is mandatory.
    Required,
}

impl Level {
    pub fn is_checked(self) -> bool {
        self != Level::Never
    }
}

/// Signature policy, which pacman tracks separately for packages and for the
/// repository databases themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigLevel {
    pub package: Level,
    pub database: Level,
}

impl SigLevel {
    /// Arch ships `SigLevel = Required DatabaseOptional`, which is what a
    /// configuration without an explicit setting is assumed to mean.
    pub const fn default_level() -> SigLevel {
        SigLevel {
            package: Level::Required,
            database: Level::Optional,
        }
    }

    /// Applies a whitespace-separated list of `SigLevel` tokens on top of an
    /// inherited policy.
    ///
    /// A bare `Required`/`Optional`/`Never` sets both halves; a `Package`- or
    /// `Database`-prefixed token sets only its own, and later tokens win —
    /// which is what makes `Required DatabaseOptional` mean strict packages
    /// and lenient databases.
    fn parse(values: &str, inherited: SigLevel) -> SigLevel {
        let mut level = inherited;

        for token in values.split_whitespace() {
            match token {
                "Never" => {
                    level.package = Level::Never;
                    level.database = Level::Never;
                }
                "Optional" => {
                    level.package = Level::Optional;
                    level.database = Level::Optional;
                }
                "Required" => {
                    level.package = Level::Required;
                    level.database = Level::Required;
                }
                "PackageNever" => level.package = Level::Never,
                "PackageOptional" => level.package = Level::Optional,
                "PackageRequired" => level.package = Level::Required,
                "DatabaseNever" => level.database = Level::Never,
                "DatabaseOptional" => level.database = Level::Optional,
                "DatabaseRequired" => level.database = Level::Required,
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
        let mut current = String::from("options");
        parse_into(path, &mut sections, 0, &mut current)?;

        let mut global_siglevel = SigLevel::default_level();

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

/// Expands an `Include` value, which pacman allows to be a glob.
fn include_paths(pattern: &str) -> Vec<PathBuf> {
    if !pattern.contains('*') {
        return vec![PathBuf::from(pattern)];
    }

    let path = Path::new(pattern);
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };

    // Only the common `dir/*.conf` shape is supported, which is what pacman
    // configurations use in practice.
    let (prefix, suffix) = match name.split_once('*') {
        Some(parts) => parts,
        None => return vec![path.to_path_buf()],
    };

    let mut matches: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(prefix) && n.ends_with(suffix))
                .unwrap_or(false)
        })
        .collect();

    // Directory order is arbitrary; sort so configuration is deterministic.
    matches.sort();
    matches
}

/// Reads a config file into ordered sections, following `Include` directives.
///
/// An `Include` is a textual splice at the point it appears, so an included
/// file inherits the section it was included from — that is what makes a
/// mirrorlist of bare `Server =` lines belong to the repository that included
/// it — and may itself open new sections.
fn parse_into(
    path: &Path,
    sections: &mut Vec<(String, Vec<(String, String)>)>,
    depth: usize,
    current: &mut String,
) -> io::Result<()> {
    if depth > 10 {
        return Ok(()); // Guard against Include cycles.
    }
    let text = std::fs::read_to_string(path)?;

    for line in text.lines() {
        let line = strip_comment(line);
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            *current = line[1..line.len() - 1].trim().to_string();
            if !sections.iter().any(|(name, _)| name == current) {
                sections.push((current.clone(), Vec::new()));
            }
            continue;
        }

        let (key, value) = match split_kv(line) {
            Some(kv) => kv,
            // Bare directives such as `Color` or `ILoveCandy`.
            None => (line.to_string(), String::new()),
        };

        if key == "Include" {
            for included in include_paths(&value) {
                // A missing include is not fatal: pacman ships repository
                // stanzas that reference mirrorlists which may not exist yet.
                let _ = parse_into(&included, sections, depth + 1, current);
            }
            continue;
        }

        if sections.iter().all(|(name, _)| name != current) {
            sections.push((current.clone(), Vec::new()));
        }
        let entry = sections
            .iter_mut()
            .find(|(name, _)| name == current)
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
        // `Required DatabaseOptional` must not make databases mandatory.
        assert_eq!(core.siglevel.package, Level::Required);
        assert_eq!(core.siglevel.database, Level::Optional);

        let custom = cfg.repo("custom").expect("custom repo");
        assert_eq!(custom.siglevel.package, Level::Never);
        assert_eq!(custom.siglevel.database, Level::Never);
        assert_eq!(custom.servers, vec!["file:///opt/repo"]);
    }

    #[test]
    fn an_include_can_define_whole_repositories() {
        // A user splitting repositories into a separate file must not have
        // them silently disappear.
        let extra = write_temp(
            "extra-repos.conf",
            "[myrepo]\nSigLevel = Never\nServer = https://my.host/$repo\n",
        );
        let conf = write_temp(
            "with-included-repos.conf",
            &format!("[options]\nArchitecture = x86_64\n\nInclude = {}\n", extra.display()),
        );

        let cfg = Config::load(&conf).unwrap();
        let repo = cfg.repo("myrepo").expect("repo from the included file");
        assert_eq!(repo.siglevel.package, Level::Never);
        assert_eq!(repo.servers, vec!["https://my.host/myrepo"]);
    }

    #[test]
    fn an_include_inherits_the_including_section() {
        // A mirrorlist is bare `Server =` lines; they belong to whichever
        // repository included them.
        let mirrors = write_temp("inherit-mirrors", "Server = https://a/$repo/os/$arch\n");
        let conf = write_temp(
            "inherit.conf",
            &format!(
                "[options]\nArchitecture = x86_64\n\n[core]\nInclude = {}\n[extra]\nInclude = {}\n",
                mirrors.display(),
                mirrors.display()
            ),
        );

        let cfg = Config::load(&conf).unwrap();
        // Each repository gets exactly one server, substituted for its name.
        assert_eq!(
            cfg.repo("core").unwrap().servers,
            vec!["https://a/core/os/x86_64"]
        );
        assert_eq!(
            cfg.repo("extra").unwrap().servers,
            vec!["https://a/extra/os/x86_64"]
        );
    }

    #[test]
    fn included_files_are_not_read_twice() {
        let mirrors = write_temp("dup-mirrors", "Server = https://a/$repo\n");
        let conf = write_temp(
            "dup.conf",
            &format!("[options]\n\n[core]\nInclude = {}\n", mirrors.display()),
        );
        let cfg = Config::load(&conf).unwrap();
        assert_eq!(cfg.repo("core").unwrap().servers.len(), 1, "no duplicates");
    }

    #[test]
    fn an_include_cycle_terminates() {
        let dir = std::env::temp_dir();
        let a = dir.join("rvn-test-cycle-a.conf");
        let b = dir.join("rvn-test-cycle-b.conf");
        std::fs::write(&a, format!("[options]\nInclude = {}\n", b.display())).unwrap();
        std::fs::write(&b, format!("Include = {}\n", a.display())).unwrap();

        // Must return rather than recurse forever.
        let cfg = Config::load(&a).unwrap();
        assert!(cfg.repos.is_empty());
    }

    #[test]
    fn a_missing_include_is_tolerated() {
        let conf = write_temp(
            "missing-include.conf",
            "[options]\n\n[core]\nInclude = /nonexistent/mirrorlist\nServer = https://fallback/$repo\n",
        );
        // The repository must survive with the servers it does declare.
        let cfg = Config::load(&conf).unwrap();
        assert_eq!(cfg.repo("core").unwrap().servers, vec!["https://fallback/core"]);
    }

    #[test]
    fn include_globs_expand_in_a_stable_order() {
        let dir = std::env::temp_dir().join("rvn-test-glob");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("20-b.conf"), "[bee]\nServer = https://b\n").unwrap();
        std::fs::write(dir.join("10-a.conf"), "[ay]\nServer = https://a\n").unwrap();
        std::fs::write(dir.join("ignored.txt"), "[nope]\nServer = https://n\n").unwrap();

        let conf = write_temp(
            "glob.conf",
            &format!("[options]\n\nInclude = {}/*.conf\n", dir.display()),
        );
        let cfg = Config::load(&conf).unwrap();

        let names: Vec<&str> = cfg.repos.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["ay", "bee"], "sorted, and .txt excluded");
    }

    #[test]
    fn siglevel_tokens_apply_in_order() {
        let base = SigLevel::default_level();

        // A bare keyword sets both halves.
        let both = SigLevel::parse("Never", base);
        assert_eq!(both.package, Level::Never);
        assert_eq!(both.database, Level::Never);

        // A prefixed token overrides only its own half, and later wins.
        let mixed = SigLevel::parse("Required DatabaseNever", base);
        assert_eq!(mixed.package, Level::Required);
        assert_eq!(mixed.database, Level::Never);

        let reversed = SigLevel::parse("DatabaseNever Required", base);
        assert_eq!(reversed.database, Level::Required, "later tokens win");

        // Trust tokens say which keys count, not whether to check.
        let trust = SigLevel::parse("Required TrustedOnly", base);
        assert_eq!(trust.package, Level::Required);
    }

    #[test]
    fn a_repo_inherits_the_global_siglevel() {
        let conf = write_temp(
            "inherit-siglevel.conf",
            "[options]\nSigLevel = Never\n\n[core]\nServer = https://a/$repo\n",
        );
        let cfg = Config::load(&conf).unwrap();
        assert_eq!(cfg.repo("core").unwrap().siglevel.package, Level::Never);
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
