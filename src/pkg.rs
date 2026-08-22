//! Package records and dependency constraints.

use crate::version::{Version, vercmp};
use std::cmp::Ordering;
use std::fmt;

/// Which source a package came from. Drives both display tagging and how the
/// install pipeline handles it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// An official repository, e.g. `core`, `extra`, `multilib`.
    Repo(String),
    /// The Arch User Repository, which must be built from source.
    Aur,
    /// Already present in the local database.
    Local,
}

impl Origin {
    pub fn label(&self) -> &str {
        match self {
            Origin::Repo(name) => name,
            Origin::Aur => "aur",
            Origin::Local => "local",
        }
    }

    pub fn is_aur(&self) -> bool {
        matches!(self, Origin::Aur)
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The comparison operator in a versioned dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ge,
    Le,
    Gt,
    Lt,
}

impl Op {
    fn satisfied_by(self, ord: Ordering) -> bool {
        match self {
            Op::Eq => ord == Ordering::Equal,
            Op::Ge => ord != Ordering::Less,
            Op::Le => ord != Ordering::Greater,
            Op::Gt => ord == Ordering::Greater,
            Op::Lt => ord == Ordering::Less,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ge => ">=",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }
}

/// A dependency such as `glibc`, `openssl>=3.0`, or `sh: bash` style descriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub name: String,
    pub constraint: Option<(Op, String)>,
    /// The `: description` suffix used by optdepends.
    pub description: Option<String>,
}

impl Dep {
    /// Parses one dependency string. Order matters: `>=` and `<=` must be
    /// tested before the single-character forms.
    pub fn parse(raw: &str) -> Dep {
        // alpm splits on ": " rather than ':' so that an epoch in a versioned
        // dependency (`foo>=1:1.0`) is not mistaken for a description.
        let (raw, description) = match raw.split_once(": ") {
            Some((dep, desc)) => (dep.trim(), Some(desc.trim().to_string())),
            None => (raw.trim(), None),
        };

        for (token, op) in [
            (">=", Op::Ge),
            ("<=", Op::Le),
            ("=", Op::Eq),
            (">", Op::Gt),
            ("<", Op::Lt),
        ] {
            if let Some((name, ver)) = raw.split_once(token) {
                return Dep {
                    name: name.trim().to_string(),
                    constraint: Some((op, ver.trim().to_string())),
                    description,
                };
            }
        }

        Dep {
            name: raw.to_string(),
            constraint: None,
            description,
        }
    }

    /// Whether a concrete version satisfies this dependency. An unversioned
    /// dependency is satisfied by anything.
    pub fn satisfied_by(&self, version: &str) -> bool {
        match &self.constraint {
            None => true,
            Some((op, want)) => op.satisfied_by(vercmp(version, want)),
        }
    }

    /// Whether `provide` — an entry from a package's `%PROVIDES%` — satisfies
    /// this dependency. A bare provide (no version) only satisfies an
    /// unversioned dependency, matching alpm's behaviour.
    pub fn satisfied_by_provide(&self, provide: &Dep) -> bool {
        if provide.name != self.name {
            return false;
        }
        match (&self.constraint, &provide.constraint) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(_), Some((_, provided_version))) => self.satisfied_by(provided_version),
        }
    }
}

impl fmt::Display for Dep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if let Some((op, ver)) = &self.constraint {
            write!(f, "{}{}", op.as_str(), ver)?;
        }
        Ok(())
    }
}

/// Why a package is present on the system. Pacman records this as `%REASON%`
/// and it drives orphan detection: only packages installed as dependencies can
/// become orphans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InstallReason {
    /// Asked for by name.
    #[default]
    Explicit,
    /// Pulled in to satisfy another package.
    Dependency,
}

impl InstallReason {
    /// The `%REASON%` value pacman writes: 0 explicit, 1 dependency.
    pub fn as_code(self) -> &'static str {
        match self {
            InstallReason::Explicit => "0",
            InstallReason::Dependency => "1",
        }
    }

    pub fn from_code(code: &str) -> InstallReason {
        match code.trim() {
            "1" => InstallReason::Dependency,
            _ => InstallReason::Explicit,
        }
    }
}

/// A configuration file the package asked to preserve, with the checksum it
/// had when installed. Removal compares against that checksum to tell an
/// untouched file (delete) from one the administrator edited (keep).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFile {
    pub path: String,
    /// Absent until the file has actually been installed and hashed.
    pub hash: Option<String>,
}

impl BackupFile {
    /// Parses a `%BACKUP%` line, which is `path` optionally followed by a
    /// tab and the checksum.
    pub fn parse(entry: &str) -> BackupFile {
        match entry.split_once('\t') {
            Some((path, hash)) if !hash.trim().is_empty() => BackupFile {
                path: path.to_string(),
                hash: Some(hash.trim().to_string()),
            },
            _ => BackupFile {
                path: entry.split('\t').next().unwrap_or(entry).to_string(),
                hash: None,
            },
        }
    }

    /// Serialises back to the on-disk `%BACKUP%` form.
    pub fn to_entry(&self) -> String {
        match &self.hash {
            Some(hash) => format!("{}\t{}", self.path, hash),
            None => self.path.clone(),
        }
    }
}

/// How thoroughly a package was checked before installation. Pacman records
/// this as `%VALIDATION%`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Validation {
    #[default]
    None,
    Sha256,
    Pgp,
}

impl Validation {
    pub fn as_str(self) -> &'static str {
        match self {
            Validation::None => "none",
            Validation::Sha256 => "sha256",
            Validation::Pgp => "pgp",
        }
    }
}

/// A package as described by a sync database, the AUR, or the local database.
#[derive(Debug, Clone, Default)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub description: String,
    pub url: Option<String>,
    pub packager: Option<String>,
    pub licenses: Vec<String>,
    pub groups: Vec<String>,
    pub provides: Vec<Dep>,
    pub depends: Vec<Dep>,
    pub makedepends: Vec<Dep>,
    pub optdepends: Vec<Dep>,
    pub conflicts: Vec<Dep>,
    pub replaces: Vec<Dep>,
    /// Filename within the repo, e.g. `go-2:1.22.0-1-x86_64.pkg.tar.zst`.
    pub filename: Option<String>,
    /// Compressed (download) size in bytes.
    pub csize: u64,
    /// Installed size in bytes.
    pub isize: u64,
    pub sha256: Option<String>,
    /// Whether the repo database advertises a detached PGP signature.
    pub has_sig: bool,
    pub origin: Origin,
    /// AUR popularity, used only for ranking search results.
    pub popularity: f64,
    pub out_of_date: bool,
    /// Configuration files that must survive removal, from `%BACKUP%`.
    pub backup: Vec<BackupFile>,
    /// Only meaningful for installed packages.
    pub install_reason: InstallReason,
    /// The architecture the package was built for.
    pub arch: Option<String>,
    /// The `pkgbase` a split package was built from.
    pub base: Option<String>,
    /// Build timestamp, as seconds since the epoch.
    pub build_date: u64,
    /// How the package was verified at install time.
    pub validation: Validation,
}

impl Default for Origin {
    fn default() -> Self {
        Origin::Local
    }
}

impl Package {
    pub fn parsed_version(&self) -> Version {
        Version::parse(&self.version)
    }

    /// Whether a path is a configuration file the package asked to preserve.
    pub fn is_backup(&self, path: &str) -> bool {
        self.backup.iter().any(|b| b.path == path)
    }

    /// The checksum a backup file had when it was installed.
    pub fn backup_hash(&self, path: &str) -> Option<&str> {
        self.backup
            .iter()
            .find(|b| b.path == path)
            .and_then(|b| b.hash.as_deref())
    }

    /// Whether this package satisfies `dep`, either by name or by a provide.
    pub fn satisfies(&self, dep: &Dep) -> bool {
        if self.name == dep.name && dep.satisfied_by(&self.version) {
            return true;
        }
        self.provides.iter().any(|p| dep.satisfied_by_provide(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unversioned() {
        let d = Dep::parse("glibc");
        assert_eq!(d.name, "glibc");
        assert!(d.constraint.is_none());
    }

    #[test]
    fn parses_operators() {
        // `>=` must win over `>`, and `<=` over `<`.
        let d = Dep::parse("openssl>=3.0");
        assert_eq!(d.name, "openssl");
        assert_eq!(d.constraint, Some((Op::Ge, "3.0".to_string())));

        let d = Dep::parse("foo<=1.2-3");
        assert_eq!(d.constraint, Some((Op::Le, "1.2-3".to_string())));

        let d = Dep::parse("bar>1.0");
        assert_eq!(d.constraint, Some((Op::Gt, "1.0".to_string())));

        let d = Dep::parse("baz=2.0");
        assert_eq!(d.constraint, Some((Op::Eq, "2.0".to_string())));
    }

    #[test]
    fn parses_optdepend_description() {
        let d = Dep::parse("python: for the bindings");
        assert_eq!(d.name, "python");
        assert_eq!(d.description.as_deref(), Some("for the bindings"));
    }

    #[test]
    fn satisfaction_uses_vercmp() {
        let d = Dep::parse("openssl>=3.0");
        assert!(d.satisfied_by("3.0"));
        assert!(d.satisfied_by("3.1"));
        assert!(d.satisfied_by("3.0.10"));
        assert!(!d.satisfied_by("2.9"));

        // Epoch beats a numerically larger plain version.
        let d = Dep::parse("foo>=1:1.0");
        assert!(d.satisfied_by("1:1.0"));
        assert!(!d.satisfied_by("99.0"));
    }

    #[test]
    fn bare_provide_does_not_satisfy_versioned_dep() {
        let dep = Dep::parse("sh>=5.0");
        let bare = Dep::parse("sh");
        assert!(!dep.satisfied_by_provide(&bare));

        let versioned = Dep::parse("sh=5.2");
        assert!(dep.satisfied_by_provide(&versioned));

        // But an unversioned dep is happy with a bare provide.
        assert!(Dep::parse("sh").satisfied_by_provide(&bare));
    }

    #[test]
    fn install_reason_round_trips_pacman_codes() {
        assert_eq!(InstallReason::Explicit.as_code(), "0");
        assert_eq!(InstallReason::Dependency.as_code(), "1");
        assert_eq!(InstallReason::from_code("1"), InstallReason::Dependency);
        assert_eq!(InstallReason::from_code("0"), InstallReason::Explicit);
        // An absent or unexpected value means explicit, as pacman assumes.
        assert_eq!(InstallReason::from_code(""), InstallReason::Explicit);
        assert_eq!(InstallReason::default(), InstallReason::Explicit);
    }

    #[test]
    fn backup_paths_are_recognised() {
        let pkg = Package {
            backup: vec![BackupFile::parse("etc/demo.conf\tabc123")],
            ..Default::default()
        };
        assert!(pkg.is_backup("etc/demo.conf"));
        assert!(!pkg.is_backup("usr/bin/demo"));
        assert_eq!(pkg.backup_hash("etc/demo.conf"), Some("abc123"));
        assert_eq!(pkg.backup_hash("usr/bin/demo"), None);
    }

    #[test]
    fn backup_entries_round_trip() {
        let with_hash = BackupFile::parse("etc/demo.conf\tdeadbeef");
        assert_eq!(with_hash.path, "etc/demo.conf");
        assert_eq!(with_hash.hash.as_deref(), Some("deadbeef"));
        assert_eq!(with_hash.to_entry(), "etc/demo.conf\tdeadbeef");

        // A path with no checksum yet is legal and stays hashless.
        let bare = BackupFile::parse("etc/bare.conf");
        assert_eq!(bare.path, "etc/bare.conf");
        assert!(bare.hash.is_none());
        assert_eq!(bare.to_entry(), "etc/bare.conf");
    }

    #[test]
    fn package_satisfies_via_provides() {
        let pkg = Package {
            name: "bash".into(),
            version: "5.2.26-1".into(),
            provides: vec![Dep::parse("sh=5.2")],
            ..Default::default()
        };
        assert!(pkg.satisfies(&Dep::parse("bash")));
        assert!(pkg.satisfies(&Dep::parse("sh>=5.0")));
        assert!(!pkg.satisfies(&Dep::parse("zsh")));
        assert!(!pkg.satisfies(&Dep::parse("bash>=6")));
    }
}
