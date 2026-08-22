//! Parser for the `%KEY%` record format used by pacman's `desc`, `files`, and
//! `.PKGINFO`-adjacent files.
//!
//! A record is a sequence of `%KEY%` headers, each followed by one or more
//! value lines and terminated by a blank line.

use crate::pkg::{BackupFile, Dep, InstallReason, Origin, Package};
use std::collections::HashMap;

/// Splits a desc blob into key -> values.
pub fn parse_fields(text: &str) -> HashMap<String, Vec<String>> {
    let mut fields: HashMap<String, Vec<String>> = HashMap::new();
    let mut key: Option<String> = None;

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with('%') && line.ends_with('%') && line.len() > 2 {
            key = Some(line[1..line.len() - 1].to_string());
            fields.entry(key.clone().unwrap()).or_default();
        } else if line.trim().is_empty() {
            key = None;
        } else if let Some(k) = &key {
            fields.entry(k.clone()).or_default().push(line.to_string());
        }
    }

    fields
}

fn one(fields: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    fields.get(key)?.first().cloned()
}

fn num(fields: &HashMap<String, Vec<String>>, key: &str) -> u64 {
    one(fields, key)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn list(fields: &HashMap<String, Vec<String>>, key: &str) -> Vec<String> {
    fields.get(key).cloned().unwrap_or_default()
}

fn deps(fields: &HashMap<String, Vec<String>>, key: &str) -> Vec<Dep> {
    list(fields, key).iter().map(|s| Dep::parse(s)).collect()
}

/// Builds a [`Package`] from a parsed desc record.
pub fn package_from_fields(fields: &HashMap<String, Vec<String>>, origin: Origin) -> Option<Package> {
    let name = one(fields, "NAME")?;
    let version = one(fields, "VERSION").unwrap_or_default();

    Some(Package {
        name,
        version,
        description: one(fields, "DESC").unwrap_or_default(),
        url: one(fields, "URL"),
        packager: one(fields, "PACKAGER"),
        licenses: list(fields, "LICENSE"),
        groups: list(fields, "GROUPS"),
        provides: deps(fields, "PROVIDES"),
        depends: deps(fields, "DEPENDS"),
        makedepends: deps(fields, "MAKEDEPENDS"),
        optdepends: deps(fields, "OPTDEPENDS"),
        conflicts: deps(fields, "CONFLICTS"),
        replaces: deps(fields, "REPLACES"),
        filename: one(fields, "FILENAME"),
        csize: num(fields, "CSIZE"),
        isize: num(fields, "ISIZE"),
        sha256: one(fields, "SHA256SUM"),
        has_sig: fields.contains_key("PGPSIG"),
        origin,
        popularity: 0.0,
        out_of_date: false,
        // `%BACKUP%` lines are `path<TAB>checksum`.
        backup: list(fields, "BACKUP")
            .iter()
            .map(|entry| BackupFile::parse(entry))
            .collect(),
        install_reason: one(fields, "REASON")
            .map(|r| InstallReason::from_code(&r))
            .unwrap_or_default(),
    })
}

/// Convenience wrapper: parse a desc blob straight into a package.
pub fn parse_package(text: &str, origin: Origin) -> Option<Package> {
    package_from_fields(&parse_fields(text), origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
%FILENAME%
go-2:1.22.0-1-x86_64.pkg.tar.zst

%NAME%
go

%VERSION%
2:1.22.0-1

%DESC%
Core compiler tools for the Go programming language

%CSIZE%
70123456

%ISIZE%
250000000

%SHA256SUM%
abc123

%PGPSIG%
iQIzBAAB

%LICENSE%
BSD

%DEPENDS%
glibc
openssl>=3.0

%OPTDEPENDS%
go-tools: additional Go tools

%PROVIDES%
go-compiler=1.22.0
";

    #[test]
    fn parses_a_full_record() {
        let pkg = parse_package(SAMPLE, Origin::Repo("extra".into())).unwrap();
        assert_eq!(pkg.name, "go");
        assert_eq!(pkg.version, "2:1.22.0-1");
        assert_eq!(pkg.csize, 70123456);
        assert_eq!(pkg.isize, 250000000);
        assert_eq!(pkg.sha256.as_deref(), Some("abc123"));
        assert!(pkg.has_sig);
        assert_eq!(pkg.licenses, vec!["BSD"]);
        assert_eq!(pkg.origin.label(), "extra");
    }

    #[test]
    fn parses_dependency_lists() {
        let pkg = parse_package(SAMPLE, Origin::Repo("extra".into())).unwrap();
        assert_eq!(pkg.depends.len(), 2);
        assert_eq!(pkg.depends[1].to_string(), "openssl>=3.0");

        // The optdepend description survives the ": " split.
        assert_eq!(pkg.optdepends[0].name, "go-tools");
        assert_eq!(
            pkg.optdepends[0].description.as_deref(),
            Some("additional Go tools")
        );

        assert_eq!(pkg.provides[0].to_string(), "go-compiler=1.22.0");
    }

    #[test]
    fn parses_backup_paths_and_reason() {
        let text = "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n\n%REASON%\n1\n\n\
                    %BACKUP%\netc/foo.conf\t9a8b7c\netc/bar.conf\n";
        let pkg = parse_package(text, Origin::Local).unwrap();
        assert_eq!(pkg.install_reason, InstallReason::Dependency);
        // The checksum after the tab is kept alongside the path.
        assert_eq!(pkg.backup.len(), 2);
        assert_eq!(pkg.backup[0].path, "etc/foo.conf");
        assert_eq!(pkg.backup[0].hash.as_deref(), Some("9a8b7c"));
        assert_eq!(pkg.backup[1].path, "etc/bar.conf");
        assert!(pkg.backup[1].hash.is_none());
    }

    #[test]
    fn absent_reason_defaults_to_explicit() {
        let pkg = parse_package("%NAME%\nfoo\n\n%VERSION%\n1.0-1\n", Origin::Local).unwrap();
        assert_eq!(pkg.install_reason, InstallReason::Explicit);
        assert!(pkg.backup.is_empty());
    }

    #[test]
    fn missing_name_is_rejected() {
        assert!(parse_package("%VERSION%\n1.0\n", Origin::Local).is_none());
    }

    #[test]
    fn absent_pgpsig_means_unsigned() {
        let text = "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n";
        let pkg = parse_package(text, Origin::Local).unwrap();
        assert!(!pkg.has_sig);
        assert_eq!(pkg.csize, 0);
    }
}
