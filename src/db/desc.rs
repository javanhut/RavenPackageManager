//! Parser for the `%KEY%` record format used by pacman's `desc`, `files`, and
//! `.PKGINFO`-adjacent files.
//!
//! A record is a sequence of `%KEY%` headers, each followed by one or more
//! value lines and terminated by a blank line.

use crate::pkg::{BackupFile, Dep, InstallReason, Origin, Package, Validation};
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

/// Whether a `%FILENAME%` may be used as a file name.
///
/// `%FILENAME%` is the one field in a repository database that rvn turns
/// straight into a path: the download destination is `<cache>/<filename>` and
/// the download URL is `<server>/<filename>`. Neither is a name rvn chose, and
/// `Path::join` replaces the whole path when what it is given is absolute, so
/// a database record carrying `%FILENAME%` = `/usr/lib/libc.so.6` would aim a
/// root-owned write at libc itself -- and `../../..` escapes the cache just as
/// well, because `join` does not normalise a parent component away either.
///
/// A package archive is a plain name in one directory. Anything that is not
/// one is a record trying to be a path, so it is refused here, at the parse,
/// rather than at each of the places that later builds a path out of it.
pub fn is_safe_archive_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        // A separator covers the absolute case and the parent-directory case
        // at once: neither can be spelled without one.
        && !name.contains('/')
        // A NUL cannot reach a syscall as part of a path, and a name carrying
        // one is either corrupt or an attempt to truncate what follows it.
        && !name.contains('\0')
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
        // A record whose filename is a path rather than a name is dropped
        // rather than trusted; see [`is_safe_archive_name`]. Every consumer
        // then sees the same thing it sees for a record that never carried a
        // filename at all, which they all already refuse to act on.
        filename: one(fields, "FILENAME").filter(|name| is_safe_archive_name(name)),
        csize: num(fields, "CSIZE"),
        // Sync databases call the installed size ISIZE; the local database
        // calls the same value SIZE.
        isize: if fields.contains_key("ISIZE") {
            num(fields, "ISIZE")
        } else {
            num(fields, "SIZE")
        },
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
        arch: one(fields, "ARCH"),
        base: one(fields, "BASE"),
        build_date: num(fields, "BUILDDATE"),
        validation: match one(fields, "VALIDATION").as_deref() {
            Some("pgp") => Validation::Pgp,
            Some("sha256") => Validation::Sha256,
            _ => Validation::None,
        },
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
    fn local_database_size_field_is_understood() {
        // The local database writes SIZE where a sync database writes ISIZE.
        let pkg = parse_package("%NAME%\nfoo\n\n%SIZE%\n4096\n", Origin::Local).unwrap();
        assert_eq!(pkg.isize, 4096);
    }

    #[test]
    fn parses_arch_base_and_validation() {
        let text = "%NAME%\nfoo\n\n%ARCH%\naarch64\n\n%BASE%\nfoo-git\n\n\
                    %BUILDDATE%\n1700000000\n\n%VALIDATION%\npgp\n";
        let pkg = parse_package(text, Origin::Local).unwrap();
        assert_eq!(pkg.arch.as_deref(), Some("aarch64"));
        assert_eq!(pkg.base.as_deref(), Some("foo-git"));
        assert_eq!(pkg.build_date, 1_700_000_000);
        assert_eq!(pkg.validation, Validation::Pgp);
    }

    #[test]
    fn absent_reason_defaults_to_explicit() {
        let pkg = parse_package("%NAME%\nfoo\n\n%VERSION%\n1.0-1\n", Origin::Local).unwrap();
        assert_eq!(pkg.install_reason, InstallReason::Explicit);
        assert!(pkg.backup.is_empty());
    }

    /// `%FILENAME%` becomes both a path under the cache and the tail of a
    /// download URL, so a record that spells a path there is a repository (or
    /// a mirror answering for one) choosing where root writes. The name has to
    /// be dropped at the parse, where every consumer inherits the refusal.
    #[test]
    fn a_filename_that_is_a_path_is_not_a_filename() {
        for hostile in [
            // Absolute: `Path::join` throws the cache prefix away entirely and
            // the write lands on the real libc.
            "/usr/lib/libc.so.6",
            // Relative escape: `join` does not normalise `..` away.
            "../../../etc/cron.d/x",
            "./foo.pkg.tar.zst",
            // A separator anywhere is enough to reshape the URL as well.
            "sub/dir/foo.pkg.tar.zst",
            "foo.pkg.tar.zst/",
            ".",
            "..",
            "",
            "foo\0.pkg.tar.zst",
        ] {
            assert!(
                !is_safe_archive_name(hostile),
                "{hostile:?} was accepted as a file name"
            );
            let text = format!("%NAME%\nfoo\n\n%VERSION%\n1.0-1\n\n%FILENAME%\n{hostile}\n");
            let pkg = parse_package(&text, Origin::Repo("extra".into())).unwrap();
            assert_eq!(
                pkg.filename, None,
                "{hostile:?} survived the parse as a filename"
            );
        }
    }

    #[test]
    fn an_ordinary_archive_name_still_parses() {
        assert!(is_safe_archive_name("go-2:1.22.0-1-x86_64.pkg.tar.zst"));
        // A name with dots and a dash in it is ordinary; only separators are
        // the problem.
        assert!(is_safe_archive_name("lib32-glibc-2.39-1-x86_64.pkg.tar.zst"));
        let pkg = parse_package(SAMPLE, Origin::Repo("extra".into())).unwrap();
        assert_eq!(
            pkg.filename.as_deref(),
            Some("go-2:1.22.0-1-x86_64.pkg.tar.zst")
        );
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
