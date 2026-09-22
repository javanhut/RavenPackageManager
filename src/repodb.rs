//! Building a repository database from a directory of packages.
//!
//! A `.db` is a gzipped tar of `pkgname-version/desc` records in pacman's
//! `%KEY%` format. rvn has read them since it existed -- that is what
//! [`crate::db::sync::SyncDb::from_tar`] is -- and this is the other half:
//! given the packages, write the database that describes them, so a
//! `[raven]` section in `/etc/pacman.conf` can point at a directory of
//! RavenLinux's own components and `rvn install huginn` works like any other
//! install.
//!
//! # Why this is not `repo-add`
//!
//! Arch's `repo-add` is on this machine and produces the same file. Shelling
//! out to it would have been shorter. It is not what rvn should do, for the
//! same reason rvn parses pacman's databases rather than calling `pacman`:
//! the format is the interface between a package manager and the repositories
//! it serves, and a package manager that can read a format but not write it
//! is only half a package manager. The whole of the writer is the `%KEY%`
//! emitter below, which is the same shape as the one
//! [`crate::db::local::LocalDb::register`] already uses for the local
//! database, and the test at the bottom of this file reads what it writes
//! back through rvn's own parser -- which is the consumer that actually has
//! to be satisfied.
//!
//! # `%PGPSIG%` is not decoration
//!
//! [`crate::ops::install`] only fetches a package's detached signature when
//! the database says the package has one, so a database that leaves
//! `%PGPSIG%` out turns every signed package in the repository into an
//! unsigned one -- and a repository configured `SigLevel = Required` then
//! fails to install anything at all, reporting a missing signature that is
//! sitting right next to the archive on the server. The signature is
//! therefore read from the `.sig` beside each package and written into the
//! record, base64-encoded as pacman writes it.

use crate::extract;
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The suffix pacman's tooling gives a repository database, and what the
/// bare `<repo>.db` name is a symlink to.
const DB_SUFFIX: &str = ".db.tar.gz";

/// The same, for the companion database that lists each package's contents.
const FILES_SUFFIX: &str = ".files.tar.gz";

#[derive(Debug)]
pub enum Error {
    /// A package could not be read. Carries the file, because the usual
    /// cause is a truncated download or a half-written build in the
    /// directory being scanned.
    Unreadable { path: PathBuf, message: String },
    /// An archive carries no `.PKGINFO`, so there is nothing to describe.
    NotAPackage { path: PathBuf },
    Io {
        doing: String,
        source: std::io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unreadable { path, message } => write!(f, "{}: {message}", path.display()),
            Error::NotAPackage { path } => write!(
                f,
                "{} has no .PKGINFO, so it is not a package — move it out of the directory and retry",
                path.display()
            ),
            Error::Io { doing, source } => write!(f, "{doing}: {source}"),
        }
    }
}

fn io(doing: impl Into<String>) -> impl FnOnce(std::io::Error) -> Error {
    let doing = doing.into();
    move |source| Error::Io { doing, source }
}

/// One package's entry in the database.
#[derive(Debug, Clone)]
pub struct Description {
    pub name: String,
    pub version: String,
    pub filename: String,
    pub csize: u64,
    pub isize: u64,
    pub sha256: String,
    /// The detached signature, base64-encoded, when one sits beside the
    /// archive.
    pub pgpsig: Option<String>,
    /// Everything the archive installs, as `<repo>.files` lists it: every
    /// member except the dot-files pacman's own metadata lives in,
    /// directories included and spelled with their trailing slash, sorted by
    /// byte and deduplicated.
    pub files: Vec<String>,
    fields: HashMap<String, Vec<String>>,
}

impl Description {
    /// The directory name the record lives under inside the database.
    fn directory(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }
}

/// Reads one package archive into the record that describes it.
///
/// Everything comes out of the archive rather than out of whatever built it,
/// so a package somebody else produced -- an AUR build, or one from a mirror
/// being mirrored again -- describes itself correctly too.
pub fn describe(archive: &Path) -> Result<Description, Error> {
    let manifest = extract::manifest(archive).map_err(|e| Error::Unreadable {
        path: archive.to_path_buf(),
        message: e.to_string(),
    })?;
    if manifest.pkginfo.is_empty() {
        return Err(Error::NotAPackage {
            path: archive.to_path_buf(),
        });
    }

    let first = |key: &str| {
        manifest
            .pkginfo
            .get(key)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    };
    let name = first("pkgname");
    if name.is_empty() {
        return Err(Error::NotAPackage {
            path: archive.to_path_buf(),
        });
    }

    let csize = std::fs::metadata(archive)
        .map(|m| m.len())
        .map_err(io(format!("measuring {}", archive.display())))?;
    let sha256 = crate::verify::sha256_file(archive)
        .map_err(io(format!("hashing {}", archive.display())))?;

    // Read, not just noted: the base64 of the signature is what pacman
    // verifies against, and rvn reads the key's presence to decide whether to
    // fetch the `.sig` at all.
    let signature = archive.with_file_name(format!(
        "{}.sig",
        archive.file_name().unwrap_or_default().to_string_lossy()
    ));
    let pgpsig = std::fs::read(&signature).ok().map(|bytes| base64(&bytes));

    let mut fields: HashMap<String, Vec<String>> = HashMap::new();
    let mut set = |key: &str, values: Vec<String>| {
        let values: Vec<String> = values.into_iter().filter(|v| !v.is_empty()).collect();
        if !values.is_empty() {
            fields.insert(key.to_string(), values);
        }
    };
    let list = |key: &str| manifest.pkginfo.get(key).cloned().unwrap_or_default();

    set("BASE", vec![first("pkgbase")]);
    set("DESC", vec![first("pkgdesc")]);
    set("URL", vec![first("url")]);
    set("ARCH", vec![first("arch")]);
    set("BUILDDATE", vec![first("builddate")]);
    set("PACKAGER", vec![first("packager")]);
    set("LICENSE", list("license"));
    set("GROUPS", list("group"));
    set("PROVIDES", list("provides"));
    set("DEPENDS", list("depend"));
    set("OPTDEPENDS", list("optdepend"));
    set("MAKEDEPENDS", list("makedepend"));
    set("CHECKDEPENDS", list("checkdepend"));
    set("CONFLICTS", list("conflict"));
    set("REPLACES", list("replaces"));

    // `repo-add` builds this list with `bsdtar --exclude='^.*' -tf`, which is
    // every member of the archive bar pacman's own dot-files; `extract`
    // already separates exactly that split, since it is the same distinction
    // an install has to draw. Sorted by byte and deduplicated to match the
    // `LC_ALL=C sort -u` on the other end of repo-add's pipe -- the ordering
    // is not load-bearing for any reader, but a database that reshuffles
    // itself between rebuilds is a needless diff on every mirror.
    let mut files: Vec<String> = manifest
        .files
        .iter()
        .chain(manifest.directories.iter())
        .cloned()
        .collect();
    files.sort();
    files.dedup();

    Ok(Description {
        name,
        version: first("pkgver"),
        filename: archive
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        csize,
        // `.PKGINFO` calls the installed size `size`; a sync database calls
        // the same number `%ISIZE%`. The local database calls it `%SIZE%`, a
        // disagreement db::desc already carries a comment about.
        isize: first("size").parse().unwrap_or(manifest.total_size),
        sha256,
        pgpsig,
        files,
        fields,
    })
}

/// Serialises one record in the `%KEY%` format
/// [`crate::db::desc::parse_fields`] reads.
///
/// The field order is the one a repository from a mirror uses. Nothing parses
/// positionally -- `parse_fields` builds a map -- but a database is a file
/// people read with `tar -xOf` when something is wrong, and one whose fields
/// arrive in a different order every time it is rebuilt is a needless diff.
fn desc(entry: &Description) -> String {
    let mut out = String::new();
    let mut field = |key: &str, values: &[String]| {
        if values.is_empty() {
            return;
        }
        out.push_str(&format!("%{key}%\n"));
        for value in values {
            out.push_str(value);
            out.push('\n');
        }
        out.push('\n');
    };

    let get = |key: &str| entry.fields.get(key).cloned().unwrap_or_default();

    field("FILENAME", std::slice::from_ref(&entry.filename));
    field("NAME", std::slice::from_ref(&entry.name));
    field("BASE", &get("BASE"));
    field("VERSION", std::slice::from_ref(&entry.version));
    field("DESC", &get("DESC"));
    field("GROUPS", &get("GROUPS"));
    field("CSIZE", &[entry.csize.to_string()]);
    field("ISIZE", &[entry.isize.to_string()]);
    field("SHA256SUM", std::slice::from_ref(&entry.sha256));
    if let Some(sig) = &entry.pgpsig {
        field("PGPSIG", std::slice::from_ref(sig));
    }
    field("URL", &get("URL"));
    field("LICENSE", &get("LICENSE"));
    field("ARCH", &get("ARCH"));
    field("BUILDDATE", &get("BUILDDATE"));
    field("PACKAGER", &get("PACKAGER"));
    field("REPLACES", &get("REPLACES"));
    field("CONFLICTS", &get("CONFLICTS"));
    field("PROVIDES", &get("PROVIDES"));
    field("DEPENDS", &get("DEPENDS"));
    field("OPTDEPENDS", &get("OPTDEPENDS"));
    field("MAKEDEPENDS", &get("MAKEDEPENDS"));
    field("CHECKDEPENDS", &get("CHECKDEPENDS"));

    out
}

/// Whether to write the companion `<repo>.files` database alongside `.db`.
///
/// `repo-add` always writes both, and this defaults to doing the same,
/// because a repository missing its `.files` is not broken so much as subtly
/// non-standard: nothing in rvn reads it -- [`crate::db::sync`] only ever
/// fetches `<repo>.db` -- but `pacman -F`, which is how people find out which
/// package owns a file they have in front of them, has nothing else to read.
/// The opt-out exists for the case the extra file actually costs something:
/// a database of a few thousand packages, where the file lists are an order
/// of magnitude more bytes than the descriptions and every mirror pays for
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Files {
    Write,
    Skip,
}

/// The body of a `files` member.
///
/// `repo-add` builds this as `echo %FILES%` followed by the output of a
/// `bsdtar -tf | sort -u` pipe, so there is a header line, one path per line,
/// and -- unlike every field in `desc` -- no blank line at the end. The
/// shape is copied rather than improved on: what reads this is `pacman -F`.
fn file_list(entry: &Description) -> String {
    let mut out = String::from("%FILES%\n");
    for path in &entry.files {
        out.push_str(path);
        out.push('\n');
    }
    out
}

/// What building a database found and wrote.
pub struct Summary {
    /// `<repo>.db.tar.gz`, the real file.
    pub database: PathBuf,
    /// `<repo>.db`, the name rvn and pacman actually fetch.
    pub alias: PathBuf,
    /// `<repo>.files.tar.gz` and the `<repo>.files` name it is fetched under,
    /// when [`Files::Write`] was asked for.
    pub files_database: Option<PathBuf>,
    pub files_alias: Option<PathBuf>,
    pub packages: Vec<Description>,
    /// Archives that were skipped, with why. A directory of packages usually
    /// has something else in it, and refusing to build the database because
    /// one file is not a package would be the wrong call for a command whose
    /// input is "whatever is in this directory".
    pub skipped: Vec<(PathBuf, String)>,
}

/// Builds `<repo>.db.tar.gz` from every package in `dir`.
///
/// Newest-wins when a directory holds several versions of one package, which
/// it will as soon as anything has been rebuilt: a repository database names
/// one version per package, and the one it should name is the one people
/// would be upgrading to. `crate::version::vercmp` decides, never mtime --
/// the file that was written most recently is not necessarily the highest
/// version, and a rebuild of an old release would otherwise silently
/// downgrade the whole repository.
pub fn build(
    repo: &str,
    dir: &Path,
    files: Files,
    note: &mut dyn FnMut(&str),
) -> Result<Summary, Error> {
    let mut newest: HashMap<String, Description> = HashMap::new();
    let mut skipped = Vec::new();

    let entries = std::fs::read_dir(dir).map_err(io(format!("reading {}", dir.display())))?;
    let mut archives: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_package(p))
        .collect();
    archives.sort();

    for archive in &archives {
        note(&archive.file_name().unwrap_or_default().to_string_lossy());
        let description = match describe(archive) {
            Ok(description) => description,
            // One unreadable archive does not make the other thirty
            // undescribable, and the caller reports every skip by name.
            Err(e) => {
                skipped.push((archive.clone(), e.to_string()));
                continue;
            }
        };
        match newest.get(&description.name) {
            Some(existing)
                if crate::version::vercmp(&description.version, &existing.version).is_le() => {}
            _ => {
                newest.insert(description.name.clone(), description);
            }
        }
    }

    // Sorted by name so the database is byte-identical when nothing changed,
    // which is what makes it worth signing and worth diffing.
    let mut packages: Vec<Description> = newest.into_values().collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));

    let database = dir.join(format!("{repo}{DB_SUFFIX}"));
    write(&database, &packages)?;

    // `<repo>.db` is the name that is fetched; `<repo>.db.tar.gz` is the file
    // it points at. That is repo-add's layout and pacman's expectation, and a
    // symlink rather than a copy so the two can never disagree about which
    // one is current.
    let alias = link(dir, repo, ".db", DB_SUFFIX)?;

    let (files_database, files_alias) = match files {
        Files::Write => {
            let path = dir.join(format!("{repo}{FILES_SUFFIX}"));
            write_files(&path, &packages)?;
            let alias = link(dir, repo, ".files", FILES_SUFFIX)?;
            (Some(path), Some(alias))
        }
        // A stale `.files` beside a fresh `.db` would describe packages the
        // repository no longer carries, which is worse than having none at
        // all, so opting out removes any left by an earlier run.
        Files::Skip => {
            let _ = std::fs::remove_file(dir.join(format!("{repo}{FILES_SUFFIX}")));
            let _ = std::fs::remove_file(dir.join(format!("{repo}.files")));
            (None, None)
        }
    };

    Ok(Summary {
        database,
        alias,
        files_database,
        files_alias,
        packages,
        skipped,
    })
}

/// Points `<repo><fetched>` at `<repo><real>` beside it, replacing whatever
/// was there. Shared by the two databases because getting one of the pair
/// right and the other wrong is exactly the kind of mistake a repository only
/// reveals on another machine.
fn link(dir: &Path, repo: &str, fetched: &str, real: &str) -> Result<PathBuf, Error> {
    let alias = dir.join(format!("{repo}{fetched}"));
    let _ = std::fs::remove_file(&alias);
    std::os::unix::fs::symlink(format!("{repo}{real}"), &alias)
        .map_err(io(format!("linking {}", alias.display())))?;
    Ok(alias)
}

/// Whether a path looks like a package rather than a signature, a database or
/// whatever else shares the directory.
fn is_package(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    // Dotfiles are skipped outright. A package filename never begins with a
    // dot, and everything that does in an output directory is somebody's
    // work in progress -- `rvn build` writes its tar as `.rvn-<name>-<pid>`
    // and stages into `.rvn-stage-<name>-<pid>` before renaming the finished
    // archive into place. Reading one of those would describe half a package
    // in a database other machines then fetch.
    !name.starts_with('.')
        && name.contains(".pkg.tar")
        && !name.ends_with(".sig")
        && !name.ends_with(".part")
}

/// Writes the gzipped tar itself.
///
/// Each package gets a directory entry and a `desc` member inside it, which
/// is the layout `SyncDb::from_tar` walks. `depends` is deliberately not
/// written as a separate member: pacman stopped splitting it out years ago
/// and puts everything in `desc`, and rvn's reader merges both anyway.
pub fn write(path: &Path, packages: &[Description]) -> Result<(), Error> {
    write_archive(path, packages, Files::Skip)
}

/// Writes `<repo>.files.tar.gz`: the same records, each with a `files` member
/// listing what the package installs.
///
/// The `desc` member is repeated rather than omitted because that is what
/// `repo-add` does -- it literally copies the directory it built for the
/// `.db` and adds one file to it -- and because a `.files` database is
/// fetched on its own by `pacman -Fy`, so a reader of it has no `desc` to
/// hand unless it carries one.
pub fn write_files(path: &Path, packages: &[Description]) -> Result<(), Error> {
    write_archive(path, packages, Files::Write)
}

fn write_archive(path: &Path, packages: &[Description], files: Files) -> Result<(), Error> {
    // Written beside the destination and renamed over it. A repository
    // database is fetched by every machine that uses the repository, and a
    // half-written one served for the few seconds gzip takes is a sync
    // failure on all of them at once.
    let staging = path.with_extension("rvn-new");
    let file =
        std::fs::File::create(&staging).map_err(io(format!("creating {}", staging.display())))?;
    let gz = flate2::write::GzEncoder::new(
        std::io::BufWriter::new(file),
        flate2::Compression::default(),
    );
    let mut builder = tar::Builder::new(gz);

    // One timestamp for the whole database, so rebuilding it from unchanged
    // packages produces an unchanged file and mirrors have nothing to ship.
    let stamp = packages
        .iter()
        .filter_map(|p| p.fields.get("BUILDDATE")?.first()?.parse::<u64>().ok())
        .max()
        .unwrap_or(0);

    for package in packages {
        let directory = package.directory();

        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(stamp);
        header.set_mode(0o755);
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("{directory}/"), std::io::empty())
            .map_err(io(format!("writing {directory} into the database")))?;

        let mut member = |name: &str, body: &str| -> Result<(), Error> {
            let mut header = tar::Header::new_gnu();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(stamp);
            header.set_mode(0o644);
            header.set_size(body.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("{directory}/{name}"), body.as_bytes())
                .map_err(io(format!("writing {directory}/{name} into the database")))
        };

        member("desc", &desc(package))?;
        if files == Files::Write {
            member("files", &file_list(package))?;
        }
    }

    builder
        .into_inner()
        .map_err(io("finishing the database"))?
        .finish()
        .map_err(io("compressing the database"))?
        .flush()
        .map_err(io("flushing the database"))?;

    std::fs::rename(&staging, path)
        .map_err(io(format!("moving the database to {}", path.display())))
}

/// Standard base64, as `%PGPSIG%` carries it.
///
/// Fifteen lines rather than a dependency, in a crate that already hand-rolls
/// an OpenPGP packet walker next door in [`crate::verify`]. The alphabet is
/// the RFC 4648 one and the padding is the ordinary `=`, because what reads
/// this is pacman.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let triple = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-repodb-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp dir");
        dir
    }

    /// Builds a real package into `out`, so the database is built from the
    /// same thing a repository would actually hold.
    fn a_package(dir: &Path, out: &Path, name: &str, version: &str) -> PathBuf {
        let source = dir.join(name);
        std::fs::create_dir_all(source.join("bin")).unwrap();
        std::fs::write(source.join("bin").join(name), format!("payload {version}")).unwrap();
        std::fs::write(
            source.join("package.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\
                 description = \"a component\"\nlicense = \"MIT\"\n\
                 [dependencies]\nruntime = [\"glibc\"]\n\
                 [install]\nfiles = [{{ src = \"bin/{name}\", dest = \"/usr/bin/{name}\", mode = 755 }}]\n"
            ),
        )
        .unwrap();

        let manifest = build::Manifest::read(&source.join("package.toml")).unwrap();
        let mut options = build::Options::new(out.to_path_buf());
        options.run_build = false;
        options.timestamp = 1_700_000_000;
        build::package(&manifest, &options, &mut |_| {})
            .expect("the package should build")
            .path
    }

    #[test]
    fn the_database_reads_back_through_rvns_own_sync_parser() {
        let dir = temp_dir("roundtrip");
        let out = dir.join("repo");
        a_package(&dir, &out, "huginn", "1.2.0");
        a_package(&dir, &out, "roostbar", "0.3.1");

        let summary =
            build("raven", &out, Files::Write, &mut |_| {}).expect("the database should build");
        assert!(summary.skipped.is_empty(), "{:?}", summary.skipped);
        assert_eq!(summary.packages.len(), 2);
        assert!(summary.database.is_file());
        // The name that is actually fetched resolves to the file.
        assert!(summary.alias.exists());

        // The consumer that has to be satisfied is rvn's own reader, not a
        // fixture of what the format is believed to look like.
        let db = crate::db::sync::SyncDb::from_file("raven", &summary.alias)
            .expect("rvn should be able to parse the database it just wrote");
        let huginn = db.get("huginn").expect("huginn should be in the database");
        assert_eq!(huginn.version, "1.2.0-1");
        assert_eq!(
            huginn.filename.as_deref(),
            Some("huginn-1.2.0-1-x86_64.pkg.tar.zst")
        );
        assert_eq!(huginn.arch.as_deref(), Some("x86_64"));
        assert_eq!(huginn.description, "a component");
        assert!(huginn.isize > 0, "the installed size must survive");
        assert!(huginn.csize > 0, "the download size must survive");
        assert_eq!(huginn.sha256.as_ref().map(String::len), Some(64));
        assert_eq!(huginn.depends.len(), 1);
        assert_eq!(huginn.depends[0].name, "glibc");
        // Nothing signed these, so nothing claims they are signed -- which is
        // what stops rvn fetching a `.sig` that is not there.
        assert!(!huginn.has_sig);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_highest_version_wins_rather_than_the_newest_file() {
        let dir = temp_dir("versions");
        let out = dir.join("repo");
        // Built in the order that makes mtime the wrong answer: the older
        // version is written last, so anything ordering by file time would
        // publish a downgrade.
        a_package(&dir, &out, "huginn", "1.10.0");
        a_package(&dir, &out, "huginn", "1.9.0");

        let summary =
            build("raven", &out, Files::Write, &mut |_| {}).expect("the database should build");
        assert_eq!(summary.packages.len(), 1);
        assert_eq!(summary.packages[0].version, "1.10.0-1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_signature_beside_a_package_is_recorded_so_it_gets_fetched() {
        let dir = temp_dir("pgpsig");
        let out = dir.join("repo");
        let archive = a_package(&dir, &out, "huginn", "1.2.0");
        // Not a real signature: what is being tested is that its presence
        // reaches `%PGPSIG%`, because that key is what makes rvn fetch the
        // `.sig` at install time at all.
        std::fs::write(
            archive.with_file_name(format!(
                "{}.sig",
                archive.file_name().unwrap().to_string_lossy()
            )),
            b"\x89\x01\x15\x03\x05\x00",
        )
        .unwrap();

        let summary =
            build("raven", &out, Files::Write, &mut |_| {}).expect("the database should build");
        assert_eq!(summary.packages[0].pgpsig.as_deref(), Some("iQEVAwUA"));

        let db = crate::db::sync::SyncDb::from_file("raven", &summary.alias).unwrap();
        assert!(db.get("huginn").unwrap().has_sig);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reads one member out of a gzipped tar database.
    fn member(path: &Path, name: &str) -> Option<String> {
        let file = std::fs::File::open(path).unwrap();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == name {
                let mut body = String::new();
                std::io::Read::read_to_string(&mut entry, &mut body).unwrap();
                return Some(body);
            }
        }
        None
    }

    #[test]
    fn the_files_database_lists_what_each_package_installs() {
        let dir = temp_dir("filesdb");
        let out = dir.join("repo");
        a_package(&dir, &out, "huginn", "1.2.0");

        let summary =
            build("raven", &out, Files::Write, &mut |_| {}).expect("the database should build");

        let files_db = summary.files_database.expect("a .files database");
        assert!(files_db.is_file());
        // `pacman -Fy` fetches `<repo>.files`, exactly as it fetches
        // `<repo>.db`, so the same symlink has to be there.
        let alias = summary.files_alias.expect("a .files alias");
        assert!(alias.exists());
        assert_eq!(alias.file_name().unwrap(), "raven.files");

        // repo-add's layout: `%FILES%`, then one path per line, root-relative
        // and with directories spelled with a trailing slash.
        let listing = member(&files_db, "huginn-1.2.0-1/files").expect("a files member");
        let lines: Vec<&str> = listing.lines().collect();
        assert_eq!(lines[0], "%FILES%");
        assert!(lines.contains(&"usr/bin/huginn"), "{lines:?}");
        assert!(lines.contains(&"usr/bin/"), "{lines:?}");
        assert!(
            !lines.iter().any(|l| l.starts_with('.')),
            "pacman's own metadata is not part of the package's contents: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.starts_with('/')),
            "paths are root-relative, not absolute: {lines:?}"
        );
        // Sorted and deduplicated, which is the `sort -u` at the end of
        // repo-add's pipe.
        let mut sorted = lines[1..].to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, lines[1..]);

        // repo-add copies the record it built for the `.db` and adds `files`
        // to it, so a `.files` fetched on its own still describes the package.
        assert_eq!(
            member(&files_db, "huginn-1.2.0-1/desc"),
            member(&summary.database, "huginn-1.2.0-1/desc"),
        );
        // And the `.db` itself carries no file lists, so nothing downloading
        // only it pays for them.
        assert!(member(&summary.database, "huginn-1.2.0-1/files").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skipping_the_files_database_removes_a_stale_one() {
        // A `.files` left over from an earlier run would describe packages
        // the repository no longer carries, which is worse than having none.
        let dir = temp_dir("nofiles");
        let out = dir.join("repo");
        a_package(&dir, &out, "huginn", "1.2.0");

        build("raven", &out, Files::Write, &mut |_| {}).unwrap();
        assert!(out.join("raven.files.tar.gz").is_file());

        let summary = build("raven", &out, Files::Skip, &mut |_| {}).unwrap();
        assert!(summary.files_database.is_none());
        assert!(!out.join("raven.files.tar.gz").exists());
        assert!(!out.join("raven.files").exists());
        // The database that actually matters is untouched by the choice.
        assert!(summary.database.is_file());
        assert!(summary.alias.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn base64_matches_the_encoding_pacman_reads() {
        // The three padding cases, which is all base64 has.
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // Every byte value, so the high bits are exercised rather than only
        // the ASCII range a lazy test would cover.
        assert_eq!(base64(&[0xfb, 0xff, 0xbf]), "+/+/");
    }
}
