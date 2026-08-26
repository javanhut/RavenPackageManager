//! Unpacking `.pkg.tar.zst` archives onto the filesystem.
//!
//! Extraction is deliberately two-phase: the archive is first inspected to
//! build the file list and detect conflicts, and only then are files written.
//! That keeps a conflicting package from leaving a half-installed mess.

use crate::db::local::LocalDb;
use bzip2::read::BzDecoder;
use filetime::FileTime;
use flate2::read::GzDecoder;
use liblzma::read::XzDecoder;
use ruzstd::decoding::StreamingDecoder;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Archive members that are pacman metadata rather than installed files.
const METADATA: &[&str] = &[
    ".PKGINFO",
    ".MTREE",
    ".INSTALL",
    ".BUILDINFO",
    ".CHANGELOG",
];

#[derive(Debug)]
pub enum ExtractError {
    /// An archive member tried to escape the install root.
    UnsafePath(String),
    /// A file is already owned by a different installed package.
    FileConflict {
        path: String,
        owner: String,
    },
    UnsupportedFormat(String),
    /// A hard link could not be recreated, with the entry that caused it.
    LinkFailed {
        path: String,
        target: String,
        reason: String,
    },
    /// The package ships one kind of entry where a different kind already
    /// exists. Arch's `filesystem` package ships /bin, /lib, /lib64, /sbin,
    /// /usr/lib64 and /usr/sbin as usrmerge symlinks; this distribution's root
    /// has them as real, populated directories. Converting a live directory
    /// into a symlink is a migration, not an extraction, so it is refused
    /// before a single byte is written rather than half-applied.
    TypeConflict {
        path: String,
        wanted: String,
        found: String,
    },
    /// An io operation failed, with the path it failed on and what was being
    /// attempted. The failure this exists for reported only "File exists (os
    /// error 17)": no path, no operation, and four thousand candidate entries
    /// in the archive.
    IoAt {
        operation: &'static str,
        path: String,
        source: io::Error,
    },
    Io(io::Error),
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractError::UnsafePath(p) => write!(f, "archive contains unsafe path: {p}"),
            ExtractError::FileConflict { path, owner } => {
                write!(f, "{path} is already owned by {owner}")
            }
            ExtractError::UnsupportedFormat(e) => write!(f, "unsupported package format: {e}"),
            ExtractError::LinkFailed {
                path,
                target,
                reason,
            } => write!(f, "could not link {path} -> {target}: {reason}"),
            ExtractError::TypeConflict {
                path,
                wanted,
                found,
            } => write!(f, "{path} would be {wanted}, but {found} is already there"),
            ExtractError::IoAt {
                operation,
                path,
                source,
            } => write!(f, "{operation} {path}: {source}"),
            ExtractError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ExtractError {}

impl From<io::Error> for ExtractError {
    fn from(e: io::Error) -> Self {
        ExtractError::Io(e)
    }
}

/// Opens a package archive, transparently handling zstd, gzip, xz-less plain
/// tar, based on the file extension.
fn open_archive(path: &Path) -> Result<Box<dyn Read>, ExtractError> {
    let file = std::fs::File::open(path).map_err(io_error("opening", path))?;
    let reader = io::BufReader::new(file);
    let name = path.to_string_lossy();

    // Arch has moved to zstd, but xz is still what Arch Linux ARM ships and
    // what older packages in every repository use.
    if name.ends_with(".zst") || name.ends_with(".zstd") {
        let decoder = StreamingDecoder::new(reader)
            .map_err(|e| ExtractError::UnsupportedFormat(e.to_string()))?;
        Ok(Box::new(decoder))
    } else if name.ends_with(".xz") || name.ends_with(".lzma") {
        Ok(Box::new(XzDecoder::new(reader)))
    } else if name.ends_with(".gz") {
        Ok(Box::new(GzDecoder::new(reader)))
    } else if name.ends_with(".bz2") {
        Ok(Box::new(BzDecoder::new(reader)))
    } else if name.ends_with(".tar") {
        Ok(Box::new(reader))
    } else {
        Err(ExtractError::UnsupportedFormat(format!(
            "{name}: expected .pkg.tar.zst, .xz, .gz, .bz2 or .tar"
        )))
    }
}

/// Rejects absolute paths and any `..` component, so a malicious archive
/// cannot write outside the install root.
fn safe_relative(path: &Path) -> Result<PathBuf, ExtractError> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ExtractError::UnsafePath(path.display().to_string()));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(ExtractError::UnsafePath(path.display().to_string()));
    }
    Ok(out)
}

/// Whether two paths resolve to the same existing file.
///
/// Distinct hard links to one inode have distinct paths, so this stays false
/// for genuine links on a case-sensitive filesystem.
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Turns a bare io error into one that names the path and the operation.
///
/// The bug this exists for: extracting `filesystem` over a non-usrmerge root
/// failed with "File exists (os error 17)" and nothing else -- no path, no
/// operation, no way to tell which of the package's entries collided.
fn io_error(operation: &'static str, path: &Path) -> impl FnOnce(io::Error) -> ExtractError {
    let path = path.display().to_string();
    move |source| ExtractError::IoAt {
        operation,
        path,
        source,
    }
}

/// Describes what is already at `path`, for a type-conflict message.
///
/// `symlink_metadata` is required rather than `metadata`: the latter follows
/// the link, so an already-correct usrmerge symlink would be reported as the
/// directory it points at and a no-op re-install would look like a conflict.
fn describe_existing(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return Some(match std::fs::read_link(path) {
            Ok(target) => format!("a symlink to {}", target.display()),
            Err(_) => "a symlink".to_string(),
        });
    }
    if meta.file_type().is_dir() {
        return Some(match std::fs::read_dir(path).map(|d| d.count()) {
            Ok(0) => "an empty directory".to_string(),
            Ok(1) => "a directory with 1 entry".to_string(),
            Ok(n) => format!("a directory with {n} entries"),
            // Unreadable, but still a directory and still a conflict.
            Err(_) => "a directory".to_string(),
        });
    }
    Some(format!("a regular file ({} bytes)", meta.len()))
}

/// Describes what the archive wants at a path.
fn describe_wanted(entry: &ManifestEntry) -> String {
    match (entry.kind, &entry.link_target) {
        (EntryKind::Symlink, Some(t)) => format!("a symlink to {t}"),
        (EntryKind::HardLink, Some(t)) => format!("a hard link to {t}"),
        (kind, _) => kind.describe().to_string(),
    }
}

fn is_metadata(path: &Path) -> bool {
    path.components().count() == 1
        && path
            .to_str()
            .map(|p| METADATA.contains(&p))
            .unwrap_or(false)
}

/// What an archive member is.
///
/// The type is kept per entry because a path collision and a *change of type*
/// are different problems: overwriting a file with a file is an upgrade, while
/// replacing a populated directory with a symlink destroys whatever was inside
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    HardLink,
}

impl EntryKind {
    /// The article-prefixed noun used in conflict messages.
    pub fn describe(self) -> &'static str {
        match self {
            EntryKind::File => "a regular file",
            EntryKind::Dir => "a directory",
            EntryKind::Symlink => "a symlink",
            EntryKind::HardLink => "a hard link",
        }
    }

    fn from_header(kind: tar::EntryType) -> EntryKind {
        if kind.is_dir() {
            EntryKind::Dir
        } else if kind.is_symlink() {
            EntryKind::Symlink
        } else if kind.is_hard_link() {
            EntryKind::HardLink
        } else {
            // POSIX says an unrecognised typeflag is a regular file, and that
            // is what `Entry::unpack` does with it too.
            EntryKind::File
        }
    }
}

/// One installable archive member.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    /// Root-relative, with a trailing slash for directories -- the same
    /// spelling that lands in `files`/`directories` and in the local database.
    pub path: String,
    pub kind: EntryKind,
    /// A symlink's or hard link's target, verbatim from the header.
    pub link_target: Option<String>,
}

/// What an archive contains, determined without writing anything.
#[derive(Debug, Default)]
pub struct Manifest {
    /// Regular files and symlinks, as root-relative paths.
    pub files: Vec<String>,
    /// Directories the package creates.
    pub directories: Vec<String>,
    /// Every installable member in archive order, with its type. `files` and
    /// `directories` are views onto this and stay populated exactly as before,
    /// so callers that only want the path lists are untouched.
    pub entries: Vec<ManifestEntry>,
    /// Whether the package ships an `.INSTALL` scriptlet.
    pub has_install_script: bool,
    /// The scriptlet itself, kept so its hooks can run and so it can be stored
    /// for later removal hooks.
    pub install_script: Option<Vec<u8>>,
    /// The scriptlet's timestamp in the archive. pacman preserves it when
    /// storing the file, and `pacman -Qkk` checks it against the `.MTREE`.
    pub install_script_mtime: Option<u64>,
    pub total_size: u64,
    /// Configuration files listed as `backup` in `.PKGINFO`, which must be
    /// preserved rather than deleted on removal.
    pub backup: Vec<String>,
    /// The raw `.MTREE`, stored verbatim in the local database so `pacman
    /// -Qkk` can verify the package.
    pub mtree: Option<Vec<u8>>,
    /// Dependencies declared in `.PKGINFO`, which is authoritative when a
    /// sync database entry is incomplete.
    pub depends: Vec<String>,
    /// Every `.PKGINFO` field. For a package rvn built itself this is the only
    /// source of metadata — the AUR RPC supplies neither size nor architecture.
    pub pkginfo: HashMap<String, Vec<String>>,
}

/// Parses a `.PKGINFO` body into key -> values.
///
/// The format is plain `key = value` lines with `#` comments; keys repeat for
/// list-valued fields such as `depend` and `backup`.
pub fn parse_pkginfo(text: &str) -> HashMap<String, Vec<String>> {
    let mut fields: HashMap<String, Vec<String>> = HashMap::new();

    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        fields
            .entry(key.trim().to_string())
            .or_default()
            .push(value.to_string());
    }

    fields
}

/// Pulls one repeated field out of a `.PKGINFO` body.
pub fn parse_pkginfo_field(text: &str, key: &str) -> Vec<String> {
    parse_pkginfo(text).remove(key).unwrap_or_default()
}

/// Reads an archive's table of contents.
pub fn manifest(path: &Path) -> Result<Manifest, ExtractError> {
    let mut archive = tar::Archive::new(open_archive(path)?);
    let mut manifest = Manifest::default();

    for entry in archive.entries()? {
        let entry = entry?;
        let entry_path = entry.path()?.to_path_buf();

        if is_metadata(&entry_path) {
            match entry_path.to_str() {
                Some(".INSTALL") => {
                    manifest.has_install_script = true;
                    let mtime = entry.header().mtime().ok();
                    let mut bytes = Vec::new();
                    let mut entry = entry;
                    if entry.read_to_end(&mut bytes).is_ok() {
                        manifest.install_script = Some(bytes);
                        manifest.install_script_mtime = mtime;
                    }
                }
                Some(".PKGINFO") => {
                    let mut text = String::new();
                    let mut entry = entry;
                    if entry.read_to_string(&mut text).is_ok() {
                        manifest.pkginfo = parse_pkginfo(&text);
                        manifest.backup = manifest
                            .pkginfo
                            .get("backup")
                            .cloned()
                            .unwrap_or_default();
                        manifest.depends = manifest
                            .pkginfo
                            .get("depend")
                            .cloned()
                            .unwrap_or_default();
                    }
                }
                Some(".MTREE") => {
                    let mut bytes = Vec::new();
                    let mut entry = entry;
                    if entry.read_to_end(&mut bytes).is_ok() {
                        manifest.mtree = Some(bytes);
                    }
                }
                _ => {}
            }
            continue;
        }

        let relative = safe_relative(&entry_path)?;
        let as_string = relative.to_string_lossy().to_string();

        let kind = EntryKind::from_header(entry.header().entry_type());
        // A header-only read, but a malformed link name is an error, so it is
        // given the entry it came from rather than surfacing bare.
        let link_target = entry
            .link_name()
            .map_err(io_error("reading the link target of", &entry_path))?
            .map(|t| t.to_string_lossy().to_string());

        let recorded = if kind == EntryKind::Dir {
            let with_slash = format!("{as_string}/");
            manifest.directories.push(with_slash.clone());
            with_slash
        } else {
            manifest.total_size += entry.header().size().unwrap_or(0);
            manifest.files.push(as_string.clone());
            as_string
        };

        manifest.entries.push(ManifestEntry {
            path: recorded,
            kind,
            link_target,
        });
    }

    Ok(manifest)
}

/// Maps every installed file to the package that owns it.
///
/// Built once rather than rescanning per file, and shared by conflict
/// detection and by the rollback in [`unpack`], which must never delete a path
/// that belongs to somebody else.
///
/// Files owned by `upgrading` are left out — a version replacing itself owns
/// its own files.
pub fn owned_by_others(
    local: &LocalDb,
    upgrading: Option<&str>,
) -> Result<HashMap<String, String>, ExtractError> {
    let mut owners: HashMap<String, String> = HashMap::new();
    for name in local.packages.keys() {
        if Some(name.as_str()) == upgrading {
            continue;
        }
        // An unreadable file list must not be skipped: doing so would leave
        // that package's files looking unowned, and the conflict they
        // represent would go unreported right before they are overwritten.
        for file in local.files_or_empty(name)? {
            owners.insert(file, name.clone());
        }
    }
    Ok(owners)
}

/// Finds everything in `manifest` that cannot be installed into `root`: files
/// already owned by another package, and entries whose type disagrees with
/// what is on disk.
///
/// This stats `root`, which the owner check alone did not have to. It is the
/// only place a type conflict can be caught while it is still free to abort:
/// once `unpack` starts writing, a refusal leaves a partially installed
/// package behind. Arch's `filesystem` shipping /bin as a symlink onto a root
/// whose /bin is a populated directory is the case that motivated it.
///
/// A file owned by `upgrading` is not a conflict — that is just a version
/// replacing itself.
pub fn find_conflicts(
    manifest: &Manifest,
    local: &LocalDb,
    root: &Path,
    upgrading: Option<&str>,
) -> Result<Vec<ExtractError>, ExtractError> {
    let owners = owned_by_others(local, upgrading)?;

    let mut problems: Vec<ExtractError> = manifest
        .files
        .iter()
        .filter_map(|file| {
            owners.get(file).map(|owner| ExtractError::FileConflict {
                path: file.clone(),
                owner: owner.clone(),
            })
        })
        .collect();

    // What the package being upgraded already owns. A version that turns one
    // of its own directories into a symlink is doing an ordinary upstream
    // migration on its own files, and refusing that would abort every
    // `rvn -Syu` that contained one.
    let mine: std::collections::HashSet<String> = match upgrading {
        Some(name) => local.files_or_empty(name)?.into_iter().collect(),
        None => std::collections::HashSet::new(),
    };
    let owned_by_upgrading = |relative: &str| {
        let bare = relative.trim_end_matches('/');
        mine.contains(bare) || mine.contains(&format!("{bare}/"))
    };

    for entry in &manifest.entries {
        let destination = root.join(entry.path.trim_end_matches('/'));

        // A directory over a directory is the ordinary case, and a file
        // landing on a file is what the owner check above already covers --
        // but a directory entry landing on a regular file is neither, and
        // `create_dir_all` would only discover it mid-write.
        if entry.kind == EntryKind::Dir {
            if let Ok(meta) = std::fs::symlink_metadata(&destination)
                && !meta.file_type().is_dir()
                && !destination.is_dir()
            {
                problems.push(ExtractError::TypeConflict {
                    path: entry.path.clone(),
                    wanted: "a directory".to_string(),
                    found: describe_existing(&destination).unwrap_or_else(|| "a file".into()),
                });
            }
            problems.extend(blocked_ancestor(&entry.path, root, &owners));
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&destination) else {
            // Nothing is in the way here, but something may be in the way of
            // the parents that have to be created to reach it.
            problems.extend(blocked_ancestor(&entry.path, root, &owners));
            continue;
        };
        // Only a *real* directory is a type conflict. A symlink where the
        // package wants a symlink, or a file where it wants a file, is simply
        // replaced — and `symlink_metadata` is what keeps an already-correct
        // usrmerge link from reading as the directory it points at.
        if !meta.file_type().is_dir() {
            continue;
        }
        if owned_by_upgrading(&entry.path) {
            continue;
        }
        // An empty directory can be swapped for the entry without losing
        // anything, so only a populated one is fatal. An unreadable directory
        // fails closed and counts as populated.
        if std::fs::read_dir(&destination).map(|d| d.count()).unwrap_or(1) == 0 {
            // Empty, but not necessarily unowned. The local database spells a
            // directory with a trailing slash, so the plain lookup above --
            // keyed on the symlink's own spelling -- cannot see it, and
            // `unpack` would quietly delete another package's directory and
            // claim the path.
            let bare = entry.path.trim_end_matches('/');
            if let Some(owner) = owners.get(&format!("{bare}/")) {
                problems.push(ExtractError::FileConflict {
                    path: entry.path.clone(),
                    owner: owner.clone(),
                });
            }
            continue;
        }
        problems.push(ExtractError::TypeConflict {
            path: entry.path.clone(),
            wanted: describe_wanted(entry),
            found: describe_existing(&destination).unwrap_or_else(|| "a directory".into()),
        });
    }

    Ok(problems)
}

/// Reports a non-directory sitting where one of `relative`'s parents has to be
/// created.
///
/// Without this the failure surfaces mid-write as `creating directory
/// /opt/thing: File exists (os error 17)`, after everything earlier in the
/// archive has already landed. The rollback would undo it, but a conflict that
/// can be seen before the first byte is written belongs in the pre-flight.
fn blocked_ancestor(
    relative: &str,
    root: &Path,
    owners: &HashMap<String, String>,
) -> Option<ExtractError> {
    let path = Path::new(relative.trim_end_matches('/'));
    let mut prefix = PathBuf::new();

    for parent in path.parent()?.components() {
        prefix.push(parent.as_os_str());
        let absolute = root.join(&prefix);
        // `symlink_metadata`, so a dangling link is caught rather than read as
        // the directory it fails to point at.
        let Ok(meta) = std::fs::symlink_metadata(&absolute) else {
            // Nothing here yet, so nothing below it can be blocked either.
            return None;
        };
        // A symlink to a directory is how a usrmerge root spells /lib, and
        // `create_dir_all` is happy with it.
        if meta.file_type().is_dir() || absolute.is_dir() {
            continue;
        }
        let spelling = prefix.to_string_lossy().to_string();
        return Some(match owners.get(&spelling) {
            Some(owner) => ExtractError::FileConflict {
                path: spelling,
                owner: owner.clone(),
            },
            None => ExtractError::TypeConflict {
                path: spelling,
                wanted: "a directory".to_string(),
                found: describe_existing(&absolute).unwrap_or_else(|| "a file".into()),
            },
        });
    }
    None
}

/// A path this run brought into being, remembered so a failure part-way
/// through can undo it.
///
/// Only paths that did not exist beforehand are recorded: rvn keeps no copy of
/// an overwritten file, so deleting one on the way out would turn a failed
/// install into data loss.
struct Created {
    absolute: PathBuf,
    /// Root-relative, so ownership can be looked up without re-deriving it.
    relative: String,
    is_dir: bool,
    /// Set when this entry replaced an empty directory. The path existed
    /// before the run, so it would otherwise not be recorded at all -- and the
    /// rollback would leave behind a type change nobody asked for and nobody
    /// owns.
    replaced_empty_dir: bool,
}

/// Unpacks an archive into `root`, returning the installed file list.
///
/// `on_file` is called for each extracted entry so callers can drive progress.
///
/// `foreign` maps root-relative paths to the package that owns them, as
/// [`owned_by_others`] builds it, and is here so the rollback below can refuse
/// to touch another package's files.
///
/// Nothing this run *creates* survives a failure. An error at entry 900 of
/// 1000 used to leave those 900 files on disk, owned by nothing and recorded
/// nowhere; now they are removed and the original error is returned unchanged.
///
/// What this is not is a transaction. A file the package overwrites is gone
/// the moment it is written, and rvn keeps no copy to restore -- so a failed
/// upgrade still leaves every file replaced before the failing entry at its
/// new version. That was true before the rollback existed and is unchanged by
/// it; undoing it needs the overwritten contents saved somewhere first.
pub fn unpack(
    archive_path: &Path,
    root: &Path,
    foreign: &HashMap<String, String>,
    on_file: impl FnMut(&str),
) -> Result<Vec<String>, ExtractError> {
    let mut created = Vec::new();
    match extract_entries(archive_path, root, &mut created, on_file) {
        Ok(installed) => Ok(installed),
        Err(err) => {
            roll_back(created, foreign);
            Err(err)
        }
    }
}

/// Removes what a failed extraction wrote, and only that.
fn roll_back(mut created: Vec<Created>, foreign: &HashMap<String, String>) {
    // Files first, then directories from the deepest upward: a directory only
    // comes off once whatever this run put inside it is gone.
    created.sort_by_key(|c| {
        (
            c.is_dir,
            std::cmp::Reverse(c.absolute.components().count()),
        )
    });

    for entry in created {
        // Belt and braces. A path another package owns is on disk already, so
        // it never gets recorded as created -- and in the one case where it is
        // *not* on disk, `find_conflicts` refuses the install before `unpack`
        // is ever reached.
        // A directory is spelled with a trailing slash in the local database
        // but without one here, so both spellings have to be tried or the
        // guard is inert for exactly the entries it most needs to protect.
        if foreign.contains_key(&entry.relative)
            || foreign.contains_key(&format!("{}/", entry.relative.trim_end_matches('/')))
        {
            continue;
        }
        // The rollback runs while an error is already on its way out; a path
        // that will not come off must not replace or hide it.
        let _ = if entry.is_dir {
            // `remove_dir`, never `remove_dir_all`: anything that appeared
            // inside and was not written by this run is not ours to delete.
            std::fs::remove_dir(&entry.absolute)
        } else {
            std::fs::remove_file(&entry.absolute)
        };

        // The empty directory this entry displaced was on disk before the run
        // and has to go back, or a failed install has silently changed the
        // type of a path it does not own.
        if entry.replaced_empty_dir {
            let _ = std::fs::create_dir(&entry.absolute);
        }
    }
}

/// Creates `path` and any missing parents, recording each directory this run
/// actually brings into being.
///
/// `create_dir_all` reports only that *something* already exists, never which
/// component, so the missing ancestors are noted before it runs. Directories
/// that were already there are deliberately not recorded: a package that fails
/// must not take /usr with it.
fn create_dirs(path: &Path, root: &Path, created: &mut Vec<Created>) -> Result<(), ExtractError> {
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cursor = Some(path);
    while let Some(current) = cursor {
        // `exists` follows symlinks on purpose: on a usrmerge root /lib is a
        // link to usr/lib and the directory is already there, which is exactly
        // how `create_dir_all` sees it too.
        if current == root || current.exists() {
            break;
        }
        missing.push(current.to_path_buf());
        cursor = current.parent();
    }

    // This succeeds over a symlink to an existing directory, so re-installing
    // the same package onto a usrmerge root is a no-op. A dangling symlink or
    // a plain file at that path is not -- and that failure now names the path
    // and the operation instead of reading "File exists (os error 17)".
    std::fs::create_dir_all(path).map_err(io_error("creating directory", path))?;

    for dir in missing {
        let relative = dir
            .strip_prefix(root)
            .unwrap_or(&dir)
            .to_string_lossy()
            .to_string();
        created.push(Created {
            absolute: dir,
            relative,
            is_dir: true,
            replaced_empty_dir: false,
        });
    }
    Ok(())
}

/// The extraction itself. Split out from [`unpack`] so that every `?` in it is
/// caught in one place and handed to the rollback.
fn extract_entries(
    archive_path: &Path,
    root: &Path,
    created: &mut Vec<Created>,
    mut on_file: impl FnMut(&str),
) -> Result<Vec<String>, ExtractError> {
    let mut archive = tar::Archive::new(open_archive(archive_path)?);
    archive.set_overwrite(true);
    archive.set_preserve_permissions(true);

    let mut installed = Vec::new();
    // (link path, target path), both root-relative.
    let mut deferred_links: Vec<(PathBuf, PathBuf)> = Vec::new();
    // Symlink and directory timestamps, applied at the end. `Entry::unpack`
    // restores mtime for regular files, but not for these — and pacman's
    // `-Qkk` reports the difference as an altered file.
    let mut deferred_times: Vec<(PathBuf, u64, bool)> = Vec::new();

    for entry in archive
        .entries()
        .map_err(io_error("reading", archive_path))?
    {
        let mut entry = entry.map_err(io_error("reading", archive_path))?;
        let entry_path = entry
            .path()
            .map_err(io_error("reading an entry name in", archive_path))?
            .to_path_buf();

        if is_metadata(&entry_path) {
            continue;
        }

        let relative = safe_relative(&entry_path)?;
        let destination = root.join(&relative);
        let as_string = relative.to_string_lossy().to_string();

        if let Some(parent) = destination.parent() {
            create_dirs(parent, root, created)?;
        }

        let kind = entry.header().entry_type();

        if kind.is_dir() {
            create_dirs(&destination, root, created)?;
            deferred_times.push((destination.clone(), entry.header().mtime().unwrap_or(0), true));
            // Recorded with a trailing slash, as pacman does, so removal can
            // prune directories a package created but never filled.
            installed.push(format!("{as_string}/"));
            continue;
        }

        // Links must be recreated by hand. `Entry::unpack` resolves a link
        // target relative to the process's working directory, which would
        // either fail or — worse — point outside the install root.
        if kind.is_hard_link() || kind.is_symlink() {
            let target = entry
                .link_name()
                .map_err(io_error("reading the link target of", &destination))?
                .ok_or_else(|| {
                    ExtractError::UnsafePath(format!("{} has no link target", relative.display()))
                })?
                .to_path_buf();

            if kind.is_hard_link() {
                // Deferred: an archive may reference a target that appears
                // later, and the target must exist before `link` is called.
                let source = safe_relative(&target)?;
                deferred_links.push((relative.clone(), source));
                // Counted when the link is actually created, below.
                continue;
            } else {
                // Symlink targets are stored verbatim and may legitimately be
                // relative or absolute; they are resolved at use time inside
                // the installed root.

                // The link this package wants is already the link on disk, so
                // re-installing it must not churn the inode, and must not open
                // a window in which the link is missing.
                if std::fs::read_link(&destination).is_ok_and(|current| current == target) {
                    // Still stamped: `pacman -Qkk` compares a symlink's mtime
                    // against the `.MTREE`, so a link left at the timestamp
                    // some earlier rootfs gave it reads as altered even though
                    // its target is exactly right.
                    deferred_times.push((
                        destination.clone(),
                        entry.header().mtime().unwrap_or(0),
                        false,
                    ));
                    on_file(&as_string);
                    installed.push(as_string);
                    // Deliberately not recorded as created: this run did not
                    // make it, so a rollback must leave it alone.
                    continue;
                }

                let existed = std::fs::symlink_metadata(&destination).is_ok();
                // An empty directory has nothing to lose, so it gives way to
                // the link -- which is exactly what `find_conflicts` promised
                // by refusing only a populated one. `remove_file` cannot take
                // a directory, so this needs its own call.
                let replaced_empty_dir = std::fs::remove_dir(&destination).is_ok();
                let _ = std::fs::remove_file(&destination);
                if let Err(err) = std::os::unix::fs::symlink(&target, &destination) {
                    // `remove_file` cannot take a directory, so a package
                    // symlink aimed at an existing real directory lands here.
                    // Arch's `filesystem` package does exactly this: it ships
                    // /bin, /lib and /sbin as usrmerge symlinks, and a
                    // split-usr root's are real, populated directories.
                    //
                    // `find_conflicts` already refuses that before a byte is
                    // written; reaching it here means the directory appeared
                    // during the transaction. Converting a live directory into
                    // a symlink is a migration, not an extraction, so it is
                    // refused in both places rather than being skipped in one
                    // and rejected in the other.
                    let existing_dir = err.kind() == std::io::ErrorKind::AlreadyExists
                        && std::fs::symlink_metadata(&destination)
                            .is_ok_and(|meta| meta.is_dir());
                    if existing_dir {
                        return Err(ExtractError::TypeConflict {
                            path: as_string.clone(),
                            wanted: format!("a symlink to {}", target.display()),
                            found: describe_existing(&destination)
                                .unwrap_or_else(|| "a directory".into()),
                        });
                    }
                    return Err(ExtractError::LinkFailed {
                        path: relative.to_string_lossy().to_string(),
                        target: target.to_string_lossy().to_string(),
                        reason: err.to_string(),
                    });
                }
                if !existed || replaced_empty_dir {
                    created.push(Created {
                        absolute: destination.clone(),
                        relative: as_string.clone(),
                        is_dir: false,
                        replaced_empty_dir,
                    });
                }
                deferred_times.push((
                    destination.clone(),
                    entry.header().mtime().unwrap_or(0),
                    false,
                ));
            }
        } else {
            // Explicit remove-then-create rather than trusting the archive's
            // overwrite flag. `Entry::unpack` unlinks only when its own
            // `create_new` reports AlreadyExists, and phrases whatever goes
            // wrong as "failed to unpack X into Y" -- which names neither the
            // operation that failed nor, usefully, what was in the way. The
            // case that matters is a directory sitting where a file belongs:
            // the unlink fails with "Is a directory", and that is a type
            // conflict, not an io error.
            let existing = std::fs::symlink_metadata(&destination).ok();
            if let Some(meta) = &existing {
                if meta.file_type().is_dir() {
                    return Err(ExtractError::TypeConflict {
                        path: as_string.clone(),
                        wanted: EntryKind::from_header(kind).describe().to_string(),
                        found: describe_existing(&destination)
                            .unwrap_or_else(|| "a directory".into()),
                    });
                }
                std::fs::remove_file(&destination).map_err(io_error("replacing", &destination))?;
            }
            entry
                .unpack(&destination)
                .map_err(io_error("writing", &destination))?;
            if existing.is_none() {
                created.push(Created {
                    absolute: destination.clone(),
                    relative: as_string.clone(),
                    is_dir: false,
                    replaced_empty_dir: false,
                });
            }
        }

        on_file(&as_string);
        installed.push(as_string);
    }

    // Second pass: every regular file now exists, so hard links can resolve
    // regardless of the order they appeared in the archive.
    for (link, target) in deferred_links {
        let destination = root.join(&link);
        let source = root.join(&target);
        let as_string = link.to_string_lossy().to_string();

        // On a case-insensitive filesystem the link and its target can name
        // the same file (`terminfo/l/lft-pc850` and `terminfo/L/LFT-PC850`).
        // Removing the destination would then destroy the source, so treat
        // the link as already satisfied.
        if same_file(&source, &destination) {
            on_file(&as_string);
            installed.push(as_string);
            continue;
        }

        let existed = std::fs::symlink_metadata(&destination).is_ok();
        let _ = std::fs::remove_file(&destination);

        if let Err(e) = std::fs::hard_link(&source, &destination) {
            // Some filesystems refuse cross-device or case-colliding links.
            // A copy preserves the package's contents, which matters more
            // than the inode being shared.
            std::fs::copy(&source, &destination).map_err(|_| ExtractError::LinkFailed {
                path: link.display().to_string(),
                target: target.display().to_string(),
                reason: e.to_string(),
            })?;
        }

        if !existed {
            created.push(Created {
                absolute: destination,
                relative: as_string.clone(),
                is_dir: false,
                replaced_empty_dir: false,
            });
        }

        on_file(&as_string);
        installed.push(as_string);
    }

    apply_timestamps(deferred_times);

    Ok(installed)
}

/// Restores mtimes on symlinks and directories.
///
/// Directories are done deepest-first: writing a child updates its parent's
/// mtime, so parents must be stamped after everything inside them.
fn apply_timestamps(mut entries: Vec<(PathBuf, u64, bool)>) {
    entries.sort_by_key(|(path, _, is_dir)| {
        // Symlinks first, then directories from the deepest upward.
        (*is_dir, std::cmp::Reverse(path.components().count()))
    });

    for (path, mtime, is_dir) in entries {
        if mtime == 0 {
            continue;
        }
        let stamp = FileTime::from_unix_time(mtime as i64, 0);
        // Symlinks must be stamped without following them, or the target's
        // timestamp is changed instead.
        let _ = if is_dir {
            filetime::set_file_times(&path, stamp, stamp)
        } else {
            filetime::set_symlink_file_times(&path, stamp, stamp)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tar(entries: &[(&str, &str, bool)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, body, is_dir) in entries {
            let mut header = tar::Header::new_gnu();
            if *is_dir {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
            } else {
                header.set_size(body.len() as u64);
            }
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, body.as_bytes())
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn write_tar(tag: &str, data: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rvn-extract-{tag}.tar"));
        std::fs::write(&path, data).unwrap();
        path
    }

    /// No other package owns anything in a fixture root, so the rollback has
    /// nothing to protect.
    fn unowned() -> HashMap<String, String> {
        HashMap::new()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-extract-root-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn manifest_lists_files_and_skips_metadata() {
        let tar = build_tar(&[
            (".PKGINFO", "pkgname = demo", false),
            (".MTREE", "binary", false),
            (".INSTALL", "post_install() { :; }", false),
            ("usr/", "", true),
            ("usr/bin/demo", "#!/bin/sh\n", false),
            ("usr/share/doc/demo/README", "hi", false),
        ]);
        let path = write_tar("manifest", &tar);

        let m = manifest(&path).unwrap();
        assert_eq!(m.files.len(), 2);
        assert!(m.files.contains(&"usr/bin/demo".to_string()));
        assert!(m.files.contains(&"usr/share/doc/demo/README".to_string()));
        // Metadata members are recorded but never installed.
        assert!(m.has_install_script);
        assert_eq!(
            m.install_script.as_deref(),
            Some(&b"post_install() { :; }"[..])
        );
        assert!(!m.files.iter().any(|f| f.starts_with('.')));
        assert_eq!(m.directories, vec!["usr/"]);
        assert!(m.total_size > 0);
    }

    /// Hand-builds a ustar header so the fixture can contain a hostile path.
    /// The `tar` crate's builder refuses to write `..` entries, but a real
    /// attacker's archive has no such scruples.
    fn malicious_tar(name: &str, body: &str) -> Vec<u8> {
        let mut header = [0u8; 512];
        let write = |buf: &mut [u8; 512], offset: usize, bytes: &[u8]| {
            buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        };

        write(&mut header, 0, name.as_bytes());
        write(&mut header, 100, b"0000644\0");
        write(&mut header, 108, b"0000000\0");
        write(&mut header, 116, b"0000000\0");
        write(&mut header, 124, format!("{:011o}\0", body.len()).as_bytes());
        write(&mut header, 136, b"00000000000\0");
        header[156] = b'0'; // Regular file.
        write(&mut header, 257, b"ustar\0");
        write(&mut header, 263, b"00");

        // Checksum is computed with the checksum field itself read as spaces.
        for byte in header.iter_mut().skip(148).take(8) {
            *byte = b' ';
        }
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        write(&mut header, 148, format!("{sum:06o}\0 ").as_bytes());

        let mut out = header.to_vec();
        let mut block = body.as_bytes().to_vec();
        block.resize(block.len().div_ceil(512) * 512, 0);
        out.extend_from_slice(&block);
        out.extend_from_slice(&[0u8; 1024]); // End-of-archive marker.
        out
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        let tar = malicious_tar("../../etc/passwd", "root::0:0");
        let path = write_tar("traversal", &tar);
        let err = manifest(&path).unwrap_err();
        assert!(
            matches!(err, ExtractError::UnsafePath(_)),
            "escaping path must be rejected, got {err:?}"
        );
    }

    #[test]
    fn unpack_refuses_to_write_outside_the_root() {
        let tar = malicious_tar("../escaped.txt", "pwned");
        let archive = write_tar("traversal-unpack", &tar);
        let root = temp_dir("traversal-unpack");

        let err = unpack(&archive, &root, &unowned(), |_| {}).unwrap_err();
        assert!(matches!(err, ExtractError::UnsafePath(_)));
        // Nothing may have been written next to the root either.
        assert!(!root.parent().unwrap().join("escaped.txt").exists());
    }

    #[test]
    fn rejects_absolute_paths() {
        // tar normalises a leading slash away, so assert on the checker itself.
        let err = safe_relative(Path::new("/etc/shadow")).unwrap_err();
        assert!(matches!(err, ExtractError::UnsafePath(_)));
        assert!(safe_relative(Path::new("usr/bin/demo")).is_ok());
        assert!(safe_relative(Path::new("./usr/bin/demo")).is_ok());
        assert!(safe_relative(Path::new("usr/../../etc")).is_err());
    }

    #[test]
    fn unpacks_into_the_root_and_reports_files() {
        let tar = build_tar(&[
            (".PKGINFO", "pkgname = demo", false),
            ("usr/bin/demo", "#!/bin/sh\necho hi\n", false),
            ("etc/demo.conf", "key=value\n", false),
        ]);
        let archive = write_tar("unpack", &tar);
        let root = temp_dir("unpack");

        let mut seen = Vec::new();
        let files = unpack(&archive, &root, &unowned(), |f| seen.push(f.to_string())).unwrap();

        assert_eq!(files.len(), 2);
        assert_eq!(seen.len(), 2);
        assert!(root.join("usr/bin/demo").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("etc/demo.conf")).unwrap(),
            "key=value\n"
        );
        // Metadata must not land on the filesystem.
        assert!(!root.join(".PKGINFO").exists());
    }

    /// Appends a link entry, which `tar::Builder` has no helper for.
    fn link_entry(
        builder: &mut tar::Builder<Vec<u8>>,
        path: &str,
        target: &str,
        kind: tar::EntryType,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name(target).unwrap();
        header.set_cksum();
        builder.append_data(&mut header, path, &[][..]).unwrap();
    }

    #[test]
    fn recreates_hard_links_inside_the_root() {
        let mut builder = tar::Builder::new(Vec::new());
        let body = "UTC data";
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/share/zoneinfo/Abidjan", body.as_bytes())
            .unwrap();
        link_entry(
            &mut builder,
            "usr/share/zoneinfo/Accra",
            "usr/share/zoneinfo/Abidjan",
            tar::EntryType::Link,
        );
        let archive = write_tar("hardlink", &builder.into_inner().unwrap());
        let root = temp_dir("hardlink");

        let files = unpack(&archive, &root, &unowned(), |_| {}).unwrap();
        assert_eq!(files.len(), 2, "the link counts as an installed file");

        let linked = root.join("usr/share/zoneinfo/Accra");
        assert!(linked.exists(), "hard link must be created");
        // The link must point at the copy inside the root, with real content.
        assert_eq!(std::fs::read_to_string(&linked).unwrap(), body);
    }

    #[test]
    fn restores_symlink_and_directory_timestamps() {
        const STAMP: u64 = 1_700_000_000;

        let mut builder = tar::Builder::new(Vec::new());
        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_mtime(STAMP);
        dir_header.set_cksum();
        builder.append_data(&mut dir_header, "usr/lib/", &[][..]).unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_size(0);
        link_header.set_mode(0o777);
        link_header.set_mtime(STAMP);
        link_header.set_link_name("libfoo.so.1").unwrap();
        link_header.set_cksum();
        builder
            .append_data(&mut link_header, "usr/lib/libfoo.so", &[][..])
            .unwrap();

        let archive = write_tar("mtime", &builder.into_inner().unwrap());
        let root = temp_dir("mtime");
        unpack(&archive, &root, &unowned(), |_| {}).unwrap();

        // The symlink's own timestamp, not its target's.
        let link_meta = std::fs::symlink_metadata(root.join("usr/lib/libfoo.so")).unwrap();
        assert_eq!(
            FileTime::from_last_modification_time(&link_meta).unix_seconds(),
            STAMP as i64
        );

        let dir_meta = std::fs::metadata(root.join("usr/lib")).unwrap();
        assert_eq!(
            FileTime::from_last_modification_time(&dir_meta).unix_seconds(),
            STAMP as i64
        );
    }

    #[test]
    fn recreates_symlinks_verbatim() {
        let mut builder = tar::Builder::new(Vec::new());
        link_entry(
            &mut builder,
            "usr/bin/sh",
            "bash",
            tar::EntryType::Symlink,
        );
        let archive = write_tar("symlink", &builder.into_inner().unwrap());
        let root = temp_dir("symlink");

        let files = unpack(&archive, &root, &unowned(), |_| {}).unwrap();
        assert_eq!(files, vec!["usr/bin/sh"]);

        let link = root.join("usr/bin/sh");
        let target = std::fs::read_link(&link).unwrap();
        // The target is stored as-is; it resolves inside the installed root.
        assert_eq!(target, PathBuf::from("bash"));
    }

    #[test]
    fn symlink_over_a_populated_directory_is_refused_not_skipped() {
        // Arch's `filesystem` package ships /bin as a usrmerge symlink to
        // usr/bin. On a root whose /bin is a real, populated directory --
        // a split-usr one -- honouring that entry would replace the directory
        // holding the userland with a link.
        //
        // `find_conflicts` refuses that before a byte is written. This asserts
        // the same answer from `unpack`, which is only reached if the
        // directory appeared during the transaction: one policy, so a package
        // cannot be quietly half-installed by one path and rejected by the
        // other. Converting the root is `scripts/usrmerge-rootfs.sh`'s job.
        let mut builder = tar::Builder::new(Vec::new());
        link_entry(&mut builder, "bin", "usr/bin", tar::EntryType::Symlink);
        let mut header = tar::Header::new_gnu();
        header.set_path("etc/issue").unwrap();
        header.set_size(6);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &b"raven\n"[..]).unwrap();
        let archive = write_tar("dir-collision", &builder.into_inner().unwrap());
        let root = temp_dir("dir-collision");

        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/sh"), b"#!").unwrap();

        let error = unpack(&archive, &root, &unowned(), |_| {}).unwrap_err();
        assert!(
            matches!(&error, ExtractError::TypeConflict { path, .. } if path == "bin"),
            "got {error:?}"
        );
        // The message has to name the path, what was wanted and what is there.
        let rendered = error.to_string();
        assert!(rendered.contains("bin"), "{rendered}");
        assert!(rendered.contains("a symlink to usr/bin"), "{rendered}");
        assert!(rendered.contains("a directory with 1 entry"), "{rendered}");

        // The directory is untouched, and the rollback took the rest with it.
        assert!(std::fs::symlink_metadata(root.join("bin")).unwrap().is_dir());
        assert!(root.join("bin/sh").exists());
        assert!(
            !root.join("etc/issue").exists(),
            "a refused package must leave nothing behind"
        );
    }

    /// The pre-flight must reach the same verdict, so the refusal happens
    /// before anything is written rather than being undone afterwards.
    #[test]
    fn the_preflight_refuses_a_symlink_over_a_populated_directory() {
        let mut builder = tar::Builder::new(Vec::new());
        link_entry(&mut builder, "bin", "usr/bin", tar::EntryType::Symlink);
        let archive = write_tar("dir-collision-preflight", &builder.into_inner().unwrap());
        let root = temp_dir("dir-collision-preflight");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/sh"), b"#!").unwrap();

        let manifest = manifest(&archive).unwrap();
        let local = LocalDb::default();
        let problems = find_conflicts(&manifest, &local, &root, None).unwrap();

        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            matches!(&problems[0], ExtractError::TypeConflict { path, .. } if path == "bin"),
            "{problems:?}"
        );
    }

    #[test]
    fn hard_link_escaping_the_root_is_rejected() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o777);
        // A link target outside the archive must not be followed.
        header.set_link_name("../../../etc/shadow").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/bin/evil", &[][..])
            .unwrap();
        let archive = write_tar("hardlink-escape", &builder.into_inner().unwrap());
        let root = temp_dir("hardlink-escape");

        let err = unpack(&archive, &root, &unowned(), |_| {}).unwrap_err();
        assert!(matches!(err, ExtractError::UnsafePath(_)));
    }

    #[test]
    fn same_file_is_false_for_distinct_paths() {
        let dir = temp_dir("same-file");
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "x").unwrap();

        assert!(same_file(&a, &a));
        assert!(!same_file(&a, &b));
        // A path that does not exist can never be the same file.
        assert!(!same_file(&a, &dir.join("missing")));
    }

    #[test]
    fn reads_backup_paths_from_pkginfo() {
        let pkginfo = "# Generated by makepkg\n\
                       pkgname = demo\n\
                       pkgver = 1.0-1\n\
                       backup = etc/demo.conf\n\
                       backup = etc/demo.d/extra.conf\n\
                       depend = glibc\n";
        let tar = build_tar(&[
            (".PKGINFO", pkginfo, false),
            ("etc/demo.conf", "key=value\n", false),
        ]);
        let path = write_tar("pkginfo", &tar);

        let m = manifest(&path).unwrap();
        assert_eq!(m.backup, vec!["etc/demo.conf", "etc/demo.d/extra.conf"]);
        // .PKGINFO is authoritative for dependencies.
        assert_eq!(m.depends, vec!["glibc"]);
        // .PKGINFO itself is still never installed.
        assert_eq!(m.files, vec!["etc/demo.conf"]);
    }

    #[test]
    fn pkginfo_without_backup_entries_yields_none() {
        let entries = parse_pkginfo_field("pkgname = demo\ndepend = glibc\n", "backup");
        assert!(entries.is_empty());
        // Comments and blank lines must not confuse the parser.
        assert!(parse_pkginfo_field("# backup = fake\n\n", "backup").is_empty());
    }

    #[test]
    fn pkginfo_fields_are_all_captured() {
        let pkginfo = "pkgname = demo\n\
                       pkgver = 1.2.3-1\n\
                       pkgdesc = A demo package\n\
                       url = https://example.com\n\
                       builddate = 1700000000\n\
                       packager = Someone <a@b.c>\n\
                       size = 123456\n\
                       arch = any\n\
                       license = MIT\n\
                       depend = glibc\n\
                       depend = pcre2\n";
        let tar = build_tar(&[
            (".PKGINFO", pkginfo, false),
            ("usr/bin/demo", "x", false),
        ]);
        let path = write_tar("pkginfo-full", &tar);
        let m = manifest(&path).unwrap();

        assert_eq!(m.pkginfo.get("size").unwrap(), &["123456"]);
        assert_eq!(m.pkginfo.get("arch").unwrap(), &["any"]);
        assert_eq!(m.pkginfo.get("pkgver").unwrap(), &["1.2.3-1"]);
        assert_eq!(m.pkginfo.get("depend").unwrap().len(), 2);
        // The convenience views stay in agreement with the map.
        assert_eq!(m.depends, vec!["glibc", "pcre2"]);
    }

    #[test]
    fn mtree_is_captured_for_the_local_database() {
        let tar = build_tar(&[
            (".MTREE", "#mtree binary-ish payload", false),
            ("usr/bin/demo", "x", false),
        ]);
        let path = write_tar("mtree", &tar);
        let m = manifest(&path).unwrap();
        assert_eq!(m.mtree.as_deref(), Some(&b"#mtree binary-ish payload"[..]));
        // It must not be installed onto the filesystem.
        assert_eq!(m.files, vec!["usr/bin/demo"]);
    }

    #[test]
    fn directories_are_recorded_with_a_trailing_slash() {
        let tar = build_tar(&[
            ("usr/", "", true),
            ("usr/bin/", "", true),
            ("usr/bin/demo", "#!/bin/sh\n", false),
        ]);
        let archive = write_tar("dirs", &tar);
        let root = temp_dir("dirs");

        let files = unpack(&archive, &root, &unowned(), |_| {}).unwrap();
        assert!(files.contains(&"usr/".to_string()));
        assert!(files.contains(&"usr/bin/".to_string()));
        assert!(files.contains(&"usr/bin/demo".to_string()));

        // The manifest keeps them separate, so a shared directory is never
        // reported as a file conflict.
        let m = manifest(&archive).unwrap();
        assert_eq!(m.files, vec!["usr/bin/demo"]);
        assert_eq!(m.directories, vec!["usr/", "usr/bin/"]);
    }

    /// Compresses a tar with the given external-format writer and returns the
    /// path, so each supported container is exercised end to end.
    fn write_compressed(tag: &str, ext: &str, tar: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rvn-extract-{tag}.tar.{ext}"));
        let out = std::fs::File::create(&path).unwrap();
        match ext {
            "xz" => {
                let mut enc = liblzma::write::XzEncoder::new(out, 1);
                std::io::Write::write_all(&mut enc, tar).unwrap();
                enc.finish().unwrap();
            }
            "gz" => {
                let mut enc =
                    flate2::write::GzEncoder::new(out, flate2::Compression::fast());
                std::io::Write::write_all(&mut enc, tar).unwrap();
                enc.finish().unwrap();
            }
            "bz2" => {
                let mut enc = bzip2::write::BzEncoder::new(out, bzip2::Compression::fast());
                std::io::Write::write_all(&mut enc, tar).unwrap();
                enc.finish().unwrap();
            }
            other => panic!("unhandled format {other}"),
        }
        path
    }

    #[test]
    fn reads_every_supported_container_format() {
        let tar = build_tar(&[
            (".PKGINFO", "pkgname = demo", false),
            ("usr/bin/demo", "#!/bin/sh\n", false),
        ]);

        for ext in ["xz", "gz", "bz2"] {
            let path = write_compressed(&format!("fmt-{ext}"), ext, &tar);
            let m = manifest(&path)
                .unwrap_or_else(|e| panic!("{ext} manifest failed: {e}"));
            assert_eq!(m.files, vec!["usr/bin/demo"], "format {ext}");

            let root = temp_dir(&format!("fmt-{ext}"));
            let files = unpack(&path, &root, &unowned(), |_| {}).unwrap();
            assert_eq!(files, vec!["usr/bin/demo"], "format {ext}");
            assert!(root.join("usr/bin/demo").exists(), "format {ext}");
        }
    }

    #[test]
    fn unsupported_extension_is_rejected() {
        let path = std::env::temp_dir().join("rvn-extract-bogus.rar");
        std::fs::write(&path, b"nope").unwrap();
        assert!(matches!(
            manifest(&path).unwrap_err(),
            ExtractError::UnsupportedFormat(_)
        ));
    }

    /// Appends a regular file, so a fixture can mix files with links.
    fn file_entry(builder: &mut tar::Builder<Vec<u8>>, path: &str, body: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, body.as_bytes())
            .unwrap();
    }

    /// An archive shipping `bin` as a usrmerge symlink to `usr/bin`, plus one
    /// ordinary file — the shape of Arch's `filesystem` package.
    fn usrmerge_archive(tag: &str) -> PathBuf {
        let mut builder = tar::Builder::new(Vec::new());
        link_entry(&mut builder, "bin", "usr/bin", tar::EntryType::Symlink);
        file_entry(&mut builder, "etc/issue", "raven\n");
        write_tar(tag, &builder.into_inner().unwrap())
    }

    #[test]
    fn the_manifest_records_what_each_entry_is() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.set_cksum();
        builder.append_data(&mut dir, "usr/bin/", &[][..]).unwrap();
        file_entry(&mut builder, "usr/bin/demo", "#!/bin/sh\n");
        link_entry(&mut builder, "usr/bin/sh", "bash", tar::EntryType::Symlink);
        link_entry(
            &mut builder,
            "usr/bin/copy",
            "usr/bin/demo",
            tar::EntryType::Link,
        );
        let archive = write_tar("entry-kinds", &builder.into_inner().unwrap());

        let m = manifest(&archive).unwrap();
        let kinds: Vec<(&str, EntryKind)> = m
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("usr/bin/", EntryKind::Dir),
                ("usr/bin/demo", EntryKind::File),
                ("usr/bin/sh", EntryKind::Symlink),
                ("usr/bin/copy", EntryKind::HardLink),
            ]
        );
        // The target is kept so a conflict can say what the link would be.
        assert_eq!(m.entries[2].link_target.as_deref(), Some("bash"));
        assert_eq!(m.entries[3].link_target.as_deref(), Some("usr/bin/demo"));
        assert_eq!(m.entries[1].link_target, None);

        // The path lists are unchanged views onto the same entries.
        assert_eq!(m.files, vec!["usr/bin/demo", "usr/bin/sh", "usr/bin/copy"]);
        assert_eq!(m.directories, vec!["usr/bin/"]);
    }

    #[test]
    fn a_symlink_over_a_populated_directory_is_refused_before_anything_is_written() {
        // The failure this whole path exists for: Arch's `filesystem` ships
        // /bin as a symlink to usr/bin, and this distribution's /bin is a real
        // directory holding the userland. Extraction used to find that out at
        // write time -- `remove_file` silently failing on a directory, then
        // `symlink` returning EEXIST with no path in the message -- by which
        // point part of the package was already on disk. Refusing costs
        // nothing before the first byte is written.
        let archive = usrmerge_archive("type-conflict");
        let root = temp_dir("type-conflict");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/sh"), b"#!").unwrap();

        let local = LocalDb::load(&temp_dir("type-conflict-db"));
        let m = manifest(&archive).unwrap();
        let conflicts = find_conflicts(&m, &local, &root, None).unwrap();

        assert_eq!(conflicts.len(), 1, "got {conflicts:?}");
        assert!(matches!(conflicts[0], ExtractError::TypeConflict { .. }));
        // The message names the path, what the package wanted, and what is in
        // the way -- all three were missing from the original EEXIST.
        assert_eq!(
            conflicts[0].to_string(),
            "bin would be a symlink to usr/bin, but a directory with 1 entry is already there"
        );

        // Nothing may have been written, moved or removed by looking.
        assert!(std::fs::symlink_metadata(root.join("bin")).unwrap().is_dir());
        assert_eq!(std::fs::read_to_string(root.join("bin/sh")).unwrap(), "#!");
        assert!(!root.join("etc").exists(), "the install must not have begun");
    }

    #[test]
    fn a_symlink_matching_the_disk_or_over_an_empty_directory_is_not_a_conflict() {
        let archive = usrmerge_archive("no-type-conflict");
        let m = manifest(&archive).unwrap();
        let local = LocalDb::load(&temp_dir("no-type-conflict-db"));

        // Already the link the package ships: re-installing must be silent.
        let merged = temp_dir("no-type-conflict-merged");
        std::fs::create_dir_all(merged.join("usr/bin")).unwrap();
        std::os::unix::fs::symlink("usr/bin", merged.join("bin")).unwrap();
        assert!(find_conflicts(&m, &local, &merged, None).unwrap().is_empty());

        // An empty directory has nothing to lose, so the link may replace it.
        let empty = temp_dir("no-type-conflict-empty");
        std::fs::create_dir_all(empty.join("bin")).unwrap();
        assert!(find_conflicts(&m, &local, &empty, None).unwrap().is_empty());
        // ...and extraction agrees, rather than skipping the entry.
        unpack(&archive, &empty, &unowned(), |_| {}).unwrap();
        assert_eq!(
            std::fs::read_link(empty.join("bin")).unwrap(),
            PathBuf::from("usr/bin")
        );
    }

    #[test]
    fn unpacking_the_same_archive_twice_succeeds_and_changes_nothing() {
        use std::os::unix::fs::MetadataExt;

        let mut builder = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        dir.set_cksum();
        builder.append_data(&mut dir, "usr/lib/", &[][..]).unwrap();
        file_entry(&mut builder, "usr/bin/demo", "#!/bin/sh\n");
        link_entry(
            &mut builder,
            "usr/lib/libfoo.so",
            "libfoo.so.1",
            tar::EntryType::Symlink,
        );
        let archive = write_tar("idempotent", &builder.into_inner().unwrap());
        let root = temp_dir("idempotent");

        let first = unpack(&archive, &root, &unowned(), |_| {}).unwrap();
        let link = root.join("usr/lib/libfoo.so");
        let inode = std::fs::symlink_metadata(&link).unwrap().ino();

        let second = unpack(&archive, &root, &unowned(), |_| {}).unwrap();

        // The same file list, so the local database records the same package.
        assert_eq!(first, second);
        // A link that already points where it should is left alone: recreating
        // it churns the inode and leaves a window with no link at all.
        assert_eq!(
            std::fs::symlink_metadata(&link).unwrap().ino(),
            inode,
            "an unchanged symlink must not be recreated"
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), PathBuf::from("libfoo.so.1"));
        assert_eq!(
            std::fs::read_to_string(root.join("usr/bin/demo")).unwrap(),
            "#!/bin/sh\n"
        );
    }

    #[test]
    fn a_failed_unpack_leaves_no_new_files_behind() {
        // The second entry lands on a populated directory and cannot be
        // written. Everything the first entry created must come back off, or
        // the root keeps files that no package owns and no removal will find.
        let mut builder = tar::Builder::new(Vec::new());
        file_entry(&mut builder, "usr/bin/demo", "#!/bin/sh\n");
        file_entry(&mut builder, "usr/share/doc", "not a directory");
        let archive = write_tar("rollback", &builder.into_inner().unwrap());

        let root = temp_dir("rollback");
        std::fs::create_dir_all(root.join("usr/share/doc")).unwrap();
        std::fs::write(root.join("usr/share/doc/README"), b"docs").unwrap();

        let err = unpack(&archive, &root, &unowned(), |_| {}).unwrap_err();
        assert!(matches!(err, ExtractError::TypeConflict { .. }), "got {err:?}");

        // What this run wrote is gone, directories included.
        assert!(!root.join("usr/bin/demo").exists());
        assert!(!root.join("usr/bin").exists(), "a created directory must be pruned");
        // What was already there is untouched: rvn keeps no copy of it, so
        // undoing must never mean deleting it.
        assert!(root.join("usr").is_dir());
        assert_eq!(
            std::fs::read_to_string(root.join("usr/share/doc/README")).unwrap(),
            "docs"
        );
    }

    #[test]
    fn the_rollback_never_removes_another_packages_file() {
        let root = temp_dir("rollback-owned");
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        let ours = root.join("usr/bin/ours");
        let theirs = root.join("usr/bin/theirs");
        std::fs::write(&ours, "ours").unwrap();
        std::fs::write(&theirs, "theirs").unwrap();

        let mut foreign = HashMap::new();
        foreign.insert("usr/bin/theirs".to_string(), "other".to_string());
        // Spelled the way the local database spells a directory -- with a
        // trailing slash. The guard has to match that, or it protects only the
        // spelling a test happens to hand it.
        foreign.insert("usr/bin/".to_string(), "other".to_string());

        // A path another package owns is on disk already, so it is never
        // recorded as created and should not reach this list at all. The
        // guard is the last line of defence, and it holds.
        roll_back(
            vec![
                Created {
                    absolute: ours.clone(),
                    relative: "usr/bin/ours".into(),
                    is_dir: false,
                    replaced_empty_dir: false,
                },
                Created {
                    absolute: theirs.clone(),
                    relative: "usr/bin/theirs".into(),
                    is_dir: false,
                    replaced_empty_dir: false,
                },
                Created {
                    absolute: root.join("usr/bin"),
                    relative: "usr/bin".into(),
                    is_dir: true,
                    replaced_empty_dir: false,
                },
            ],
            &foreign,
        );

        assert!(!ours.exists(), "this run's own file comes off");
        assert!(theirs.exists(), "another package's file must survive");
        // And the directory holding it survives with it: `remove_dir` refuses
        // a directory that still has something in it, which is the point.
        assert!(root.join("usr/bin").is_dir());
    }

    #[test]
    fn an_io_failure_names_the_path_and_the_operation() {
        // "File exists (os error 17)", with no path and no operation, was the
        // entire error message this replaces.
        let dangling = temp_dir("io-context-dangling");
        std::os::unix::fs::symlink("nowhere", dangling.join("usr")).unwrap();
        let archive = write_tar("io-context-dangling", &build_tar(&[("usr/", "", true)]));

        let err = unpack(&archive, &dangling, &unowned(), |_| {}).unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, ExtractError::IoAt { .. }), "got {err:?}");
        assert!(message.starts_with("creating directory "), "{message}");
        assert!(message.ends_with("/usr: File exists (os error 17)"), "{message}");

        // A plain file where a parent directory belongs reports the same way.
        let blocked = temp_dir("io-context-file");
        std::fs::write(blocked.join("usr"), b"not a directory").unwrap();
        let archive = write_tar("io-context-file", &build_tar(&[("usr/bin/demo", "x", false)]));

        let err = unpack(&archive, &blocked, &unowned(), |_| {}).unwrap_err();
        let message = err.to_string();
        assert!(message.starts_with("creating directory "), "{message}");
        assert!(message.contains("/usr/bin:"), "{message}");
    }

    #[test]
    fn detects_conflicts_against_other_packages_only() {
        let root = temp_dir("conflicts-db");
        let mut local = LocalDb::load(&root);

        let other = crate::pkg::Package {
            name: "other".into(),
            version: "1.0-1".into(),
            ..Default::default()
        };
        local.register(&other, &["usr/bin/demo".into()]).unwrap();

        let manifest = Manifest {
            files: vec!["usr/bin/demo".into(), "usr/bin/fresh".into()],
            ..Default::default()
        };

        let install_root = temp_dir("conflicts-root");
        let conflicts = find_conflicts(&manifest, &local, &install_root, None).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].to_string().contains("owned by other"));

        // Upgrading the owning package is not a conflict with itself.
        let none = find_conflicts(&manifest, &local, &install_root, Some("other")).unwrap();
        assert!(none.is_empty());
    }

    /// A symlink builder that can stamp an mtime, for the timestamp cases.
    fn stamped_link(builder: &mut tar::Builder<Vec<u8>>, path: &str, target: &str, mtime: u64) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_mtime(mtime);
        header.set_link_name(target).unwrap();
        header.set_cksum();
        builder.append_data(&mut header, path, &[][..]).unwrap();
    }

    /// A link already pointing at the right target still has to take the
    /// archive's timestamp. `pacman -Qkk` compares a symlink's mtime against
    /// the `.MTREE`, so skipping the stamp reports a correct link as altered.
    #[test]
    fn a_matching_symlink_still_takes_the_archive_mtime() {
        const STAMP: u64 = 1_700_000_000;
        let mut builder = tar::Builder::new(Vec::new());
        stamped_link(&mut builder, "usr/lib/libfoo.so", "libfoo.so.1", STAMP);
        let archive = write_tar("mtime-skip", &builder.into_inner().unwrap());
        let root = temp_dir("mtime-skip");

        // Correct on disk, but stamped by whatever built the rootfs.
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::os::unix::fs::symlink("libfoo.so.1", root.join("usr/lib/libfoo.so")).unwrap();
        let old = FileTime::from_unix_time(315_532_800, 0);
        filetime::set_symlink_file_times(root.join("usr/lib/libfoo.so"), old, old).unwrap();

        unpack(&archive, &root, &unowned(), |_| {}).unwrap();

        let meta = std::fs::symlink_metadata(root.join("usr/lib/libfoo.so")).unwrap();
        let got = FileTime::from_last_modification_time(&meta).unix_seconds();
        assert_eq!(got, STAMP as i64, "the archive's mtime must be restored");
    }

    /// An empty directory gives way to a symlink, but the swap is a change
    /// this run made and a failure has to put it back.
    #[test]
    fn the_rollback_restores_an_empty_directory_it_replaced() {
        let mut builder = tar::Builder::new(Vec::new());
        link_entry(&mut builder, "bin", "usr/bin", tar::EntryType::Symlink);
        // A later entry that cannot be written: a file onto a populated dir.
        let mut header = tar::Header::new_gnu();
        header.set_path("usr/share/doc").unwrap();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &b"boom"[..]).unwrap();
        let archive = write_tar("rb-emptydir", &builder.into_inner().unwrap());

        let root = temp_dir("rb-emptydir");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::create_dir_all(root.join("usr/share/doc")).unwrap();
        std::fs::write(root.join("usr/share/doc/README"), b"docs").unwrap();

        unpack(&archive, &root, &unowned(), |_| {}).unwrap_err();

        let meta = std::fs::symlink_metadata(root.join("bin")).unwrap();
        assert!(
            meta.file_type().is_dir(),
            "the empty directory this run replaced must come back"
        );
    }

    /// An empty directory is still somebody's. The local database spells it
    /// with a trailing slash, so the plain owner lookup cannot see it and
    /// `unpack` would delete it and claim the path.
    #[test]
    fn an_empty_directory_owned_by_another_package_is_a_conflict() {
        let mut builder = tar::Builder::new(Vec::new());
        link_entry(&mut builder, "var/empty", "usr/empty", tar::EntryType::Symlink);
        let archive = write_tar("steal-dir", &builder.into_inner().unwrap());
        let root = temp_dir("steal-dir");
        std::fs::create_dir_all(root.join("var/empty")).unwrap();

        let dbroot = temp_dir("steal-dir-db");
        let mut local = LocalDb::load(&dbroot);
        let other = crate::pkg::Package {
            name: "other".into(),
            version: "1.0-1".into(),
            ..Default::default()
        };
        local.register(&other, &["var/empty/".into()]).unwrap();

        let manifest = manifest(&archive).unwrap();
        let problems = find_conflicts(&manifest, &local, &root, None).unwrap();
        assert!(
            matches!(&problems[..], [ExtractError::FileConflict { owner, .. }] if owner == "other"),
            "{problems:?}"
        );
        assert!(root.join("var/empty").is_dir());
    }

    /// A package converting one of its *own* directories into a symlink is an
    /// ordinary upstream migration, not a conflict -- refusing it would abort
    /// every `rvn -Syu` that contained one.
    #[test]
    fn an_upgrade_may_turn_its_own_directory_into_a_symlink() {
        let mut builder = tar::Builder::new(Vec::new());
        link_entry(&mut builder, "usr/share/foo", "bar", tar::EntryType::Symlink);
        let archive = write_tar("selfconv", &builder.into_inner().unwrap());
        let root = temp_dir("selfconv");
        std::fs::create_dir_all(root.join("usr/share/foo")).unwrap();
        std::fs::write(root.join("usr/share/foo/data"), b"x").unwrap();

        let dbroot = temp_dir("selfconv-db");
        let mut local = LocalDb::load(&dbroot);
        let foo = crate::pkg::Package {
            name: "foo".into(),
            version: "1.0-1".into(),
            ..Default::default()
        };
        local
            .register(&foo, &["usr/share/foo/".into(), "usr/share/foo/data".into()])
            .unwrap();

        let manifest = manifest(&archive).unwrap();
        let problems = find_conflicts(&manifest, &local, &root, Some("foo")).unwrap();
        assert!(problems.is_empty(), "{problems:?}");

        // ...and someone else's directory of the same shape still is one.
        let problems = find_conflicts(&manifest, &local, &root, None).unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
    }

    /// A plain file where a parent directory has to be created is found by the
    /// pre-flight, not by `create_dir_all` half way through the archive.
    #[test]
    fn a_file_blocking_an_ancestor_directory_is_pre_flighted() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("opt/thing/a").unwrap();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &b"a"[..]).unwrap();
        let archive = write_tar("ancestor", &builder.into_inner().unwrap());
        let root = temp_dir("ancestor");
        std::fs::create_dir_all(root.join("opt")).unwrap();
        std::fs::write(root.join("opt/thing"), b"i am a file").unwrap();

        let manifest = manifest(&archive).unwrap();
        let local = LocalDb::load(&temp_dir("ancestor-db"));
        let problems = find_conflicts(&manifest, &local, &root, None).unwrap();
        assert!(
            matches!(&problems[..], [ExtractError::TypeConflict { path, .. }] if path == "opt/thing"),
            "{problems:?}"
        );
    }

    /// The same, for a directory entry landing squarely on a regular file.
    #[test]
    fn a_directory_entry_over_a_regular_file_is_pre_flighted() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, "opt/thing/", &[][..]).unwrap();
        let archive = write_tar("direntry", &builder.into_inner().unwrap());
        let root = temp_dir("direntry");
        std::fs::create_dir_all(root.join("opt")).unwrap();
        std::fs::write(root.join("opt/thing"), b"i am a file").unwrap();

        let manifest = manifest(&archive).unwrap();
        let local = LocalDb::load(&temp_dir("direntry-db"));
        let problems = find_conflicts(&manifest, &local, &root, None).unwrap();
        assert!(!problems.is_empty(), "a directory over a file must be caught");
    }

}
