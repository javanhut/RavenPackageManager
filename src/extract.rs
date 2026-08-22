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
    let file = std::fs::File::open(path)?;
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

fn is_metadata(path: &Path) -> bool {
    path.components().count() == 1
        && path
            .to_str()
            .map(|p| METADATA.contains(&p))
            .unwrap_or(false)
}

/// What an archive contains, determined without writing anything.
#[derive(Debug, Default)]
pub struct Manifest {
    /// Regular files and symlinks, as root-relative paths.
    pub files: Vec<String>,
    /// Directories the package creates.
    pub directories: Vec<String>,
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

        if entry.header().entry_type().is_dir() {
            manifest.directories.push(format!("{as_string}/"));
        } else {
            manifest.total_size += entry.header().size().unwrap_or(0);
            manifest.files.push(as_string);
        }
    }

    Ok(manifest)
}

/// Finds files in `manifest` that are already owned by another package.
///
/// A file owned by `upgrading` is not a conflict — that is just a version
/// replacing itself.
pub fn find_conflicts(
    manifest: &Manifest,
    local: &LocalDb,
    upgrading: Option<&str>,
) -> Result<Vec<ExtractError>, ExtractError> {
    // Build an owner index once rather than rescanning per file.
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

    Ok(manifest
        .files
        .iter()
        .filter_map(|file| {
            owners.get(file).map(|owner| ExtractError::FileConflict {
                path: file.clone(),
                owner: owner.clone(),
            })
        })
        .collect())
}

/// Unpacks an archive into `root`, returning the installed file list.
///
/// `on_file` is called for each extracted entry so callers can drive progress.
pub fn unpack(
    archive_path: &Path,
    root: &Path,
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

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.to_path_buf();

        if is_metadata(&entry_path) {
            continue;
        }

        let relative = safe_relative(&entry_path)?;
        let destination = root.join(&relative);

        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let kind = entry.header().entry_type();

        if kind.is_dir() {
            std::fs::create_dir_all(&destination)?;
            deferred_times.push((destination.clone(), entry.header().mtime().unwrap_or(0), true));
            // Recorded with a trailing slash, as pacman does, so removal can
            // prune directories a package created but never filled.
            installed.push(format!("{}/", relative.to_string_lossy()));
            continue;
        }

        // Links must be recreated by hand. `Entry::unpack` resolves a link
        // target relative to the process's working directory, which would
        // either fail or — worse — point outside the install root.
        if kind.is_hard_link() || kind.is_symlink() {
            let target = entry
                .link_name()?
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
                let _ = std::fs::remove_file(&destination);
                std::os::unix::fs::symlink(&target, &destination)?;
                deferred_times.push((
                    destination.clone(),
                    entry.header().mtime().unwrap_or(0),
                    false,
                ));
            }
        } else {
            entry.unpack(&destination)?;
        }

        let as_string = relative.to_string_lossy().to_string();
        on_file(&as_string);
        installed.push(as_string);
    }

    // Second pass: every regular file now exists, so hard links can resolve
    // regardless of the order they appeared in the archive.
    for (link, target) in deferred_links {
        let destination = root.join(&link);
        let source = root.join(&target);

        // On a case-insensitive filesystem the link and its target can name
        // the same file (`terminfo/l/lft-pc850` and `terminfo/L/LFT-PC850`).
        // Removing the destination would then destroy the source, so treat
        // the link as already satisfied.
        if same_file(&source, &destination) {
            let as_string = link.to_string_lossy().to_string();
            on_file(&as_string);
            installed.push(as_string);
            continue;
        }

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

        let as_string = link.to_string_lossy().to_string();
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

        let err = unpack(&archive, &root, |_| {}).unwrap_err();
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
        let files = unpack(&archive, &root, |f| seen.push(f.to_string())).unwrap();

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

        let files = unpack(&archive, &root, |_| {}).unwrap();
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
        unpack(&archive, &root, |_| {}).unwrap();

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

        let files = unpack(&archive, &root, |_| {}).unwrap();
        assert_eq!(files, vec!["usr/bin/sh"]);

        let link = root.join("usr/bin/sh");
        let target = std::fs::read_link(&link).unwrap();
        // The target is stored as-is; it resolves inside the installed root.
        assert_eq!(target, PathBuf::from("bash"));
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

        let err = unpack(&archive, &root, |_| {}).unwrap_err();
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

        let files = unpack(&archive, &root, |_| {}).unwrap();
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
            let files = unpack(&path, &root, |_| {}).unwrap();
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

        let conflicts = find_conflicts(&manifest, &local, None).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].to_string().contains("owned by other"));

        // Upgrading the owning package is not a conflict with itself.
        let none = find_conflicts(&manifest, &local, Some("other")).unwrap();
        assert!(none.is_empty());
    }
}
