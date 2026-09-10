//! A parsed-package cache for sync databases.
//!
//! Turning `extra.db` into packages costs several hundred milliseconds — most
//! of it not the gunzip but the record parsing — and every `rvn list` or
//! `rvn find` paid it for a database that changes only when it is synced.
//! So once a database has been parsed, its packages are written out in a
//! flat binary form under `$XDG_CACHE_HOME/rvn/index`, and later runs read
//! that back in a few milliseconds instead.
//!
//! The cache is an optimisation and nothing more: any doubt about it — the
//! database has a different size or mtime than the one that was parsed, the
//! file is truncated or unreadable, the directory is not writable, rvn has
//! been rebuilt since — silently falls back to parsing the database itself.
//! Nothing ever needs to invalidate it by hand.

use crate::pkg::{BackupFile, Dep, InstallReason, Op, Origin, Package, Validation};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

const MAGIC: &[u8; 8] = b"rvnidx\0\x01";

/// The user's cache root: `$XDG_CACHE_HOME`, else `~/.cache`.
pub fn cache_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|home| PathBuf::from(home).join(".cache"))
        })
}

/// Where the cache entry for a database lives. The name carries a digest of
/// the database's path because the same repository can be read from two
/// places — the system copy and the per-user copy an unprivileged update
/// check syncs into — and each needs its own entry.
fn entry_path(repo: &str, db: &Path) -> Option<PathBuf> {
    let digest = Sha256::digest(db.to_string_lossy().as_bytes());
    let name = format!("{repo}-{}.idx", hex::encode(&digest[..8]));
    cache_home().map(|base| base.join("rvn").join("index").join(name))
}

/// What identifies a file's contents without reading them: size and mtime.
pub type Stamp = (u64, u64, u32);

/// The stamp of an open file. A sync replaces a database by renaming a new
/// file over it, and a cold parse is exactly what runs right after one, so
/// the stamp an entry records must come from the inode that was parsed —
/// a stat by path could describe a file that landed during the parse.
pub fn stamp_of(meta: &std::fs::Metadata) -> Stamp {
    let (secs, nanos) = match meta.modified().ok().map(|t| t.duration_since(UNIX_EPOCH)) {
        Some(Ok(d)) => (d.as_secs(), d.subsec_nanos()),
        _ => (0, 0),
    };
    (meta.len(), secs, nanos)
}

fn stamp(path: &Path) -> Option<Stamp> {
    std::fs::metadata(path).ok().map(|meta| stamp_of(&meta))
}

/// The encoding mirrors `Package` field for field and is not self-describing,
/// so an rvn built with a different `Package` would read an old entry as
/// garbage. Tying every entry to the executable that wrote it makes a rebuild
/// re-parse once rather than trusting whatever a previous build left behind.
fn exe_stamp() -> Stamp {
    std::env::current_exe()
        .ok()
        .and_then(|exe| stamp(&exe))
        .unwrap_or((0, 0, 0))
}

/// Reads the cached packages for `db`, if the cache still describes it.
pub fn load(repo: &str, db: &Path) -> Option<Vec<Package>> {
    let (size, secs, nanos) = stamp(db)?;
    let data = std::fs::read(entry_path(repo, db)?).ok()?;
    let mut r = Reader { buf: &data, pos: 0 };

    if r.bytes(MAGIC.len())? != MAGIC {
        return None;
    }
    if (r.u64()?, r.u64()?, r.u32()?) != exe_stamp() {
        return None;
    }
    if r.string()? != db.to_string_lossy() || (r.u64()?, r.u64()?, r.u32()?) != (size, secs, nanos)
    {
        return None;
    }
    if r.string()? != repo {
        return None;
    }

    let count = r.count()?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.u32()? as usize;
        records.push(r.bytes(len)?);
    }
    // Trailing bytes mean this is not a file this code wrote.
    if r.pos != data.len() {
        return None;
    }
    decode(&records)
}

/// Decodes the packages, one record each, on every core. The work is almost
/// entirely allocating strings, and `extra` alone has fifteen thousand
/// packages' worth; splitting it up brings the read to a few milliseconds.
fn decode(records: &[&[u8]]) -> Option<Vec<Package>> {
    fn decode_one(record: &[u8]) -> Option<Package> {
        let mut r = Reader {
            buf: record,
            pos: 0,
        };
        let package = r.package()?;
        (r.pos == record.len()).then_some(package)
    }

    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    // Below this, spawning costs more than it saves.
    let per_thread = records.len().div_ceil(threads).max(1024);
    if records.len() <= per_thread {
        return records.iter().map(|r| decode_one(r)).collect();
    }
    let parts: Vec<Option<Vec<Package>>> = std::thread::scope(|scope| {
        let handles: Vec<_> = records
            .chunks(per_thread)
            .map(|chunk| scope.spawn(move || chunk.iter().map(|r| decode_one(r)).collect()))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().ok().flatten())
            .collect()
    });
    let mut packages = Vec::with_capacity(records.len());
    for part in parts {
        packages.extend(part?);
    }
    Some(packages)
}

/// Records `packages` as the parse of `db`, where `stamp` describes the
/// file those packages were read from (see [`stamp_of`]). Failure is not
/// reported: the cache directory may not exist or be writable, and the next
/// run simply parses again.
pub fn store(repo: &str, db: &Path, stamp: Stamp, packages: &[Package]) {
    let (size, secs, nanos) = stamp;
    let Some(path) = entry_path(repo, db) else {
        return;
    };

    let mut w = Writer(Vec::new());
    w.0.extend_from_slice(MAGIC);
    let (exe_size, exe_secs, exe_nanos) = exe_stamp();
    w.u64(exe_size);
    w.u64(exe_secs);
    w.u32(exe_nanos);
    w.string(&db.to_string_lossy());
    w.u64(size);
    w.u64(secs);
    w.u32(nanos);
    w.string(repo);
    w.u32(packages.len() as u32);
    for pkg in packages {
        // Each record is length-prefixed so the reader can split the file
        // between threads without decoding it first.
        let start = w.0.len();
        w.u32(0);
        w.package(pkg);
        let len = (w.0.len() - start - 4) as u32;
        w.0[start..start + 4].copy_from_slice(&len.to_le_bytes());
    }

    // Written beside its final name and renamed into place, so a run that
    // starts while this one is still writing never reads half an entry.
    let Some(dir) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let tmp = dir.join(format!(
        ".{}.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let written = std::fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(&w.0))
        .and_then(|_| std::fs::rename(&tmp, &path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn bool(&mut self, v: bool) {
        self.u8(v as u8);
    }

    fn string(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }

    fn opt_string(&mut self, s: Option<&str>) {
        match s {
            Some(s) => {
                self.u8(1);
                self.string(s);
            }
            None => self.u8(0),
        }
    }

    fn strings(&mut self, list: &[String]) {
        self.u32(list.len() as u32);
        for s in list {
            self.string(s);
        }
    }

    fn dep(&mut self, dep: &Dep) {
        self.string(&dep.name);
        match &dep.constraint {
            Some((op, version)) => {
                self.u8(match op {
                    Op::Eq => 1,
                    Op::Ge => 2,
                    Op::Le => 3,
                    Op::Gt => 4,
                    Op::Lt => 5,
                });
                self.string(version);
            }
            None => self.u8(0),
        }
        self.opt_string(dep.description.as_deref());
    }

    fn deps(&mut self, list: &[Dep]) {
        self.u32(list.len() as u32);
        for dep in list {
            self.dep(dep);
        }
    }

    fn package(&mut self, p: &Package) {
        self.string(&p.name);
        self.string(&p.version);
        self.string(&p.description);
        self.opt_string(p.url.as_deref());
        self.opt_string(p.packager.as_deref());
        self.strings(&p.licenses);
        self.strings(&p.groups);
        self.deps(&p.provides);
        self.deps(&p.depends);
        self.deps(&p.makedepends);
        self.deps(&p.optdepends);
        self.deps(&p.conflicts);
        self.deps(&p.replaces);
        self.opt_string(p.filename.as_deref());
        self.u64(p.csize);
        self.u64(p.isize);
        self.opt_string(p.sha256.as_deref());
        self.bool(p.has_sig);
        match &p.origin {
            Origin::Local => self.u8(0),
            Origin::Aur => self.u8(1),
            Origin::Repo(name) => {
                self.u8(2);
                self.string(name);
            }
        }
        self.u64(p.popularity.to_bits());
        self.bool(p.out_of_date);
        self.u32(p.backup.len() as u32);
        for b in &p.backup {
            self.string(&b.path);
            self.opt_string(b.hash.as_deref());
        }
        self.u8(match p.install_reason {
            InstallReason::Explicit => 0,
            InstallReason::Dependency => 1,
        });
        self.opt_string(p.arch.as_deref());
        self.opt_string(p.base.as_deref());
        self.u64(p.build_date);
        self.u8(match p.validation {
            Validation::None => 0,
            Validation::Sha256 => 1,
            Validation::Pgp => 2,
        });
    }
}

/// Every read is bounds-checked and returns `None` past the end, so a
/// truncated or corrupt entry is rejected rather than trusted.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(8)?.try_into().ok()?))
    }

    fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        Some(std::str::from_utf8(self.bytes(len)?).ok()?.to_string())
    }

    fn opt_string(&mut self) -> Option<Option<String>> {
        match self.u8()? {
            0 => Some(None),
            1 => Some(Some(self.string()?)),
            _ => None,
        }
    }

    /// A count is capped by what could possibly follow it, so a corrupt one
    /// cannot ask for an absurd allocation before the reads fail.
    fn count(&mut self) -> Option<usize> {
        let n = self.u32()? as usize;
        (n <= self.buf.len() - self.pos).then_some(n)
    }

    fn strings(&mut self) -> Option<Vec<String>> {
        let n = self.count()?;
        let mut list = Vec::with_capacity(n);
        for _ in 0..n {
            list.push(self.string()?);
        }
        Some(list)
    }

    fn dep(&mut self) -> Option<Dep> {
        let name = self.string()?;
        let constraint = match self.u8()? {
            0 => None,
            tag => {
                let op = match tag {
                    1 => Op::Eq,
                    2 => Op::Ge,
                    3 => Op::Le,
                    4 => Op::Gt,
                    5 => Op::Lt,
                    _ => return None,
                };
                Some((op, self.string()?))
            }
        };
        let description = self.opt_string()?;
        Some(Dep {
            name,
            constraint,
            description,
        })
    }

    fn deps(&mut self) -> Option<Vec<Dep>> {
        let n = self.count()?;
        let mut list = Vec::with_capacity(n);
        for _ in 0..n {
            list.push(self.dep()?);
        }
        Some(list)
    }

    fn package(&mut self) -> Option<Package> {
        Some(Package {
            name: self.string()?,
            version: self.string()?,
            description: self.string()?,
            url: self.opt_string()?,
            packager: self.opt_string()?,
            licenses: self.strings()?,
            groups: self.strings()?,
            provides: self.deps()?,
            depends: self.deps()?,
            makedepends: self.deps()?,
            optdepends: self.deps()?,
            conflicts: self.deps()?,
            replaces: self.deps()?,
            filename: self.opt_string()?,
            csize: self.u64()?,
            isize: self.u64()?,
            sha256: self.opt_string()?,
            has_sig: self.bool()?,
            origin: match self.u8()? {
                0 => Origin::Local,
                1 => Origin::Aur,
                2 => Origin::Repo(self.string()?),
                _ => return None,
            },
            popularity: f64::from_bits(self.u64()?),
            out_of_date: self.bool()?,
            backup: {
                let n = self.count()?;
                let mut list = Vec::with_capacity(n);
                for _ in 0..n {
                    list.push(BackupFile {
                        path: self.string()?,
                        hash: self.opt_string()?,
                    });
                }
                list
            },
            install_reason: match self.u8()? {
                0 => InstallReason::Explicit,
                1 => InstallReason::Dependency,
                _ => return None,
            },
            arch: self.opt_string()?,
            base: self.opt_string()?,
            build_date: self.u64()?,
            validation: match self.u8()? {
                0 => Validation::None,
                1 => Validation::Sha256,
                2 => Validation::Pgp,
                _ => return None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests share the process environment, so those that point
    /// `XDG_CACHE_HOME` somewhere take turns.
    static ENV: Mutex<()> = Mutex::new(());

    /// A package with every field populated, so the round trip proves each
    /// one is encoded.
    fn full_package() -> Package {
        Package {
            name: "go".into(),
            version: "2:1.22.0-1".into(),
            description: "Core compiler tools".into(),
            url: Some("https://go.dev".into()),
            packager: Some("Someone <a@b.c>".into()),
            licenses: vec!["BSD".into(), "MIT".into()],
            groups: vec!["devel".into()],
            provides: vec![Dep::parse("go-compiler=1.22.0")],
            depends: vec![Dep::parse("glibc"), Dep::parse("openssl>=3.0")],
            makedepends: vec![Dep::parse("git<3"), Dep::parse("perl<=6")],
            optdepends: vec![Dep::parse("go-tools: additional tools")],
            conflicts: vec![Dep::parse("gcc-go>1")],
            replaces: vec![Dep::parse("go-old")],
            filename: Some("go-2:1.22.0-1-x86_64.pkg.tar.zst".into()),
            csize: 70_123_456,
            isize: 250_000_000,
            sha256: Some("abc123".into()),
            has_sig: true,
            origin: Origin::Repo("extra".into()),
            popularity: 1.5,
            out_of_date: true,
            backup: vec![
                BackupFile::parse("etc/go.conf\tdeadbeef"),
                BackupFile::parse("etc/bare.conf"),
            ],
            install_reason: InstallReason::Dependency,
            arch: Some("x86_64".into()),
            base: Some("go".into()),
            build_date: 1_700_000_000,
            validation: Validation::Pgp,
        }
    }

    /// A fresh scratch directory that stands in for the cache home while
    /// the test runs, so the tests never touch the real one. Dropping it
    /// puts `XDG_CACHE_HOME` back and removes the directory, so nothing
    /// leaks into later tests or is left on disk.
    struct Scratch {
        dir: PathBuf,
        previous: Option<std::ffi::OsString>,
    }

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!("rvn-index-{tag}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let previous = std::env::var_os("XDG_CACHE_HOME");
            let scratch = Scratch { dir, previous };
            scratch.set_cache_home(&scratch.dir);
            scratch
        }

        fn set_cache_home(&self, path: &Path) {
            // SAFETY: the ENV lock serialises every writer of this variable,
            // and nothing else in the suite reads it.
            unsafe { std::env::set_var("XDG_CACHE_HOME", path) };
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // SAFETY: as above.
            unsafe {
                match &self.previous {
                    Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
                    None => std::env::remove_var("XDG_CACHE_HOME"),
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn encode(packages: &[Package]) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        for p in packages {
            let start = w.0.len();
            w.u32(0);
            w.package(p);
            let len = (w.0.len() - start - 4) as u32;
            w.0[start..start + 4].copy_from_slice(&len.to_le_bytes());
        }
        w.0
    }

    fn decode_records(bytes: &[u8]) -> Option<Vec<Package>> {
        let mut r = Reader { buf: bytes, pos: 0 };
        let mut records = Vec::new();
        while r.pos < bytes.len() {
            let len = r.u32()? as usize;
            records.push(r.bytes(len)?);
        }
        decode(&records)
    }

    #[test]
    fn every_field_survives_a_round_trip() {
        let original = vec![full_package(), Package::default()];
        let decoded = decode_records(&encode(&original)).expect("decodes");
        // Package has no PartialEq; Debug covers every field.
        assert_eq!(format!("{decoded:?}"), format!("{original:?}"));
    }

    #[test]
    fn truncation_and_corruption_are_rejected_not_trusted() {
        let bytes = encode(&[full_package()]);
        for cut in [1, 4, 5, bytes.len() / 2, bytes.len() - 1] {
            assert!(decode_records(&bytes[..cut]).is_none(), "cut at {cut}");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode_records(&extra).is_none(), "trailing bytes");

        // A bogus enum tag, and a record shorter than its fields.
        let mut bad_tag = bytes.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] = 9;
        assert!(decode_records(&bad_tag).is_none(), "validation tag");
        let mut short = bytes.clone();
        short[..4].copy_from_slice(&((bytes.len() - 8) as u32).to_le_bytes());
        short.truncate(bytes.len() - 4);
        assert!(decode_records(&short).is_none(), "short record");
    }

    #[test]
    fn a_large_database_decodes_in_the_same_order() {
        // Enough packages to be split between threads.
        let original: Vec<Package> = (0..5000)
            .map(|i| Package {
                name: format!("pkg{i}"),
                depends: vec![Dep::parse(&format!("dep{i}>=1"))],
                ..Default::default()
            })
            .collect();
        let decoded = decode_records(&encode(&original)).expect("decodes");
        assert_eq!(decoded.len(), original.len());
        assert!(decoded.iter().zip(&original).all(|(a, b)| a.name == b.name));
        assert_eq!(
            format!("{:?}", decoded[4999]),
            format!("{:?}", original[4999])
        );
    }

    #[test]
    fn entry_follows_the_database_and_the_stamp() {
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let scratch = Scratch::new("stamp");
        let db = scratch.dir.join("extra.db");
        std::fs::write(&db, b"one").unwrap();

        assert!(load("extra", &db).is_none(), "nothing cached yet");
        store("extra", &db, stamp(&db).unwrap(), &[full_package()]);
        let cached = load("extra", &db).expect("cached after store");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].name, "go");

        // The same file under another repo name is another database.
        assert!(load("core", &db).is_none());

        // A re-synced database is a different size or time; either way
        // the entry no longer applies.
        std::fs::write(&db, b"three").unwrap();
        assert!(load("extra", &db).is_none(), "size changed");

        // A database that is gone has no cache either.
        std::fs::remove_file(&db).unwrap();
        assert!(load("extra", &db).is_none());

        // And a damaged entry is ignored, never an error.
        std::fs::write(&db, b"one").unwrap();
        store("extra", &db, stamp(&db).unwrap(), &[full_package()]);
        let entry = entry_path("extra", &db).unwrap();
        let bytes = std::fs::read(&entry).unwrap();
        std::fs::write(&entry, &bytes[..bytes.len() / 2]).unwrap();
        assert!(load("extra", &db).is_none(), "truncated entry");
        std::fs::write(&entry, b"not an index").unwrap();
        assert!(load("extra", &db).is_none(), "garbage entry");
    }

    #[test]
    fn an_unwritable_cache_is_silently_skipped() {
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let scratch = Scratch::new("unwritable");
        let db = scratch.dir.join("core.db");
        std::fs::write(&db, b"db").unwrap();
        // A file where the cache directory should be makes every write fail.
        let blocker = scratch.dir.join("blocker");
        std::fs::write(&blocker, b"").unwrap();
        scratch.set_cache_home(&blocker);
        store("core", &db, stamp(&db).unwrap(), &[full_package()]);
        assert!(load("core", &db).is_none());
    }

    #[test]
    fn the_entry_describes_the_file_that_was_parsed() {
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let scratch = Scratch::new("replaced");
        let db = scratch.dir.join("extra.db");
        std::fs::write(&db, b"one").unwrap();

        // Open the database, then let a sync rename another one over it
        // before the parse is stored — the stamp of the open handle is what
        // the entry must record, so the new file is not mistaken for the
        // old packages.
        let parsed = std::fs::File::open(&db).unwrap();
        let parsed_stamp = stamp_of(&parsed.metadata().unwrap());
        let part = scratch.dir.join("extra.db.part");
        std::fs::write(&part, b"three").unwrap();
        std::fs::rename(&part, &db).unwrap();
        store("extra", &db, parsed_stamp, &[full_package()]);
        assert!(
            load("extra", &db).is_none(),
            "entry is for the replaced file"
        );
        assert_ne!(parsed_stamp, stamp(&db).unwrap());
    }
}
