//! The package cache: what is in it, what is allowed to stay, and why.
//!
//! rvn deletes the archives a transaction downloaded the moment it finishes,
//! and has done since the beginning, so the cache was never supposed to grow.
//! On the machine this was written on it was 8.4 GB, and finding out why took
//! longer than it should have because the clearing code is not wrong -- it is
//! just much narrower than its name suggests.
//!
//! `clear_cache` in [`crate::ops::install`] is handed `downloaded`: the repo
//! archives *this* transaction fetched. Three things are therefore outside it
//! by construction. An AUR package's archive is built, not downloaded, and is
//! passed to `install_archives` as `built` from inside the build tree, so it
//! has never been in that list. The build tree around it -- the git checkout,
//! the extracted sources, the object files -- is never looked at by anything.
//! And an archive from a transaction that failed after the fetch, or from
//! before rvn existed at all, was never in any list rvn held. Of the 8.4 GB,
//! 8.0 GB was the `aur/` subtree: five packages' build trees, some of them
//! years old.
//!
//! So this module does not clear a transaction's downloads -- that still
//! belongs to the transaction. It answers the other question: given a cache
//! directory that nobody has been watching, what is actually in it, and what
//! can be deleted without taking something irreplaceable with it.
//!
//! Three rules run through everything below, and each of them exists because
//! the obvious implementation would break something real:
//!
//! The version currently installed is never deleted. It is the file a
//! reinstall reads instead of the network, it is what `rvn rollback` will need
//! once it exists, and for a package built from the AUR it is the only copy
//! that will ever exist -- getting it back means a full rebuild.
//!
//! Retention is by version, not by modification time. The cache holds
//! `name-version-release-arch.pkg.tar.zst` and its mtime is the order things
//! were downloaded in, which is not the order they were released in: a
//! downgrade, a rebuild of an older release, or a `--keep-cache` install of a
//! version the machine already had all put a newer file on disk for an older
//! version. Versions are compared with [`crate::version::vercmp`], the same
//! comparison the resolver makes upgrade decisions with.
//!
//! The AUR build trees are never swept unless they are asked for by name. A
//! build tree is not a cache in the sense the rest of this file means: it
//! holds a git checkout an administrator may have edited, a PKGBUILD they may
//! have patched, and every `source=` tarball the build downloaded. Deleting it
//! reclaims the most space of anything here and costs a full re-clone and a
//! full re-download on the next build, so it is opt-in, it is confirmed, and
//! any archive in it that the retention rule decided to keep is moved out
//! before the tree goes.

use crate::version::vercmp;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// How many versions of each package `rvn cache clean` keeps when nobody says
/// otherwise.
///
/// Two, not one and not zero. One means the cache holds exactly what is
/// installed, which is enough to reinstall but leaves nothing to go back to;
/// two keeps the version that was running before the last upgrade, which is
/// the one anybody asks for after an upgrade breaks something, and it is what
/// `rvn rollback` will have to read. Zero is available as `--keep 0` for a
/// machine that is short of disk, and even then the installed version stays.
///
/// The cost is bounded by what has actually been upgraded since the last
/// clean rather than by the size of the system: a package nobody has upgraded
/// has one version in the cache and keeping two changes nothing.
pub const DEFAULT_KEEP: usize = 2;

/// Where AUR build trees live inside a cache directory; see
/// [`crate::aur::build_dir`], which is what puts them there.
const BUILD_SUBDIR: &str = "aur";

/// How long a `.part` file must have sat untouched before it counts as
/// abandoned rather than in flight.
///
/// [`crate::fetch::download_with_mirrors`] writes to `<archive>.part` and
/// renames on success, deleting it itself when a mirror fails, so one that
/// survives is the remains of an rvn that was killed or a machine that lost
/// power. The only way to leave a live download without its temporary file is
/// to sweep one that is being written right now, and an hour is far longer
/// than any single archive takes to fetch on a connection slow enough to
/// matter.
const ABANDONED_AFTER: Duration = Duration::from_secs(60 * 60);

/// One package archive on disk, with the detached signature that belongs to
/// it.
///
/// The signature travels with the archive rather than being listed separately
/// because it is never useful alone: deleting the archive and leaving the
/// `.sig` behind is how a cache ends up with thousands of 500-byte files that
/// verify nothing.
#[derive(Debug, Clone)]
pub struct Archive {
    pub path: PathBuf,
    /// The package name parsed out of the filename.
    pub package: String,
    /// `version-release`, epoch included when the filename carries one --
    /// exactly the string [`crate::version::vercmp`] expects.
    pub version: String,
    pub size: u64,
    pub signature: Option<PathBuf>,
    pub signature_size: u64,
    /// Whether this archive was found inside an AUR build tree, which means
    /// it was built on this machine and no mirror has a copy.
    pub built: bool,
    pub modified: Option<SystemTime>,
}

impl Archive {
    /// What deleting this archive would reclaim, signature included.
    pub fn total(&self) -> u64 {
        self.size + self.signature_size
    }

    /// The files that make it up, for a sweep that has to delete them.
    fn files(&self) -> Vec<(PathBuf, u64)> {
        let mut files = vec![(self.path.clone(), self.size)];
        if let Some(sig) = &self.signature {
            files.push((sig.clone(), self.signature_size));
        }
        files
    }
}

/// A file in the cache that is not a package archive: an interrupted
/// download, or anything else that ended up there.
#[derive(Debug, Clone)]
pub struct Stray {
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<SystemTime>,
    /// Whether it was found inside a build tree, whose size already counts
    /// it. Nothing but the arithmetic in [`Inventory::total`] cares.
    built: bool,
}

/// One `<cache>/aur/<package>` build tree.
///
/// `total` is the whole subtree and `artifacts` is the part of it that is
/// built package archives, so the difference is the git checkout and the
/// extracted sources -- the part that is expensive to recreate and that
/// nobody but the administrator can replace if they had edited it.
#[derive(Debug, Clone)]
pub struct BuildTree {
    pub package: String,
    pub path: PathBuf,
    pub total: u64,
    pub artifacts: u64,
    pub modified: Option<SystemTime>,
}

impl BuildTree {
    /// The checkout and the downloaded sources: everything that is not a
    /// finished package.
    pub fn sources(&self) -> u64 {
        self.total.saturating_sub(self.artifacts)
    }
}

/// Everything found under the configured cache directories.
#[derive(Debug, Default)]
pub struct Inventory {
    /// The directories this inventory covers, in configuration order.
    pub roots: Vec<PathBuf>,
    pub archives: Vec<Archive>,
    /// `.part` files: downloads that were interrupted.
    pub partials: Vec<Stray>,
    /// Files and directories in a cache root that are neither archives nor
    /// build trees. Reported so a surprising 4 GB has somewhere to show up,
    /// and never deleted, because rvn did not put them there.
    pub other: Vec<Stray>,
    pub builds: Vec<BuildTree>,
    /// Directories that exist but could not be read, usually because the
    /// caller is not root. Reported rather than silently treated as empty: a
    /// status that says "0 B" for /var/cache/pacman/pkg would be a lie.
    pub unreadable: Vec<PathBuf>,
}

impl Inventory {
    /// Walks each cache directory once and classifies everything in it.
    ///
    /// A missing directory is not an error -- a configured `CacheDir` that no
    /// transaction has written to yet simply does not exist, and reporting it
    /// as unreadable would be noise on a fresh machine.
    pub fn scan(roots: &[PathBuf]) -> Inventory {
        let mut inventory = Inventory {
            roots: roots.to_vec(),
            ..Default::default()
        };

        // One set of inodes for the whole walk: a file hard-linked between
        // two cache directories, or between a build tree and the cache it
        // sits in, is one file on the disk and is counted once.
        let mut seen = HashSet::new();
        for root in roots {
            if !root.exists() {
                continue;
            }
            inventory.scan_root(root, &mut seen);
        }

        // Signatures are matched to archives afterwards rather than during the
        // walk, because read_dir hands them over in whatever order the
        // filesystem feels like and a `.sig` is as likely to come first as
        // second.
        inventory.pair_signatures();
        inventory
            .archives
            .sort_by(|a, b| a.package.cmp(&b.package).then_with(|| a.path.cmp(&b.path)));
        inventory
    }

    fn scan_root(&mut self, root: &Path, seen: &mut HashSet<(u64, u64)>) {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(_) => {
                self.unreadable.push(root.to_path_buf());
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };

            if meta.is_dir() {
                if name == BUILD_SUBDIR {
                    self.scan_build_root(&path, seen);
                } else {
                    let (size, _) = tree_size(&path, seen);
                    self.other.push(Stray {
                        path,
                        size,
                        modified: meta.modified().ok(),
                        built: false,
                    });
                }
                continue;
            }

            self.classify_file(&path, &name, meta.len(), meta.modified().ok(), false);
        }
    }

    /// The `aur/` subdirectory: one build tree per package, each sized whole.
    fn scan_build_root(&mut self, root: &Path, seen: &mut HashSet<(u64, u64)>) {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(_) => {
                self.unreadable.push(root.to_path_buf());
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_dir() {
                // A loose file directly in aur/ is not a build tree; it is
                // whatever somebody left there.
                self.other.push(Stray {
                    path,
                    size: meta.len(),
                    modified: meta.modified().ok(),
                    built: false,
                });
                continue;
            }

            let (total, archives) = tree_size(&path, seen);
            let mut artifacts = 0;
            for (file, size, modified) in archives {
                let name = file
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                artifacts += size;
                self.classify_file(&file, &name, size, modified, true);
            }

            self.builds.push(BuildTree {
                package: entry.file_name().to_string_lossy().into_owned(),
                path,
                total,
                artifacts,
                modified: meta.modified().ok(),
            });
        }
        self.builds.sort_by(|a, b| a.package.cmp(&b.package));
    }

    fn classify_file(
        &mut self,
        path: &Path,
        name: &str,
        size: u64,
        modified: Option<SystemTime>,
        built: bool,
    ) {
        let stray = || Stray {
            path: path.to_path_buf(),
            size,
            modified,
            built,
        };

        if name.ends_with(".part") {
            self.partials.push(stray());
            return;
        }
        if !name.contains(".pkg.tar") {
            self.other.push(stray());
            return;
        }
        if name.ends_with(".sig") {
            // Held until pairing; an orphan is dealt with there.
            self.other.push(stray());
            return;
        }

        match parse_archive_name(name) {
            Some((package, version)) => self.archives.push(Archive {
                path: path.to_path_buf(),
                package,
                version,
                size,
                signature: None,
                signature_size: 0,
                built,
                modified,
            }),
            // A file that looks like an archive but whose name cannot be
            // parsed is left strictly alone. Nothing here can tell which
            // package it belongs to or which version it is, so no retention
            // rule can be applied to it honestly, and guessing would delete
            // somebody's hand-built package.
            None => self.other.push(stray()),
        }
    }

    /// Moves each `.sig` from `other` onto the archive it signs.
    fn pair_signatures(&mut self) {
        let owned: HashMap<PathBuf, usize> = self
            .archives
            .iter()
            .enumerate()
            .map(|(index, archive)| (signature_path(&archive.path), index))
            .collect();

        let mut orphans = Vec::new();
        for stray in std::mem::take(&mut self.other) {
            match owned.get(&stray.path) {
                Some(&index) => {
                    self.archives[index].signature = Some(stray.path);
                    self.archives[index].signature_size = stray.size;
                }
                None => orphans.push(stray),
            }
        }
        self.other = orphans;
    }

    /// Every byte this inventory accounts for.
    pub fn total(&self) -> u64 {
        // Build-tree artifacts are counted inside `builds.total`, so adding
        // the archives found in them again would double them.
        self.archives
            .iter()
            .filter(|a| !a.built)
            .map(|a| a.total())
            .sum::<u64>()
            + self.partials.iter().map(|s| s.size).sum::<u64>()
            + self
                .other
                .iter()
                .filter(|s| !s.built)
                .map(|s| s.size)
                .sum::<u64>()
            + self.builds.iter().map(|b| b.total).sum::<u64>()
    }

    /// The archives held for each package, newest version first.
    ///
    /// This is the shape both halves of the command want: `status` counts the
    /// entries to say how many versions are held, and `clean` keeps the front
    /// of each list and retires the tail.
    pub fn by_package(&self) -> Vec<(&str, Vec<&Archive>)> {
        let mut grouped: HashMap<&str, Vec<&Archive>> = HashMap::new();
        for archive in &self.archives {
            grouped
                .entry(archive.package.as_str())
                .or_default()
                .push(archive);
        }

        let mut packages: Vec<(&str, Vec<&Archive>)> = grouped.into_iter().collect();
        for (_, archives) in &mut packages {
            archives.sort_by(|a, b| {
                // Newest version first. Two files claiming the same version --
                // a rebuild, or the same package in two cache directories --
                // are ordered by mtime so the one most recently put there
                // survives a `--keep 1`.
                vercmp(&b.version, &a.version)
                    .then_with(|| b.modified.cmp(&a.modified))
                    .then_with(|| a.path.cmp(&b.path))
            });
        }
        packages.sort_by(|a, b| a.0.cmp(b.0));
        packages
    }
}

/// What a clean is allowed to do.
pub struct Policy {
    /// How many versions of each package survive.
    pub keep: usize,
    /// Whether the AUR build trees go as well. Opt-in, always: see the module
    /// documentation for what is lost with them.
    pub builds: bool,
    /// `(package, version)` pairs that are installed right now and must
    /// survive whatever the count says.
    pub protected: HashSet<(String, String)>,
}

impl Policy {
    fn is_installed(&self, archive: &Archive) -> bool {
        self.protected
            .contains(&(archive.package.clone(), archive.version.clone()))
    }
}

/// An archive that has to leave a build tree before that tree is deleted.
///
/// It exists because the two halves of `--builds` disagree: the retention rule
/// says this version is worth keeping, and removing the tree would delete it.
/// A built archive has no mirror to be fetched from again, so the tree waits
/// until its keepers are out.
#[derive(Debug, Clone)]
pub struct Rescue {
    pub from: PathBuf,
    pub to: PathBuf,
    pub signature: Option<(PathBuf, PathBuf)>,
    /// Archive and signature together. Recorded here because it has to be
    /// subtracted from what removing the tree reclaims, and by then the file
    /// is no longer in the tree to be measured.
    pub size: u64,
}

/// One package's worth of archives the retention rule retires.
#[derive(Debug, Clone)]
pub struct Retired {
    pub package: String,
    pub version: String,
    pub built: bool,
    pub files: Vec<(PathBuf, u64)>,
}

impl Retired {
    pub fn size(&self) -> u64 {
        self.files.iter().map(|(_, size)| size).sum()
    }
}

/// Everything a clean would do, decided before anything is touched.
///
/// Built as a whole and reported before it is applied, so `--dry-run` is the
/// same decision as the real thing rather than a second code path that might
/// answer differently.
#[derive(Debug, Default)]
pub struct Sweep {
    pub rescue: Vec<Rescue>,
    pub retired: Vec<Retired>,
    pub partials: Vec<Stray>,
    pub trees: Vec<BuildTree>,
    /// How many archives the policy kept, for the sentence that says so.
    pub kept: usize,
    /// Bytes this sweep would reclaim, with anything rescued out of a build
    /// tree already subtracted.
    pub reclaimed: u64,
}

impl Sweep {
    pub fn is_empty(&self) -> bool {
        self.retired.is_empty() && self.partials.is_empty() && self.trees.is_empty()
    }
}

/// What applying a sweep actually managed to do.
#[derive(Debug, Default)]
pub struct Swept {
    pub freed: u64,
    pub archives: usize,
    pub partials: usize,
    pub trees: usize,
    pub rescued: usize,
    /// Whether anything failed because the caller may not write here. It is
    /// worth one sentence about sudo rather than the same permission error
    /// repeated once per archive.
    pub denied: bool,
    /// Anything that could not be deleted, named. A cache clean that cannot
    /// remove a file is a warning and not a failure -- nothing downstream
    /// depends on the space -- but staying quiet about it would leave somebody
    /// wondering why the number did not move.
    pub failures: Vec<String>,
}

/// Decides what a clean removes, without removing anything.
pub fn plan(inventory: &Inventory, policy: &Policy) -> Sweep {
    let mut sweep = Sweep::default();
    let cache_root = inventory.roots.first().cloned();
    let mut keeping: Vec<&Archive> = Vec::new();

    for (_, archives) in inventory.by_package() {
        for (index, archive) in archives.iter().enumerate() {
            // The installed version survives its position in the list. On a
            // machine where somebody has been testing a newer build, the
            // version that is actually running can easily be third or fourth
            // from the top, and deleting it is how a reinstall turns into a
            // download -- or, for an AUR package, into a rebuild.
            if index < policy.keep || policy.is_installed(archive) {
                keeping.push(archive);
                continue;
            }
            sweep.retired.push(Retired {
                package: archive.package.clone(),
                version: archive.version.clone(),
                built: archive.built,
                files: archive.files(),
            });
        }
    }

    sweep.kept = keeping.len();
    sweep.reclaimed += sweep.retired.iter().map(|r| r.size()).sum::<u64>();

    let now = SystemTime::now();
    for partial in &inventory.partials {
        if is_abandoned(partial, now) {
            sweep.reclaimed += partial.size;
            sweep.partials.push(partial.clone());
        }
    }

    if policy.builds {
        for tree in &inventory.builds {
            let mut rescued = 0;
            if let Some(root) = &cache_root {
                for archive in keeping.iter().filter(|a| a.path.starts_with(&tree.path)) {
                    rescued += archive.total();
                    sweep.rescue.push(rescue_into(archive, root));
                }
            }
            sweep.reclaimed += tree.total.saturating_sub(rescued);
            sweep.trees.push(tree.clone());
        }
    }

    sweep
}

/// Carries out a sweep, in the order that loses the least if it is
/// interrupted.
///
/// Rescues run first, and a tree whose rescue failed is left standing: the
/// whole reason to move an archive out is that the tree is about to take it
/// with it, so a failed move has to stop the deletion rather than be noted and
/// stepped over.
pub fn apply(sweep: &Sweep) -> Swept {
    let mut swept = Swept::default();
    let mut stranded: HashSet<PathBuf> = HashSet::new();

    for rescue in &sweep.rescue {
        match promote(&rescue.from, &rescue.to) {
            Ok(()) => {
                swept.rescued += 1;
                if let Some((from, to)) = &rescue.signature {
                    // A signature that will not follow its archive is not
                    // worth stopping for; the archive is what matters and an
                    // unsigned one still installs.
                    let _ = promote(from, to);
                }
            }
            Err(e) => {
                swept.denied |= e.kind() == std::io::ErrorKind::PermissionDenied;
                swept
                    .failures
                    .push(format!("could not move {} out: {e}", rescue.from.display()));
                stranded.insert(rescue.from.clone());
            }
        }
    }

    for retired in &sweep.retired {
        let mut removed_any = false;
        for (path, size) in &retired.files {
            match std::fs::remove_file(path) {
                Ok(()) => {
                    swept.freed += size;
                    removed_any = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    swept.denied |= e.kind() == std::io::ErrorKind::PermissionDenied;
                    swept
                        .failures
                        .push(format!("could not remove {}: {e}", path.display()));
                }
            }
        }
        if removed_any {
            swept.archives += 1;
        }
    }

    for partial in &sweep.partials {
        match std::fs::remove_file(&partial.path) {
            Ok(()) => {
                swept.freed += partial.size;
                swept.partials += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                swept.denied |= e.kind() == std::io::ErrorKind::PermissionDenied;
                swept
                    .failures
                    .push(format!("could not remove {}: {e}", partial.path.display()));
            }
        }
    }

    for tree in &sweep.trees {
        if stranded.iter().any(|path| path.starts_with(&tree.path)) {
            swept.failures.push(format!(
                "left {} alone: the package it built could not be moved to safety first",
                tree.path.display()
            ));
            continue;
        }
        let rescued: u64 = sweep
            .rescue
            .iter()
            .filter(|r| r.from.starts_with(&tree.path))
            .map(|r| r.size)
            .sum();
        match std::fs::remove_dir_all(&tree.path) {
            Ok(()) => {
                swept.freed += tree.total.saturating_sub(rescued);
                swept.trees += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                swept.denied |= e.kind() == std::io::ErrorKind::PermissionDenied;
                swept
                    .failures
                    .push(format!("could not remove {}: {e}", tree.path.display()));
            }
        }
    }

    swept
}

/// Moves a built archive into the cache proper.
///
/// This is the other half of the leak, and it is why it is a public function
/// rather than a detail of the sweep. An AUR archive that stays in its build
/// tree is invisible to every rule in this file: no retention count reaches
/// it, `rvn cache status` reports it as part of a build tree rather than as
/// the package it is, and the only thing that would ever delete it is a
/// sweep of the whole tree. Moved here, it is an ordinary cache entry and the
/// same rules that govern a downloaded archive govern it.
///
/// A rename is tried first and is what normally happens, since the build tree
/// is a subdirectory of the cache. The copy is for the case where somebody has
/// mounted them separately.
pub fn promote(from: &Path, to: &Path) -> std::io::Result<()> {
    if from == to {
        return Ok(());
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(from, to)?;
            std::fs::remove_file(from)
        }
    }
}

/// Where an archive sitting in a build tree belongs once it is kept.
pub fn promoted_path(archive: &Path, cache_root: &Path) -> PathBuf {
    match archive.file_name() {
        Some(name) => cache_root.join(name),
        None => archive.to_path_buf(),
    }
}

fn rescue_into(archive: &Archive, cache_root: &Path) -> Rescue {
    let to = promoted_path(&archive.path, cache_root);
    Rescue {
        signature: archive
            .signature
            .as_ref()
            .map(|sig| (sig.clone(), signature_path(&to))),
        from: archive.path.clone(),
        to,
        size: archive.total(),
    }
}

/// Whether a `.part` file is old enough to be certainly nobody's.
fn is_abandoned(partial: &Stray, now: SystemTime) -> bool {
    match partial.modified {
        Some(modified) => now
            .duration_since(modified)
            .map(|age| age >= ABANDONED_AFTER)
            // A file stamped in the future is a clock that has been put back,
            // not a download in flight; treat it as too uncertain to touch.
            .unwrap_or(false),
        None => false,
    }
}

/// The detached signature that sits beside a package archive.
fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".sig");
    PathBuf::from(name)
}

/// Splits `name-version-release-arch.pkg.tar.<ext>` into the package name and
/// the `version-release` string.
///
/// A package name may itself contain hyphens -- `ttf-material-design-icons-git`
/// is one -- so the name is whatever is left once the final three fields are
/// removed, and the version is the third-from-last joined to the
/// second-from-last. An epoch survives the round trip because it is written
/// into the version field as `2:1.22.0`, which is exactly what
/// [`crate::version::vercmp`] parses.
///
/// This is the one parser: [`crate::ops::install::package_name_from_filename`]
/// asks it for the name and throws the version away.
pub fn parse_archive_name(filename: &str) -> Option<(String, String)> {
    let stem = filename.split(".pkg.tar").next()?;
    let fields: Vec<&str> = stem.split('-').collect();
    if fields.len() < 4 {
        return None;
    }
    let cut = fields.len() - 3;
    Some((
        fields[..cut].join("-"),
        format!("{}-{}", fields[cut], fields[cut + 1]),
    ))
}

/// Total size of a directory tree, and every package archive found in it.
///
/// Symbolic links are counted by their own size and never followed: a build
/// tree can easily contain a link into /usr, and following it would both
/// inflate the number and, in a sweep, hand `remove_dir_all` a path outside
/// the cache.
///
/// A file with more than one link is counted once, which is why `seen` is
/// threaded through the whole walk rather than kept per directory. makepkg's
/// `pkg/` staging directory is full of hard links back into `src/`, and on
/// this machine counting them each time made the AUR trees read as 9.6 GB
/// when `du` -- and the disk -- said 8.1. Overstating what a sweep will
/// reclaim is the one arithmetic error here that would be noticed, because
/// the number printed afterwards would not match.
fn tree_size(
    root: &Path,
    seen: &mut HashSet<(u64, u64)>,
) -> (u64, Vec<(PathBuf, u64, Option<SystemTime>)>) {
    use std::os::unix::fs::MetadataExt;

    let mut total = 0;
    let mut archives = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                total += meta.len();
                stack.push(path);
                continue;
            }
            if meta.nlink() <= 1 || seen.insert((meta.dev(), meta.ino())) {
                total += meta.len();
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains(".pkg.tar") && !name.ends_with(".part") {
                archives.push((path, meta.len(), meta.modified().ok()));
            }
        }
    }

    (total, archives)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-cache-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    fn policy(keep: usize, installed: &[(&str, &str)]) -> Policy {
        Policy {
            keep,
            builds: false,
            protected: installed
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn a_name_with_hyphens_keeps_all_of_them_and_the_version_is_whole() {
        assert_eq!(
            parse_archive_name("foo-1.0-1-x86_64.pkg.tar.zst"),
            Some(("foo".into(), "1.0-1".into()))
        );
        assert_eq!(
            parse_archive_name("ttf-material-design-icons-git-v7.4.r0.g57b-1-any.pkg.tar.zst"),
            Some((
                "ttf-material-design-icons-git".into(),
                "v7.4.r0.g57b-1".into()
            ))
        );
        // An epoch stays in the version, where vercmp expects it.
        assert_eq!(
            parse_archive_name("go-2:1.22.0-1-x86_64.pkg.tar.zst"),
            Some(("go".into(), "2:1.22.0-1".into()))
        );
        assert_eq!(parse_archive_name("junk.pkg.tar.zst"), None);
    }

    #[test]
    fn versions_are_held_newest_first_whatever_order_they_arrived_in() {
        let dir = temp("order");
        write(&dir.join("foo-1.0.2-1-x86_64.pkg.tar.zst"), 10);
        write(&dir.join("foo-1.0.10-1-x86_64.pkg.tar.zst"), 10);
        write(&dir.join("foo-1.0.9-1-x86_64.pkg.tar.zst"), 10);

        let inventory = Inventory::scan(std::slice::from_ref(&dir));
        let grouped = inventory.by_package();
        let versions: Vec<&str> = grouped[0].1.iter().map(|a| a.version.as_str()).collect();
        // Not lexical order, and not mtime order: 1.0.10 is the newest.
        assert_eq!(versions, vec!["1.0.10-1", "1.0.9-1", "1.0.2-1"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_signature_is_deleted_with_the_archive_it_signs() {
        let dir = temp("signatures");
        write(&dir.join("foo-1.0-1-x86_64.pkg.tar.zst"), 100);
        write(&dir.join("foo-1.0-1-x86_64.pkg.tar.zst.sig"), 10);
        write(&dir.join("foo-2.0-1-x86_64.pkg.tar.zst"), 100);
        write(&dir.join("foo-2.0-1-x86_64.pkg.tar.zst.sig"), 10);

        let inventory = Inventory::scan(std::slice::from_ref(&dir));
        assert_eq!(inventory.archives.len(), 2);
        assert!(inventory.other.is_empty(), "a paired .sig is not a stray");

        let sweep = plan(&inventory, &policy(1, &[]));
        assert_eq!(sweep.retired.len(), 1);
        assert_eq!(sweep.retired[0].version, "1.0-1");
        assert_eq!(sweep.reclaimed, 110);

        let swept = apply(&sweep);
        assert_eq!(swept.freed, 110);
        assert!(swept.failures.is_empty());
        assert!(!dir.join("foo-1.0-1-x86_64.pkg.tar.zst.sig").exists());
        assert!(dir.join("foo-2.0-1-x86_64.pkg.tar.zst").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_installed_version_survives_however_old_it_is() {
        let dir = temp("installed");
        for version in ["1.0", "2.0", "3.0", "4.0"] {
            write(&dir.join(format!("foo-{version}-1-x86_64.pkg.tar.zst")), 10);
        }

        let inventory = Inventory::scan(std::slice::from_ref(&dir));
        // Keeping one would leave 4.0 alone; 1.0-1 is what is running.
        let sweep = plan(&inventory, &policy(1, &[("foo", "1.0-1")]));
        let gone: Vec<&str> = sweep.retired.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(gone, vec!["3.0-1", "2.0-1"]);
        assert_eq!(sweep.kept, 2);

        // Even --keep 0 leaves it: a machine with no copy of what it is
        // running cannot reinstall it without the network.
        let sweep = plan(&inventory, &policy(0, &[("foo", "1.0-1")]));
        assert_eq!(sweep.retired.len(), 3);
        assert!(sweep.retired.iter().all(|r| r.version != "1.0-1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unparseable_archive_is_never_touched() {
        let dir = temp("unparseable");
        write(&dir.join("junk.pkg.tar.zst"), 500);
        write(&dir.join("foo-1.0-1-x86_64.pkg.tar.zst"), 10);

        let inventory = Inventory::scan(std::slice::from_ref(&dir));
        assert_eq!(inventory.archives.len(), 1);
        assert_eq!(inventory.other.len(), 1);

        let sweep = plan(&inventory, &policy(0, &[]));
        assert!(
            sweep
                .retired
                .iter()
                .all(|r| !r.files.iter().any(|(p, _)| p.ends_with("junk.pkg.tar.zst")))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_trees_are_left_alone_unless_they_are_asked_for() {
        let dir = temp("builds");
        let tree = dir.join("aur").join("brave-bin");
        write(&tree.join("src").join("blob"), 1000);
        write(&tree.join("brave-bin-1.0-1-x86_64.pkg.tar.zst"), 100);

        let inventory = Inventory::scan(std::slice::from_ref(&dir));
        assert_eq!(inventory.builds.len(), 1);
        assert_eq!(inventory.builds[0].artifacts, 100);
        assert_eq!(
            inventory.builds[0].sources(),
            inventory.builds[0].total - 100
        );
        assert!(inventory.archives[0].built);

        // The default sweep does not mention it at all.
        let sweep = plan(&inventory, &policy(0, &[]));
        assert!(sweep.trees.is_empty());
        assert!(sweep.rescue.is_empty());
        assert!(tree.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_kept_build_leaves_the_tree_before_the_tree_is_deleted() {
        let dir = temp("rescue");
        let tree = dir.join("aur").join("brave-bin");
        write(&tree.join("src").join("blob"), 1000);
        write(&tree.join("brave-bin-1.0-1-x86_64.pkg.tar.zst"), 100);

        let inventory = Inventory::scan(std::slice::from_ref(&dir));
        let sweep = plan(
            &inventory,
            &Policy {
                keep: 1,
                builds: true,
                protected: HashSet::new(),
            },
        );
        assert_eq!(sweep.rescue.len(), 1);
        assert_eq!(sweep.trees.len(), 1);

        let swept = apply(&sweep);
        assert!(swept.failures.is_empty(), "{:?}", swept.failures);
        assert_eq!(swept.rescued, 1);
        assert!(!tree.exists(), "the tree goes");
        assert!(
            dir.join("brave-bin-1.0-1-x86_64.pkg.tar.zst").exists(),
            "the only copy of a built package does not"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_download_still_in_flight_is_not_swept_away() {
        let dir = temp("partials");
        write(&dir.join("foo-1.0-1-x86_64.pkg.tar.zst.part"), 50);

        let inventory = Inventory::scan(std::slice::from_ref(&dir));
        assert_eq!(inventory.partials.len(), 1);

        // Written a moment ago, so it may well be somebody's live download.
        let sweep = plan(&inventory, &policy(2, &[]));
        assert!(sweep.partials.is_empty());

        let old = Stray {
            path: dir.join("old.part"),
            size: 1,
            modified: Some(SystemTime::now() - ABANDONED_AFTER - Duration::from_secs(1)),
            built: false,
        };
        assert!(is_abandoned(&old, SystemTime::now()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_built_package_moved_into_the_cache_becomes_an_ordinary_entry() {
        // This is what `--keep-cache` does with an AUR build, and the point of
        // it: before the move the archive is part of a build tree and no
        // retention rule can see it; after, it is a version of its package
        // like any other.
        let dir = temp("promote");
        let built = dir.join("aur/brave-bin/brave-bin-1.5-1-x86_64.pkg.tar.zst");
        write(&built, 120);

        let destination = promoted_path(&built, &dir);
        assert_eq!(destination, dir.join("brave-bin-1.5-1-x86_64.pkg.tar.zst"));
        promote(&built, &destination).unwrap();
        assert!(!built.exists());

        let inventory = Inventory::scan(std::slice::from_ref(&dir));
        let archive = &inventory.archives[0];
        assert_eq!(archive.package, "brave-bin");
        assert_eq!(archive.version, "1.5-1");
        assert!(!archive.built, "it is in the cache proper now");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_cache_directory_is_empty_rather_than_unreadable() {
        let inventory = Inventory::scan(&[PathBuf::from("/nonexistent/rvn-cache")]);
        assert!(inventory.unreadable.is_empty());
        assert_eq!(inventory.total(), 0);
    }
}
