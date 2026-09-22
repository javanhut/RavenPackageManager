//! Turning a `package.toml` into a `.pkg.tar.zst` rvn can install.
//!
//! Until now rvn has only ever read archives. Everything it installs was made
//! by somebody else -- an Arch mirror, or `makepkg` running on this machine
//! against a PKGBUILD from the AUR. RavenLinux's own userland is in neither
//! category: huginn, ravend, raven-init, roostbar and rvn itself are put into
//! the sysroot by `install -m 0755` from a shell script, so no package owns
//! them. That has four consequences and all of them are felt. There is no
//! version to ask for, so `rvn list` cannot say what is installed. There is
//! no `.MTREE`, so `pacman -Qkk` cannot say whether a file was altered. There
//! is no file list, so there is no uninstall. And there is no archive, so
//! there is no upgrade path that is not another run of the whole image build.
//!
//! The manifests already exist. `RavenLinux/packages/*/*/package.toml`
//! describes each component -- where its source is, how to build it, and
//! which built files go where with which mode -- and nothing has ever read
//! them. This module reads them and produces a package, so the thing that
//! installs RavenLinux's own software is the thing that installs everything
//! else.
//!
//! # What is produced, and why it has to be exact
//!
//! A package is an archive of four parts: `.PKGINFO`, which is the metadata
//! [`crate::extract::parse_pkginfo`] reads back; `.MTREE`, which is a
//! gzip-compressed listing of every payload entry with its size, mode, mtime
//! and SHA-256; an optional `.INSTALL` scriptlet; and the payload itself.
//!
//! The `.MTREE` is the part with no margin for error. `rvn` stores it
//! verbatim in the local database (see
//! [`crate::db::local::LocalDb::register_with_mtree`]) and `pacman -Qkk`
//! reads it back and compares every recorded field against the file on disk.
//! A `time=` that does not match the tar header's mtime makes every file in
//! the package report as altered, which is not a cosmetic failure: README.md
//! advertises that `pacman -Qkk` passes on a machine rvn installed, and a
//! package that breaks it makes the one tool anybody would use to check for
//! tampering useless. Everything in here is stamped from a single build
//! timestamp for exactly that reason -- the tar header and the mtree entry
//! cannot disagree if there is only one value.
//!
//! # Compression is `zstd`, the program
//!
//! The crate's zstd dependency is `ruzstd`, which decodes and cannot encode.
//! Packaging therefore needs either a second, encoding zstd crate or the
//! `zstd` binary. It shells out to the binary, and the argument is not just
//! that it is a smaller change. `rvn build` is a build-time command: it runs
//! on a machine that already has a Rust toolchain, `cargo`, `go` and `make`
//! on it, because the manifests it reads tell it to run them. A dependency
//! bought for that command would be linked into every `rvn install` on every
//! installed machine, where nothing would ever call it, and the one thing
//! this crate is careful about is what a package manager drags along with it.
//! `zstd` is present in the build container and on any machine that can build
//! a package at all; if it is missing, that is said plainly rather than
//! worked around.

use crate::toml::{Document, Table, Value};
use crate::verify::sha256_file;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// The architecture a package is built for when the manifest does not say.
///
/// Manifests do not carry an `arch` today -- every one of them cross-builds
/// to `x86_64-unknown-linux-musl` and says so in `[build] target` -- so the
/// value is taken from the target triple when there is one and falls back to
/// the machine's own. `any` is available for a package of scripts and data,
/// and is what pacman uses for the same thing.
const DEFAULT_ARCH: &str = "x86_64";

/// The default `pkgrel`.
///
/// Manifests carry an upstream `version` and no release number, because until
/// now nothing downstream of them could be rebuilt independently of upstream.
/// A package can be: the same source rebuilt against a newer libc is a new
/// package and has to sort as newer, which is exactly what `pkgrel` is for.
/// `--release` on the command line sets it; the manifest keeps saying what
/// upstream calls the version and nothing more.
const DEFAULT_RELEASE: &str = "1";

#[derive(Debug)]
pub enum Error {
    /// The manifest could not be read or does not parse. Carries the path so
    /// a build of forty packages says which one.
    Manifest { path: PathBuf, message: String },
    /// A file the manifest says to install is not where it says it is. This
    /// is the common failure and it is almost always "the build has not run
    /// yet", so the message says so.
    MissingFile { src: PathBuf, dest: String },
    /// A build command exited non-zero, with its last output.
    BuildFailed { system: String, message: String },
    /// A program the build needs is not installed.
    MissingProgram { program: String, needed_for: String },
    Io {
        doing: String,
        source: std::io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Manifest { path, message } => write!(f, "{}: {message}", path.display()),
            Error::MissingFile { src, dest } => write!(
                f,
                "{} is not there, so {dest} cannot be packaged — build the component first, or drop --no-build",
                src.display()
            ),
            Error::BuildFailed { system, message } => {
                write!(f, "the {system} build failed: {message}")
            }
            Error::MissingProgram {
                program,
                needed_for,
            } => write!(
                f,
                "{program} is not installed, and {needed_for} needs it — install it and retry"
            ),
            Error::Io { doing, source } => write!(f, "{doing}: {source}"),
        }
    }
}

fn io(doing: impl Into<String>) -> impl FnOnce(std::io::Error) -> Error {
    let doing = doing.into();
    move |source| Error::Io { doing, source }
}

/// The build system a component is built with.
///
/// `None` is not a placeholder: a package of configuration files, scripts or
/// firmware has nothing to compile, and saying `system = "none"` is how a
/// manifest states that rather than leaving the key out and being guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum System {
    Cargo,
    Go,
    Make,
    /// A script in the source tree does the build. `evdi` is the reason: it is
    /// an out-of-tree kernel module built against a kernel tree that only the
    /// image build knows where to find.
    Custom,
    None,
}

impl System {
    fn parse(text: &str) -> Option<System> {
        match text {
            "cargo" => Some(System::Cargo),
            "go" => Some(System::Go),
            "make" => Some(System::Make),
            "custom" => Some(System::Custom),
            "none" => Some(System::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            System::Cargo => "cargo",
            System::Go => "go",
            System::Make => "make",
            System::Custom => "custom",
            System::None => "none",
        }
    }
}

/// How to build the component, from `[build]`.
#[derive(Debug, Default)]
pub struct Build {
    pub system: Option<System>,
    /// `[build] target`. A Rust target triple for cargo, the package
    /// directory for go, and unused elsewhere -- the key means different
    /// things per system because that is how the manifests already use it.
    pub target: Option<String>,
    pub flags: Vec<String>,
    /// `[build] env`, applied on top of the inherited environment.
    pub env: Vec<(String, String)>,
    /// `[build] package`: the workspace member to build, for a cargo
    /// workspace whose binary is not the root crate.
    pub package: Option<String>,
    /// `[build] script`, for `system = "custom"`.
    pub script: Option<String>,
}

/// One file the package installs.
#[derive(Debug, Clone)]
pub struct InstallFile {
    /// Where it is in the built source tree, relative to the manifest.
    pub src: PathBuf,
    /// Where it goes, relative to the install root and with no leading
    /// slash -- `usr/bin/rvn`. The manifests write it absolute and it is
    /// normalised on the way in, because a package's payload paths are
    /// root-relative and an absolute one in a tar is how an archive escapes
    /// its root.
    pub dest: String,
    pub mode: u32,
}

/// One symlink the package creates.
#[derive(Debug, Clone)]
pub struct Symlink {
    pub dest: String,
    pub target: String,
}

/// One directory the package owns even though it ships nothing in it.
#[derive(Debug, Clone)]
pub struct Directory {
    pub path: String,
    pub mode: u32,
}

/// A parsed `package.toml`.
#[derive(Debug)]
pub struct Manifest {
    /// The directory the manifest was read from. Every `src` is relative to
    /// it, and it is where a build runs unless `[build] source_dir` moves it.
    pub root: PathBuf,
    pub name: String,
    pub version: String,
    pub release: String,
    pub epoch: Option<String>,
    pub description: String,
    pub url: Option<String>,
    pub licenses: Vec<String>,
    /// `[package] categories`, which become pacman's `%GROUPS%`. They are the
    /// same idea under two names: "everything tagged raven" is a group.
    pub groups: Vec<String>,
    pub packager: Option<String>,
    pub arch: String,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub optdepends: Vec<String>,
    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
    pub replaces: Vec<String>,
    /// Configuration files that must survive an upgrade, becoming `backup`
    /// in `.PKGINFO`. Written root-relative, as pacman records them.
    pub backup: Vec<String>,
    pub build: Build,
    pub files: Vec<InstallFile>,
    pub symlinks: Vec<Symlink>,
    pub directories: Vec<Directory>,
    /// `[install] script`: a scriptlet shipped as `.INSTALL`.
    pub script: Option<PathBuf>,
}

/// The sections and keys a manifest may use.
///
/// Refused by name rather than ignored, the way [`crate::policy`] and
/// [`crate::txhooks`] refuse theirs. A manifest is a description of a package
/// somebody will install on other people's machines; a key that is quietly
/// dropped because it was misspelled is a file that quietly does not get
/// installed, and the first anyone hears of it is a missing binary.
const SECTIONS: &[(&str, &[&str])] = &[
    (
        "package",
        &[
            "name",
            "version",
            "release",
            "epoch",
            "description",
            "license",
            "licenses",
            "homepage",
            "repository",
            "maintainers",
            "categories",
            "arch",
        ],
    ),
    // Read but not acted on: rvn packages a tree that is already checked out,
    // and fetching the source is the build system's job. They are listed so a
    // manifest that carries them is not refused for having them.
    (
        "source",
        &["type", "url", "commit", "tag", "branch", "sha256"],
    ),
    (
        "build",
        &[
            "system",
            "target",
            "build_flags",
            "env",
            "package",
            "script",
        ],
    ),
    (
        "dependencies",
        &[
            "runtime",
            "build",
            "optional",
            "provides",
            "conflicts",
            "replaces",
        ],
    ),
    (
        "install",
        &["files", "symlinks", "directories", "backup", "script"],
    ),
];

impl Manifest {
    /// Reads a `package.toml`.
    pub fn read(path: &Path) -> Result<Manifest, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Manifest {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        let document = Document::parse(&text).map_err(|e| Error::Manifest {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        let root = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();

        Manifest::from_document(&document, root).map_err(|message| Error::Manifest {
            path: path.to_path_buf(),
            message,
        })
    }

    fn from_document(document: &Document, root: PathBuf) -> Result<Manifest, String> {
        for section in document.sections() {
            if section.name.is_empty() {
                if !section.is_empty() {
                    return Err(format!(
                        "line {}: keys before the first [section]; every key in a manifest belongs to one",
                        section.line + 1
                    ));
                }
                continue;
            }
            let Some((_, keys)) = SECTIONS.iter().find(|(name, _)| *name == section.name) else {
                return Err(format!(
                    "line {}: [{}] is not a section a manifest has; the sections are {}",
                    section.line,
                    section.name,
                    SECTIONS
                        .iter()
                        .map(|(name, _)| format!("[{name}]"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            };
            for key in section.keys() {
                if !keys.contains(&key) {
                    return Err(format!(
                        "line {}: `{key}` is not a key [{}] has",
                        section.line_of(key),
                        section.name
                    ));
                }
            }
        }

        let package = document
            .section("package")
            .ok_or("a manifest needs a [package] section saying at least name and version")?;
        let name = string(package.get("name"), package.line_of("name"), "name")?
            .ok_or_else(|| format!("line {}: [package] needs a name", package.line))?;
        let version = string(
            package.get("version"),
            package.line_of("version"),
            "version",
        )?
        .ok_or_else(|| format!("line {}: [package] needs a version", package.line))?;

        // The version is what goes into a filename and into every comparison
        // `crate::version::vercmp` will ever make about this package, so the
        // characters pacman reserves are refused here rather than producing
        // an archive whose name cannot be parsed back.
        for (label, value) in [("name", &name), ("version", &version)] {
            if value.is_empty() {
                return Err(format!("line {}: the {label} is empty", package.line));
            }
            if value.contains('/') || value.contains(' ') {
                return Err(format!(
                    "line {}: the {label} `{value}` has a space or a slash in it, which a package filename cannot carry",
                    package.line
                ));
            }
        }
        if version.contains('-') {
            return Err(format!(
                "line {}: the version `{version}` has a `-` in it; that character separates the version from the release, so write the release as `release = \"...\"`",
                package.line_of("version")
            ));
        }

        let build = document.section("build");
        let target = build
            .and_then(|s| s.get("target"))
            .and_then(Value::as_str)
            .map(str::to_string);

        let manifest = Manifest {
            name,
            version,
            release: string(
                package.get("release"),
                package.line_of("release"),
                "release",
            )?
            .unwrap_or_else(|| DEFAULT_RELEASE.to_string()),
            epoch: string(package.get("epoch"), package.line_of("epoch"), "epoch")?,
            description: string(
                package.get("description"),
                package.line_of("description"),
                "description",
            )?
            .unwrap_or_default(),
            // `homepage` is what the manifests write; pacman calls the same
            // thing `url` and so does everything downstream of it.
            url: string(
                package.get("homepage"),
                package.line_of("homepage"),
                "homepage",
            )?,
            licenses: strings(
                package.get("license"),
                package.line_of("license"),
                "license",
            )?
            .into_iter()
            .chain(strings(
                package.get("licenses"),
                package.line_of("licenses"),
                "licenses",
            )?)
            .collect(),
            groups: strings(
                package.get("categories"),
                package.line_of("categories"),
                "categories",
            )?,
            // One `%PACKAGER%` line, so several maintainers are joined rather
            // than silently reduced to the first.
            packager: {
                let maintainers = strings(
                    package.get("maintainers"),
                    package.line_of("maintainers"),
                    "maintainers",
                )?;
                (!maintainers.is_empty()).then(|| maintainers.join(", "))
            },
            arch: string(package.get("arch"), package.line_of("arch"), "arch")?
                .or_else(|| target.as_deref().and_then(arch_from_target))
                .unwrap_or_else(|| DEFAULT_ARCH.to_string()),
            depends: section_list(document, "dependencies", "runtime")?,
            makedepends: section_list(document, "dependencies", "build")?,
            optdepends: section_list(document, "dependencies", "optional")?,
            provides: section_list(document, "dependencies", "provides")?,
            conflicts: section_list(document, "dependencies", "conflicts")?,
            replaces: section_list(document, "dependencies", "replaces")?,
            backup: section_list(document, "install", "backup")?
                .iter()
                .map(|p| normalise_dest(p))
                .collect(),
            build: read_build(document, target)?,
            files: read_files(document)?,
            symlinks: read_symlinks(document)?,
            directories: read_directories(document)?,
            script: document
                .section("install")
                .and_then(|s| s.get("script"))
                .and_then(Value::as_str)
                .map(|s| root.join(s)),
            root,
        };

        if manifest.files.is_empty() && manifest.symlinks.is_empty() {
            return Err(
                "the manifest installs nothing: [install] needs a `files` or `symlinks` entry"
                    .to_string(),
            );
        }

        Ok(manifest)
    }

    /// The version as pacman writes it: `epoch:version-release`.
    pub fn full_version(&self) -> String {
        match &self.epoch {
            Some(epoch) => format!("{epoch}:{}-{}", self.version, self.release),
            None => format!("{}-{}", self.version, self.release),
        }
    }

    /// The archive filename, which is also how [`crate::cache`] and
    /// [`crate::ops::install::package_name_from_filename`] read the name and
    /// version back out.
    pub fn filename(&self) -> String {
        format!(
            "{}-{}-{}.pkg.tar.zst",
            self.name,
            self.full_version(),
            self.arch
        )
    }
}

/// The architecture inside a target triple, so a manifest that already says
/// `x86_64-unknown-linux-musl` does not have to repeat itself.
fn arch_from_target(target: &str) -> Option<String> {
    let arch = target.split('-').next()?;
    (!arch.is_empty()).then(|| arch.to_string())
}

fn string(value: Option<&Value>, line: usize, key: &str) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(other) => Err(format!(
            "line {line}: `{key}` is a string, not {}",
            other.kind()
        )),
    }
}

fn strings(value: Option<&Value>, line: usize, key: &str) -> Result<Vec<String>, String> {
    match value {
        None => Ok(Vec::new()),
        Some(value) => value.as_strings().ok_or_else(|| {
            format!(
                "line {line}: `{key}` is a list of strings, not {}",
                value.kind()
            )
        }),
    }
}

fn section_list(document: &Document, section: &str, key: &str) -> Result<Vec<String>, String> {
    let Some(section) = document.section(section) else {
        return Ok(Vec::new());
    };
    strings(section.get(key), section.line_of(key), key)
}

fn read_build(document: &Document, target: Option<String>) -> Result<Build, String> {
    let Some(section) = document.section("build") else {
        return Ok(Build::default());
    };

    let system = match section.get("system") {
        None => None,
        Some(Value::String(text)) => Some(System::parse(text).ok_or_else(|| {
            format!(
                "line {}: `{text}` is not a build system rvn runs: cargo, go, make, custom or none",
                section.line_of("system")
            )
        })?),
        Some(other) => {
            return Err(format!(
                "line {}: `system` is a string, not {}",
                section.line_of("system"),
                other.kind()
            ));
        }
    };

    // `env` is the one place a manifest uses an inline table for something
    // other than a file list, and every value in it becomes an environment
    // variable, so a number written without quotes would arrive as a string
    // anyway. Saying so is better than converting it silently.
    let mut env = Vec::new();
    if let Some(value) = section.get("env") {
        let table = value.as_table().ok_or_else(|| {
            format!(
                "line {}: `env` is a {{ NAME = \"value\" }} table, not {}",
                section.line_of("env"),
                value.kind()
            )
        })?;
        for key in table.keys() {
            let entry = table.get(key).expect("keys() only names keys that are set");
            let text = entry.as_str().ok_or_else(|| {
                format!(
                    "line {}: `env.{key}` is a string, not {} — an environment variable is text",
                    section.line_of("env"),
                    entry.kind()
                )
            })?;
            env.push((key.to_string(), text.to_string()));
        }
    }

    Ok(Build {
        system,
        target,
        flags: strings(
            section.get("build_flags"),
            section.line_of("build_flags"),
            "build_flags",
        )?,
        env,
        package: string(
            section.get("package"),
            section.line_of("package"),
            "package",
        )?,
        script: string(section.get("script"), section.line_of("script"), "script")?,
    })
}

/// A mode written in a manifest.
///
/// `mode = 755` is decimal in TOML and octal to everybody who writes it, and
/// there is no reading of `755` that means decimal 755 -- it is not a valid
/// mode. The digits are therefore re-read as octal, and a digit that cannot
/// be octal is refused rather than masked off into something plausible.
fn mode(table: &Table, line: usize, dest: &str, default: u32) -> Result<u32, String> {
    let Some(value) = table.get("mode") else {
        return Ok(default);
    };
    let digits = match value {
        Value::Integer(number) => number.to_string(),
        Value::String(text) => text.clone(),
        other => {
            return Err(format!(
                "line {line}: the mode for {dest} is {}, not a number like 755",
                other.kind()
            ));
        }
    };
    u32::from_str_radix(digits.trim_start_matches("0o"), 8).map_err(|_| {
        format!("line {line}: `{digits}` is not a mode for {dest}; write it as octal, e.g. 755")
    })
}

/// A payload path, root-relative and with no `.` or `..` in it.
///
/// Manifests write `dest = "/usr/bin/rvn"` because that is where the file
/// ends up on a running machine, but inside an archive the same path must be
/// relative: an absolute member is how a tar escapes the root it is being
/// unpacked into, and [`crate::extract::safe_relative`] refuses one on the
/// way back in. Normalising here means the manifest stays readable and the
/// archive stays safe.
fn normalise_dest(dest: &str) -> String {
    let path = Path::new(dest);
    let mut out = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part.to_string_lossy().to_string()),
            // `.` is noise and `..` cannot be honoured, so both are dropped;
            // what is left is checked by the caller against the manifest's
            // own text, so a `..` that mattered does not pass silently.
            Component::CurDir | Component::ParentDir => {}
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    out.join("/")
}

fn checked_dest(raw: &str, line: usize) -> Result<String, String> {
    if raw.contains("..") {
        return Err(format!(
            "line {line}: `{raw}` contains `..`; a package's paths are relative to the install root and cannot climb out of it"
        ));
    }
    let dest = normalise_dest(raw);
    if dest.is_empty() {
        return Err(format!("line {line}: `{raw}` is not a path to install to"));
    }
    Ok(dest)
}

fn read_files(document: &Document) -> Result<Vec<InstallFile>, String> {
    let Some(section) = document.section("install") else {
        return Ok(Vec::new());
    };
    let Some(value) = section.get("files") else {
        return Ok(Vec::new());
    };
    let line = section.line_of("files");
    let tables = value.as_tables().ok_or_else(|| {
        format!(
            "line {line}: `files` is a list of {{ src = \"...\", dest = \"...\", mode = 755 }} tables, not {}",
            value.kind()
        )
    })?;

    let mut files = Vec::new();
    for table in tables {
        for key in table.keys() {
            if !["src", "dest", "mode"].contains(&key) {
                return Err(format!(
                    "line {line}: an [install] file has `{key}`, which is not one of src, dest or mode"
                ));
            }
        }
        let src = table
            .get("src")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("line {line}: an [install] file has no `src`"))?;
        let dest = table
            .get("dest")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("line {line}: an [install] file has no `dest`"))?;
        let dest = checked_dest(dest, line)?;
        // 644 rather than 755: most of what a package ships is data, and a
        // file that has to be executable is one whose manifest says so.
        let mode = mode(table, line, &dest, 0o644)?;
        files.push(InstallFile {
            src: PathBuf::from(src),
            dest,
            mode,
        });
    }
    Ok(files)
}

fn read_symlinks(document: &Document) -> Result<Vec<Symlink>, String> {
    let Some(section) = document.section("install") else {
        return Ok(Vec::new());
    };
    let Some(value) = section.get("symlinks") else {
        return Ok(Vec::new());
    };
    let line = section.line_of("symlinks");
    let tables = value.as_tables().ok_or_else(|| {
        format!(
            "line {line}: `symlinks` is a list of {{ dest = \"...\", target = \"...\" }} tables, not {}",
            value.kind()
        )
    })?;

    let mut links = Vec::new();
    for table in tables {
        for key in table.keys() {
            if !["dest", "target"].contains(&key) {
                return Err(format!(
                    "line {line}: an [install] symlink has `{key}`, which is not one of dest or target"
                ));
            }
        }
        let dest = table
            .get("dest")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("line {line}: an [install] symlink has no `dest`"))?;
        let target = table
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("line {line}: an [install] symlink has no `target`"))?;
        links.push(Symlink {
            dest: checked_dest(dest, line)?,
            // Not normalised: a symlink target is resolved by the kernel
            // relative to the link, and `../lib/x.so` is a correct and common
            // way to write one.
            target: target.to_string(),
        });
    }
    Ok(links)
}

fn read_directories(document: &Document) -> Result<Vec<Directory>, String> {
    let Some(section) = document.section("install") else {
        return Ok(Vec::new());
    };
    let Some(value) = section.get("directories") else {
        return Ok(Vec::new());
    };
    let line = section.line_of("directories");
    let Value::Array(items) = value else {
        return Err(format!(
            "line {line}: `directories` is a list, not {}",
            value.kind()
        ));
    };

    let mut directories = Vec::new();
    for item in items {
        // Both forms are read: a bare path, which is what every manifest
        // writes today, and `{ path = "...", mode = 700 }` for a directory
        // whose mode is the point of declaring it. caw's /var/lib/caw is
        // exactly that case -- its manifest records 0700 in a comment because
        // there was nowhere to write it.
        let (path, mode) = match item {
            Value::String(path) => (path.clone(), 0o755),
            Value::Table(table) => {
                for key in table.keys() {
                    if !["path", "mode"].contains(&key) {
                        return Err(format!(
                            "line {line}: an [install] directory has `{key}`, which is not one of path or mode"
                        ));
                    }
                }
                let path = table
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("line {line}: an [install] directory has no `path`"))?
                    .to_string();
                let mode = mode(table, line, &path, 0o755)?;
                (path, mode)
            }
            other => {
                return Err(format!(
                    "line {line}: a directory is a path or a {{ path = \"...\", mode = 755 }} table, not {}",
                    other.kind()
                ));
            }
        };
        directories.push(Directory {
            path: checked_dest(&path, line)?,
            mode,
        });
    }
    Ok(directories)
}

/// What a payload entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Dir,
    File { size: u64, sha256: String },
    Link { target: String },
}

/// One entry in both the tar and the `.MTREE`.
///
/// The two listings are built from one vector rather than from two walks of
/// the staging directory, because the only way they can disagree is if
/// something reads the tree twice. A size or an mtime that differs between
/// them is the failure this module exists to avoid.
#[derive(Debug, Clone)]
struct Entry {
    /// Root-relative, no leading `./`.
    path: String,
    mode: u32,
    kind: Kind,
    /// Where the bytes are, for a file. Directories and links have none.
    source: Option<PathBuf>,
}

/// A staged package: the tree as it will be installed, plus the listing.
struct Staging {
    dir: PathBuf,
    entries: Vec<Entry>,
    /// Sum of the payload's regular files, which is `size` in `.PKGINFO` and
    /// `%ISIZE%` in a repository database.
    installed_size: u64,
}

impl Drop for Staging {
    /// The staging tree is rvn's own scratch space and is removed whichever
    /// way packaging ends. It is dropped rather than deleted at the end of
    /// the happy path so that a failure half-way through -- a missing file,
    /// a `zstd` that is not installed -- does not leave a fakeroot tree
    /// behind for somebody to find later and wonder about.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// How a package is built.
pub struct Options {
    /// Where the finished archive goes.
    pub outdir: PathBuf,
    /// Run `[build]` before staging. Off means the tree is already built,
    /// which is how the image build will call this: it compiles every
    /// component itself and then wants them packaged.
    pub run_build: bool,
    /// The built source tree every `src` is relative to, when it is not the
    /// directory the manifest sits in.
    ///
    /// This is not a convenience, it is the only way the RavenLinux manifests
    /// work at all. `packages/raven/rvn/package.toml` holds nothing but the
    /// manifest, and its `src = "target/x86_64-unknown-linux-musl/release/rvn"`
    /// names a path inside a checkout of RavenPackageManager that the build
    /// scripts clone somewhere else entirely -- `raven_fetch_repo` takes the
    /// destination as an argument and it is never the manifest's directory.
    /// So the manifest says *what* to package and this says *where the built
    /// tree is*, and the image build passes the checkout it just compiled.
    ///
    /// Unset means the manifest's own directory, which is right for a
    /// manifest that lives in the tree it describes.
    pub source_dir: Option<PathBuf>,
    /// The timestamp stamped on every entry and recorded as `builddate`.
    ///
    /// One value for the whole package, and settable so a reproducible build
    /// can pass `SOURCE_DATE_EPOCH` and get the same bytes twice.
    pub timestamp: u64,
}

impl Options {
    pub fn new(outdir: PathBuf) -> Options {
        Options {
            outdir,
            run_build: true,
            source_dir: None,
            timestamp: source_date_epoch().unwrap_or_else(now),
        }
    }

    /// The tree `src` paths, a `custom` script and the build command all
    /// resolve against.
    fn source_root<'a>(&'a self, manifest: &'a Manifest) -> &'a Path {
        self.source_dir.as_deref().unwrap_or(&manifest.root)
    }
}

/// `SOURCE_DATE_EPOCH`, the convention every reproducible-build toolchain
/// already reads, including the one [`crate::ops::install::BUILD_ENV_PASSTHROUGH`]
/// lets through to makepkg.
fn source_date_epoch() -> Option<u64> {
    std::env::var("SOURCE_DATE_EPOCH").ok()?.trim().parse().ok()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A finished package.
#[derive(Debug)]
pub struct Built {
    pub path: PathBuf,
    pub name: String,
    pub version: String,
    pub arch: String,
    /// The archive's own size on disk, which is `%CSIZE%` in a repository
    /// database.
    pub csize: u64,
    /// What it unpacks to, which is `%ISIZE%`.
    pub isize: u64,
    pub sha256: String,
    pub files: usize,
}

/// Builds, stages and packages one manifest.
///
/// `note` is called with each step as it starts, so a caller with a terminal
/// can show progress without this module knowing what a terminal is.
pub fn package(
    manifest: &Manifest,
    options: &Options,
    note: &mut dyn FnMut(&str),
) -> Result<Built, Error> {
    if options.run_build {
        run_build(manifest, options, note)?;
    }

    note("staging files");
    let staging = stage(manifest, options)?;

    note("writing metadata");
    let pkginfo = pkginfo(manifest, &staging, options.timestamp);
    std::fs::write(staging.dir.join(".PKGINFO"), &pkginfo)
        .map_err(io("writing .PKGINFO into the staging tree"))?;

    let script = match &manifest.script {
        Some(path) => Some(
            std::fs::read(path)
                .map_err(io(format!("reading the install script {}", path.display())))?,
        ),
        None => None,
    };

    // The mtree describes `.PKGINFO`, `.INSTALL` and the payload, and not
    // itself: it cannot record its own hash, and makepkg's does not either.
    let mut metadata: Vec<(String, Vec<u8>)> = vec![(".PKGINFO".to_string(), pkginfo)];
    if let Some(script) = &script {
        metadata.push((".INSTALL".to_string(), script.clone()));
    }
    metadata.sort_by(|a, b| a.0.cmp(&b.0));
    let mtree = mtree(&metadata, &staging.entries, options.timestamp);

    note("packaging");
    std::fs::create_dir_all(&options.outdir).map_err(io(format!(
        "creating the output directory {}",
        options.outdir.display()
    )))?;
    let final_path = options.outdir.join(manifest.filename());
    // Written beside the destination and renamed over it, so a `zstd` that
    // fails half-way cannot leave something that looks like a finished
    // package in a directory `rvn repo-add` is about to read. The name is
    // dotted and carries the pid for the same reason the staging directory
    // does: `repo-add` skips dotfiles, and building forty components into
    // one output directory must not have two of them choose the same
    // temporary name.
    let stem = format!(
        ".rvn-{}-{}-{}",
        manifest.name,
        manifest.full_version(),
        std::process::id()
    );
    let tar_path = options.outdir.join(format!("{stem}.tar"));
    write_tar(
        &tar_path,
        &metadata,
        &mtree,
        &staging.entries,
        options.timestamp,
    )?;

    let compressed = compress(&tar_path)?;
    let _ = std::fs::remove_file(&tar_path);
    std::fs::rename(&compressed, &final_path).map_err(io(format!(
        "moving the finished package to {}",
        final_path.display()
    )))?;

    let csize = std::fs::metadata(&final_path)
        .map(|m| m.len())
        .map_err(io("measuring the finished package"))?;
    let sha256 = sha256_file(&final_path).map_err(io("hashing the finished package"))?;

    Ok(Built {
        path: final_path,
        name: manifest.name.clone(),
        version: manifest.full_version(),
        arch: manifest.arch.clone(),
        csize,
        isize: staging.installed_size,
        sha256,
        files: staging
            .entries
            .iter()
            .filter(|e| !matches!(e.kind, Kind::Dir))
            .count(),
    })
}

/// Runs `[build]`, in the source tree the manifest sits in.
fn run_build(
    manifest: &Manifest,
    options: &Options,
    note: &mut dyn FnMut(&str),
) -> Result<(), Error> {
    let Some(system) = manifest.build.system else {
        return Ok(());
    };
    if system == System::None {
        return Ok(());
    }

    let build = &manifest.build;
    let source = options.source_root(manifest);
    let mut command = match system {
        System::Cargo => {
            let mut c = Command::new("cargo");
            c.arg("build");
            c.args(&build.flags);
            if let Some(target) = &build.target {
                c.args(["--target", target]);
            }
            if let Some(package) = &build.package {
                c.args(["-p", package]);
            }
            c
        }
        System::Go => {
            let mut c = Command::new("go");
            c.arg("build");
            c.args(&build.flags);
            // Named after the package rather than let go choose: go names the
            // binary after the directory, so `target = "./cmd"` would produce
            // `cmd` and the manifest's `src = "poxy"` would not be there.
            c.args(["-o", &manifest.name]);
            c.arg(build.target.as_deref().unwrap_or("."));
            c
        }
        System::Make => {
            let mut c = Command::new("make");
            c.args(&build.flags);
            c
        }
        System::Custom => {
            let script = build.script.as_deref().ok_or_else(|| Error::BuildFailed {
                system: "custom".to_string(),
                message: "[build] system = \"custom\" needs a `script` to run".to_string(),
            })?;
            // Resolved in the source tree, like every other path in a
            // manifest. evdi's `scripts/build-evdi.sh` is the exception that
            // proves the rule -- it lives in the RavenLinux repository rather
            // than in evdi's checkout, because it needs the kernel tree the
            // image build just made. That component is built with --no-build
            // and packaged, which is what a build only the image build can
            // perform looks like from here.
            Command::new(source.join(script))
        }
        System::None => unreachable!("returned above"),
    };

    command.current_dir(source);
    for (key, value) in &build.env {
        command.env(key, value);
    }

    note(&format!("building with {}", system.as_str()));
    let output = command.output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::MissingProgram {
                program: system.as_str().to_string(),
                needed_for: format!("[build] system = \"{}\"", system.as_str()),
            }
        } else {
            Error::Io {
                doing: format!("running the {} build", system.as_str()),
                source: e,
            }
        }
    })?;

    if !output.status.success() {
        // The last non-empty line of stderr, the way `scriptlet::run` picks a
        // message: a failed cargo build is hundreds of lines and the useful
        // one is at the end.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("no output")
            .to_string();
        return Err(Error::BuildFailed {
            system: system.as_str().to_string(),
            message,
        });
    }

    Ok(())
}

/// Copies the manifest's files into a private tree laid out as the install
/// root, and records what went in.
///
/// This is the fakeroot step without fakeroot: rvn never needs the staged
/// files to be owned by root, because nothing in the finished archive records
/// who owns them on this machine -- every tar header and every mtree entry is
/// written as uid 0, gid 0 by construction. fakeroot exists for build systems
/// that call `chown` during `make install` and would fail without it; a
/// manifest cannot, because all it can say is which file goes where.
fn stage(manifest: &Manifest, options: &Options) -> Result<Staging, Error> {
    // Named for this process so two `rvn build` runs sharing an output
    // directory -- which is exactly what building forty components does --
    // cannot stage into each other.
    let dir = options.outdir.join(format!(
        ".rvn-stage-{}-{}",
        manifest.name,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(io(format!(
        "creating the staging directory {}",
        dir.display()
    )))?;

    let mut staging = Staging {
        dir,
        entries: Vec::new(),
        installed_size: 0,
    };

    // Keyed by path so a parent directory created for one file is not added
    // again for the next, and sorted so the archive is byte-identical
    // whichever order the manifest lists things in. A parent is always a
    // strict prefix of its children ending at a `/`, so sorting the paths as
    // strings is enough to put every directory before what is in it.
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();

    for directory in &manifest.directories {
        let target = staging.dir.join(&directory.path);
        std::fs::create_dir_all(&target).map_err(io(format!(
            "creating {} in the staging tree",
            directory.path
        )))?;
        add_parents(&mut entries, &directory.path);
        entries.insert(
            directory.path.clone(),
            Entry {
                path: directory.path.clone(),
                mode: directory.mode,
                kind: Kind::Dir,
                source: None,
            },
        );
    }

    for file in &manifest.files {
        let source = options.source_root(manifest).join(&file.src);
        if !source.is_file() {
            return Err(Error::MissingFile {
                src: source,
                dest: file.dest.clone(),
            });
        }
        let target = staging.dir.join(&file.dest);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(io(format!("creating the directory for {}", file.dest)))?;
        }
        std::fs::copy(&source, &target).map_err(io(format!(
            "copying {} to {}",
            source.display(),
            file.dest
        )))?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(file.mode))
            .map_err(io(format!("setting the mode of {}", file.dest)))?;

        let size = std::fs::metadata(&target)
            .map(|m| m.len())
            .map_err(io(format!("measuring {}", file.dest)))?;
        let sha256 = sha256_file(&target).map_err(io(format!("hashing {}", file.dest)))?;

        add_parents(&mut entries, &file.dest);
        entries.insert(
            file.dest.clone(),
            Entry {
                path: file.dest.clone(),
                mode: file.mode,
                kind: Kind::File { size, sha256 },
                source: Some(target),
            },
        );
    }

    for link in &manifest.symlinks {
        let target = staging.dir.join(&link.dest);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(io(format!("creating the directory for {}", link.dest)))?;
        }
        add_parents(&mut entries, &link.dest);
        entries.insert(
            link.dest.clone(),
            Entry {
                path: link.dest.clone(),
                // The mode of a symlink is not the mode of what it points at
                // and nothing reads it, but 777 is what every tool writes and
                // what `pacman -Qkk` expects to see.
                mode: 0o777,
                kind: Kind::Link {
                    target: link.target.clone(),
                },
                source: None,
            },
        );
    }

    staging.installed_size = entries
        .values()
        .filter_map(|entry| match &entry.kind {
            Kind::File { size, .. } => Some(*size),
            _ => None,
        })
        .sum();
    staging.entries = entries.into_values().collect();
    Ok(staging)
}

/// Adds every directory above `path` that is not already recorded.
///
/// A package that ships `/usr/bin/rvn` owns `usr` and `usr/bin` too, the way
/// every package from a mirror does. Leaving them out would mean the
/// directory is created by extraction but belongs to nobody, so removing the
/// package would leave it behind for ever -- [`crate::ops::remove`] only
/// prunes directories a package it is removing declared.
fn add_parents(entries: &mut BTreeMap<String, Entry>, path: &str) {
    let mut prefix = String::new();
    let mut parts: Vec<&str> = path.split('/').collect();
    parts.pop();
    for part in parts {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        entries.entry(prefix.clone()).or_insert_with(|| Entry {
            path: prefix.clone(),
            mode: 0o755,
            kind: Kind::Dir,
            source: None,
        });
    }
}

/// Writes the `.PKGINFO` body.
///
/// The keys are the ones [`crate::ops::install::apply_pkginfo`] reads back,
/// in the order makepkg writes them, because a person comparing a package rvn
/// built against one from a mirror should be looking at the same file in the
/// same order.
fn pkginfo(manifest: &Manifest, staging: &Staging, timestamp: u64) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(&format!(
        "# Generated by rvn {}\n",
        env!("CARGO_PKG_VERSION")
    ));

    let mut field = |key: &str, value: &str| {
        if !value.is_empty() {
            out.push_str(&format!("{key} = {value}\n"));
        }
    };

    field("pkgname", &manifest.name);
    field("pkgbase", &manifest.name);
    field("pkgver", &manifest.full_version());
    field("pkgdesc", &manifest.description);
    field("url", manifest.url.as_deref().unwrap_or(""));
    field("builddate", &timestamp.to_string());
    field("packager", manifest.packager.as_deref().unwrap_or(""));
    field("size", &staging.installed_size.to_string());
    field("arch", &manifest.arch);

    for (key, values) in [
        ("license", &manifest.licenses),
        ("group", &manifest.groups),
        ("provides", &manifest.provides),
        ("conflict", &manifest.conflicts),
        ("replaces", &manifest.replaces),
        ("depend", &manifest.depends),
        ("optdepend", &manifest.optdepends),
        ("makedepend", &manifest.makedepends),
        ("backup", &manifest.backup),
    ] {
        for value in values {
            field(key, value);
        }
    }

    out.into_bytes()
}

/// Writes the gzip-compressed `.MTREE`.
///
/// The format is the one `bsdtar --format=mtree` produces and the one pacman
/// parses: a `/set` line establishing the common case, then one line per
/// entry carrying only what differs from it. The keyword order -- time, mode,
/// type, size, link, sha256digest -- is makepkg's, verified against a package
/// from a mirror rather than written from memory, because a reader that
/// tolerates one order is not guaranteed to tolerate another and there is no
/// reason to find out the hard way.
///
/// `time` is written as `<seconds>.0`. The fractional part is not optional in
/// practice: every `.MTREE` on a mirror carries it, and matching what pacman
/// has been reading for twenty years is worth one character.
fn mtree(metadata: &[(String, Vec<u8>)], entries: &[Entry], timestamp: u64) -> Vec<u8> {
    let mut text = String::from("#mtree\n");
    // The common case for a payload: an ordinary root-owned data file. Every
    // line below carries only what differs from this.
    text.push_str("/set type=file uid=0 gid=0 mode=644\n");

    for (name, body) in metadata {
        text.push_str(&format!(
            "./{name} time={timestamp}.0 size={} sha256digest={}\n",
            body.len(),
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(body))
        ));
    }

    for entry in entries {
        let mut line = format!("./{} time={timestamp}.0", vis(&entry.path));
        if entry.mode != 0o644 {
            line.push_str(&format!(" mode={:o}", entry.mode));
        }
        match &entry.kind {
            Kind::Dir => line.push_str(" type=dir"),
            Kind::Link { target } => {
                line.push_str(&format!(" type=link link={}", vis(target)));
            }
            Kind::File { size, sha256 } => {
                line.push_str(&format!(" size={size} sha256digest={sha256}"));
            }
        }
        line.push('\n');
        text.push_str(&line);
    }

    // Compressed at the default level: a .MTREE is a few kilobytes of highly
    // repetitive text and the difference between levels is noise, while the
    // difference between gzip and no gzip is whether pacman can read it at
    // all.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    let _ = encoder.write_all(text.as_bytes());
    encoder.finish().unwrap_or_default()
}

/// mtree's escaping for a path.
///
/// Every field in an mtree line is separated by a space, so a path with a
/// space in it would silently become a path plus a keyword that is not one.
/// The escapes are the vis(3) octal form the format specifies; the set here
/// is the one that can actually break a line -- whitespace, the backslash
/// that introduces an escape, the `#` that starts a comment, and anything
/// outside printable ASCII.
fn vis(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b' ' | b'\t' | b'\n' | b'\r' | b'#' | b'=' => {
                out.push_str(&format!("\\{byte:03o}"));
            }
            0x21..=0x7e => out.push(byte as char),
            other => out.push_str(&format!("\\{other:03o}")),
        }
    }
    out
}

/// Writes the uncompressed tar.
///
/// Metadata members come first and in name order, which is where every
/// package from a mirror has them, and then the payload in the same order the
/// mtree lists it. Every header is uid 0, gid 0, root/root and stamped with
/// the one build timestamp: what a file is owned by on the machine that built
/// it is not what it is owned by on the machine it lands on, and recording
/// the builder's uid would be both wrong and a small privacy leak.
fn write_tar(
    path: &Path,
    metadata: &[(String, Vec<u8>)],
    mtree: &[u8],
    entries: &[Entry],
    timestamp: u64,
) -> Result<(), Error> {
    let file = std::fs::File::create(path)
        .map_err(io(format!("creating the archive {}", path.display())))?;
    let mut builder = tar::Builder::new(std::io::BufWriter::new(file));

    let mut members: Vec<(&str, &[u8])> = metadata
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_slice()))
        .collect();
    members.push((".MTREE", mtree));
    members.sort_by(|a, b| a.0.cmp(b.0));

    for (name, body) in members {
        let mut header = tar::Header::new_gnu();
        base_header(&mut header, timestamp);
        header.set_mode(0o644);
        header.set_size(body.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, name, body)
            .map_err(io(format!("writing {name} into the archive")))?;
    }

    for entry in entries {
        let mut header = tar::Header::new_gnu();
        base_header(&mut header, timestamp);
        header.set_mode(entry.mode);

        match &entry.kind {
            Kind::Dir => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("{}/", entry.path), std::io::empty())
                    .map_err(io(format!("writing {} into the archive", entry.path)))?;
            }
            Kind::Link { target } => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header
                    .set_link_name(target)
                    .map_err(io(format!("recording the link target of {}", entry.path)))?;
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.path, std::io::empty())
                    .map_err(io(format!("writing {} into the archive", entry.path)))?;
            }
            Kind::File { size, .. } => {
                let source = entry
                    .source
                    .as_ref()
                    .expect("a staged file always records where its bytes are");
                let mut body = std::fs::File::open(source).map_err(io(format!(
                    "reading {} back from the staging tree",
                    entry.path
                )))?;
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(*size);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.path, &mut body)
                    .map_err(io(format!("writing {} into the archive", entry.path)))?;
            }
        }
    }

    builder
        .into_inner()
        .map_err(io("finishing the archive"))?
        .flush()
        .map_err(io("flushing the archive"))?;
    Ok(())
}

/// The fields every header in the archive shares.
fn base_header(header: &mut tar::Header, timestamp: u64) {
    header.set_uid(0);
    header.set_gid(0);
    // Written as well as the numeric ids: tar readers that show a listing use
    // the names, and a package whose files read as owned by uid 0 with no
    // name looks like it was made by something that did not know better.
    let _ = header.set_username("root");
    let _ = header.set_groupname("root");
    header.set_mtime(timestamp);
}

/// Compresses the tar with the `zstd` program, returning the compressed path.
///
/// The default compression level is used deliberately. `--ultra` and the long
/// window modes produce frames whose window is larger than the decoder side
/// of this crate -- `ruzstd` -- will allocate for, so a package compressed
/// that way would be one rvn could not install. The default is well inside
/// what every zstd decoder handles, and a package archive is already mostly
/// incompressible binaries.
fn compress(tar: &Path) -> Result<PathBuf, Error> {
    // Built by appending rather than by `with_extension`, which replaces the
    // last extension and would turn `x.pkg.tar` into something that is no
    // longer recognisably a temporary file.
    let mut output = tar.as_os_str().to_os_string();
    output.push(".zst");
    let output = PathBuf::from(output);
    let status = Command::new("zstd")
        .arg("-q")
        .arg("-f")
        // Every core, because this is the slow part of packaging and the
        // machine is not doing anything else at the time.
        .arg("-T0")
        .arg(tar)
        .arg("-o")
        .arg(&output)
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::MissingProgram {
                    program: "zstd".to_string(),
                    needed_for: "compressing the package".to_string(),
                }
            } else {
                Error::Io {
                    doing: "running zstd".to_string(),
                    source: e,
                }
            }
        })?;

    if !status.success() {
        return Err(Error::BuildFailed {
            system: "zstd".to_string(),
            message: format!("zstd exited with {status}"),
        });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-build-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp dir");
        dir
    }

    const MANIFEST: &str = r#"
[package]
name = "roostbar"
version = "0.3.1"
description = "the status bar"
license = "MIT"
homepage = "https://example.invalid/roostbar"
maintainers = ["RavenLinux Team"]
categories = ["raven", "desktop"]

[build]
system = "cargo"
target = "x86_64-unknown-linux-musl"
build_flags = ["--release"]

[dependencies]
runtime = ["huginn"]
build = ["rust", "cargo"]

[install]
files = [
    { src = "bin/roostbar", dest = "/usr/bin/roostbar", mode = 755 },
    { src = "etc/roostbar.conf", dest = "/etc/roostbar.conf", mode = 644 }
]
backup = ["/etc/roostbar.conf"]
directories = [{ path = "/var/lib/roostbar", mode = 700 }]
symlinks = [{ dest = "/usr/bin/bar", target = "roostbar" }]
"#;

    fn written(dir: &Path) -> Manifest {
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("bin/roostbar"), b"ELF-ish payload").unwrap();
        std::fs::write(dir.join("etc/roostbar.conf"), b"bar = true\n").unwrap();
        std::fs::write(dir.join("package.toml"), MANIFEST).unwrap();
        Manifest::read(&dir.join("package.toml")).expect("this manifest should read")
    }

    #[test]
    fn a_real_manifests_shape_reads_back_into_a_package_description() {
        let dir = temp_dir("read");
        let manifest = written(&dir);

        assert_eq!(manifest.name, "roostbar");
        assert_eq!(manifest.full_version(), "0.3.1-1");
        // Taken from the target triple rather than defaulted, which is the
        // only place the manifests say it today.
        assert_eq!(manifest.arch, "x86_64");
        assert_eq!(manifest.filename(), "roostbar-0.3.1-1-x86_64.pkg.tar.zst");
        assert_eq!(manifest.groups, ["raven", "desktop"]);
        assert_eq!(manifest.depends, ["huginn"]);
        assert_eq!(manifest.makedepends, ["rust", "cargo"]);
        assert_eq!(manifest.packager.as_deref(), Some("RavenLinux Team"));
        // The leading slash is gone: a payload path is relative to the root.
        assert_eq!(manifest.files[0].dest, "usr/bin/roostbar");
        assert_eq!(manifest.files[0].mode, 0o755);
        assert_eq!(manifest.backup, ["etc/roostbar.conf"]);
        assert_eq!(manifest.directories[0].mode, 0o700);
        assert_eq!(manifest.symlinks[0].dest, "usr/bin/bar");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_archive_reads_back_through_rvns_own_extractor() {
        let dir = temp_dir("roundtrip");
        let manifest = written(&dir);
        let mut options = Options::new(dir.join("out"));
        options.run_build = false;
        options.timestamp = 1_700_000_000;

        let built = package(&manifest, &options, &mut |_| {}).expect("packaging should succeed");
        assert_eq!(
            built.path.file_name().unwrap(),
            manifest.filename().as_str()
        );

        // The point of the test: what rvn writes is what rvn reads. This is
        // the same function every install goes through.
        let read = crate::extract::manifest(&built.path).expect("the package should be readable");
        assert!(read.files.contains(&"usr/bin/roostbar".to_string()));
        assert!(read.files.contains(&"usr/bin/bar".to_string()));
        assert!(read.directories.contains(&"usr/bin/".to_string()));
        assert!(read.directories.contains(&"var/lib/roostbar/".to_string()));
        assert_eq!(read.backup, ["etc/roostbar.conf"]);
        assert_eq!(read.depends, ["huginn"]);
        assert_eq!(
            read.pkginfo.get("pkgver").map(Vec::as_slice),
            Some(["0.3.1-1".to_string()].as_slice())
        );
        assert_eq!(
            read.pkginfo.get("size").map(Vec::as_slice),
            Some([built.isize.to_string()].as_slice())
        );
        assert!(read.mtree.is_some(), "the package must carry a .MTREE");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_mtree_records_what_the_tar_headers_record() {
        // A `.MTREE` whose `time=` disagrees with the tar header's mtime
        // makes `pacman -Qkk` report every file in the package as altered,
        // because the mtree is what it compares the extracted file against.
        // Nothing else in this crate can catch that, so it is asserted here.
        let dir = temp_dir("mtree");
        let manifest = written(&dir);
        let mut options = Options::new(dir.join("out"));
        options.run_build = false;
        options.timestamp = 1_700_000_000;

        let built = package(&manifest, &options, &mut |_| {}).expect("packaging should succeed");
        let read = crate::extract::manifest(&built.path).unwrap();
        let mut gz = flate2::read::GzDecoder::new(read.mtree.as_deref().unwrap());
        let mut text = String::new();
        std::io::Read::read_to_string(&mut gz, &mut text).expect("the .MTREE should be gzip");

        assert!(
            text.starts_with("#mtree\n/set type=file uid=0 gid=0 mode=644\n"),
            "{text}"
        );
        // Every line is stamped with the one build timestamp the tar headers
        // carry, so the two cannot drift.
        for line in text.lines().filter(|l| l.starts_with("./")) {
            assert!(
                line.contains(" time=1700000000.0"),
                "entry is not stamped with the build timestamp: {line}"
            );
        }
        assert!(
            text.contains("./usr/bin/roostbar time=1700000000.0 mode=755 size=15 sha256digest="),
            "{text}"
        );
        assert!(
            text.contains("./usr/bin/bar time=1700000000.0 mode=777 type=link link=roostbar"),
            "{text}"
        );
        assert!(
            text.contains("./var/lib/roostbar time=1700000000.0 mode=700 type=dir"),
            "{text}"
        );
        // The mtree describes .PKGINFO and never itself.
        assert!(
            text.contains("./.PKGINFO time=1700000000.0 size="),
            "{text}"
        );
        assert!(!text.contains("./.MTREE"), "{text}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manifest_that_says_something_unreadable_is_refused_by_name_and_line() {
        let dir = temp_dir("refuse");
        for (text, says) in [
            ("[package]\nname = \"x\"\n", "needs a version"),
            (
                "[package]\nname = \"x\"\nversion = \"1.0-2\"\n",
                "separates the version from the release",
            ),
            (
                "[package]\nname = \"x\"\nversion = \"1\"\n[nope]\na = 1\n",
                "is not a section a manifest has",
            ),
            (
                "[package]\nname = \"x\"\nversion = \"1\"\nnmae = \"y\"\n",
                "is not a key [package] has",
            ),
            (
                "[package]\nname = \"x\"\nversion = \"1\"\n[install]\nfiles = [{ src = \"a\", dest = \"../etc/passwd\" }]\n",
                "cannot climb out of it",
            ),
            (
                "[package]\nname = \"x\"\nversion = \"1\"\n[install]\nfiles = [{ src = \"a\", dest = \"/b\", mode = 799 }]\n",
                "write it as octal",
            ),
            (
                "[package]\nname = \"x\"\nversion = \"1\"\n",
                "installs nothing",
            ),
        ] {
            let path = dir.join("package.toml");
            std::fs::write(&path, text).unwrap();
            let e = Manifest::read(&path).expect_err("this manifest should be refused");
            assert!(e.to_string().contains(says), "{text:?} -> {e}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_source_tree_can_live_somewhere_other_than_the_manifest() {
        // The RavenLinux layout: the manifest is in packages/ and holds
        // nothing else, while its `src` paths name files in a checkout the
        // build scripts cloned elsewhere. Without `source_dir` this cannot
        // work at all, and the failure has to name the path it looked for
        // rather than producing an empty package.
        let dir = temp_dir("srcdir");
        let manifests = dir.join("packages/roostbar");
        let checkout = dir.join("checkout");
        std::fs::create_dir_all(&manifests).unwrap();
        std::fs::create_dir_all(checkout.join("bin")).unwrap();
        std::fs::create_dir_all(checkout.join("etc")).unwrap();
        std::fs::write(checkout.join("bin/roostbar"), b"ELF-ish payload").unwrap();
        std::fs::write(checkout.join("etc/roostbar.conf"), b"bar = true\n").unwrap();
        std::fs::write(manifests.join("package.toml"), MANIFEST).unwrap();
        let manifest = Manifest::read(&manifests.join("package.toml")).unwrap();

        let mut options = Options::new(dir.join("out"));
        options.run_build = false;

        // The manifest's own directory holds no payload, so this must fail
        // and say which file it wanted.
        let e = package(&manifest, &options, &mut |_| {})
            .expect_err("a manifest with no tree beside it cannot be packaged");
        assert!(e.to_string().contains("bin/roostbar"), "{e}");
        assert!(e.to_string().contains("is not there"), "{e}");

        options.source_dir = Some(checkout);
        let built = package(&manifest, &options, &mut |_| {})
            .expect("with the checkout named, it packages");
        let read = crate::extract::manifest(&built.path).unwrap();
        assert!(read.files.contains(&"usr/bin/roostbar".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_manifests_ravenlinux_already_ships_are_ones_this_can_read() {
        // Not a fixture: the real files, when they are there. This is the
        // whole point of the module and the shape it had to be written
        // against, so it is checked against the shape rather than a copy of
        // it that can drift. Skipped rather than failed when the sibling
        // checkout is absent, because the test suite has to pass on a machine
        // that only has this repository.
        let packages = Path::new("/home/javanstorm/Development/RavenLinux/packages/raven");
        let Ok(entries) = std::fs::read_dir(packages) else {
            return;
        };

        let mut read = 0;
        for entry in entries.flatten() {
            let manifest = entry.path().join("package.toml");
            if !manifest.is_file() {
                continue;
            }
            let parsed = Manifest::read(&manifest)
                .unwrap_or_else(|e| panic!("{} should read: {e}", manifest.display()));
            assert!(!parsed.name.is_empty());
            assert!(!parsed.files.is_empty(), "{} installs nothing", parsed.name);
            for file in &parsed.files {
                assert!(
                    !file.dest.starts_with('/'),
                    "{} has an absolute payload path",
                    parsed.name
                );
            }
            read += 1;
        }
        assert!(read > 0, "the packages directory held no manifests");
    }
}
