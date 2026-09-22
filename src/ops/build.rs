//! `rvn build` and `rvn repo-add`.
//!
//! # The interface the image build should call
//!
//! RavenLinux's build scripts already compile every component and then
//! `install -m 0755` the results into the sysroot, which is why nothing on a
//! RavenLinux machine owns `/usr/bin/huginn`. The change this makes possible
//! is to package instead of installing, and it is two commands:
//!
//! ```text
//! rvn build packages/raven/<component>/package.toml \
//!           --no-build --srcdir <the checkout that was just built> \
//!           --outdir build/packages
//! rvn repo-add build/packages --name raven
//! ```
//!
//! `--no-build` is the important half. The image build has already run cargo
//! or go with its own toolchain, its own target directory and its own
//! environment, and rvn re-running the build would at best duplicate it and
//! at worst use different flags. With `--no-build`, rvn reads the same
//! `[install] files` table the scripts read, stages exactly those files, and
//! produces an archive -- so the manifest stays the single description of
//! what the component installs, and the sysroot is populated by installing
//! the packages rather than by copying files into it.
//!
//! `--srcdir` is the half that is easy to miss. A manifest under
//! `packages/raven/<component>/` holds nothing but the manifest, and its
//! `src` paths -- `target/x86_64-unknown-linux-musl/release/rvn` -- name
//! files inside a checkout that `raven_fetch_repo` put somewhere else, since
//! that function takes its destination as an argument. `--srcdir` is that
//! destination. Without it the manifest's directory is used, which is right
//! only for a manifest that lives in the tree it describes; when it is wrong
//! the failure names the exact path that was not there, rather than producing
//! an empty package.
//!
//! One component does not fit and is worth naming: `evdi` is
//! `system = "custom"` with a script in the RavenLinux repository rather than
//! in its own checkout, because the script needs the kernel tree the image
//! build has just produced. It is built by the image build and packaged here
//! with `--no-build`, which is what "a build only the image build can
//! perform" looks like from this side.
//!
//! What comes back on stdout under `--json` is a `built` event per package
//! with its path, version and sizes, and a `repo_db` event for the database,
//! so a build script can collect them without parsing terminal output.
//!
//! Nothing here writes outside `--outdir`. `rvn build` needs no root and must
//! not be given any: it reads a manifest, copies files into a staging tree of
//! its own, and writes one archive.

use super::Context;
use crate::build::{self, Manifest};
use crate::repodb;
use crate::sign::Signer;
use crate::ui::theme::bytes;
use std::path::{Path, PathBuf};

/// Where packages go when `--outdir` is not given.
///
/// The working directory, not the package cache. A built package is output,
/// not a cached download: putting it in /var/cache/pacman/pkg would need root
/// for a command that otherwise needs none, and would hand it to
/// `rvn cache clean`, which would eventually delete the only copy of
/// something no mirror has.
const DEFAULT_OUTDIR: &str = ".";

/// How the caller asked for packages to be built.
pub struct Options {
    pub outdir: PathBuf,
    /// Whether to run `[build]`, or take the tree as already built.
    pub run_build: bool,
    /// The built source tree `[install] files` are relative to, when the
    /// manifest does not live in it. See [`crate::build::Options::source_dir`]
    /// -- for the RavenLinux manifests this is not optional, because those
    /// manifests sit in `packages/` and describe files in a checkout.
    pub source_dir: Option<PathBuf>,
    /// Rebuild a repository database in the output directory afterwards.
    pub repo: Option<String>,
    pub signing: Signing,
    /// Whether that database gets its `<repo>.files` companion. See
    /// [`repodb::Files`] for why the answer is normally yes.
    pub files: repodb::Files,
}

/// What to do about signatures.
pub enum Signing {
    /// Whatever `etc/rvn/build.toml` says: sign if it names a key, and do not
    /// if it does not. A file that names a key is an administrator saying
    /// packages from this machine are signed, and honouring that without
    /// being asked again is the same reasoning the rest of the crate applies
    /// to configuration it finds.
    Configured,
    /// `--key`, which also implies signing.
    Key(String),
    /// `--sign` with no key of its own: use the configured one and fail if
    /// there is none, rather than quietly producing unsigned packages.
    Required,
    /// `--no-sign`.
    Never,
}

impl Signing {
    /// Resolves to the signer to use, or to nothing.
    fn signer(&self, ctx: &Context) -> Result<Option<Signer>, String> {
        match self {
            Signing::Never => Ok(None),
            Signing::Key(key) => Ok(Some(Signer::named(key))),
            Signing::Configured => Signer::configured(&ctx.config.root_dir),
            Signing::Required => Signer::configured(&ctx.config.root_dir)?.map(Some).ok_or_else(
                || {
                    format!(
                        "--sign was given but no key is configured: write `[sign] key = \"...\"` in /{}, or pass --key",
                        crate::sign::CONFIG
                    )
                },
            ),
        }
    }
}

/// Builds every manifest named, then optionally the repository database.
pub fn run(ctx: &mut Context, manifests: &[String], options: &Options) -> Result<(), String> {
    ctx.ui.banner(&format!("v{}", env!("CARGO_PKG_VERSION")));

    // Resolved once, before anything is built: a misconfigured key should
    // stop the run at the start rather than after forty packages have been
    // compiled and none of them can be signed.
    let signer = options.signing.signer(ctx)?;

    let outdir = if options.outdir.as_os_str().is_empty() {
        PathBuf::from(DEFAULT_OUTDIR)
    } else {
        options.outdir.clone()
    };

    let mut built = Vec::new();
    for path in manifests {
        let path = resolve_manifest(Path::new(path))?;
        let manifest = Manifest::read(&path).map_err(|e| e.to_string())?;

        ctx.ui.blank();
        let spinner = ctx.ui.stage(&format!(
            "building {} {}",
            manifest.name,
            manifest.full_version()
        ));

        let mut build_options = build::Options::new(outdir.clone());
        build_options.run_build = options.run_build;
        build_options.source_dir = options.source_dir.clone();

        let result = build::package(&manifest, &build_options, &mut |step| {
            spinner.set_message(&format!("{} — {step}", manifest.name));
        });

        let package = match result {
            Ok(package) => package,
            Err(e) => {
                spinner.fail(&format!("{} failed", manifest.name));
                return Err(e.to_string());
            }
        };

        let signature = match &signer {
            Some(signer) => {
                spinner.set_message(&format!("{} — signing", manifest.name));
                Some(signer.sign(&package.path).map_err(|e| {
                    format!("{} was built but not signed: {e}", package.path.display())
                })?)
            }
            None => None,
        };

        spinner.succeed(&format!(
            "{} {} ({}, {} files)",
            package.name,
            package.version,
            bytes(package.csize),
            package.files
        ));
        ctx.ui.emit(
            "built",
            serde_json::json!({
                "package": package.name,
                "version": package.version,
                "arch": package.arch,
                "path": package.path.display().to_string(),
                "csize": package.csize,
                "isize": package.isize,
                "sha256": package.sha256,
                "signed": signature.is_some(),
            }),
        );
        built.push(package);
    }

    if let Some(repo) = &options.repo {
        add_to_repo(ctx, repo, &outdir, signer.as_ref(), options.files)?;
    }

    ctx.ui.blank();
    let s = &ctx.ui.style;
    ctx.ui.ok(&format!(
        "{} {} built",
        s.bold(&built.len().to_string()),
        if built.len() == 1 {
            "package"
        } else {
            "packages"
        }
    ));
    if signer.is_none() && !ctx.ui.is_json() {
        // Said once, at the end, rather than per package. An unsigned
        // package installs fine from a `SigLevel = Optional` repository and
        // not at all from a required one, and the moment to learn that is
        // now rather than on somebody else's machine.
        ctx.ui.detail(&format!(
            "not signed — configure `[sign] key` in /{} to sign, or pass --key",
            crate::sign::CONFIG
        ));
    }

    Ok(())
}

/// `rvn repo-add`: builds the database for a directory of packages.
pub fn repo_add(
    ctx: &mut Context,
    directory: &Path,
    name: Option<&str>,
    signing: &Signing,
    files: repodb::Files,
) -> Result<(), String> {
    let signer = signing.signer(ctx)?;
    let repo = match name {
        Some(name) => name.to_string(),
        // The directory's own name, which is what a repository is usually
        // called: `build/packages/raven` is the `raven` repository.
        None => directory
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .ok_or_else(|| {
                format!(
                    "{} has no name to call the repository; pass --name",
                    directory.display()
                )
            })?,
    };

    add_to_repo(ctx, &repo, directory, signer.as_ref(), files)
}

/// Writes `<repo>.db` for `directory`, signing it when there is a key.
fn add_to_repo(
    ctx: &mut Context,
    repo: &str,
    directory: &Path,
    signer: Option<&Signer>,
    files: repodb::Files,
) -> Result<(), String> {
    ctx.ui.blank();
    let spinner = ctx.ui.stage(&format!("building the {repo} database"));

    let summary = repodb::build(repo, directory, files, &mut |name| {
        spinner.set_message(&format!("{repo} — {name}"));
    })
    .map_err(|e| e.to_string())?;

    // Signed over the real file rather than the `<repo>.db` symlink, and the
    // signature linked under the fetched name beside it. That is repo-add's
    // layout, and it is the one `ops::sync::verify_database` reads: it
    // fetches `<repo>.db.sig` and checks it against the bytes it got from
    // `<repo>.db`, which are the same bytes either way.
    if let Some(signer) = signer {
        spinner.set_message(&format!("{repo} — signing"));
        let signature = signer
            .sign(&summary.database)
            .map_err(|e| format!("the {repo} database was written but not signed: {e}"))?;
        let alias = directory.join(format!("{repo}.db.sig"));
        let _ = std::fs::remove_file(&alias);
        let target = signature
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        std::os::unix::fs::symlink(&target, &alias)
            .map_err(|e| format!("{}: {e}", alias.display()))?;
    }

    spinner.succeed(&format!(
        "{repo}: {} {}",
        summary.packages.len(),
        if summary.packages.len() == 1 {
            "package"
        } else {
            "packages"
        }
    ));

    // Said rather than left to be discovered, because the file-list database
    // is new and somebody who has run repo-add before will want to know
    // whether this wrote the same pair of files it does.
    match &summary.files_alias {
        Some(_) => ctx.ui.detail(&format!(
            "{repo}.db and {repo}.files — the second is what `pacman -F` reads"
        )),
        None => ctx.ui.detail(&format!(
            "{repo}.db only; --no-files was given, so `pacman -F` has nothing to read for this repository"
        )),
    }

    if !summary.skipped.is_empty() {
        // Named rather than counted: a file in a package directory that is
        // not a package is nearly always a truncated download or a build that
        // died half-way, and the useful thing is which one.
        ctx.ui.warn(&format!(
            "{} {} in {} could not be read and {} left out",
            summary.skipped.len(),
            if summary.skipped.len() == 1 {
                "file"
            } else {
                "files"
            },
            directory.display(),
            if summary.skipped.len() == 1 {
                "was"
            } else {
                "were"
            }
        ));
        ctx.ui.tree(
            &summary
                .skipped
                .iter()
                .map(|(path, why)| {
                    format!(
                        "{} — {why}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    )
                })
                .collect::<Vec<_>>(),
        );
    }

    ctx.ui.emit(
        "repo_db",
        serde_json::json!({
            "repo": repo,
            "database": summary.database.display().to_string(),
            "fetched_as": summary.alias.display().to_string(),
            "files_database": summary.files_database.as_ref().map(|p| p.display().to_string()),
            "files_fetched_as": summary.files_alias.as_ref().map(|p| p.display().to_string()),
            "signed": signer.is_some(),
            "packages": summary
                .packages
                .iter()
                .map(|p| serde_json::json!({
                    "package": p.name,
                    "version": p.version,
                    "filename": p.filename,
                    "csize": p.csize,
                    "isize": p.isize,
                }))
                .collect::<Vec<_>>(),
            "skipped": summary
                .skipped
                .iter()
                .map(|(path, why)| serde_json::json!({
                    "path": path.display().to_string(),
                    "reason": why,
                }))
                .collect::<Vec<_>>(),
        }),
    );

    if !ctx.ui.is_json() {
        ctx.ui.detail(&format!(
            "point a repository at it: Server = file://{}",
            directory
                .canonicalize()
                .unwrap_or_else(|_| directory.to_path_buf())
                .display()
        ));
    }

    Ok(())
}

/// Accepts either a `package.toml` or the directory holding one.
///
/// `rvn build packages/raven/huginn` is what a person types, and refusing it
/// because the file is called `package.toml` and they did not say so would be
/// pedantry. A directory with no manifest is still an error, and says which
/// file it looked for.
fn resolve_manifest(path: &Path) -> Result<PathBuf, String> {
    if path.is_dir() {
        let manifest = path.join("package.toml");
        if manifest.is_file() {
            return Ok(manifest);
        }
        return Err(format!("{} holds no package.toml", path.display()));
    }
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    Err(format!("{}: no such manifest", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_may_be_named_by_its_directory() {
        let dir = std::env::temp_dir().join(format!("rvn-opsbuild-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.toml"), "[package]\n").unwrap();

        assert_eq!(
            resolve_manifest(&dir).unwrap(),
            dir.join("package.toml"),
            "naming the directory should find the manifest in it"
        );
        assert_eq!(
            resolve_manifest(&dir.join("package.toml")).unwrap(),
            dir.join("package.toml")
        );

        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(
            resolve_manifest(&empty)
                .unwrap_err()
                .contains("holds no package.toml")
        );
        assert!(
            resolve_manifest(&dir.join("nope"))
                .unwrap_err()
                .contains("no such manifest")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
