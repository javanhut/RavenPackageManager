//! The install pipeline: resolve, fetch, verify, build, unpack, register.
//!
//! Each phase is a distinct animated stage so the user can see exactly where
//! a long install is spending its time.

use super::Context;
use crate::aur::{Aur, SrcInfo};
use crate::db::sync as syncdb;
use crate::extract;
use crate::fetch;
use crate::pkg::{BackupFile, InstallReason, Package};
use crate::resolve::{NoSource, Plan, Resolved, Resolver};
use crate::scriptlet::{self, Hook};
use crate::ui::spinner::Spinner;
use crate::ui::theme::{Color, bytes, bytes_signed};
use crate::config::Level;
use crate::verify::{self, Verified};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct Outcome {
    pub installed: Vec<String>,
    pub skipped: Vec<String>,
    /// Packages retired because something replaced them.
    pub replaced: Vec<String>,
}

/// Runs `rvn install`, including the masthead.
pub fn run(ctx: &mut Context, targets: &[String]) -> Result<Outcome, String> {
    ctx.ui.banner(&format!("v{}", env!("CARGO_PKG_VERSION")));
    execute(ctx, targets)
}

/// The install pipeline without the masthead, so other operations — notably
/// `update` — can drive it as one step of a larger flow.
pub fn execute(ctx: &mut Context, targets: &[String]) -> Result<Outcome, String> {
    // Databases are rvn's problem, not the user's: refresh them when they are
    // missing or stale rather than failing with an instruction to run `sync`.
    if ctx.auto_sync && !ctx.dry_run && (ctx.sync.is_empty() || super::sync::needs_refresh(ctx)) {
        super::sync::refresh(ctx)?;
    } else if ctx.sync.is_empty() {
        ctx.ui
            .warn("no repository databases found — run `rvn sync` first");
    }

    // ---- resolve -------------------------------------------------------
    let plan = {
        let spinner = ctx
            .ui
            .stage(&format!("resolving {}", targets.join(", ")));

        let plan = if ctx.repo_only {
            Resolver::new(&ctx.sync, &ctx.local, &NoSource)
                .ignoring(&ctx.config.ignore_pkg)
                .forcing(&ctx.force_rebuild)
                .resolve(targets)
        } else {
            Resolver::new(&ctx.sync, &ctx.local, &ctx.aur)
                .ignoring(&ctx.config.ignore_pkg)
                .forcing(&ctx.force_rebuild)
                .resolve(targets)
        };

        let deps = plan.install.len().saturating_sub(
            plan.install.iter().filter(|r| r.reason.is_explicit()).count(),
        );
        spinner.succeed(&format!(
            "resolved {} package{}, {} dependenc{}",
            plan.install.len(),
            if plan.install.len() == 1 { "" } else { "s" },
            deps,
            if deps == 1 { "y" } else { "ies" }
        ));
        plan
    };

    report_problems(ctx, &plan)?;

    if plan.is_empty() {
        for name in &plan.already_satisfied {
            ctx.ui.ok(&format!("{name} is already installed and current"));
        }
        return Ok(Outcome {
            installed: Vec::new(),
            skipped: plan.already_satisfied.clone(),
            replaced: Vec::new(),
        });
    }

    show_plan(ctx, &plan);

    if ctx.dry_run {
        ctx.ui.info("dry run — nothing was changed");
        return Ok(Outcome {
            installed: Vec::new(),
            skipped: plan
                .install
                .iter()
                .map(|r| r.package.name.clone())
                .collect(),
            replaced: Vec::new(),
        });
    }

    if !ctx.assume_yes && !ctx.ui.confirm("proceed with installation?", true) {
        return Err("cancelled".into());
    }

    if !super::is_root() && ctx.config.root_dir == Path::new("/") {
        ctx.ui
            .warn("not running as root — writing to / will fail without elevated privileges");
    }

    // ---- fetch ---------------------------------------------------------
    let cache = ctx.cache_dir();
    let repo_targets: Vec<&Resolved> = plan
        .install
        .iter()
        .filter(|r| !r.package.origin.is_aur())
        .collect();
    let aur_targets: Vec<&Resolved> = plan
        .install
        .iter()
        .filter(|r| r.package.origin.is_aur())
        .collect();

    let mut downloaded: Vec<(String, PathBuf)> = Vec::new();

    if !repo_targets.is_empty() {
        let total: u64 = repo_targets.iter().map(|r| r.package.csize).sum();
        let mut progress = ctx.ui.progress("fetching", total);

        for (index, resolved) in repo_targets.iter().enumerate() {
            let pkg = &resolved.package;
            progress.set_detail(&format!(
                "{}/{} {}",
                index + 1,
                repo_targets.len(),
                pkg.name
            ));

            match fetch_package(ctx, pkg, &cache, &mut progress) {
                Ok(path) => downloaded.push((pkg.name.clone(), path)),
                Err(e) => {
                    return Err(format!("failed to download {}: {e}", pkg.name));
                }
            }
        }

        progress.finish(&format!(
            "fetched {} package{}",
            repo_targets.len(),
            if repo_targets.len() == 1 { "" } else { "s" }
        ));
    }

    // ---- verify --------------------------------------------------------
    let mut validations: HashMap<String, crate::pkg::Validation> = HashMap::new();

    if !downloaded.is_empty() {
        let spinner = ctx.ui.stage("verifying signatures");
        let mut signed = 0;

        for (name, path) in &downloaded {
            let resolved = plan
                .install
                .iter()
                .find(|r| r.package.name == *name)
                .expect("downloaded package must be in the plan");
            spinner.set_message(&format!("verifying {name}"));

            match verify_one(ctx, &resolved.package, path) {
                Ok(Verified::ChecksumAndSignature { .. }) => {
                    validations.insert(name.clone(), crate::pkg::Validation::Pgp);
                    signed += 1;
                }
                Ok(Verified::ChecksumOnly) => {
                    validations.insert(name.clone(), crate::pkg::Validation::Sha256);
                }
                Ok(Verified::Skipped) => {}
                Err(e) => {
                    spinner.fail(&format!("{name} failed verification"));
                    // A bad package must never reach the filesystem.
                    let _ = std::fs::remove_file(path);
                    return Err(format!("{name}: {e}"));
                }
            }
        }

        spinner.succeed(&format!(
            "verified {} package{} ({signed} signed)",
            downloaded.len(),
            if downloaded.len() == 1 { "" } else { "s" }
        ));
    }

    // ---- install repository packages -----------------------------------
    //
    // This must happen before any AUR build: a PKGBUILD's makedepends are
    // ordinary repository packages, and they have to exist on disk before
    // makepkg runs.
    let mut installed_names = Vec::new();
    let mut removed_stale = 0usize;

    if !downloaded.is_empty() {
        let (names, stale) = install_archives(ctx, &plan, &downloaded, &validations)?;
        installed_names.extend(names);
        removed_stale += stale;
    }

    // ---- build and install AUR packages --------------------------------
    //
    // Built one at a time and installed immediately, so an AUR package that
    // depends on another AUR package finds it already present.
    for resolved in &aur_targets {
        let pkg = &resolved.package;
        ctx.ui.blank();
        let spinner = ctx.ui.stage(&format!("building {} (aur)", pkg.name));

        let artifacts = match build_aur(ctx, pkg, &cache, &spinner) {
            Ok(artifacts) => {
                spinner.succeed(&format!("built {}", pkg.name));
                artifacts
            }
            Err(e) => {
                spinner.fail(&format!("{} failed to build", pkg.name));
                return Err(format!("{}: {e}", pkg.name));
            }
        };

        // Remember where upstream was, so a later update can tell whether a
        // rebuild is due — a VCS package's version alone never reveals that.
        if crate::devel::is_devel(&pkg.name) {
            record_devel(ctx, &pkg.name, &cache);
        }

        // A split PKGBUILD produces one archive per pkgname. Naming them all
        // after the requested package would register each one under the wrong
        // name, the last write winning.
        let mut built: Vec<(String, PathBuf)> = Vec::new();
        for path in artifacts {
            let name = archive_package_name(&path).unwrap_or_else(|| pkg.name.clone());
            // Only outputs the plan actually asked for get installed; a split
            // build may produce siblings nobody requested.
            if plan.install.iter().any(|r| r.package.name == name) {
                built.push((name, path));
            } else {
                ctx.ui
                    .detail(&format!("skipping {name}, which was not requested"));
            }
        }

        if built.is_empty() {
            return Err(format!(
                "{} built successfully but produced nothing matching the request",
                pkg.name
            ));
        }

        let (names, stale) = install_archives(ctx, &plan, &built, &validations)?;
        installed_names.extend(names);
        removed_stale += stale;
    }

    if removed_stale > 0 {
        ctx.ui.info(&format!(
            "cleaned up {removed_stale} file{} left by the previous version",
            if removed_stale == 1 { "" } else { "s" }
        ));
    }

    // ---- retire replaced packages --------------------------------------
    //
    // Only now that the successors are installed: removing first would leave
    // the system without either package if an install failed.
    let superseded: Vec<String> = plan
        .replacing
        .iter()
        .filter(|(new, _)| installed_names.contains(new))
        .map(|(_, old)| old.clone())
        .filter(|old| ctx.local.is_installed(old))
        .collect();

    let mut retired = Vec::new();
    if !superseded.is_empty() {
        ctx.ui.blank();
        let spinner = ctx.ui.stage(&format!("retiring {}", superseded.join(", ")));
        // The successor already provides what these offered, so the reverse
        // dependency check would fire spuriously.
        let removal = crate::remove::plan(
            &ctx.local,
            &superseded,
            crate::remove::Options {
                nodeps: true,
                ..Default::default()
            },
        );
        spinner.clear();
        retired = super::remove::apply(ctx, &removal)?.removed;
    }

    // Downloaded archives have served their purpose. Clearing them is the
    // default so the cache cannot quietly grow without bound.
    if !ctx.keep_cache {
        let freed = clear_cache(&downloaded);
        if freed > 0 {
            ctx.ui
                .info(&format!("reclaimed {} of downloads", bytes(freed)));
        }
    }

    // ---- summary -------------------------------------------------------
    ctx.ui.blank();
    let s = &ctx.ui.style;
    ctx.ui.ok(&format!(
        "{} {} now installed",
        s.bold(&installed_names.len().to_string()),
        if installed_names.len() == 1 {
            "package is"
        } else {
            "packages are"
        }
    ));

    let optional: Vec<String> = plan
        .install
        .iter()
        .filter(|r| r.reason.is_explicit())
        .flat_map(|r| r.package.optdepends.iter())
        .filter(|d| !ctx.local.is_installed(&d.name))
        .map(|d| match &d.description {
            Some(desc) => format!("{} — {}", s.bold(&d.name), s.dim(desc)),
            None => s.bold(&d.name),
        })
        .collect();

    if !optional.is_empty() {
        ctx.ui.blank();
        ctx.ui.info("optional dependencies you may also want:");
        ctx.ui.tree(&optional);
    }

    Ok(Outcome {
        installed: installed_names,
        skipped: plan.already_satisfied.clone(),
        replaced: retired,
    })
}

/// Deletes the archives (and detached signatures) a transaction downloaded,
/// returning how many bytes were reclaimed.
fn clear_cache(downloaded: &[(String, PathBuf)]) -> u64 {
    let mut freed = 0;

    for (_, path) in downloaded {
        for candidate in [path.clone(), signature_path(path)] {
            if let Ok(meta) = std::fs::metadata(&candidate) {
                if std::fs::remove_file(&candidate).is_ok() {
                    freed += meta.len();
                }
            }
        }
    }

    freed
}

/// The detached signature that sits beside a package archive.
fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".sig");
    PathBuf::from(name)
}

/// Deletes files an upgrade left behind: present in the old version, absent
/// from the new one, and not owned by any other installed package.
fn prune_stale(ctx: &Context, previous: &[String], current: &[String], name: &str) -> usize {
    if previous.is_empty() {
        return 0;
    }

    let kept: HashSet<&String> = current.iter().collect();
    let mut removed = 0;

    for file in previous {
        if kept.contains(file) || file.ends_with('/') {
            continue;
        }
        // Another package owning the file means it must stay.
        let shared = ctx.local.packages.keys().any(|other| {
            other != name
                && ctx
                    .local
                    .files(other)
                    .map(|files| files.iter().any(|f| f == file))
                    .unwrap_or(false)
        });
        if shared {
            continue;
        }
        if std::fs::remove_file(ctx.config.root_dir.join(file)).is_ok() {
            removed += 1;
        }
    }

    removed
}

/// Offers to show the PKGBUILD before it runs, and lets the user abort.
fn review_build_files(ctx: &Context, name: &str, dir: &Path) -> Result<(), String> {
    let pkgbuild = dir.join("PKGBUILD");
    ctx.ui
        .detail(&format!("build files: {}", pkgbuild.display()));

    if !ctx.ui.confirm(&format!("review the PKGBUILD for {name}?"), false) {
        return Ok(());
    }

    match std::fs::read_to_string(&pkgbuild) {
        Ok(text) => {
            ctx.ui.blank();
            for line in text.lines() {
                println!("    {line}");
            }
            ctx.ui.blank();
        }
        Err(e) => ctx.ui.warn(&format!("could not read the PKGBUILD: {e}")),
    }

    // An install scriptlet runs as root on the machine, so it deserves the
    // same scrutiny as the build itself.
    for candidate in [format!("{name}.install"), ".INSTALL".to_string()] {
        let path = dir.join(&candidate);
        if let Ok(text) = std::fs::read_to_string(&path) {
            ctx.ui.warn(&format!("{name} ships an install scriptlet ({candidate}):"));
            for line in text.lines() {
                println!("    {line}");
            }
            ctx.ui.blank();
            break;
        }
    }

    if ctx.ui.confirm(&format!("continue building {name}?"), true) {
        Ok(())
    } else {
        Err("cancelled after review".into())
    }
}

/// Records the upstream head commit of a freshly built VCS package.
fn record_devel(ctx: &mut Context, name: &str, cache: &Path) {
    let dir = crate::aur::build_dir(cache, name);
    let Ok(srcinfo) = SrcInfo::read(&dir) else {
        return;
    };
    let Some(url) = crate::devel::vcs_source(&srcinfo.sources) else {
        return;
    };
    let Some(commit) = crate::devel::remote_head(&url) else {
        return;
    };

    ctx.devel
        .record(name, crate::devel::Tracked { url, commit });
    if let Err(e) = ctx.devel.save(&ctx.config.db_path) {
        ctx.ui
            .warn(&format!("could not record upstream state for {name}: {e}"));
    }
}

/// Runs one scriptlet hook, reporting rather than aborting on failure.
///
/// pacman treats a failing scriptlet as a warning: the files are already on
/// disk, and unwinding a partially applied transaction would leave the system
/// in a worse state than a package whose post-install step misbehaved.
pub(crate) fn run_scriptlet(
    ctx: &Context,
    package: &str,
    script: Option<&[u8]>,
    hook: Hook,
    new_version: &str,
    old_version: Option<&str>,
) {
    let Some(script) = script else {
        return;
    };

    match scriptlet::run(
        &ctx.config.root_dir,
        package,
        script,
        hook,
        new_version,
        old_version,
    ) {
        scriptlet::Outcome::Ran => {
            ctx.ui
                .detail(&format!("{package}: ran {}", hook.function()));
        }
        scriptlet::Outcome::NotDefined => {}
        scriptlet::Outcome::Failed(message) => {
            ctx.ui.warn(&format!(
                "{package}: {} failed: {message}",
                hook.function()
            ));
        }
    }
}

/// Fills a package record from the `.PKGINFO` inside the archive.
///
/// The archive is the ground truth: a sync database entry can be incomplete,
/// and for something rvn built from the AUR there is no database entry at all
/// — the RPC reports neither installed size nor architecture.
fn apply_pkginfo(record: &mut Package, pkginfo: &HashMap<String, Vec<String>>) {
    if pkginfo.is_empty() {
        return;
    }

    let first = |key: &str| pkginfo.get(key).and_then(|v| v.first()).cloned();
    let list = |key: &str| pkginfo.get(key).cloned().unwrap_or_default();
    let deps = |key: &str| {
        list(key)
            .iter()
            .map(|d| crate::pkg::Dep::parse(d))
            .collect::<Vec<_>>()
    };

    // A `-git` package's version is only known after pkgver() has run, so the
    // built artefact always wins over whatever the AUR RPC advertised.
    if let Some(version) = first("pkgver") {
        record.version = version;
    }
    if let Some(size) = first("size").and_then(|s| s.parse::<u64>().ok()) {
        record.isize = size;
    }
    if let Some(arch) = first("arch") {
        record.arch = Some(arch);
    }
    if let Some(date) = first("builddate").and_then(|s| s.parse::<u64>().ok()) {
        record.build_date = date;
    }
    if record.packager.is_none() {
        record.packager = first("packager");
    }
    if record.base.is_none() {
        record.base = first("pkgbase");
    }
    if record.url.is_none() {
        record.url = first("url");
    }
    if record.description.is_empty() {
        record.description = first("pkgdesc").unwrap_or_default();
    }
    if record.licenses.is_empty() {
        record.licenses = list("license");
    }
    if record.groups.is_empty() {
        record.groups = list("group");
    }

    for (field, key) in [
        (&mut record.depends, "depend"),
        (&mut record.provides, "provides"),
        (&mut record.conflicts, "conflict"),
        (&mut record.replaces, "replaces"),
        (&mut record.optdepends, "optdepend"),
    ] {
        let parsed = deps(key);
        if !parsed.is_empty() {
            *field = parsed;
        }
    }
}

/// Checks a batch of archives for file conflicts, unpacks them, and records
/// them in the local database. Returns the installed names and how many stale
/// files an upgrade cleaned up.
fn install_archives(
    ctx: &mut Context,
    plan: &Plan,
    archives: &[(String, PathBuf)],
    validations: &HashMap<String, crate::pkg::Validation>,
) -> Result<(Vec<String>, usize), String> {
    let spinner = ctx.ui.stage("checking for file conflicts");
    let mut manifests = Vec::new();

    for (name, path) in archives {
        let manifest = extract::manifest(path).map_err(|e| format!("{name}: {e}"))?;
        let upgrading = ctx.local.get(name).map(|_| name.as_str());
        let conflicts = extract::find_conflicts(&manifest, &ctx.local, upgrading)
            .map_err(|e| format!("{name}: could not check for file conflicts: {e}"))?;
        if !conflicts.is_empty() {
            spinner.fail("file conflicts detected");
            let lines: Vec<String> = conflicts.iter().map(|c| c.to_string()).collect();
            ctx.ui.tree(&lines);
            return Err(format!("{name} conflicts with installed files"));
        }
        manifests.push((name.clone(), path.clone(), manifest));
    }
    spinner.succeed("no file conflicts");

    let total_files: u64 = manifests.iter().map(|(_, _, m)| m.files.len() as u64).sum();
    let mut progress = ctx.ui.counter("installing", total_files, "files");
    let mut installed_names = Vec::new();
    let mut removed_stale = 0usize;

    for (name, path, manifest) in &manifests {
        progress.set_detail(name);
        let Some(resolved) = plan.install.iter().find(|r| r.package.name == *name) else {
            // An archive naming something outside the plan is a packaging
            // surprise, not a reason to abort a transaction already underway.
            ctx.ui
                .warn(&format!("{name} is not part of this transaction; skipping"));
            continue;
        };

        let previous_files = ctx.local.files(name).unwrap_or_default();
        let old_version = resolved.replaces_version.clone();
        let upgrading = old_version.is_some();

        // Pre hooks run before anything is written, so a package can bail out
        // or migrate state while the old version is still in place.
        run_scriptlet(
            ctx,
            name,
            manifest.install_script.as_deref(),
            Hook::for_install(upgrading, true),
            &resolved.package.version,
            old_version.as_deref(),
        );

        let files = extract::unpack(path, &ctx.config.root_dir, |_| progress.advance(1))
            .map_err(|e| format!("{name}: {e}"))?;

        removed_stale += prune_stale(ctx, &previous_files, &files, name);

        let mut record = resolved.package.clone();
        apply_pkginfo(&mut record, &manifest.pkginfo);
        record.backup = manifest
            .backup
            .iter()
            .map(|path| BackupFile {
                path: path.clone(),
                hash: crate::verify::sha256_file(&ctx.config.root_dir.join(path)).ok(),
            })
            .collect();
        record.validation = validations
            .get(name)
            .copied()
            .unwrap_or(crate::pkg::Validation::None);
        record.install_reason = match ctx.local.get(name).map(|p| p.install_reason) {
            Some(InstallReason::Explicit) => InstallReason::Explicit,
            _ if resolved.reason.is_explicit() => InstallReason::Explicit,
            _ => InstallReason::Dependency,
        };

        ctx.local
            .register_with_mtree(
                &record,
                &files,
                manifest.mtree.as_deref(),
                manifest.install_script.as_deref(),
                manifest.install_script_mtime,
            )
            .map_err(|e| format!("{name}: could not record installation: {e}"))?;

        run_scriptlet(
            ctx,
            name,
            manifest.install_script.as_deref(),
            Hook::for_install(upgrading, false),
            &record.version,
            old_version.as_deref(),
        );

        installed_names.push(name.clone());
    }

    progress.finish(&format!(
        "installed {} package{}",
        installed_names.len(),
        if installed_names.len() == 1 { "" } else { "s" }
    ));

    Ok((installed_names, removed_stale))
}

/// Reports anything that makes the plan unusable.
fn report_problems(ctx: &Context, plan: &Plan) -> Result<(), String> {
    if !plan.cycles.is_empty() {
        for cycle in &plan.cycles {
            ctx.ui
                .warn(&format!("dependency cycle: {}", cycle.join(" → ")));
        }
    }

    if !plan.conflicts.is_empty() {
        ctx.ui.err("conflicting packages:");
        let lines: Vec<String> = plan
            .conflicts
            .iter()
            .map(|c| format!("{} conflicts with {}", c.package, c.conflicts_with))
            .collect();
        ctx.ui.tree(&lines);
        return Err("resolve the conflicts above and try again".into());
    }

    if !plan.missing.is_empty() {
        ctx.ui.err("unresolvable dependencies:");
        let lines: Vec<String> = plan
            .missing
            .iter()
            .map(|m| match &m.required_by {
                Some(parent) => format!("{} (required by {parent})", m.dep),
                None => format!("{} (not found in any repository or the AUR)", m.dep),
            })
            .collect();
        ctx.ui.tree(&lines);
        return Err("could not satisfy every dependency".into());
    }

    Ok(())
}

/// Prints the transaction summary the user is about to approve.
fn show_plan(ctx: &Context, plan: &Plan) {
    let s = &ctx.ui.style;
    ctx.ui.blank();

    let explicit: Vec<&Resolved> = plan.install.iter().filter(|r| r.reason.is_explicit()).collect();
    let implicit: Vec<&Resolved> = plan
        .install
        .iter()
        .filter(|r| !r.reason.is_explicit())
        .collect();

    let render = |r: &Resolved| {
        let pkg = &r.package;
        let origin = s.paint(
            if pkg.origin.is_aur() {
                Color::Cyan
            } else {
                Color::Violet
            },
            pkg.origin.label(),
        );
        match &r.replaces_version {
            Some(old) => format!(
                "{origin}/{} {} {} {}",
                s.bold(&pkg.name),
                s.dim(old),
                s.glyphs.arrow,
                s.paint(Color::Green, &pkg.version)
            ),
            None => format!(
                "{origin}/{} {}",
                s.bold(&pkg.name),
                s.paint(Color::Green, &pkg.version)
            ),
        }
    };

    if !explicit.is_empty() {
        ctx.ui.step("packages requested");
        ctx.ui
            .tree(&explicit.iter().map(|r| render(r)).collect::<Vec<_>>());
    }

    if !implicit.is_empty() {
        ctx.ui.step(&format!("dependencies ({})", implicit.len()));
        ctx.ui
            .tree(&implicit.iter().map(|r| render(r)).collect::<Vec<_>>());
    }

    if !plan.replacing.is_empty() {
        ctx.ui
            .step(&format!("replacing ({})", plan.replacing.len()));
        ctx.ui.tree(
            &plan
                .replacing
                .iter()
                .map(|(new, old)| {
                    format!(
                        "{} {} {}",
                        s.bold(old),
                        s.glyphs.arrow,
                        s.paint(Color::Green, new)
                    )
                })
                .collect::<Vec<_>>(),
        );
    }

    ctx.ui.blank();
    let aur = plan.aur_count();
    ctx.ui.info(&format!(
        "download {}   installed size {}{}",
        s.bold(&bytes(plan.download_size())),
        s.bold(&bytes_signed(plan.installed_size_delta())),
        if aur > 0 {
            format!("   {} to build from source", s.paint(Color::Cyan, &aur.to_string()))
        } else {
            String::new()
        }
    ));
    ctx.ui.blank();
}

/// Downloads one repository package, reusing a valid cache entry.
fn fetch_package(
    ctx: &Context,
    pkg: &Package,
    cache: &Path,
    progress: &mut crate::ui::progress::Progress,
) -> Result<PathBuf, String> {
    let filename = pkg
        .filename
        .clone()
        .ok_or_else(|| format!("{} has no filename in the repository database", pkg.name))?;
    let dest = cache.join(&filename);

    if fetch::cached_ok(&dest, pkg.csize) {
        // Cache hits still have to move the bar or it would stall visibly.
        progress.advance(pkg.csize);
        return Ok(dest);
    }

    let repo_name = pkg.origin.label();
    let repo = ctx
        .config
        .repo(repo_name)
        .ok_or_else(|| format!("repository {repo_name} is not configured"))?;
    let urls = syncdb::package_urls(repo, &filename);

    fetch::download_with_mirrors(&urls, &dest, Some(progress)).map_err(|e| e.to_string())?;

    // Fetch the detached signature when the repo expects one.
    if pkg.has_sig && repo.siglevel.package.is_checked() {
        let sig_urls: Vec<String> = urls.iter().map(|u| format!("{u}.sig")).collect();
        let sig_dest = signature_path(&dest);
        let _ = fetch::download_with_mirrors(&sig_urls, &sig_dest, None);
    }

    Ok(dest)
}

/// Runs checksum and signature verification for one downloaded package.
fn verify_one(ctx: &Context, pkg: &Package, path: &Path) -> Result<Verified, String> {
    let level = ctx
        .config
        .repo(pkg.origin.label())
        .map(|r| r.siglevel.package)
        // A locally built package has no repo entry and no signature.
        .unwrap_or(Level::Never);

    let signature = std::fs::read(signature_path(path)).ok();

    verify::verify_package(
        path,
        pkg.sha256.as_deref(),
        signature.as_deref(),
        ctx.keyring.as_ref(),
        level,
    )
    .map_err(|e| e.to_string())
}

/// The identity a build should run as.
///
/// makepkg refuses to run as root, but rvn needs root to install. When running
/// privileged, the build is dropped to an unprivileged user.
#[derive(Debug, Clone)]
pub struct BuildIdentity {
    pub user: String,
    pub uid: u32,
    pub gid: u32,
}

/// Looks up a user's numeric ids.
fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let uid = Command::new("id").arg("-u").arg(name).output().ok()?;
    let gid = Command::new("id").arg("-g").arg(name).output().ok()?;
    if !uid.status.success() || !gid.status.success() {
        return None;
    }
    Some((
        String::from_utf8_lossy(&uid.stdout).trim().parse().ok()?,
        String::from_utf8_lossy(&gid.stdout).trim().parse().ok()?,
    ))
}

/// Chooses who to build as. `None` means the current user is already fine.
fn build_identity() -> Option<BuildIdentity> {
    if !super::is_root() {
        return None;
    }

    // Prefer whoever invoked `sudo rvn`, so build artefacts and caches stay
    // owned by a real account. Fall back to `nobody` for a true root login.
    let candidates: Vec<String> = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| u != "root")
        .into_iter()
        .chain(["nobody".to_string()])
        .collect();

    for candidate in candidates {
        if let Some((uid, gid)) = lookup_user(&candidate) {
            if uid != 0 {
                return Some(BuildIdentity {
                    user: candidate,
                    uid,
                    gid,
                });
            }
        }
    }

    None
}

/// Recursively gives a tree to the build user so makepkg can write into it.
fn chown_tree(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))?;
    if path.is_dir() && !path.is_symlink() {
        for entry in std::fs::read_dir(path)? {
            chown_tree(&entry?.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// Builds a command that runs as the build user when privileges must be
/// dropped, and as the current user otherwise.
///
/// Everything touching the build tree goes through this — git included — so
/// the tree has a single consistent owner. Running git as root against a tree
/// owned by someone else trips its "dubious ownership" refusal.
fn build_command(program: &str, dir: &Path, identity: Option<&BuildIdentity>) -> Command {
    match identity {
        Some(id) => {
            // `setpriv` drops to the target uid without going through PAM,
            // which matters because `nobody` is a locked account.
            let mut command = Command::new("setpriv");
            command
                .arg(format!("--reuid={}", id.uid))
                .arg(format!("--regid={}", id.gid))
                .arg("--clear-groups")
                .arg(program)
                .current_dir(dir)
                // makepkg and git both write into $HOME.
                .env("HOME", dir);
            command
        }
        None => {
            let mut command = Command::new(program);
            command.current_dir(dir);
            command
        }
    }
}

/// A git invocation scoped to the build tree.
fn git_command(dir: &Path, identity: Option<&BuildIdentity>) -> Command {
    let mut command = build_command("git", dir, identity);
    // Belt and braces: even with consistent ownership, a tree created under a
    // different SUDO_USER would otherwise be rejected.
    command
        .arg("-c")
        .arg(format!("safe.directory={}", dir.display()));
    command
}

/// Builds the makepkg invocation.
fn makepkg_command(dir: &Path, identity: Option<&BuildIdentity>) -> Command {
    let mut command = build_command("makepkg", dir, identity);
    command.args([
        "--force",
        "--noconfirm",
        "--noprogressbar",
        // rvn has already resolved and installed the dependencies.
        "--nodeps",
    ]);
    command
}

/// Turns a raw makepkg failure into something actionable.
fn explain_build_failure(output: &str) -> String {
    if output.contains("unknown public key") {
        let key = output
            .split("unknown public key ")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_alphanumeric()).next())
            .unwrap_or("");
        return format!(
            "the source is signed by a key that is not trusted locally. \
             Import it with `gpg --recv-keys {key}` and try again"
        );
    }
    if output.contains("Running makepkg as root") {
        return "makepkg refused to run as root and no unprivileged user was available; \
                run rvn with sudo from a normal account"
            .to_string();
    }
    output
        .lines()
        .rev()
        .find(|line| line.contains("ERROR") || line.contains("error:"))
        .unwrap_or_else(|| output.lines().last().unwrap_or("build failed"))
        .trim()
        .to_string()
}

/// Clones an AUR package's build files and builds it.
///
/// rvn drives the build itself rather than shelling out to another package
/// manager, but a PKGBUILD is a bash script, so bash and makepkg are required.
fn build_aur(
    ctx: &Context,
    pkg: &Package,
    cache: &Path,
    spinner: &Spinner,
) -> Result<Vec<PathBuf>, String> {
    let on_step = |step: &str| spinner.set_message(&format!("building {} — {step}", pkg.name));
    let dir = crate::aur::build_dir(cache, &pkg.name);

    if Command::new("makepkg").arg("--version").output().is_err() {
        return Err(
            "makepkg is required to build AUR packages; install the `pacman` package".into(),
        );
    }

    let identity = build_identity();
    if identity.is_none() && super::is_root() {
        return Err("makepkg cannot run as root and no unprivileged build user was found".into());
    }

    on_step("fetching build files");
    let is_repo = dir.join(".git").exists();
    if !is_repo && dir.exists() {
        // A partial checkout from an interrupted run would confuse git.
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // Hand the tree over before git touches it, so every file it writes is
    // owned by the account that will run the build.
    if let Some(id) = &identity {
        chown_tree(&dir, id.uid, id.gid)
            .map_err(|e| format!("could not hand the build tree to {}: {e}", id.user))?;
    }

    if is_repo {
        run_command(git_command(&dir, identity.as_ref()).arg("pull").arg("--ff-only"))
            .map_err(|e| format!("git pull failed: {e}"))?;
    } else {
        run_command(
            git_command(&dir, identity.as_ref())
                .arg("clone")
                .arg("--depth=1")
                .arg(Aur::git_url(&pkg.name))
                .arg("."),
        )
        .map_err(|e| format!("git clone failed: {e}"))?;
    }

    on_step("reading .SRCINFO");
    let srcinfo = SrcInfo::read(&dir).map_err(|e| format!("could not read .SRCINFO: {e}"))?;

    // A PKGBUILD is arbitrary code from a stranger, run with the build user's
    // privileges. Offer a look before that happens.
    if !ctx.assume_yes && ctx.ui.style.interactive {
        spinner.suspend(|| review_build_files(ctx, &pkg.name, &dir))?;
    } else {
        ctx.ui.detail(&format!("build files: {}", dir.display()));
    }

    on_step("compiling");
    // makepkg's own log is the only honest progress report a long build has,
    // so the spinner stands down and hands it the terminal.
    let (status, log) = spinner.suspend(|| {
        run_streamed(
            &mut makepkg_command(&dir, identity.as_ref()),
            std::io::stderr,
        )
        .map_err(|e| format!("could not run makepkg: {e}"))
    })?;

    if !status.success() {
        return Err(explain_build_failure(&log));
    }

    on_step("collecting artifacts");
    let artifacts = collect_artifacts(&dir, &srcinfo)?;
    if artifacts.is_empty() {
        return Err(format!(
            "build produced no package files in {}",
            dir.display()
        ));
    }
    Ok(artifacts)
}

/// Extracts the package name from an archive filename.
///
/// The layout is `name-version-release-arch.pkg.tar.<ext>`, and a name may
/// itself contain hyphens, so the name is whatever remains after removing the
/// final three fields.
pub fn package_name_from_filename(filename: &str) -> Option<String> {
    let stem = filename.split(".pkg.tar").next()?;
    let fields: Vec<&str> = stem.split('-').collect();
    if fields.len() < 4 {
        return None;
    }
    Some(fields[..fields.len() - 3].join("-"))
}

/// The package name recorded inside an archive's `.PKGINFO`.
fn archive_package_name(path: &Path) -> Option<String> {
    extract::manifest(path)
        .ok()?
        .pkginfo
        .get("pkgname")
        .and_then(|values| values.first())
        .cloned()
}

/// Finds the `.pkg.tar.*` files a build produced.
fn collect_artifacts(dir: &Path, srcinfo: &SrcInfo) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| e.to_string())?;

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.contains(".pkg.tar") || name.ends_with(".sig") {
            continue;
        }
        // Prefix matching would let `foo` claim `foo-docs-1.0-1-any...`, so
        // the name is parsed out of the filename and compared exactly.
        let Some(archive_name) = package_name_from_filename(name) else {
            continue;
        };
        let belongs = srcinfo
            .pkgnames
            .iter()
            .chain(std::iter::once(&srcinfo.pkgbase))
            .any(|declared| *declared == archive_name);
        if belongs {
            found.push(path);
        }
    }

    found.sort();
    Ok(found)
}

/// Mirrors one of a child's pipes to `sink` as it arrives, accumulating the
/// text as it goes.
///
/// Reading is byte-oriented rather than line-oriented so that a build which
/// emits stray non-UTF-8 keeps streaming instead of cutting off mid-log.
fn mirror<R, W>(pipe: R, mut sink: W, collected: Arc<Mutex<String>>) -> thread::JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
    W: Write + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut raw = Vec::new();

        while matches!(reader.read_until(b'\n', &mut raw), Ok(n) if n > 0) {
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim_end_matches(['\n', '\r']);

            // Indented to sit under the stage line, but otherwise verbatim:
            // makepkg colours its own output, and wrapping it would collide
            // with the escape sequences already in the text.
            let _ = writeln!(sink, "     {line}");
            let _ = sink.flush();

            if let Ok(mut text) = collected.lock() {
                text.push_str(line);
                text.push('\n');
            }
            raw.clear();
        }
    })
}

/// Runs a command with its output mirrored to `sink` line by line, returning
/// the exit status alongside everything it printed.
///
/// A build that can run for minutes behind a captured pipe is indistinguishable
/// from a hang, so the output is echoed as it arrives — but it is still
/// collected, because a failure has to be explained after the fact.
fn run_streamed<W: Write + Send + 'static>(
    command: &mut Command,
    sink: impl Fn() -> W,
) -> Result<(ExitStatus, String), String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| e.to_string())?;

    let collected = Arc::new(Mutex::new(String::new()));
    // Each pipe gets its own reader: makepkg writes to both, and draining them
    // one after the other would wedge the build as soon as the pipe nobody is
    // reading filled its buffer.
    let out = child
        .stdout
        .take()
        .map(|pipe| mirror(pipe, sink(), Arc::clone(&collected)));
    let err = child
        .stderr
        .take()
        .map(|pipe| mirror(pipe, sink(), Arc::clone(&collected)));

    let status = child.wait().map_err(|e| e.to_string())?;
    // Joining after the wait: the readers finish when the pipes close, which
    // is guaranteed once the process is gone.
    for reader in [out, err].into_iter().flatten() {
        let _ = reader.join();
    }

    let text = collected.lock().map(|t| t.clone()).unwrap_or_default();
    Ok((status, text))
}

fn run_command(command: &mut Command) -> Result<(), String> {
    let output = command.output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(stderr.lines().last().unwrap_or("command failed").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::aur::SrcInfo;

    /// A shell script run through the streaming runner. Output goes to
    /// `io::sink` so the suite stays quiet — the mirroring itself is the same
    /// code path either way.
    fn streamed(script: &str) -> (ExitStatus, String) {
        let mut command = Command::new("sh");
        command.arg("-c").arg(script);
        run_streamed(&mut command, std::io::sink).expect("sh should run")
    }

    #[test]
    fn streaming_collects_both_pipes_and_the_exit_status() {
        let (status, log) = streamed("echo to-stdout; echo to-stderr >&2; exit 3");

        assert_eq!(status.code(), Some(3));
        // A failure is explained from this text after the fact, so makepkg's
        // errors — which land on stderr — have to survive the streaming.
        assert!(log.contains("to-stdout"), "{log}");
        assert!(log.contains("to-stderr"), "{log}");
    }

    #[test]
    fn a_build_that_floods_both_pipes_at_once_does_not_deadlock() {
        // Each pipe gets more than a pipe buffer's worth while the other is
        // also being written. Draining them in sequence would stall here
        // forever, which is exactly the hang this runner exists to avoid.
        let (status, log) = streamed(
            "line=$(head -c 1200 /dev/zero | tr '\\0' x)
             i=0; while [ $i -lt 80 ]; do echo \"$line\"; i=$((i+1)); done &
             j=0; while [ $j -lt 80 ]; do echo \"$line\" >&2; j=$((j+1)); done
             wait",
        );

        assert!(status.success());
        assert_eq!(log.lines().count(), 160);
    }

    #[test]
    fn streaming_survives_output_that_is_not_utf8() {
        let (status, log) = streamed("printf 'good\\n\\377\\nalso-good\\n'");

        assert!(status.success());
        assert!(log.contains("good"), "{log}");
        assert!(log.contains("also-good"), "{log}");
    }

    #[test]
    fn a_missing_program_is_an_error_not_a_panic() {
        let mut command = Command::new("rvn-no-such-build-tool");
        assert!(run_streamed(&mut command, std::io::sink).is_err());
    }

    /// Creates empty files with the given names so artifact selection can be
    /// exercised without building anything.
    fn artifact_dir(tag: &str, names: &[&str]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-artifacts-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in names {
            std::fs::write(dir.join(name), b"").unwrap();
        }
        dir
    }

    #[test]
    fn package_names_are_parsed_out_of_filenames() {
        assert_eq!(
            package_name_from_filename("foo-1.0-1-x86_64.pkg.tar.zst").as_deref(),
            Some("foo")
        );
        // A hyphenated name must survive intact.
        assert_eq!(
            package_name_from_filename("foo-docs-1.0-1-any.pkg.tar.zst").as_deref(),
            Some("foo-docs")
        );
        // An epoch lives inside the version field, not the name.
        assert_eq!(
            package_name_from_filename("go-2:1.22.0-1-x86_64.pkg.tar.zst").as_deref(),
            Some("go")
        );
        assert_eq!(
            package_name_from_filename("ttf-material-design-icons-git-v7.4.47.r0.g57b567a-1-any.pkg.tar.zst")
                .as_deref(),
            Some("ttf-material-design-icons-git")
        );
        // Too few fields to be a package filename.
        assert_eq!(package_name_from_filename("junk.pkg.tar.zst"), None);
    }

    #[test]
    fn a_sibling_package_is_not_claimed_by_a_name_prefix() {
        let dir = artifact_dir(
            "prefix",
            &[
                "foo-1.0-1-x86_64.pkg.tar.zst",
                "foo-docs-1.0-1-any.pkg.tar.zst",
                "unrelated-2.0-1-any.pkg.tar.zst",
            ],
        );

        // A build declaring only `foo` must not scoop up `foo-docs`.
        let srcinfo = SrcInfo::parse("pkgbase = foo\n\tpkgver = 1.0\n\tpkgrel = 1\n");
        let found = collect_artifacts(&dir, &srcinfo).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["foo-1.0-1-x86_64.pkg.tar.zst"], "{names:?}");
    }

    #[test]
    fn a_split_build_collects_every_declared_output() {
        let dir = artifact_dir(
            "split",
            &[
                "foo-1.0-1-x86_64.pkg.tar.zst",
                "foo-docs-1.0-1-any.pkg.tar.zst",
                "unrelated-2.0-1-any.pkg.tar.zst",
            ],
        );

        let srcinfo = SrcInfo::parse(
            "pkgbase = foo\n\tpkgver = 1.0\n\tpkgrel = 1\n\npkgname = foo\npkgname = foo-docs\n",
        );
        let found = collect_artifacts(&dir, &srcinfo).unwrap();
        assert_eq!(found.len(), 2, "both split outputs belong to the build");
        assert!(found.iter().all(|p| !p
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("unrelated")));
    }

    #[test]
    fn signatures_are_not_treated_as_artifacts() {
        let dir = artifact_dir(
            "sigs",
            &["foo-1.0-1-any.pkg.tar.zst", "foo-1.0-1-any.pkg.tar.zst.sig"],
        );
        let srcinfo = SrcInfo::parse("pkgbase = foo\n\tpkgver = 1.0\n\tpkgrel = 1\n");
        assert_eq!(collect_artifacts(&dir, &srcinfo).unwrap().len(), 1);
    }

    #[test]
    fn unknown_signing_key_gets_actionable_advice() {
        let output = "==> Verifying source file signatures with gpg...\n\
                      neofetch git repo ... FAILED (unknown public key 46D62DD9F1DE636E)\n\
                      ==> ERROR: One or more PGP signatures could not be verified!";
        let explained = explain_build_failure(output);
        assert!(explained.contains("gpg --recv-keys 46D62DD9F1DE636E"), "{explained}");
    }

    #[test]
    fn root_refusal_is_explained_rather_than_echoed() {
        let output = "==> ERROR: Running makepkg as root is not allowed as it can cause \
                      permanent, catastrophic damage to your system.";
        let explained = explain_build_failure(output);
        assert!(explained.contains("unprivileged"), "{explained}");
        assert!(!explained.contains("catastrophic"), "raw text should not leak through");
    }

    #[test]
    fn other_failures_surface_the_error_line() {
        let output = "checking prerequisites\n==> ERROR: missing required tool: cmake\ndone";
        assert!(explain_build_failure(output).contains("missing required tool: cmake"));
    }

    #[test]
    fn makepkg_arguments_never_pass_a_value_to_syncdeps() {
        // `--syncdeps` takes no argument; passing one makes makepkg abort.
        let dir = std::path::Path::new("/tmp");
        let command = makepkg_command(dir, None);
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.iter().all(|a| !a.contains("--syncdeps")), "{args:?}");
        assert!(args.contains(&"--noconfirm".to_string()));
        assert!(args.contains(&"--nodeps".to_string()));
    }

    #[test]
    fn git_runs_as_the_build_user_with_a_safe_directory() {
        let identity = BuildIdentity {
            user: "nobody".into(),
            uid: 65534,
            gid: 65534,
        };
        let dir = std::path::Path::new("/var/cache/aur/demo");
        let command = git_command(dir, Some(&identity));

        // Running git as root against a tree owned by the build user trips
        // git's dubious-ownership refusal, so it must drop privileges too.
        assert_eq!(command.get_program(), "setpriv");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.contains(&"git".to_string()), "{args:?}");
        assert!(
            args.contains(&"safe.directory=/var/cache/aur/demo".to_string()),
            "{args:?}"
        );
    }

    #[test]
    fn dropping_privileges_runs_makepkg_under_setpriv() {
        let identity = BuildIdentity {
            user: "nobody".into(),
            uid: 65534,
            gid: 65534,
        };
        let command = makepkg_command(std::path::Path::new("/tmp"), Some(&identity));
        assert_eq!(command.get_program(), "setpriv");

        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.contains(&"--reuid=65534".to_string()), "{args:?}");
        assert!(args.contains(&"--regid=65534".to_string()), "{args:?}");
        assert!(args.contains(&"makepkg".to_string()));
    }
}
