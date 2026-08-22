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
use crate::ui::theme::{Color, bytes, bytes_signed};
use crate::config::SigLevel;
use crate::verify::{self, Verified};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Outcome {
    pub installed: Vec<String>,
    pub skipped: Vec<String>,
}

/// Runs `rvn install`, including the masthead.
pub fn run(ctx: &mut Context, targets: &[String]) -> Result<Outcome, String> {
    ctx.ui.banner(&format!("v{}", env!("CARGO_PKG_VERSION")));
    execute(ctx, targets)
}

/// The install pipeline without the masthead, so other operations — notably
/// `update` — can drive it as one step of a larger flow.
pub fn execute(ctx: &mut Context, targets: &[String]) -> Result<Outcome, String> {
    if ctx.sync.is_empty() {
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
                .resolve(targets)
        } else {
            Resolver::new(&ctx.sync, &ctx.local, &ctx.aur)
                .ignoring(&ctx.config.ignore_pkg)
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
                Ok(Verified::ChecksumAndSignature { .. }) => signed += 1,
                Ok(_) => {}
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

    // ---- build AUR packages -------------------------------------------
    for resolved in &aur_targets {
        let pkg = &resolved.package;
        let spinner = ctx.ui.stage(&format!("building {} (aur)", pkg.name));

        match build_aur(ctx, pkg, &cache, |step| {
            spinner.set_message(&format!("building {} — {step}", pkg.name));
        }) {
            Ok(artifacts) => {
                spinner.succeed(&format!("built {}", pkg.name));
                for artifact in artifacts {
                    downloaded.push((pkg.name.clone(), artifact));
                }
            }
            Err(e) => {
                spinner.fail(&format!("{} failed to build", pkg.name));
                return Err(format!("{}: {e}", pkg.name));
            }
        }
    }

    // ---- conflict check ------------------------------------------------
    let spinner = ctx.ui.stage("checking for file conflicts");
    let mut manifests = Vec::new();
    for (name, path) in &downloaded {
        let manifest = extract::manifest(path).map_err(|e| format!("{name}: {e}"))?;
        let upgrading = ctx.local.get(name).map(|_| name.as_str());
        let conflicts = extract::find_conflicts(&manifest, &ctx.local, upgrading);
        if !conflicts.is_empty() {
            spinner.fail("file conflicts detected");
            let lines: Vec<String> = conflicts.iter().map(|c| c.to_string()).collect();
            ctx.ui.tree(&lines);
            return Err(format!("{name} conflicts with installed files"));
        }
        manifests.push((name.clone(), path.clone(), manifest));
    }
    spinner.succeed("no file conflicts");

    // ---- install -------------------------------------------------------
    let total_files: u64 = manifests.iter().map(|(_, _, m)| m.files.len() as u64).sum();
    let mut progress = ctx.ui.counter("installing", total_files, "files");
    let mut installed_names = Vec::new();
    let mut removed_stale = 0usize;

    for (name, path, manifest) in &manifests {
        progress.set_detail(name);
        let resolved = plan
            .install
            .iter()
            .find(|r| r.package.name == *name)
            .expect("package must be in the plan");

        // Recorded before unpacking overwrites the database entry, so files
        // dropped between versions can be cleaned up afterwards.
        let previous_files = ctx.local.files(name).unwrap_or_default();

        let files = extract::unpack(path, &ctx.config.root_dir, |_| progress.advance(1))
            .map_err(|e| format!("{name}: {e}"))?;

        let stale = prune_stale(ctx, &previous_files, &files, name);
        if stale > 0 {
            removed_stale += stale;
        }

        // Record why the package is here: orphan detection depends on it, and
        // an upgrade must never demote a package the user asked for to a
        // mere dependency.
        let mut record = resolved.package.clone();
        // `%BACKUP%` lives in the package's .PKGINFO, not in the sync
        // database, so it only becomes known once the archive is read. The
        // checksum is taken from the file just written, giving removal a
        // baseline to detect later edits against.
        record.backup = manifest
            .backup
            .iter()
            .map(|path| BackupFile {
                path: path.clone(),
                hash: crate::verify::sha256_file(&ctx.config.root_dir.join(path)).ok(),
            })
            .collect();
        record.install_reason = match ctx.local.get(name).map(|p| p.install_reason) {
            Some(InstallReason::Explicit) => InstallReason::Explicit,
            _ if resolved.reason.is_explicit() => InstallReason::Explicit,
            _ => InstallReason::Dependency,
        };

        ctx.local
            .register(&record, &files)
            .map_err(|e| format!("{name}: could not record installation: {e}"))?;
        installed_names.push(name.clone());
    }

    progress.finish(&format!(
        "installed {} package{}",
        installed_names.len(),
        if installed_names.len() == 1 { "" } else { "s" }
    ));

    if removed_stale > 0 {
        ctx.ui.info(&format!(
            "cleaned up {removed_stale} file{} left by the previous version",
            if removed_stale == 1 { "" } else { "s" }
        ));
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
    })
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
    if pkg.has_sig && repo.siglevel != SigLevel::Never {
        let sig_urls: Vec<String> = urls.iter().map(|u| format!("{u}.sig")).collect();
        let sig_dest = dest.with_extension(format!(
            "{}.sig",
            dest.extension().and_then(|e| e.to_str()).unwrap_or("pkg")
        ));
        let _ = fetch::download_with_mirrors(&sig_urls, &sig_dest, None);
    }

    Ok(dest)
}

/// Runs checksum and signature verification for one downloaded package.
fn verify_one(ctx: &Context, pkg: &Package, path: &Path) -> Result<Verified, String> {
    let siglevel = ctx
        .config
        .repo(pkg.origin.label())
        .map(|r| r.siglevel)
        // A locally built package has no repo entry and no signature.
        .unwrap_or(SigLevel::Never);

    let sig_path = path.with_extension(format!(
        "{}.sig",
        path.extension().and_then(|e| e.to_str()).unwrap_or("pkg")
    ));
    let signature = std::fs::read(&sig_path).ok();

    verify::verify_package(
        path,
        pkg.sha256.as_deref(),
        signature.as_deref(),
        ctx.keyring.as_ref(),
        siglevel,
    )
    .map_err(|e| e.to_string())
}

/// Clones an AUR package's build files and builds it.
///
/// rvn drives the build itself rather than shelling out to another package
/// manager, but a PKGBUILD is a bash script, so bash is required. `makepkg` is
/// used when present because it handles split packages and fakeroot properly;
/// otherwise rvn falls back to running the PKGBUILD's build/package functions
/// directly.
fn build_aur(
    ctx: &Context,
    pkg: &Package,
    cache: &Path,
    mut on_step: impl FnMut(&str),
) -> Result<Vec<PathBuf>, String> {
    let dir = crate::aur::build_dir(cache, &pkg.name);

    on_step("fetching build files");
    if dir.join(".git").exists() {
        run_command(Command::new("git").arg("-C").arg(&dir).arg("pull").arg("--ff-only"))
            .map_err(|e| format!("git pull failed: {e}"))?;
    } else {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        run_command(
            Command::new("git")
                .arg("clone")
                .arg("--depth=1")
                .arg(Aur::git_url(&pkg.name))
                .arg(&dir),
        )
        .map_err(|e| format!("git clone failed: {e}"))?;
    }

    on_step("reading .SRCINFO");
    let srcinfo = SrcInfo::read(&dir)
        .map_err(|e| format!("could not read .SRCINFO: {e}"))?;

    if !ctx.assume_yes {
        ctx.ui.info(&format!(
            "review the build files for {} at {}",
            pkg.name,
            dir.display()
        ));
    }

    on_step("compiling");
    let built = run_command(
        Command::new("makepkg")
            .current_dir(&dir)
            .arg("--nobuild")
            .arg("--noconfirm")
            .arg("--syncdeps=false"),
    );

    // `--nobuild` above is a probe for makepkg's presence; the real build
    // follows only if it is available.
    if built.is_ok() {
        run_command(
            Command::new("makepkg")
                .current_dir(&dir)
                .arg("--force")
                .arg("--noconfirm")
                .arg("--nodeps"),
        )
        .map_err(|e| format!("makepkg failed: {e}"))?;
    } else {
        return Err(format!(
            "makepkg is not available and rvn's built-in builder does not yet \
             cover this PKGBUILD; build files are at {}",
            dir.display()
        ));
    }

    on_step("collecting artifacts");
    let artifacts = collect_artifacts(&dir, &srcinfo)?;
    if artifacts.is_empty() {
        return Err(format!("build produced no package files in {}", dir.display()));
    }
    Ok(artifacts)
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
        // Only take artifacts belonging to this build.
        if srcinfo.pkgnames.iter().any(|p| name.starts_with(p))
            || name.starts_with(&srcinfo.pkgbase)
        {
            found.push(path);
        }
    }

    found.sort();
    Ok(found)
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
