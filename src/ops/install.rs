//! The install pipeline: resolve, fetch, verify, build, unpack, register.
//!
//! Each phase is a distinct animated stage so the user can see exactly where
//! a long install is spending its time.

use super::Context;
use crate::aur::{Aur, SrcInfo};
use crate::db::local::LocalDb;
use crate::db::sync as syncdb;
use crate::extract;
use crate::fetch;
use crate::pkg::{BackupFile, InstallReason, Package};

/// Paths a package payload may never replace, however the hash bookkeeping
/// comes out.
///
/// The `pristine` test in `install_one` asks "did the user edit this file?"
/// and, for an ordinary config file, answers it correctly: one that still
/// matches the hash recorded at install time is untouched, so it follows the
/// package across an upgrade. For the account database that question is the
/// wrong one. Nobody hand-edits /etc/passwd, so an image's own generated copy
/// reads as untouched -- and Arch's `filesystem` package, which lists every
/// path below as `backup`, ships a one-line /etc/passwd, a one-line
/// /etc/group and a root-only /etc/shadow.
///
/// Letting the payload win there empties the machine of accounts in one
/// extraction: `dbus-daemon --system` can no longer resolve the `dbus` user
/// and `seatd -g video` no longer resolves the `video` group, so both exit
/// the instant they start and the supervisor restarts them forever; no
/// uid >= 1000 is left for the graphical session to run as; root's password
/// hash is gone; and `sudo` answers "you do not exist in the passwd
/// database". The disk copy of these files wins unconditionally, and the
/// package's version goes to `.pacnew` like any other spared config.
const NEVER_REPLACED: &[&str] = &[
    "etc/passwd",
    "etc/group",
    "etc/shadow",
    "etc/gshadow",
    "etc/subuid",
    "etc/subgid",
    "etc/sudoers",
];
use crate::resolve::{NoSource, Plan, Resolved, Resolver};
use crate::scriptlet::{self, Hook};
use crate::txhooks;
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
    /// Configuration files this transaction refused to replace, with the
    /// package's version written alongside as `.pacnew`. Reported in the
    /// summary and settled afterwards with `rvn config`.
    pub pacnew: Vec<Pacnew>,
}

/// One configuration file an install left alone.
///
/// Both halves matter and neither is recoverable from the other later: the
/// path says which file on disk was spared, and the package says whose
/// payload is sitting beside it. `rvn config` needs both to say anything
/// useful, so they travel together rather than as a bare list of paths.
pub struct Pacnew {
    /// The package whose payload was set aside.
    pub package: String,
    /// The spared file, relative to the install root -- `etc/sudoers`. The
    /// package's version is at the same path with `.pacnew` appended.
    pub path: String,
}

/// What one call to `install_archives` did.
///
/// A transaction calls that function at least twice -- once for everything
/// that came from a repository, then once more per AUR package as each
/// finishes building -- so nothing it produces can be complete until the last
/// call returns. Every result it accumulates is merged here by `absorb` and
/// reported once, at the end, rather than from inside a loop that still has a
/// progress bar repainting over it.
#[derive(Default)]
struct Batch {
    installed: Vec<String>,
    /// Files an upgrade deleted because the new version no longer ships them.
    stale_removed: usize,
    /// Edited configuration files the new version no longer ships, set aside
    /// as `.pacsave` instead of being deleted. Reported separately because an
    /// administrator who has to go and find one needs its name, not a count.
    stale_preserved: Vec<String>,
    pacnew: Vec<Pacnew>,
}

impl Batch {
    fn absorb(&mut self, other: Batch) {
        self.installed.extend(other.installed);
        self.stale_removed += other.stale_removed;
        self.stale_preserved.extend(other.stale_preserved);
        self.pacnew.extend(other.pacnew);
    }
}

/// Runs `rvn install`, including the masthead.
pub fn run(ctx: &mut Context, targets: &[String]) -> Result<Outcome, String> {
    ctx.ui.banner(&format!("v{}", env!("CARGO_PKG_VERSION")));
    let outcome = execute(ctx, targets)?;
    if let Some(prefix) = &ctx.user_prefix
        && !outcome.installed.is_empty()
    {
        // Honest about the shape of a per-user prefix: programs work when
        // they are on the PATH; anything that hard-codes /usr does not.
        ctx.ui.info(&format!(
            "installed under {}; programs are in {}",
            prefix.root.display(),
            prefix.bin_dir().display()
        ));
        ctx.ui.detail(&format!(
            "put it on your PATH once: raven-add path {}",
            prefix.bin_dir().display()
        ));
        ctx.ui.detail(
            "self-contained tools work from there; a package that hard-codes /usr (libraries, data, D-Bus services) does not, and needs a system install",
        );
    }
    Ok(outcome)
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
                .with_system(&ctx.system)
                .ignoring(&ctx.config.ignore_pkg)
                .forcing(&ctx.force_rebuild)
                .resolve(targets)
        } else {
            Resolver::new(&ctx.sync, &ctx.local, &ctx.aur)
                .with_system(&ctx.system)
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

    for (name, by) in &plan.provided_by_system {
        ctx.ui.info(&format!(
            "{name} is provided by Raven itself ({by}); installing it would replace that, so it is skipped"
        ));
    }

    if plan.is_empty() {
        for name in &plan.already_satisfied {
            ctx.ui.ok(&format!("{name} is already installed and current"));
        }
        return Ok(Outcome {
            installed: Vec::new(),
            skipped: plan.already_satisfied.clone(),
            replaced: Vec::new(),
            pacnew: Vec::new(),
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
            pacnew: Vec::new(),
        });
    }

    if !ctx.assume_yes && !ctx.ui.confirm("proceed with installation?", true) {
        return Err("cancelled".into());
    }

    if !super::is_root() && ctx.config.root_dir == Path::new("/") {
        ctx.ui
            .warn("not running as root — writing to / will fail without elevated privileges");
    }

    // ---- pre-transaction hooks -----------------------------------------
    //
    // Here and not a line earlier: the plan has been approved, so nothing the
    // administrator wrote runs for a transaction the user has just declined.
    // Here and not a line later: nothing has been fetched and nothing has
    // been written, so a hook that says "do not do this" can still be obeyed
    // for free. After the first archive is opened it cannot be — `unpack`
    // keeps no copy of a file it overwrites, and a snapshot taken then is a
    // snapshot of a half-upgraded machine.
    let hooks = load_transaction_hooks(ctx)?;
    // Decided once and used for both moments. Asked again at the end it would
    // find every one of these packages installed and call the whole
    // transaction an update.
    let operations = transaction_operations(ctx, &plan);
    // Every package the transaction will touch, not just the ones the user
    // named: a hook that cares about the kernel cares just as much when the
    // kernel arrives as somebody else's dependency.
    let planned: Vec<String> = plan
        .install
        .iter()
        .map(|r| r.package.name.clone())
        .collect();
    let before = txhooks::Transaction::new(
        operations.clone(),
        planned.clone(),
        transaction_files(ctx, &planned, hooks.wants_paths(txhooks::When::Pre)),
    );
    run_transaction_hooks(ctx, &hooks, txhooks::When::Pre, &before)?;

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
    let mut batch = Batch::default();

    if !downloaded.is_empty() {
        batch.absorb(install_archives(ctx, &plan, &downloaded, &validations)?);
    }

    // Every archive this transaction built, kept alongside `downloaded` so the
    // cache policy at the end of the run can treat the two the same way. It
    // never used to be collected at all, and that is the whole of the leak:
    // `clear_cache` was only ever handed what was fetched, so an AUR package's
    // archive stayed in its build tree, where nothing in rvn has ever looked.
    let mut built_archives: Vec<PathBuf> = Vec::new();

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

        batch.absorb(install_archives(ctx, &plan, &built, &validations)?);
        built_archives.extend(built.into_iter().map(|(_, path)| path));
    }

    if batch.stale_removed > 0 {
        ctx.ui.info(&format!(
            "cleaned up {} file{} left by the previous version",
            batch.stale_removed,
            if batch.stale_removed == 1 { "" } else { "s" }
        ));
    }

    // Worth its own lines rather than a count: the new version stopped
    // shipping a config file the administrator had edited, and the only way
    // to get those edits back is to know where they went.
    if !batch.stale_preserved.is_empty() {
        ctx.ui.info(
            "the new version no longer ships these edited config files; \
             kept with a .pacsave suffix:",
        );
        ctx.ui.tree(&batch.stale_preserved);
    }

    // ---- retire replaced packages --------------------------------------
    //
    // Only now that the successors are installed: removing first would leave
    // the system without either package if an install failed.
    let superseded: Vec<String> = plan
        .replacing
        .iter()
        .filter(|(new, _)| batch.installed.contains(new))
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

    // ---- post-transaction hooks ----------------------------------------
    //
    // After the replaced packages have been retired, so a hook sees the state
    // the machine is actually being left in, and before the cache is cleared
    // and the summary is printed, so a hook that takes a while does it while
    // the transaction still visibly owns the terminal rather than after rvn
    // has apparently finished. The file list is exact by now: every package
    // in it is registered, so what each one owns can simply be read back.
    let after = txhooks::Transaction::new(
        operations,
        batch.installed.clone(),
        transaction_files(
            ctx,
            &batch.installed,
            hooks.wants_paths(txhooks::When::Post),
        ),
    );
    run_transaction_hooks(ctx, &hooks, txhooks::When::Post, &after)?;

    // The archives this transaction produced have served their purpose, and
    // one answer covers all of them. That is the change: until now only
    // `downloaded` was considered, so an AUR package's archive was left in the
    // build tree it was made in and no cache rule has ever reached it. On this
    // machine that was 8.0 GB of the 8.4 GB in /var/cache/pacman/pkg. A built
    // archive is not less of a cached package than a fetched one -- it is
    // more, since no mirror has a copy -- so it is either cleared with the
    // rest or kept with the rest, and never quietly kept somewhere nothing
    // looks.
    let produced: Vec<&Path> = downloaded
        .iter()
        .map(|(_, path)| path.as_path())
        .chain(built_archives.iter().map(|path| path.as_path()))
        .collect();

    if !ctx.keep_cache {
        // Clearing is the default so the cache cannot quietly grow without
        // bound.
        let freed = clear_cache(&produced);
        if freed > 0 {
            ctx.ui
                .info(&format!("reclaimed {} of packages", bytes(freed)));
        }
    } else {
        retain_built(ctx, &cache, &built_archives);
    }

    // ---- summary -------------------------------------------------------
    ctx.ui.blank();
    let s = &ctx.ui.style;
    ctx.ui.ok(&format!(
        "{} {} now installed",
        s.bold(&batch.installed.len().to_string()),
        if batch.installed.len() == 1 {
            "package is"
        } else {
            "packages are"
        }
    ));

    // A .pacnew is the one thing a transaction leaves unfinished for a human,
    // and until now it was announced from inside the install loop -- where the
    // `installing` counter still owned the line it was written on. A progress
    // bar paints with a carriage return and no newline (see ui::progress), so
    // the very next file wiped the warning before anyone could read it. That
    // is how this machine accumulated thirty-nine unmerged files in /etc,
    // sudoers, shadow, group and fstab among them, without its owner ever
    // being told once.
    //
    // Reported here instead: every bar has finished, the line is clean, and
    // nothing repaints after it. The count and the list are two separate
    // lines on purpose -- the count is the part that has to survive being
    // skim-read at the end of a long upgrade.
    if !batch.pacnew.is_empty() {
        ctx.ui.blank();
        let count = batch.pacnew.len();
        ctx.ui.warn(&pacnew_headline(count));
        ctx.ui.tree(
            &batch
                .pacnew
                .iter()
                .map(|p| format!("{} {}", s.bold(&p.path), s.dim(&format!("({})", p.package))))
                .collect::<Vec<_>>(),
        );
        // The same event name and payload shape `rvn config list` emits, so a
        // front-end has one thing to parse whichever produced it.
        ctx.ui.emit(
            "pacnew",
            serde_json::json!({
                "count": count,
                "files": batch
                    .pacnew
                    .iter()
                    .map(|p| serde_json::json!({
                        "path": p.path,
                        "package": p.package,
                        "pacnew": format!("{}.pacnew", p.path),
                    }))
                    .collect::<Vec<_>>(),
            }),
        );
    }

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
        installed: batch.installed,
        skipped: plan.already_satisfied.clone(),
        replaced: retired,
        pacnew: batch.pacnew,
    })
}

/// Installs one archive that is already on disk, outside the resolver.
///
/// This is how [`crate::ops::rollback`] puts an earlier version back, and it
/// is deliberately a thin thing. The resolver's whole job is to answer "what
/// is the newest version of this and what does it need", and a rollback has
/// already answered a different question: this exact file, whatever the
/// repositories now say. Running it through [`execute`] would resolve the
/// target straight back up to the version being rolled away from.
///
/// What it does keep is everything that makes an install an install rather
/// than an extraction: the file-conflict pre-flight, the `.INSTALL`
/// scriptlets, the `.pacnew` handling for configuration, the local database
/// record, and the transaction hooks -- a downgrade is a transaction, and a
/// machine whose snapshot hook runs before every upgrade wants it to run
/// before this too.
///
/// What it does NOT do is check whether anything else still depends on the
/// version being replaced. A downgrade can leave a dependent package with a
/// dependency it no longer satisfies; the caller warns about that, because
/// the caller is the one that can explain what it means.
pub fn install_from_cache(
    ctx: &mut Context,
    package: &str,
    archive: &Path,
) -> Result<Outcome, String> {
    let manifest = extract::manifest(archive).map_err(|e| format!("{}: {e}", archive.display()))?;

    // Every field comes out of the archive. The sync database describes some
    // newer version and the local database describes the one being replaced,
    // so neither can describe what is about to be installed.
    let mut record = Package {
        name: package.to_string(),
        ..Default::default()
    };
    apply_pkginfo(&mut record, &manifest.pkginfo);
    record.backup = manifest
        .backup
        .iter()
        .map(|path| BackupFile {
            path: path.clone(),
            hash: None,
        })
        .collect();

    let installed = ctx.local.get(package).cloned();
    // Carried over rather than defaulted: a package installed as a dependency
    // that is rolled back is still a dependency, and recording it as
    // explicitly installed would make `rvn update --orphans` stop offering to
    // remove it when whatever needed it goes away.
    let reason = match installed.as_ref().map(|p| p.install_reason) {
        Some(crate::pkg::InstallReason::Dependency) => crate::resolve::Reason::Dependency {
            // Which package required it is not recorded in the local
            // database and is not needed here: `Reason` is read for whether
            // it counts as explicit, and a dependency is a dependency
            // whoever asked for it.
            of: String::new(),
        },
        _ => crate::resolve::Reason::Explicit,
    };

    // The origin decides which repository's SigLevel applies, which decides
    // whether an unsigned archive may be installed at all. Taken from
    // whichever sync database carries the name today -- the archive itself
    // does not record where it was fetched from, and a package that came from
    // a repository still belongs to that repository's signing policy when it
    // is reinstalled from the cache.
    let origin = ctx
        .sync
        .iter()
        .find(|db| db.get(package).is_some())
        .map(|db| crate::pkg::Origin::Repo(db.repo.clone()))
        .unwrap_or(crate::pkg::Origin::Local);
    record.origin = origin;

    let resolved = Resolved {
        package: record,
        reason,
        replaces_version: installed.as_ref().map(|p| p.version.clone()),
    };

    // No expected checksum: the one in the sync database describes the newest
    // version, not this one. The signature is still checked, and under a
    // `SigLevel = Required` repository a cached archive whose `.sig` was
    // cleared away is refused rather than installed unverified.
    let verified = verify_one(ctx, &resolved.package, archive)?;
    let validation = match verified {
        Verified::ChecksumAndSignature { .. } => crate::pkg::Validation::Pgp,
        Verified::ChecksumOnly => crate::pkg::Validation::Sha256,
        Verified::Skipped => crate::pkg::Validation::None,
    };

    let plan = Plan {
        install: vec![resolved],
        ..Default::default()
    };

    let hooks = load_transaction_hooks(ctx)?;
    let planned = vec![package.to_string()];
    let operations = vec![txhooks::Operation::Update];
    let before = txhooks::Transaction::new(
        operations.clone(),
        planned.clone(),
        transaction_files(ctx, &planned, hooks.wants_paths(txhooks::When::Pre)),
    );
    run_transaction_hooks(ctx, &hooks, txhooks::When::Pre, &before)?;

    let validations = HashMap::from([(package.to_string(), validation)]);
    let archives = vec![(package.to_string(), archive.to_path_buf())];
    let batch = install_archives(ctx, &plan, &archives, &validations)?;

    let after = txhooks::Transaction::new(
        operations,
        batch.installed.clone(),
        transaction_files(
            ctx,
            &batch.installed,
            hooks.wants_paths(txhooks::When::Post),
        ),
    );
    run_transaction_hooks(ctx, &hooks, txhooks::When::Post, &after)?;

    if !batch.pacnew.is_empty() {
        ctx.ui.blank();
        ctx.ui.warn(&pacnew_headline(batch.pacnew.len()));
        ctx.ui.tree(
            &batch
                .pacnew
                .iter()
                .map(|p| p.path.clone())
                .collect::<Vec<_>>(),
        );
    }

    Ok(Outcome {
        installed: batch.installed,
        skipped: Vec::new(),
        replaced: Vec::new(),
        pacnew: batch.pacnew,
    })
}

/// The one line about unmerged configuration that has to survive being
/// skim-read at the end of a long upgrade.
///
/// A count and an instruction, in that order, because the reader has just
/// been told a number and the next thing they need is what to type. The list
/// of paths follows on its own lines; this sentence has to work without it,
/// since it is also what a notification or a front-end's toast will show.
fn pacnew_headline(count: usize) -> String {
    format!(
        "{count} config file{} {} not replaced. Run `rvn config` to review.",
        if count == 1 { "" } else { "s" },
        if count == 1 { "was" } else { "were" }
    )
}

/// Loads the machine's transaction hooks, or an empty set when this
/// transaction must not run them.
///
/// A hook file that is present and does not parse stops the transaction right
/// here, before anything has been fetched. That is deliberate, and it is why
/// the files are read this early rather than at the moment they are needed: a
/// hook is a policy somebody wrote down, and a package manager that upgrades
/// the machine while quietly ignoring the file meant to snapshot it first is
/// worse than one that refuses to start.
pub(crate) fn load_transaction_hooks(ctx: &Context) -> Result<txhooks::Set, String> {
    if ctx.user_prefix.is_some() {
        // A per-user prefix has no root and is not the system's root
        // directory, so a hook written about `/` would be wrong on both
        // counts. The system root is where they are looked for rather than
        // the prefix, because what is being skipped is the system's policy —
        // and nothing is parsed, so a typo in /etc cannot break somebody's
        // unprivileged install of one tool into their home directory.
        if txhooks::Set::present(Path::new("/")) {
            ctx.ui.detail(
                "transaction hooks are system policy and are not run for a per-user prefix",
            );
        }
        return Ok(txhooks::Set::default());
    }

    txhooks::Set::load(&ctx.config.root_dir).map_err(|e| {
        format!(
            "{e}; fix it or move it out of the hooks directory — rvn does not start a transaction whose hooks it cannot read"
        )
    })
}

/// What an install transaction is doing, in the terms a hook's `operations`
/// key uses.
///
/// Both answers can be true at once and on a Tuesday they usually are: a
/// system upgrade that pulls in one new dependency installs something *and*
/// updates several other things. There is no flag to read — `rvn update`
/// drives this same function through `ops::update` — and there need not be,
/// because what a hook is really asking is whether anything already on disk
/// is about to be replaced, and the plan answers that outright.
///
/// Retiring a package something else replaced is not counted as a removal.
/// It happens inside an install, the files it owned stay on the machine under
/// the successor's name, and a hook that wants to see it asks for `install`.
fn transaction_operations(ctx: &Context, plan: &Plan) -> Vec<txhooks::Operation> {
    let mut operations = Vec::new();
    if plan
        .install
        .iter()
        .any(|r| !ctx.local.is_installed(&r.package.name))
    {
        operations.push(txhooks::Operation::Install);
    }
    if plan
        .install
        .iter()
        .any(|r| ctx.local.is_installed(&r.package.name))
    {
        operations.push(txhooks::Operation::Update);
    }
    operations
}

/// The files a transaction's packages own, for hooks that trigger on paths.
///
/// Reading a `files` record per package is a few thousand small reads during
/// a full system upgrade, so it is only done when a hook for this moment
/// actually asked about paths — `wanted` is that answer, taken from
/// [`txhooks::Set::wants_paths`]. A package with no record yet, one being
/// installed here for the first time, contributes nothing, which is the only
/// honest answer before its archive has been downloaded.
fn transaction_files(ctx: &Context, packages: &[String], wanted: bool) -> Vec<String> {
    if !wanted {
        return Vec::new();
    }

    packages
        .iter()
        .filter_map(|name| ctx.local.files_or_empty(name).ok())
        .flatten()
        .collect()
}

/// Runs the transaction hooks for one moment, with the failure policy that
/// moment deserves.
///
/// A pre-transaction hook that set `abort_on_fail` is the only thing here
/// that returns an error, and when it does, nothing has been written yet — so
/// the transaction stops with the machine exactly as it was. Every other
/// failure is a warning. A post-transaction hook fails after the packages are
/// on disk and registered, and calling the transaction failed at that point
/// would be a lie the next `rvn update` immediately contradicts by finding
/// everything already installed.
///
/// Shared with `ops::remove`, the way `run_scriptlet` is: the policy above is
/// the interesting part and there should be exactly one copy of it.
pub(crate) fn run_transaction_hooks(
    ctx: &Context,
    hooks: &txhooks::Set,
    when: txhooks::When,
    transaction: &txhooks::Transaction,
) -> Result<(), String> {
    let matching = hooks.matching(when, transaction);
    if matching.is_empty() {
        return Ok(());
    }

    ctx.ui.blank();
    let spinner = ctx.ui.stage(&format!("{} hooks", when.as_str()));
    let mut failed: Vec<(String, String)> = Vec::new();

    for hook in &matching {
        spinner.set_message(hook.label());
        let result = hook.run(&ctx.config.root_dir, transaction);
        ctx.ui.emit(
            "transaction_hook",
            serde_json::json!({
                "when": when.as_str(),
                "hook": hook.name,
                "exec": hook.exec.display().to_string(),
                "ok": result.is_ok(),
                "message": result.as_ref().err(),
            }),
        );

        if let Err(message) = result {
            if when == txhooks::When::Pre && hook.abort_on_fail {
                spinner.fail(&format!("{} stopped the transaction", hook.name));
                return Err(format!("{}: {message} — nothing was installed", hook.name));
            }
            failed.push((hook.name.clone(), message));
        }
    }

    if failed.is_empty() {
        let ran = matching.len();
        spinner.succeed(&format!(
            "ran {ran} {} hook{}",
            when.as_str(),
            if ran == 1 { "" } else { "s" }
        ));
    } else {
        spinner.fail(&format!(
            "{} of {} {} hook{} failed",
            failed.len(),
            matching.len(),
            when.as_str(),
            if matching.len() == 1 { "" } else { "s" }
        ));
        // Named one per line, because "a hook failed" is not something anyone
        // can act on and the file's name is.
        for (name, message) in &failed {
            ctx.ui.warn(&format!("{name}: {message}"));
        }
    }

    Ok(())
}

/// Deletes the archives (and detached signatures) a transaction produced,
/// returning how many bytes were reclaimed.
///
/// Both kinds are passed in together on purpose. The caller's list used to be
/// only what was downloaded, which quietly made "clear the cache by default"
/// mean "clear the cache by default, unless the package came from the AUR".
fn clear_cache(produced: &[&Path]) -> u64 {
    let mut freed = 0;

    for path in produced {
        for candidate in [path.to_path_buf(), signature_path(path)] {
            if let Ok(meta) = std::fs::metadata(&candidate) {
                if std::fs::remove_file(&candidate).is_ok() {
                    freed += meta.len();
                }
            }
        }
    }

    freed
}

/// Moves the archives this transaction built into the cache directory proper,
/// so that `--keep-cache` keeps them somewhere the cache commands can see.
///
/// Keeping a built archive where makepkg left it is not keeping it in the
/// cache; it is leaving it in a build tree, which is the one place in this
/// directory that `rvn cache clean` deliberately does not touch. Moved here,
/// it is an ordinary entry: `rvn cache status` counts it as a version of its
/// package, `--keep N` decides whether it survives the next clean, and a
/// future `rvn rollback` can find it by name and version rather than having to
/// know which PKGBUILD produced it.
///
/// A move that fails is a warning and nothing more. The package is installed,
/// the transaction succeeded, and an archive still sitting in its build tree
/// is exactly where it would have been before this existed.
///
/// Unlike the other install-time steps added around it, this one runs under
/// `--user` too. It needs no privilege it does not already have: the source
/// and the destination are both inside the cache directory this invocation
/// has been downloading into all along, which for a per-user prefix is the
/// caller's own `$XDG_CACHE_HOME/rvn/pkg`.
fn retain_built(ctx: &Context, cache: &Path, built: &[PathBuf]) {
    let mut moved = 0;
    let mut bytes_moved = 0;

    for path in built {
        let destination = crate::cache::promoted_path(path, cache);
        if destination == *path {
            continue;
        }
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        match crate::cache::promote(path, &destination) {
            Ok(()) => {
                moved += 1;
                bytes_moved += size;
                // The signature, when a build produced one, follows its
                // archive or is no use to anybody.
                let signature = signature_path(path);
                if signature.exists() {
                    let _ = crate::cache::promote(&signature, &signature_path(&destination));
                }
            }
            Err(e) => ctx
                .ui
                .warn(&format!("kept {} where it was built: {e}", path.display())),
        }
    }

    if moved > 0 {
        ctx.ui.info(&format!(
            "kept {} built package{} ({}) in {}",
            moved,
            if moved == 1 { "" } else { "s" },
            bytes(bytes_moved),
            cache.display()
        ));
    }
}

/// The detached signature that sits beside a package archive.
fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".sig");
    PathBuf::from(name)
}

/// Retires files an upgrade left behind: present in the old version, absent
/// from the new one, and not owned by any other installed package.
///
/// Most of them are ordinary package content and are simply unlinked, but one
/// of them can be a configuration file the administrator edited: upstream
/// relocating a default out of /etc is a routine change, and the path then
/// appears in the previous version's file list and in no other package. This
/// used to unlink it like everything else, with no `.pacsave` and no mention
/// beyond "cleaned up 1 file left by the previous version" — the same class of
/// loss the note on the BACKUP record below describes. The decision is
/// [`super::remove::retire_file`]'s, which is the one an uninstall already
/// makes, so the two cannot drift apart.
///
/// `local` still holds the *previous* version's record here: the new one is
/// registered further down, after this has run. That is precisely what makes
/// its `backup` list and its recorded hashes the right yardstick — the
/// question being asked is whether the administrator edited the copy the old
/// version installed.
///
/// Returns how many files were deleted; the paths set aside as `.pacsave` are
/// appended to `preserved`.
fn prune_stale(
    root: &Path,
    local: &LocalDb,
    previous: &[String],
    current: &[String],
    name: &str,
    preserved: &mut Vec<String>,
) -> usize {
    if previous.is_empty() {
        return 0;
    }

    let kept: HashSet<&String> = current.iter().collect();
    let mut removed = 0;

    // A package with no record at all — nothing installed under this name —
    // declares no backup files, so every path below is treated as plain
    // content, which is what the unconditional unlink always did.
    let unrecorded = crate::pkg::Package::default();
    let record = local.get(name).unwrap_or(&unrecorded);

    for file in previous {
        if kept.contains(file) || file.ends_with('/') {
            continue;
        }
        // Another package owning the file means it must stay.
        let shared = local.packages.keys().any(|other| {
            other != name
                && local
                    .files(other)
                    .map(|files| files.iter().any(|f| f == file))
                    .unwrap_or(false)
        });
        if shared {
            continue;
        }
        match super::remove::retire_file(record, file, &root.join(file)) {
            super::remove::Retirement::Deleted => removed += 1,
            super::remove::Retirement::Preserved => preserved.push(file.clone()),
            super::remove::Retirement::Left => {}
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

    // A scriptlet runs in a chroot of the install root, which needs root;
    // a per-user prefix has neither. The files are in place; what the
    // scriptlet would have done (caches, users, module indexes) is not, and
    // saying so once per package beats a chroot error per hook.
    if ctx.user_prefix.is_some() {
        ctx.ui.detail(&format!(
            "{package}: {} skipped (per-user prefix, no root)",
            hook.function()
        ));
        return;
    }

    let outcome = scriptlet::run(
        &ctx.config.root_dir,
        package,
        script,
        hook,
        new_version,
        old_version,
    );

    // Recorded before it is reported, and recorded whichever way it went. A
    // scriptlet that failed is the one somebody will come looking for, and a
    // scriptlet that succeeded is how they find out what ran at all -- through
    // rvnd there is no terminal for the lines below to have reached.
    // `NotDefined` is not logged: nothing ran, and a line per package for every
    // hook no package defines would bury the ones that did.
    let record = match &outcome {
        scriptlet::Outcome::Ran => Some("ran".to_string()),
        scriptlet::Outcome::Failed(message) => Some(format!("failed: {message}")),
        scriptlet::Outcome::NotDefined => None,
    };
    if let Some(record) = record
        && let Err(e) = scriptlet::log_execution(&ctx.config.log_file, package, hook, &record)
    {
        // The install itself is not in doubt, so this warns like every other
        // bookkeeping failure -- but it is not silent, because a missing audit
        // trail that nobody was told about is worse than no audit trail.
        ctx.ui.warn(&format!(
            "could not record {package}'s {} in {}: {e}",
            hook.function(),
            ctx.config.log_file.display()
        ));
    }

    match outcome {
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

/// Records the paths one archive claims and reports any that an archive
/// already checked in this same transaction claimed first.
///
/// `find_conflicts` can only see the local database, and in `rvn install a b`
/// neither package is in it yet -- so two packages shipping the same path
/// used to sail through the pre-flight untouched. Both extracted, whichever
/// unpacked second silently overwrote the first, and the local database ended
/// up naming two owners for one file; removing either package then took the
/// file away from the other. pacman refuses the whole transaction, and so
/// does this. Two packages built from one split PKGBUILD are the case that
/// reaches it most often, because they are also the pair the repo/AUR split
/// never lets the database catch.
///
/// Only `manifest.files` is tracked, which is already just the non-directory
/// entries: packages share directories constantly and that is not a conflict.
fn claim_paths(
    claimed: &mut HashMap<String, String>,
    name: &str,
    files: &[String],
) -> Vec<extract::ExtractError> {
    let mut conflicts = Vec::new();
    for file in files {
        match claimed.get(file) {
            // One package listed twice in a batch is still one owner, and
            // reporting it as a conflict with itself would abort a
            // transaction that is perfectly well formed.
            Some(owner) if owner == name => {}
            Some(owner) => conflicts.push(extract::ExtractError::BatchConflict {
                path: file.clone(),
                other: owner.clone(),
            }),
            None => {
                claimed.insert(file.clone(), name.to_string());
            }
        }
    }
    conflicts
}

/// Checks a batch of archives for file conflicts, unpacks them, and records
/// them in the local database.
///
/// Everything worth telling the user about afterwards comes back in the
/// [`Batch`] rather than being printed here: a transaction calls this more
/// than once, and the `installing` counter owns the terminal for the whole of
/// each call.
fn install_archives(
    ctx: &mut Context,
    plan: &Plan,
    archives: &[(String, PathBuf)],
    validations: &HashMap<String, crate::pkg::Validation>,
) -> Result<Batch, String> {
    let spinner = ctx.ui.stage("checking for file conflicts");
    let mut manifests = Vec::new();
    // Every path an archive already checked in this batch has claimed, and
    // which one claimed it. `find_conflicts` can only consult the local
    // database, and nothing in this transaction is registered there yet.
    let mut claimed: HashMap<String, String> = HashMap::new();

    for (name, path) in archives {
        let manifest = extract::manifest(path).map_err(|e| format!("{name}: {e}"))?;
        // Files owned by the version being upgraded are not in the way, and
        // neither are files owned by a package this one replaces: those are
        // handed over, and their old owner is retired once this one is in.
        let mut exempt: Vec<&str> = ctx.local.get(name).map(|_| name.as_str()).into_iter().collect();
        exempt.extend(
            plan.replacing
                .iter()
                .filter(|(new, _)| new == name)
                .map(|(_, old)| old.as_str()),
        );
        let mut conflicts =
            extract::find_conflicts(&manifest, &ctx.local, &ctx.config.root_dir, &exempt)
                .map_err(|e| format!("{name}: could not check for file conflicts: {e}"))?;
        // The half the database cannot answer: `rvn install a b`, where both
        // ship the same path and neither is installed. Checked here rather
        // than inside `find_conflicts` because the claims are the caller's
        // running state, not something an archive and a database can settle
        // between them.
        conflicts.extend(claim_paths(&mut claimed, name, &manifest.files));
        if !conflicts.is_empty() {
            spinner.fail("file conflicts detected");
            let mut lines: Vec<String> = conflicts.iter().map(|c| c.to_string()).collect();
            // A type conflict on the layout paths is not a packaging mistake,
            // it is a root that was never usr-merged: Arch ships /bin, /lib,
            // /lib64 and /sbin as symlinks into /usr, and a split-usr root has
            // them as real directories. Saying so beats leaving the reader to
            // work out what to do with "bin would be a symlink to usr/bin".
            // Anywhere else it is a directory in the package's way -- blaming
            // usrmerge for firmware directories sent the reader the wrong way.
            const LAYOUT: &[&str] = &["bin", "lib", "lib64", "sbin", "usr/lib64", "usr/sbin"];
            let (layout, elsewhere): (Vec<_>, Vec<_>) = conflicts
                .iter()
                .filter_map(|c| match c {
                    extract::ExtractError::TypeConflict { path, .. } => {
                        Some(path.trim_end_matches('/'))
                    }
                    _ => None,
                })
                .partition(|path| LAYOUT.contains(path));
            if !layout.is_empty() {
                lines.push(
                    "this root is not usr-merged; convert it with \
                     scripts/usrmerge-rootfs.sh, then retry"
                        .to_string(),
                );
            }
            if !elsewhere.is_empty() {
                lines.push(
                    "if no installed package owns what is in the way, \
                     move it aside, then retry"
                        .to_string(),
                );
            }
            // A collision inside the batch is a packaging mistake in the
            // packages themselves -- most often a split PKGBUILD whose
            // package_*() functions both install the same file -- so the
            // advice above, which is about the state of the root, would send
            // the reader nowhere.
            let in_batch = conflicts
                .iter()
                .any(|c| matches!(c, extract::ExtractError::BatchConflict { .. }));
            if in_batch {
                lines.push(
                    "two packages in this transaction ship the same file; \
                     only one of them can own it"
                        .to_string(),
                );
            }
            ctx.ui.tree(&lines);
            // Not "installed files": a type conflict is about what is on disk,
            // which may be owned by no package at all.
            return Err(if in_batch {
                format!("{name} conflicts with another package in this transaction")
            } else {
                format!("{name} conflicts with what is already on disk")
            });
        }
        manifests.push((name.clone(), path.clone(), manifest));
    }
    spinner.succeed("no file conflicts");

    let total_files: u64 = manifests.iter().map(|(_, _, m)| m.files.len() as u64).sum();
    let mut progress = ctx.ui.counter("installing", total_files, "files");
    let mut batch = Batch::default();
    let mut stale_caches = crate::caches::Stale::default();

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

        // Needed before unpacking, not after: if extraction fails part-way it
        // rolls back what it wrote, and must know which paths belong to
        // another package so it leaves those alone.
        let foreign = extract::owned_by_others(&ctx.local, &[name.as_str()])
            .map_err(|e| format!("{name}: could not read the local database: {e}"))?;

        // Which backup files actually need protecting. One the user never
        // touched -- on-disk bytes still matching the hash recorded when the
        // previous version installed it -- follows the package across the
        // upgrade like any other file. Everything else keeps its disk copy,
        // with the package's version written alongside as `.pacnew`.
        let previous_backup: &[BackupFile] = ctx
            .local
            .get(name)
            .map(|p| p.backup.as_slice())
            .unwrap_or(&[]);
        let protected: Vec<String> = manifest
            .backup
            .iter()
            .filter(|rel| {
                let disk = ctx.config.root_dir.join(rel.as_str());
                if !disk.is_file() {
                    return false;
                }
                if NEVER_REPLACED.contains(&rel.as_str()) {
                    return true;
                }
                let pristine = previous_backup
                    .iter()
                    .find(|b| b.path == **rel)
                    .and_then(|b| b.hash.as_deref())
                    .zip(crate::verify::sha256_file(&disk).ok())
                    .is_some_and(|(recorded, current)| recorded == current);
                !pristine
            })
            .cloned()
            .collect();

        let mut pacnew = Vec::new();
        let files = extract::unpack(
            path,
            &ctx.config.root_dir,
            &foreign,
            &protected,
            &mut pacnew,
            |_| progress.advance(1),
        )
        .map_err(|e| format!("{name}: {e}"))?;

        // Copied out for the transaction summary, never moved: `pacnew` must
        // stay this package's own list, because the `pacnew.contains(path)`
        // test below decides which bytes the BACKUP record hashes. A shared
        // list would let a path spared for one package change how the next
        // package's record is written, which is the failure the comment on
        // that test describes.
        batch.pacnew.extend(pacnew.iter().map(|rel| Pacnew {
            package: name.clone(),
            path: rel.clone(),
        }));

        // Bound before the compound assignment so `batch` is not borrowed
        // mutably and read in the same expression.
        let pruned = prune_stale(
            &ctx.config.root_dir,
            &ctx.local,
            &previous_files,
            &files,
            name,
            &mut batch.stale_preserved,
        );
        batch.stale_removed += pruned;

        let mut record = resolved.package.clone();
        apply_pkginfo(&mut record, &manifest.pkginfo);
        record.backup = manifest
            .backup
            .iter()
            .map(|path| {
                // Where the disk copy was spared, what is on disk is not the
                // package's. Recording its hash made removal see the admin's
                // file as untouched package content and delete it -- which is
                // how Raven's /etc/pam.d/sudo went with the sudo package.
                // pacman records what the package shipped, and so does this.
                let shipped = if pacnew.contains(path) {
                    ctx.config.root_dir.join(format!("{path}.pacnew"))
                } else {
                    ctx.config.root_dir.join(path)
                };
                BackupFile {
                    path: path.clone(),
                    hash: crate::verify::sha256_file(&shipped).ok(),
                }
            })
            .collect();
        record.validation = validations
            .get(name)
            .copied()
            .unwrap_or(crate::pkg::Validation::None);
        record.install_reason = match ctx.local.get(name).map(|p| p.install_reason) {
            Some(InstallReason::Explicit) => InstallReason::Explicit,
            _ if resolved.reason.records_explicit() => InstallReason::Explicit,
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

        // The part of installation Arch delegates to systemd and Raven must
        // therefore do itself: create the accounts the package's sysusers.d
        // fragment declares, and seed /etc from its tmpfiles.d factory
        // copies. Without this, a daemon installs cleanly and then dies on
        // its missing user or missing config -- and the fix lands on the
        // operator, who was promised the installation would do it.
        let mut warnings = Vec::new();
        // sysusers needs root and tmpfiles describe system daemons; a
        // per-user prefix has neither, so its packages get no hooks.
        let hook_files: &[String] = if ctx.user_prefix.is_some() { &[] } else { &files };
        stale_caches.note(hook_files);
        let applied = crate::hooks::apply(&ctx.config.root_dir, hook_files, &mut |w| {
            warnings.push(w.to_string())
        });
        for warning in &warnings {
            ctx.ui.warn(warning);
        }
        if !applied.users.is_empty() {
            ctx.ui
                .info(&format!("created system user{}: {}",
                    if applied.users.len() == 1 { "" } else { "s" },
                    applied.users.join(", ")));
        }
        if !applied.copied.is_empty() {
            ctx.ui.info(&format!(
                "seeded default config: {}",
                applied.copied.join(", ")
            ));
        }

        batch.installed.push(name.clone());
    }

    progress.finish(&format!(
        "installed {} package{}",
        batch.installed.len(),
        if batch.installed.len() == 1 { "" } else { "s" }
    ));

    // After every package, not after each: one rebuild covers them all.
    crate::caches::refresh(&ctx.config.root_dir, stale_caches, &mut |w| ctx.ui.warn(w));

    activate_service_templates(ctx);

    Ok(batch)
}

/// Copies newly-satisfied service templates into raven-init's drop-in dir,
/// then tells raven-init they are there.
///
/// The base image ships no daemons, only inert templates under
/// /usr/share/raven/services -- each a raven-init `[[services]]` definition
/// for software `rvn install` may bring in later. Once the binary a template
/// names exists, the definition is copied into /etc/raven/init.d, which is
/// the directory raven-init folds into its service list.
///
/// # Why the copy was not the end of it
///
/// raven-init reads that directory exactly once, at boot. So for as long as
/// this function stopped at the copy, installing a daemon produced a
/// definition that nothing had read: `raven-rc start faced` answered "no such
/// service", and Raven Settings -- which can see the camera and can see
/// /usr/bin/raven-faced -- found no daemon on the socket, which is
/// indistinguishable from a daemon that crashed. The way out was two commands
/// in a terminal, `raven-rc reload` and `raven-rc start`, and knowing that it
/// was those two.
///
/// Neither command is the user's to find. An install that has got this far is
/// running as root -- `sudo rvn`, or rvn spawned by rvnd -- and root is the
/// whole of what /run/raven-init.sock asks for. So the reload is sent from
/// here, and a service whose template says `enabled = true` is started, which
/// is the same thing the next boot would do with it.
///
/// An existing drop-in of the same filename is never touched -- it may carry
/// the operator's edits.
fn activate_service_templates(ctx: &Context) {
    let templates = ctx.config.root_dir.join("usr/share/raven/services");
    let dropins = ctx.config.root_dir.join("etc/raven/init.d");

    let Ok(entries) = std::fs::read_dir(&templates) else {
        return;
    };

    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    // Sorted so that a machine installing two daemons at once reports them in
    // the same order twice running, rather than in whatever order the
    // directory happens to enumerate.
    entries.sort_by_key(|e| e.file_name());

    let mut promoted: Vec<Template> = Vec::new();

    for entry in entries {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "toml") {
            continue;
        }
        if dropins.join(entry.file_name()).exists() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };

        let template = match service_definition(&text) {
            Ok(template) => template,
            Err(e) => {
                ctx.ui.warn(&format!(
                    "{}: {e} \u{2014} the service it defines stays inert until that is fixed",
                    path.display()
                ));
                continue;
            }
        };
        if !ctx
            .config
            .root_dir
            .join(template.exec.trim_start_matches('/'))
            .exists()
        {
            continue;
        }
        // A name that could not be sent to init is one this function must not
        // promote either: it would land as a drop-in that no verb can ever
        // name. The template is the packager's file rather than anything a
        // user wrote, so this is a packaging mistake and is reported as one.
        if !crate::initctl::valid_service_name(&template.name) {
            ctx.ui.warn(&format!(
                "{}: refusing the service name {:?}",
                path.display(),
                template.name
            ));
            continue;
        }

        if std::fs::create_dir_all(&dropins).is_err() {
            return;
        }
        if std::fs::copy(&path, dropins.join(entry.file_name())).is_ok() {
            promoted.push(template);
        }
    }

    if !promoted.is_empty() {
        load_promoted_services(ctx, &promoted);
    }
}

/// Tells the running raven-init about services `activate_service_templates`
/// just defined, and starts the ones that are meant to run.
///
/// Every way this can fail ends at the same place: the definition is on disk
/// and correct, and the person is told the one command that acts on it. That
/// is strictly what they had before this function existed, so nothing here
/// fails an install -- a package is installed either way, and a supervisor
/// that could not be reached is not a reason to say otherwise.
fn load_promoted_services(ctx: &Context, promoted: &[Template]) {
    let advise = |template: &Template| {
        let name = &template.name;
        ctx.ui.info(&format!(
            "service '{name}' is now available: `raven-rc start {name}` \
             (enable at boot with `raven-rc enable {name}`)"
        ));
    };

    // An install into a --root that is not this machine's / defines services
    // for a tree that the init running here does not supervise. Telling our
    // own PID 1 to reload would be telling it about files it cannot see.
    if ctx.config.root_dir != std::path::Path::new("/") {
        for template in promoted {
            advise(template);
        }
        return;
    }

    let socket = std::path::Path::new(crate::initctl::SOCKET_PATH);
    if !crate::initctl::reachable(socket) {
        // No raven-init on this socket (a container, a build chroot, another
        // PID 1), or an rvn that is somehow not root. Either way there is
        // nobody to tell.
        for template in promoted {
            advise(template);
        }
        return;
    }

    if let Err(e) = crate::initctl::reload(socket) {
        ctx.ui
            .warn(&format!("raven-init did not reload its configuration: {e}"));
        for template in promoted {
            advise(template);
        }
        return;
    }

    for template in promoted {
        let name = &template.name;
        if !template.enabled {
            // The template's own decision: defined now, started when somebody
            // asks. `seatd`, `sshd` and `polkitd` all ship this way.
            ctx.ui.info(&format!(
                "service '{name}' is now defined: `raven-rc start {name}` \
                 (enable at boot with `raven-rc enable {name}`)"
            ));
            continue;
        }
        match crate::initctl::start(socket, name) {
            Ok(_) => ctx.ui.info(&format!("service '{name}' is running")),
            Err(e) => ctx.ui.warn(&format!(
                "service '{name}' is defined but did not start: {e} \
                 \u{2014} `raven-rc status {name}` says more"
            )),
        }
    }
}

/// What a raven-init template says about the service it defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub name: String,
    pub exec: String,
    /// Whether the machine should run it at every boot. Absent means false,
    /// which is raven-init's own default for the key and the safer way to be
    /// wrong: a service that is defined and not started is one command away,
    /// and a service started on a machine that did not want it is a daemon
    /// somebody has to notice first.
    pub enabled: bool,
}

/// What a raven-init template defines: see [`Template`].
///
/// This used to be a closure that scanned lines for `key = "value"`, with a
/// comment saying a real parser would be a dependency for nothing. The
/// dependency argument stopped applying when `crate::toml` landed -- it is
/// this crate's own parser, it costs nothing to call, and it gets quoting,
/// escapes, a `=` inside a comment and a malformed file right, which a line
/// scanner does by accident or not at all.
///
/// What is parsed is the `[[services]]` block alone, not the whole file, and
/// that is the load-bearing detail. These are raven-init's files, not rvn's,
/// and raven-init's TOML is a superset of the subset `crate::toml` reads --
/// `configs/raven/user-services/ravencanvasd.toml` already carries a
/// `[services.environment]` section, which this parser refuses by design as a
/// dotted key. Handing it the whole file would mean rvn stopped promoting a
/// template the day somebody added an environment block to it, which is a
/// regression with no upside: nothing here needs any section but the first.
/// So the block's own lines are cut out, ending at the next section header,
/// and the strict parser reads those. Everything after is raven-init's
/// business.
///
/// A file that defines two services is refused by name rather than silently
/// read as its first block. Every shipped template defines one -- it is the
/// convention `crate::toml`'s own refusal message recommends, "write one file
/// per thing instead" -- and promoting a definition rvn had only half read is
/// the wrong way to be wrong.
fn service_definition(text: &str) -> Result<Template, String> {
    /// Whether a line opens a new section, as opposed to continuing a list
    /// across several lines. A continuation carries a quote or a comma --
    /// `["-g", "video"]` -- and a header never does.
    fn is_header(line: &str) -> bool {
        let line = line.trim_start();
        line.starts_with('[') && !line.contains('"') && !line.contains(',')
    }

    let mut headers = text
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim() == "[[services]]");
    let (start, _) = headers
        .next()
        .ok_or("no [[services]] block, so there is no service definition here")?;
    if let Some((line, _)) = headers.next() {
        return Err(format!(
            "a second [[services]] block on line {}; rvn promotes a template that defines one service",
            line + 1
        ));
    }

    let block: Vec<&str> = text
        .lines()
        .skip(start + 1)
        .take_while(|line| !is_header(line))
        .collect();

    let document = crate::toml::Document::parse(&block.join("\n")).map_err(|e| e.to_string())?;
    let service = document
        .section("")
        .ok_or("the [[services]] block is empty")?;

    let field = |key: &str| {
        service
            .get(key)
            .and_then(crate::toml::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("[[services]] sets no `{key}`"))
    };
    Ok(Template {
        name: field("name")?,
        exec: field("exec")?,
        // Unlike name and exec, a missing `enabled` is not a broken template:
        // raven-init defaults the key to false and so does this.
        enabled: service
            .get("enabled")
            .and_then(crate::toml::Value::as_bool)
            .unwrap_or(false),
    })
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
        if !ctx.config.repos.iter().any(|r| r.name == "multilib") {
            ctx.ui.warn(
                "the multilib repository is not enabled in pacman.conf — \
                 steam, wine and every lib32-* package live only there",
            );
        }
        return Err("could not satisfy every dependency".into());
    }

    Ok(())
}

/// Prints the transaction summary the user is about to approve.
fn show_plan(ctx: &Context, plan: &Plan) {
    let s = &ctx.ui.style;

    if ctx.ui.is_json() {
        // A front-end wants the plan as data, not as painted lines.
        let entries: Vec<serde_json::Value> = plan
            .install
            .iter()
            .map(|r| {
                let mut v = crate::ui::json::package(&r.package);
                v["explicit"] = serde_json::Value::Bool(r.reason.is_explicit());
                v["installed_version"] = serde_json::json!(r.replaces_version);
                v
            })
            .collect();
        ctx.ui.emit(
            "plan",
            serde_json::json!({
                "install": entries,
                "replacing": plan.replacing.iter().map(|(new, old)| serde_json::json!({ "new": new, "old": old })).collect::<Vec<_>>(),
                "download_size": plan.download_size(),
                "installed_size_delta": plan.installed_size_delta(),
                "build_from_source": plan.aur_count(),
            }),
        );
        return;
    }

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

    // Checked again here, although `db::desc` already drops a record whose
    // filename is a path, because this is the line where the damage would be
    // done: `cache.join` of an absolute name discards the cache entirely and
    // hands the download a destination of the repository's choosing. A
    // `Package` can also arrive from the binary database index, which was
    // written by an older rvn that did not check, so the guarantee has to be
    // made where the path is built and not only where it was parsed.
    if !crate::db::desc::is_safe_archive_name(&filename) {
        return Err(format!(
            "{} names {filename:?} in the repository database, which is a path rather than a \
             package file name; refusing to download it",
            pkg.name
        ));
    }

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
        ctx.keyring(),
        level,
    )
    .map_err(|e| e.to_string())
}

/// The account AUR builds run as.
///
/// A PKGBUILD is a shell script written by a stranger, and building it runs
/// that script. The question is therefore not whether to drop privileges --
/// rvn already does -- but *whose* files the script gets to read and destroy
/// while it runs. Both of the accounts rvn used to drop to answer that badly.
/// `$SUDO_USER` is the human at the keyboard, so a hostile PKGBUILD lands in
/// the account holding their ssh keys, their browser profile and their
/// documents. `nobody` is worse in a quieter way: it is the shared scrap
/// account every other unprivileged service on the machine also runs as, so a
/// build could read and clobber whatever any of them owned, and anything it
/// left behind was attributable to none of them.
///
/// A dedicated account owns nothing but its own build trees, which is the
/// entire point: the blast radius of a build becomes the build.
pub(crate) const BUILD_USER: &str = "raven-build";

/// The GECOS field for [`BUILD_USER`], so `ls -l` and `ps` explain themselves.
const BUILD_USER_GECOS: &str = "Raven AUR build user";

/// The environment every build command gets, and nothing else.
///
/// `rvnd` hands rvn a three-variable environment (PATH, HOME, LANG) after
/// clearing everything else, and a build gets the same baseline for the same
/// reason: what a package builds into itself should depend on the PKGBUILD and
/// the installed toolchain, not on whether the person who typed `rvn install`
/// happened to have `CFLAGS` or `LD_PRELOAD` exported. Without this, the same
/// package built by two people on one machine could differ, and neither would
/// have any way of telling why.
pub(crate) const BUILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The only variables allowed through from rvn's own environment.
///
/// Everything else is cleared, so each of these has to earn its place. The
/// proxy variables do: on a network where the only route out is a proxy, the
/// `source=` downloads a PKGBUILD makes are curl's, not rvn's, and curl learns
/// about the proxy from the environment or not at all -- clearing them turns
/// every AUR build on such a machine into a download timeout with nothing to
/// suggest the cause. `SOURCE_DATE_EPOCH` is the reproducible-builds handle
/// itself: an operator who sets it is asking for exactly the determinism this
/// list otherwise exists to protect, so refusing to pass it on would be
/// perverse. Both spellings of the proxy names are honoured because both are in
/// wide use and a machine configured with one and not the other is common.
const BUILD_ENV_PASSTHROUGH: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
    "SOURCE_DATE_EPOCH",
];

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

/// The build account's numeric ids, or `None` if there is no such account.
///
/// This is the asking half of [`build_identity`] without the making half: it
/// creates nothing and writes nothing, so a read-only operation that merely
/// wants to know whether there is an unprivileged account to drop to can call
/// it. [`crate::devel::remote_head`] does, because talking to a repository
/// named by a PKGBUILD is a build-derived action and has no business being
/// the one such action that runs as root -- but a plain `rvn update --dry-run`
/// has no business creating a system account either.
pub(crate) fn build_user_ids() -> Option<(u32, u32)> {
    lookup_user(BUILD_USER)
}

/// The build account's home directory.
///
/// It lives under the package cache because that is already the directory rvn
/// owns and fills on this machine's behalf, and because it puts the account's
/// home on the same filesystem as the build trees it will be writing into.
/// Note that [`build_command`] still points `HOME` at the individual package's
/// build tree for the duration of a build, so makepkg's droppings stay with
/// the package that caused them and nothing carries from one build into the
/// next. This directory exists so the passwd entry names somewhere real and
/// writable: an account whose home does not exist produces a stream of
/// confusing failures from tools that expect to be able to create a dotfile.
fn build_home(cache: &Path) -> PathBuf {
    cache.join(BUILD_USER)
}

/// Chooses who to build as, creating the dedicated account if it is missing.
///
/// `Ok(None)` means rvn is not root and the build simply runs as whoever
/// invoked it -- there are no privileges to drop, and makepkg is happy. That
/// covers `--user`, which is unprivileged by definition: it creates no account
/// and asks for none, because an unprivileged install cannot write /etc/passwd
/// and has nothing to drop out of anyway. It does mean a `--user` build runs in
/// the caller's own account, which is a smaller claim than the one this
/// function makes for a system install, and the right one: they are building
/// for themselves, with their own privileges, in their own prefix. `Err`
/// means rvn *is* root and the build account could not be established, which
/// has to stop the build: the alternatives are running makepkg as root, which
/// it refuses to do and which would be catastrophic if it did, or falling back
/// to a shared account, which is the thing this function exists to stop.
///
/// The account is created through the same sysusers machinery a package's own
/// declarations go through (see [`crate::hooks::ensure_declared_user`]) rather
/// than by shelling out to `useradd`, which may not be installed. It is created
/// in the host's `/etc/passwd`, not the install root's: the build runs on this
/// machine whatever root the resulting package will be unpacked into, so it is
/// this machine that has to be able to resolve the name.
///
/// Creating an account is a change to /etc that outlives the transaction, so it
/// is announced through `notice` rather than done quietly -- the same way
/// [`crate::hooks::apply`] reports the accounts a package's own sysusers
/// fragment asked for.
fn build_identity(
    cache: &Path,
    notice: &mut impl FnMut(&str),
) -> Result<Option<BuildIdentity>, String> {
    if !super::is_root() {
        return Ok(None);
    }

    let mut ids = lookup_user(BUILD_USER);
    let created = ids.is_none();
    if created {
        crate::hooks::ensure_declared_user(
            Path::new("/"),
            BUILD_USER,
            BUILD_USER_GECOS,
            &build_home(cache).to_string_lossy(),
        )
        .map_err(|e| {
            format!(
                "could not create the {BUILD_USER} account that AUR builds run as: {e} -- \
                 check that /etc/passwd, /etc/group and /etc/shadow are writable, or create \
                 the account by hand and retry"
            )
        })?;
        ids = lookup_user(BUILD_USER);
    }

    let Some((uid, gid)) = ids else {
        return Err(format!(
            "the {BUILD_USER} account was written to /etc/passwd but the system will not \
             resolve it -- check nsswitch.conf and retry"
        ));
    };
    if uid == 0 {
        // Somebody gave the build account uid 0. Building as root is the one
        // outcome this whole path exists to prevent, so say so rather than
        // quietly doing it.
        return Err(format!(
            "the {BUILD_USER} account has uid 0, so building as it would be building as root \
             -- give it an unprivileged uid and retry"
        ));
    }
    if created {
        notice(&format!(
            "created the {BUILD_USER} system account (uid {uid}); AUR builds run as it"
        ));
    }

    // The home only has to exist and belong to the account; it holds nothing
    // valuable, and a build never writes here because HOME is repointed at the
    // package's own tree.
    let home = build_home(cache);
    if let Err(e) = std::fs::create_dir_all(&home) {
        return Err(format!(
            "could not create {}, the {BUILD_USER} home: {e}",
            home.display()
        ));
    }
    if let Err(e) = std::os::unix::fs::lchown(&home, Some(uid), Some(gid)) {
        return Err(format!(
            "could not give {} to {BUILD_USER}: {e}",
            home.display()
        ));
    }

    Ok(Some(BuildIdentity {
        user: BUILD_USER.to_string(),
        uid,
        gid,
    }))
}

/// Says out loud when an existing build tree changes hands.
///
/// Before the dedicated build account existed, a tree under `<cache>/aur/<name>`
/// belonged to whoever ran `sudo rvn` — a real person, who may well have edited
/// the PKGBUILD in it, since rvn offers them that on every build. `chown_tree`
/// would re-own the whole thing without a word, and the next time they opened
/// their own file they would be told they do not have permission to write it,
/// with nothing anywhere to explain when that happened or why.
///
/// So the first build after the upgrade says what it is doing. It does not ask:
/// the build cannot proceed without the tree belonging to the account that will
/// run makepkg, and the only alternative to taking it is to refuse to build the
/// package at all. What it can do is leave a sentence behind, and point out that
/// the files themselves — edits included — are untouched.
fn announce_build_tree_handover(
    ctx: &Context,
    spinner: &Spinner,
    dir: &Path,
    identity: &BuildIdentity,
    previous_owner: Option<u32>,
) {
    // Only a tree that was already there can surprise anybody; one rvn just
    // created is the build account's in all but the chown.
    let Some(owner) = previous_owner else {
        return;
    };
    if owner == identity.uid {
        return;
    }

    let who = crate::hooks::user_name(Path::new("/"), owner).unwrap_or_else(|| owner.to_string());
    spinner.suspend(|| {
        ctx.ui.warn(&format!(
            "{} belonged to {who}; builds now run as {} and it is changing hands",
            dir.display(),
            identity.user
        ));
        ctx.ui.detail(
            "nothing in it is modified — if you edited the PKGBUILD, your edits are still there, \
             but you will need sudo to change them again",
        );
    });
    ctx.ui.emit(
        "build_tree_handover",
        serde_json::json!({
            "path": dir.display().to_string(),
            "from": who,
            "to": identity.user,
        }),
    );
}

/// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, the flags [`open_dir_nofollow`]
/// needs.
///
/// Spelled out here for the same reason `scriptlet::euid` declares `geteuid`
/// itself: this codebase has no `libc` dependency and hand-rolls the handful
/// of constants and calls it needs. These are the asm-generic values, which
/// are what x86_64 and aarch64 -- the two architectures Raven builds for --
/// both use. A port to one of the architectures that predates asm-generic
/// (mips, parisc, sparc, alpha, 32-bit arm) would have to revisit them.
const O_DIRECTORY_NOFOLLOW_CLOEXEC: i32 = 0o200_000 | 0o400_000 | 0o2_000_000;

/// Opens a directory, refusing to follow a symlink in its last component.
///
/// The returned handle names the directory that was there at the moment of
/// the open, and goes on naming it however the tree is rearranged afterwards.
/// A failure here means the name was not a directory -- an ordinary file, or
/// a symlink, which `O_NOFOLLOW` reports as `ELOOP` -- or that it went away.
fn open_dir_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY_NOFOLLOW_CLOEXEC)
        .open(path)
}

/// Recursively gives a tree to the build user so makepkg can write into it.
///
/// The tree this walks belongs to `raven-build` and is writable by it, while
/// the walk itself runs as root. Walking it by path was therefore a race the
/// build account could win: the old code asked `path.is_dir()` and then called
/// `read_dir(path)`, and anything left running as `raven-build` by an earlier
/// build only had to swap that directory for a symlink to `/etc` in between to
/// have root hand it `/etc/shadow`. The account exists precisely so that the
/// blast radius of a build is the build, and a root-run recursive chown that
/// resolves names the build account controls is a hole straight through it.
///
/// So nothing is resolved twice. Each directory is opened `O_NOFOLLOW` once,
/// and every subsequent operation goes through `/proc/self/fd/<n>`, which the
/// kernel resolves to the inode the descriptor already holds rather than by
/// walking the name again: renaming the directory out from under the walk now
/// changes nothing about where the walk is. Entries that are not directories
/// are `lchown`ed relative to that descriptor, so a symlink is chowned as the
/// symlink it is and never as whatever it points at.
///
/// This does mean `/proc` must be mounted. It always is where this runs: an
/// AUR build shells out to makepkg, which does not work without it either.
fn chown_tree(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    // Asked once, here, rather than discovered as a bare ENOENT halfway down
    // a tree: without /proc there is no way to name an open descriptor, and
    // the only alternative is the walk by name this exists to stop doing.
    if !Path::new("/proc/self/fd").is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "/proc is not mounted, so the build tree cannot be handed over without \
             resolving names the build account controls; mount /proc and retry",
        ));
    }

    match open_dir_nofollow(path) {
        Ok(dir) => chown_open_dir(&dir, uid, gid),
        // Not a directory, or a symlink standing where one might have been.
        // Either way there is nothing to descend into, and the entry itself
        // is still given away -- without following it.
        Err(_) => std::os::unix::fs::lchown(path, Some(uid), Some(gid)),
    }
}

/// Gives one already-open directory and everything under it to `uid:gid`.
fn chown_open_dir(dir: &std::fs::File, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    // Chowning the descriptor rather than the name: `/proc/self/fd/<n>` is a
    // magic link the kernel jumps straight through to the open file, so this
    // cannot land on anything but the directory that was opened.
    let dir_path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    std::os::unix::fs::chown(&dir_path, Some(uid), Some(gid))?;

    for entry in std::fs::read_dir(&dir_path)? {
        let child = dir_path.join(entry?.file_name());
        match open_dir_nofollow(&child) {
            Ok(sub) => chown_open_dir(&sub, uid, gid)?,
            Err(_) => std::os::unix::fs::lchown(&child, Some(uid), Some(gid))?,
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
///
/// Both branches get the same cleared-and-rebuilt environment, because a build
/// that comes out differently depending on who started it is not a build
/// anybody can reason about; see [`BUILD_PATH`] and [`BUILD_ENV_PASSTHROUGH`].
fn build_command(program: &str, dir: &Path, identity: Option<&BuildIdentity>) -> Command {
    let mut command = match identity {
        Some(id) => {
            // `setpriv` drops to the target uid without going through PAM,
            // which matters because the build account is locked and has no
            // login shell -- deliberately, since nobody is meant to log into
            // it, and PAM would refuse to open a session for it.
            let mut command = Command::new("setpriv");
            command
                .arg(format!("--reuid={}", id.uid))
                .arg(format!("--regid={}", id.gid))
                .arg("--clear-groups")
                .arg(program);
            command
        }
        None => Command::new(program),
    };

    // Whose name the environment should claim. When privileges are dropped it
    // must be the account actually being dropped to, or makepkg stamps the
    // wrong packager into .PKGINFO and anything reading $USER disagrees with
    // the uid it is running under.
    let user = match identity {
        Some(id) => Some(id.user.clone()),
        None => std::env::var("USER").ok(),
    };

    command
        .current_dir(dir)
        .env_clear()
        .env("PATH", BUILD_PATH)
        // makepkg and git both write into $HOME, and pointing it at the
        // package's own tree keeps one build's caches out of the next one.
        .env("HOME", dir)
        .env("LANG", "C.UTF-8");
    if let Some(user) = user {
        command.env("USER", &user).env("LOGNAME", &user);
    }
    for name in BUILD_ENV_PASSTHROUGH {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }
    command
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
        return format!(
            "makepkg refused to run as root, which means the drop to {BUILD_USER} did not \
             happen; check that setpriv is installed and that {BUILD_USER} exists in \
             /etc/passwd with an unprivileged uid"
        );
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

    // The resolver adds the makepkg toolchain (`base-devel`, `git`) to every
    // AUR package's make-dependencies, and repository packages install before
    // any build starts -- so by the time this runs makepkg is on disk. The
    // check stays as a backstop: if it fires, the toolchain install itself
    // failed, and the message should say what to do rather than name a
    // package manager this system does not use.
    if Command::new("makepkg").arg("--version").output().is_err() {
        return Err(
            "makepkg is not installed; the build toolchain should have been pulled in \
             with this package -- try `rvn install base-devel` and then retry"
                .into(),
        );
    }

    let mut notices = Vec::new();
    let identity = build_identity(cache, &mut |m| notices.push(m.to_string()))?;
    if !notices.is_empty() {
        spinner.suspend(|| {
            for notice in &notices {
                ctx.ui.info(notice);
            }
        });
    }

    on_step("fetching build files");
    let is_repo = dir.join(".git").exists();
    if !is_repo && dir.exists() {
        // A partial checkout from an interrupted run would confuse git.
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    // Who owned the tree before rvn touched it, for the handover notice below.
    // Read here rather than after `create_dir_all`, because a tree this run is
    // about to create for the first time has no previous owner to tell anybody
    // about and would otherwise report itself as changing hands from root.
    let previous_owner = std::fs::symlink_metadata(&dir)
        .ok()
        .map(|meta| std::os::unix::fs::MetadataExt::uid(&meta));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // Hand the tree over before git touches it, so every file it writes is
    // owned by the account that will run the build.
    if let Some(id) = &identity {
        announce_build_tree_handover(ctx, spinner, &dir, id, previous_owner);
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
///
/// The parsing itself is [`crate::cache::parse_archive_name`], which also
/// returns the version, because the cache has to order versions of the same
/// package and this function does not care. There is one parser rather than
/// two: a filename this one accepts and that one rejects would be a package
/// the cache can neither count nor retire.
pub fn package_name_from_filename(filename: &str) -> Option<String> {
    crate::cache::parse_archive_name(filename).map(|(name, _)| name)
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

    /// The shape every shipped template has: a long comment block, then one
    /// `[[services]]` table. Taken from seatd.toml, which is the one somebody
    /// on a console boot actually needs promoted.
    const TEMPLATE: &str = r#"
# seatd -- seat management daemon.
#
# Comments carry `=` signs and brackets: name = "not this one", [[services]]
# written inline, and a line about `raven-rc start seatd`.

[[services]]
name = "seatd"
description = "Seat management daemon"
exec = "/sbin/seatd"
args = ["-g", "video"]
after = ["udev"]
ready_path = "/run/seatd.sock"
ready_timeout = 5
restart = true
enabled = false
critical = false
"#;

    #[test]
    fn a_template_gives_up_its_name_and_exec() {
        let t = service_definition(TEMPLATE).expect("the shipped shape should read");
        assert_eq!(t.name, "seatd");
        assert_eq!(t.exec, "/sbin/seatd");
    }

    /// The key that decides whether promoting a template also starts the
    /// daemon. seatd ships `enabled = false`; faced and fprintd ship true.
    #[test]
    fn a_template_says_whether_the_machine_should_run_it() {
        let t = service_definition(TEMPLATE).expect("the shipped shape should read");
        assert!(!t.enabled, "seatd.toml ships enabled = false");

        let t = service_definition(
            "[[services]]\nname = \"faced\"\nexec = \"/usr/bin/raven-faced\"\nenabled = true\n",
        )
        .expect("reads");
        assert!(t.enabled);

        // Absent is false, which is what raven-init does with the key.
        let t = service_definition("[[services]]\nname = \"x\"\nexec = \"/bin/x\"\n")
            .expect("reads");
        assert!(!t.enabled);
    }

    #[test]
    fn a_comment_that_looks_like_a_key_is_not_one() {
        // The line scanner this replaced matched `name = "..."` anywhere in
        // the file, comments included, and took the first hit. The commented
        // `name = "not this one"` above is that trap.
        let t = service_definition(TEMPLATE).expect("the shipped shape should read");
        assert_ne!(t.name, "not this one");
    }

    #[test]
    fn a_template_missing_what_is_needed_says_which_half() {
        let e = service_definition("[[services]]\nname = \"x\"\n").unwrap_err();
        assert!(e.contains("exec"), "{e}");

        let e = service_definition("# nothing but a comment\n").unwrap_err();
        assert!(e.contains("[[services]]"), "{e}");
    }

    #[test]
    fn two_services_in_one_file_are_refused_rather_than_half_read() {
        let text = "[[services]]\nname = \"a\"\nexec = \"/bin/a\"\n\
                    [[services]]\nname = \"b\"\nexec = \"/bin/b\"\n";
        let e = service_definition(text).unwrap_err();
        assert!(e.contains("defines one service"), "{e}");
    }

    #[test]
    fn a_section_raven_init_understands_and_rvn_does_not_is_stepped_over() {
        // raven-init's TOML is a superset of the subset `crate::toml` reads,
        // and user-services/ravencanvasd.toml already proves it: the dotted
        // `[services.environment]` header below is refused by that parser.
        // Only the first block is rvn's business, so the file still reads.
        let text = "[[services]]\nname = \"ravencanvasd\"\nexec = \"/usr/bin/ravencanvasd\"\n\
                    args = [\n  \"--idle\",\n  \"30\",\n]\n\
                    [services.environment]\nMALLOC_TRIM_THRESHOLD_ = \"131072\"\n";
        let t = service_definition(text).expect("the first block should read");
        assert_eq!(t.name, "ravencanvasd");
        assert_eq!(t.exec, "/usr/bin/ravencanvasd");
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

    /// The inode's change time, which the kernel updates on every successful
    /// chown -- including one that sets the ids a file already has. It is how
    /// a test with no privileges can tell whether a chown reached a file at
    /// all, since the only ids it is allowed to set are the ones already there.
    fn ctime_of(path: &Path) -> (i64, i64) {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path).expect("the witness file is still there");
        (meta.ctime(), meta.ctime_nsec())
    }

    /// Our own ids, read off a file we just made rather than from a syscall.
    fn own_ids(path: &Path) -> (u32, u32) {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).unwrap();
        (meta.uid(), meta.gid())
    }

    fn chown_case(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("rvn-chown-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn chown_tree_covers_the_tree_and_stops_at_a_symlink() {
        let root = chown_case("walk");
        let tree = root.join("tree");
        std::fs::create_dir_all(tree.join("src/deep")).unwrap();
        std::fs::write(tree.join("PKGBUILD"), b"").unwrap();
        std::fs::write(tree.join("src/deep/file"), b"").unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/witness"), b"").unwrap();
        std::os::unix::fs::symlink(root.join("outside"), tree.join("link")).unwrap();

        let (uid, gid) = own_ids(&tree.join("PKGBUILD"));
        let before = ctime_of(&root.join("outside/witness"));
        let deep_before = ctime_of(&tree.join("src/deep/file"));

        chown_tree(&tree, uid, gid).expect("the tree is ours to give away");

        // Everything inside was visited, however deep.
        assert_ne!(deep_before, ctime_of(&tree.join("src/deep/file")));
        // And nothing on the far side of the symlink was.
        assert_eq!(
            before,
            ctime_of(&root.join("outside/witness")),
            "the walk followed a symlink out of the tree"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// The build tree belongs to `raven-build` while this chown runs as root,
    /// so anything the build account left running gets to rearrange the tree
    /// mid-walk. Resolving each name twice -- once to ask whether it is a
    /// directory, once to read it -- let it swap a directory for a symlink in
    /// between and point root's recursive chown at `/etc`.
    ///
    /// The swap is a race, so this drives it the way an attacker would: a
    /// thread flipping one entry back and forth while the walk runs. A build
    /// tree entry standing in for `/etc`, and the witness file's ctime says
    /// whether the walk ever reached through it. Losing every race is a pass
    /// for the wrong reason, so this also has to be watched failing on the old
    /// code -- it does, every time, at the walk count below.
    #[test]
    fn a_swapped_directory_cannot_redirect_the_chown_out_of_the_tree() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = chown_case("race");
        let tree = root.join("tree");
        std::fs::create_dir_all(tree.join("other")).unwrap();
        std::fs::write(tree.join("PKGBUILD"), b"").unwrap();
        std::fs::write(tree.join("other/file"), b"").unwrap();
        let swapped: Vec<std::path::PathBuf> = ["src", "pkg", "work", "deps"]
            .iter()
            .map(|name| tree.join(name))
            .collect();
        for src in &swapped {
            std::fs::create_dir(src).unwrap();
        }

        // What the swapped-in symlink points at. Only its ctime is read, and
        // only `remove_dir`/`remove_file` are ever aimed at the tree, so the
        // swapper cannot delete the witness even when it loses its own race.
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let witness = elsewhere.join("witness");
        std::fs::write(&witness, b"").unwrap();

        let (uid, gid) = own_ids(&tree.join("PKGBUILD"));
        let before = ctime_of(&witness);

        let stop = Arc::new(AtomicBool::new(false));
        // One swapper per entry: the window in the old code is two syscalls
        // wide, so the way to make a race test land reliably is to give each
        // walk several entries that might be swapped rather than one.
        let swappers: Vec<_> = swapped
            .iter()
            .map(|src| {
                let stop = Arc::clone(&stop);
                let src = src.clone();
                let elsewhere = elsewhere.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let _ = std::fs::remove_dir(&src);
                        let _ = std::os::unix::fs::symlink(&elsewhere, &src);
                        let _ = std::fs::remove_file(&src);
                        let _ = std::fs::create_dir(&src);
                    }
                })
            })
            .collect();

        // Errors are expected and uninteresting: an entry that vanishes
        // between the listing and the chown is the swapper doing its job.
        for _ in 0..6_000 {
            let _ = chown_tree(&tree, uid, gid);
        }

        stop.store(true, Ordering::Relaxed);
        for swapper in swappers {
            swapper.join().unwrap();
        }

        assert_eq!(
            before,
            ctime_of(&witness),
            "a directory swapped for a symlink mid-walk carried the chown out of the tree"
        );
        std::fs::remove_dir_all(&root).ok();
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
    fn a_transaction_clears_what_it_built_as_well_as_what_it_downloaded() {
        // The leak, as a test. `clear_cache` used to be handed only the repo
        // archives a transaction fetched, so an AUR package's archive stayed
        // in the build tree it was made in and no cache rule ever reached it.
        let dir = artifact_dir("clear", &[]);
        let downloaded = dir.join("zlib-1.3-1-x86_64.pkg.tar.zst");
        let signature = dir.join("zlib-1.3-1-x86_64.pkg.tar.zst.sig");
        let built = dir.join("aur/brave-bin/brave-bin-1.5-1-x86_64.pkg.tar.zst");
        std::fs::create_dir_all(built.parent().unwrap()).unwrap();
        std::fs::write(&downloaded, vec![b'x'; 100]).unwrap();
        std::fs::write(&signature, vec![b'x'; 10]).unwrap();
        std::fs::write(&built, vec![b'x'; 50]).unwrap();

        let freed = clear_cache(&[downloaded.as_path(), built.as_path()]);

        assert_eq!(freed, 160, "the signature counts too");
        assert!(!downloaded.exists());
        assert!(!signature.exists());
        assert!(!built.exists(), "a built archive is a cached package too");

        let _ = std::fs::remove_dir_all(&dir);
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
            user: BUILD_USER.into(),
            uid: 973,
            gid: 973,
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
            user: BUILD_USER.into(),
            uid: 973,
            gid: 973,
        };
        let command = makepkg_command(std::path::Path::new("/tmp"), Some(&identity));
        assert_eq!(command.get_program(), "setpriv");

        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.contains(&"--reuid=973".to_string()), "{args:?}");
        assert!(args.contains(&"--regid=973".to_string()), "{args:?}");
        assert!(args.contains(&"makepkg".to_string()));
    }

    /// `nobody` is shared with every other unprivileged service on the machine,
    /// so a PKGBUILD running as it could read and destroy whatever any of them
    /// owned. That fallback is gone and must not come back.
    #[test]
    fn a_build_never_runs_as_a_shared_account() {
        let identity = BuildIdentity {
            user: BUILD_USER.into(),
            uid: 973,
            gid: 973,
        };
        let command = makepkg_command(std::path::Path::new("/tmp"), Some(&identity));
        let argv: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(!argv.iter().any(|a| a.contains("nobody")), "{argv:?}");
        assert!(!argv.iter().any(|a| a.contains("65534")), "{argv:?}");

        // The account's home is rvn's own cache, not a shared one and not a
        // real person's.
        assert_eq!(
            build_home(std::path::Path::new("/var/cache/pacman/pkg")),
            std::path::PathBuf::from("/var/cache/pacman/pkg/raven-build")
        );
    }

    #[test]
    fn an_unprivileged_rvn_builds_as_itself_and_creates_no_account() {
        if super::super::is_root() {
            // The interesting case needs a non-root process; under root this
            // would go and create the account for real.
            return;
        }
        let cache = std::env::temp_dir().join("rvn-build-identity");
        let mut notices = Vec::new();
        let identity = build_identity(&cache, &mut |m| notices.push(m.to_string()))
            .expect("not being root is not an error");
        assert!(notices.is_empty(), "{notices:?}");
        assert!(
            identity.is_none(),
            "there are no privileges to drop, so makepkg runs as the caller"
        );
        assert!(
            !cache.exists(),
            "nothing is created for a build that needs no build account"
        );
    }

    /// A build must not inherit the environment of whoever started it, or the
    /// same package built by two people on one machine can differ with nothing
    /// to say why.
    #[test]
    fn a_build_runs_in_an_environment_rvn_built() {
        let dir = std::env::temp_dir().join("rvn-build-env");
        std::fs::create_dir_all(&dir).unwrap();

        let output = build_command("env", &dir, None)
            .output()
            .expect("env(1) is in base");
        let text = String::from_utf8_lossy(&output.stdout);
        let seen: Vec<&str> = text.lines().collect();

        assert!(
            seen.contains(&format!("PATH={BUILD_PATH}").as_str()),
            "the daemon's baseline PATH, not the caller's: {text}"
        );
        assert!(
            seen.contains(&format!("HOME={}", dir.display()).as_str()),
            "{text}"
        );
        assert!(seen.contains(&"LANG=C.UTF-8"), "{text}");

        // cargo exports this into the test process; it must not survive into a
        // build. Guarded so the test still means something when the binary is
        // run directly.
        if std::env::var("CARGO_PKG_NAME").is_ok() {
            assert!(
                !text.contains("CARGO_PKG_NAME="),
                "the caller's environment leaked into the build: {text}"
            );
        }
    }

    // The account database is what `filesystem` would overwrite, and the
    // pristine test cannot protect it: nobody edits these files by hand, so an
    // image's own generated copy is indistinguishable from an untouched one.
    #[test]
    fn the_account_database_is_never_replaced_by_a_payload() {
        for path in ["etc/passwd", "etc/group", "etc/shadow", "etc/gshadow"] {
            assert!(
                NEVER_REPLACED.contains(&path),
                "{path} must never be replaced by a package payload"
            );
        }
    }

    // Paths are matched as the `backup` field spells them -- relative, no
    // leading slash -- so an absolute spelling here would silently never hit.
    #[test]
    fn never_replaced_paths_are_relative() {
        for path in NEVER_REPLACED {
            assert!(!path.starts_with('/'), "{path} must not be absolute");
        }
    }

    // A transaction calls install_archives once for the repository packages
    // and once more per AUR package, so a report built from only one call
    // would silently lose everything the others found.
    #[test]
    fn results_merge_across_the_calls_a_transaction_makes() {
        let mut repo = Batch {
            installed: vec!["sudo".into()],
            stale_removed: 2,
            stale_preserved: vec!["etc/old.conf".into()],
            pacnew: vec![Pacnew {
                package: "sudo".into(),
                path: "etc/sudoers".into(),
            }],
        };
        repo.absorb(Batch {
            installed: vec!["brave-bin".into()],
            stale_removed: 3,
            stale_preserved: vec!["etc/brave-old.conf".into()],
            pacnew: vec![Pacnew {
                package: "brave-bin".into(),
                path: "etc/brave.conf".into(),
            }],
        });

        assert_eq!(repo.installed, vec!["sudo", "brave-bin"]);
        assert_eq!(repo.stale_removed, 5);
        assert_eq!(repo.stale_preserved.len(), 2);
        assert_eq!(repo.pacnew.len(), 2);
        assert_eq!(repo.pacnew[1].package, "brave-bin");
    }

    /// Builds a local database holding one record, with `root` pointing at a
    /// directory that has no `files` entries in it. Nothing in these tests
    /// needs a second owner, and `prune_stale`'s shared-owner probe treats an
    /// unreadable file list as "not owned", which is what an empty directory
    /// gives it.
    fn one_package_db(dir: &Path, pkg: Package) -> LocalDb {
        let mut packages = HashMap::new();
        packages.insert(pkg.name.clone(), pkg);
        LocalDb {
            root: dir.to_path_buf(),
            packages,
        }
    }

    /// Upstream relocating a config file is an ordinary release note, and the
    /// administrator's edits must survive it. This is the failure that took
    /// /etc/pam.d/sudo once already, arriving by a different door: the path is
    /// not overwritten, it is simply dropped from the new version's file list
    /// and was then unlinked without a word.
    #[test]
    fn a_relocated_config_the_admin_edited_is_kept_as_pacsave() {
        let dir = std::env::temp_dir().join("rvn-prune-stale-edited");
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("root");
        let db = dir.join("db");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        // What 1.0 shipped, and the hash it recorded for it.
        std::fs::write(root.join("etc/foo.conf"), b"shipped default\n").unwrap();
        let shipped = crate::verify::sha256_file(&root.join("etc/foo.conf")).unwrap();
        // What the administrator then made of it.
        std::fs::write(root.join("etc/foo.conf"), b"shipped default\nmine = 1\n").unwrap();
        std::fs::write(root.join("usr/bin/foo-old"), b"binary").unwrap();

        let local = one_package_db(
            &db,
            Package {
                name: "foo".into(),
                version: "1.0-1".into(),
                backup: vec![BackupFile {
                    path: "etc/foo.conf".into(),
                    hash: Some(shipped),
                }],
                ..Default::default()
            },
        );

        let previous = vec!["etc/foo.conf".to_string(), "usr/bin/foo-old".to_string()];
        let current = vec!["usr/bin/foo".to_string()];
        let mut preserved = Vec::new();
        let removed = prune_stale(&root, &local, &previous, &current, "foo", &mut preserved);

        // The binary 2.0 renamed is ordinary content and goes.
        assert_eq!(removed, 1);
        assert!(!root.join("usr/bin/foo-old").exists());

        // The edited config does not.
        assert_eq!(preserved, vec!["etc/foo.conf".to_string()]);
        assert!(!root.join("etc/foo.conf").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("etc/foo.conf.pacsave")).unwrap(),
            "shipped default\nmine = 1\n"
        );
    }

    /// The other half of the rule: a config file still byte-for-byte what the
    /// package installed is package content, and leaving a `.pacsave` for it
    /// would be litter.
    #[test]
    fn a_relocated_config_the_admin_never_touched_is_deleted() {
        let dir = std::env::temp_dir().join("rvn-prune-stale-pristine");
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("root");
        let db = dir.join("db");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(&db).unwrap();

        std::fs::write(root.join("etc/foo.conf"), b"shipped default\n").unwrap();
        let shipped = crate::verify::sha256_file(&root.join("etc/foo.conf")).unwrap();

        let local = one_package_db(
            &db,
            Package {
                name: "foo".into(),
                version: "1.0-1".into(),
                backup: vec![BackupFile {
                    path: "etc/foo.conf".into(),
                    hash: Some(shipped),
                }],
                ..Default::default()
            },
        );

        let previous = vec!["etc/foo.conf".to_string()];
        let mut preserved = Vec::new();
        let removed = prune_stale(&root, &local, &previous, &[], "foo", &mut preserved);

        assert_eq!(removed, 1);
        assert!(preserved.is_empty());
        assert!(!root.join("etc/foo.conf").exists());
        assert!(!root.join("etc/foo.conf.pacsave").exists());
    }

    /// `rvn install a b`, where both ship `usr/bin/x` and neither is
    /// installed. The database pre-flight cannot see this -- it is the only
    /// conflict in the system that exists purely in the transaction -- and
    /// before this both unpacked, the second overwrote the first, and two
    /// records claimed one file. pacman refuses the transaction; so must this.
    #[test]
    fn two_packages_in_one_transaction_cannot_claim_the_same_file() {
        let mut claimed = HashMap::new();

        let first = claim_paths(
            &mut claimed,
            "a",
            &["usr/bin/x".to_string(), "usr/share/a/data".to_string()],
        );
        assert!(first.is_empty(), "nothing has been claimed yet");

        let second = claim_paths(
            &mut claimed,
            "b",
            &["usr/bin/x".to_string(), "usr/share/b/data".to_string()],
        );
        assert_eq!(second.len(), 1);
        let text = second[0].to_string();
        assert!(text.contains("usr/bin/x"), "{text}");
        assert!(text.contains(" a "), "the first claimant must be named: {text}");

        // The path b was alone in shipping is still recorded for whatever
        // comes next in the batch.
        let third = claim_paths(&mut claimed, "c", &["usr/share/b/data".to_string()]);
        assert_eq!(third.len(), 1);
    }

    /// The same archive offered twice in one batch is still one owner. Making
    /// a package conflict with itself would abort transactions that are
    /// perfectly well formed.
    #[test]
    fn a_package_listed_twice_in_a_batch_does_not_conflict_with_itself() {
        let mut claimed = HashMap::new();
        let files = vec!["usr/bin/x".to_string()];
        assert!(claim_paths(&mut claimed, "a", &files).is_empty());
        assert!(claim_paths(&mut claimed, "a", &files).is_empty());
    }

    /// A tar holding one regular file, written where a test can hand it to
    /// `install_archives` as if it had been downloaded.
    fn one_file_archive(path: &Path, member: &str, body: &[u8]) {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, member, body).unwrap();
        std::fs::write(path, builder.into_inner().unwrap()).unwrap();
    }

    /// The wiring, not just the bookkeeping: `install_archives` must refuse
    /// the whole transaction, before it writes anything, when two archives in
    /// it ship the same path. Without the batch check both unpacked into the
    /// root and the second quietly won.
    #[test]
    fn install_archives_refuses_two_packages_shipping_one_path() {
        let dir = std::env::temp_dir().join("rvn-batch-conflict");
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(dir.join("db/local")).unwrap();

        let a = dir.join("a.tar");
        let b = dir.join("b.tar");
        one_file_archive(&a, "usr/bin/x", b"from a\n");
        one_file_archive(&b, "usr/bin/x", b"from b\n");

        let config = crate::config::Config {
            root_dir: root.clone(),
            db_path: dir.join("db"),
            cache_dirs: vec![dir.join("cache")],
            log_file: dir.join("log/pacman.log"),
            ..Default::default()
        };
        let mut ctx = Context {
            local: LocalDb::load(&config.local_db_path()),
            config,
            system: Default::default(),
            sync: Vec::new(),
            aur: crate::aur::Aur::offline(),
            ui: crate::ui::Ui::new(),
            keyring: std::sync::OnceLock::new(),
            repo_only: true,
            dry_run: false,
            assume_yes: true,
            keep_cache: false,
            auto_sync: false,
            devel: Default::default(),
            force_rebuild: Vec::new(),
            user_prefix: None,
        };

        let resolved = |name: &str| Resolved {
            package: Package {
                name: name.to_string(),
                version: "1-1".into(),
                ..Default::default()
            },
            reason: crate::resolve::Reason::Explicit,
            replaces_version: None,
        };
        let plan = Plan {
            install: vec![resolved("a"), resolved("b")],
            ..Default::default()
        };

        let archives = vec![("a".to_string(), a), ("b".to_string(), b)];
        let err = match install_archives(&mut ctx, &plan, &archives, &HashMap::new()) {
            Err(e) => e,
            Ok(_) => panic!("two packages shipping usr/bin/x must be refused"),
        };
        assert!(err.contains("this transaction"), "{err}");

        // And refused before anything was written.
        assert!(
            !root.join("usr/bin/x").exists(),
            "the transaction must be refused before a byte is extracted"
        );
    }

    // The sentence is the whole of the report for anyone who reads one line
    // and moves on, so both halves of it have to agree about the count.
    #[test]
    fn the_pacnew_headline_reads_as_a_sentence() {
        assert_eq!(
            pacnew_headline(1),
            "1 config file was not replaced. Run `rvn config` to review."
        );
        assert_eq!(
            pacnew_headline(3),
            "3 config files were not replaced. Run `rvn config` to review."
        );
    }

    // An ordinary config file still follows its package across an upgrade when
    // the user has not touched it; the list is a floor, not a blanket.
    #[test]
    fn ordinary_config_is_not_on_the_list() {
        assert!(!NEVER_REPLACED.contains(&"etc/pacman.conf"));
        assert!(!NEVER_REPLACED.contains(&"etc/fstab"));
    }
}
