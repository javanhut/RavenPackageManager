//! `rvn update`: bringing installed packages up to date.
//!
//! Update is a thin decision layer over the install pipeline: it works out
//! what is out of date, then hands those names to the same resolve → fetch →
//! verify → unpack machinery that `install` uses.

use super::{Context, install, sync};
use crate::ui::theme::{Color, bytes};
use crate::upgrade::{self, Candidate, Kind};

pub struct Outcome {
    pub updated: Vec<String>,
    /// Packages retired because something replaced them.
    pub replaced: Vec<String>,
}

/// Runs `rvn update`.
///
/// With no targets this is a full system update; with targets it is limited to
/// those packages.
pub fn run(ctx: &mut Context, targets: &[String], refresh: bool) -> Result<Outcome, String> {
    ctx.ui.banner(&format!("v{}", env!("CARGO_PKG_VERSION")));

    if refresh {
        sync::refresh(ctx)?;
    } else if sync::needs_refresh(ctx) {
        ctx.ui
            .warn("repository databases are stale — run `rvn sync` or drop --no-refresh");
    }

    // ---- work out what is out of date ----------------------------------
    let candidates = {
        let scope = if targets.is_empty() {
            "checking every installed package".to_string()
        } else {
            format!("checking {}", targets.join(", "))
        };
        let spinner = ctx.ui.stage(&scope);

        let only = if targets.is_empty() {
            None
        } else {
            Some(targets)
        };

        // Ask about every AUR package in one batch rather than one request
        // per package.
        let foreign: Vec<String> = ctx
            .local
            .packages
            .values()
            .filter(|p| ctx.sync.iter().all(|db| db.get(&p.name).is_none()))
            .filter(|p| only.map(|t| t.contains(&p.name)).unwrap_or(true))
            .map(|p| p.name.clone())
            .collect();

        if !foreign.is_empty() && !ctx.repo_only {
            spinner.set_message(&format!("querying the AUR about {} packages", foreign.len()));
            if let Err(e) = ctx.aur.prefetch(&foreign) {
                ctx.ui.warn(&format!("AUR query failed: {e}"));
            }
        }

        let mut found = upgrade::candidates(&ctx.local, &ctx.sync, &ctx.aur, only.map(|t| &t[..]));

        // A VCS package's recorded version never moves on its own, so upstream
        // has to be asked directly.
        let devel_names: Vec<String> = foreign
            .iter()
            .filter(|name| crate::devel::is_devel(name))
            .cloned()
            .collect();

        if !devel_names.is_empty() && !ctx.repo_only {
            spinner.set_message(&format!(
                "checking {} devel package{} against upstream",
                devel_names.len(),
                if devel_names.len() == 1 { "" } else { "s" }
            ));
            for name in crate::devel::outdated(&ctx.devel, &devel_names) {
                if found.iter().any(|c| c.name == name) {
                    continue;
                }
                if let Some(installed) = ctx.local.get(&name) {
                    found.push(Candidate {
                        name: name.clone(),
                        installed_version: installed.version.clone(),
                        new_version: "latest commit".to_string(),
                        origin: crate::pkg::Origin::Aur,
                        kind: Kind::Devel,
                        download_size: 0,
                    });
                }
            }
        }

        spinner.succeed(&format!(
            "{} update{} available",
            found.len(),
            if found.len() == 1 { "" } else { "s" }
        ));
        found
    };

    let absent: Vec<String> = targets
        .iter()
        .filter(|t| !ctx.local.is_installed(t))
        .cloned()
        .collect();

    if !absent.is_empty() {
        // Nothing named is installed, so there is no update to speak of.
        if absent.len() == targets.len() {
            ctx.ui.err("not installed:");
            ctx.ui.tree(&absent);
            return Err(format!("no package named {}", absent.join(", ")));
        }
        for name in &absent {
            ctx.ui.warn(&format!("{name} is not installed"));
        }
    }

    if candidates.is_empty() {
        ctx.ui.emit(
            "updates",
            serde_json::json!({ "candidates": [], "downgrades": [], "download_size": 0 }),
        );
        ctx.ui.ok("everything is up to date");
        return Ok(Outcome {
            updated: Vec::new(),
            replaced: Vec::new(),
        });
    }

    // A downgrade is never applied automatically: it means the repository
    // moved backwards, which the administrator should decide about.
    let (applicable, downgrades): (Vec<Candidate>, Vec<Candidate>) = candidates
        .into_iter()
        .partition(|c| c.kind != Kind::Downgrade);

    ctx.ui.emit(
        "updates",
        serde_json::json!({
            "candidates": applicable.iter().map(crate::ui::json::candidate).collect::<Vec<_>>(),
            "downgrades": downgrades.iter().map(crate::ui::json::candidate).collect::<Vec<_>>(),
            "download_size": upgrade::download_size(&applicable),
        }),
    );
    show_candidates(ctx, &applicable, &downgrades);

    if applicable.is_empty() {
        ctx.ui.info("no updates to apply");
        return Ok(Outcome {
            updated: Vec::new(),
            replaced: Vec::new(),
        });
    }

    if ctx.dry_run {
        ctx.ui.info("dry run — nothing was changed");
        return Ok(Outcome {
            updated: Vec::new(),
            replaced: Vec::new(),
        });
    }

    if !ctx.assume_yes && !ctx.ui.confirm("apply these updates?", true) {
        return Err("cancelled".into());
    }

    // The plan was just approved; the install pipeline must not ask again.
    let previously_assumed = ctx.assume_yes;
    ctx.assume_yes = true;

    // A devel package's version is unchanged by definition, so the resolver
    // would otherwise treat it as already satisfied and skip the rebuild.
    ctx.force_rebuild = applicable
        .iter()
        .filter(|c| c.kind == Kind::Devel)
        .map(|c| c.name.clone())
        .collect();

    let names: Vec<String> = applicable.iter().map(|c| c.name.clone()).collect();
    let result = install::execute(ctx, &names);

    ctx.force_rebuild.clear();
    ctx.assume_yes = previously_assumed;
    let outcome = result?;

    // Replaced packages are retired by the install pipeline itself, which
    // knows the successors actually landed.
    let replaced = outcome.replaced.clone();

    ctx.ui.blank();
    ctx.ui.ok(&format!(
        "{} package{} updated",
        ctx.ui.style.bold(&outcome.installed.len().to_string()),
        if outcome.installed.len() == 1 { "" } else { "s" }
    ));

    Ok(Outcome {
        updated: outcome.installed,
        replaced,
    })
}

fn show_candidates(ctx: &Context, applicable: &[Candidate], downgrades: &[Candidate]) {
    if ctx.ui.is_json() {
        return;
    }
    let s = &ctx.ui.style;
    ctx.ui.blank();

    let render = |c: &Candidate| {
        let origin = s.paint(
            if c.origin.is_aur() {
                Color::Cyan
            } else {
                Color::Violet
            },
            c.origin.label(),
        );
        let mut line = if c.kind == Kind::Devel {
            format!("{origin}/{} {}", s.bold(&c.name), s.dim(&c.installed_version))
        } else {
            format!(
                "{origin}/{} {} {} {}",
                s.bold(&c.name),
                s.dim(&c.installed_version),
                s.glyphs.arrow,
                s.paint(Color::Green, &c.new_version)
            )
        };
        match &c.kind {
            Kind::Replacement { replaces } => line.push_str(&format!(
                " {}",
                s.paint(Color::Amber, &format!("(replaces {replaces})"))
            )),
            Kind::Devel => line.push_str(&format!(
                " {}",
                s.paint(Color::Cyan, "(upstream moved — rebuild)")
            )),
            _ => {}
        }
        line
    };

    if !applicable.is_empty() {
        ctx.ui
            .step(&format!("updates to apply ({})", applicable.len()));
        ctx.ui
            .tree(&applicable.iter().map(render).collect::<Vec<_>>());

        ctx.ui.blank();
        let aur = applicable.iter().filter(|c| c.origin.is_aur()).count();
        ctx.ui.info(&format!(
            "download {}{}",
            s.bold(&bytes(upgrade::download_size(applicable))),
            if aur > 0 {
                format!(
                    "   {} to rebuild from source",
                    s.paint(Color::Cyan, &aur.to_string())
                )
            } else {
                String::new()
            }
        ));
    }

    if !downgrades.is_empty() {
        ctx.ui.blank();
        ctx.ui.warn(&format!(
            "{} installed package{} newer than the repositories carry (skipped):",
            downgrades.len(),
            if downgrades.len() == 1 { " is" } else { "s are" }
        ));
        ctx.ui
            .tree(&downgrades.iter().map(render).collect::<Vec<_>>());
        ctx.ui
            .info("install a specific version explicitly to move backwards");
    }

    ctx.ui.blank();
}
