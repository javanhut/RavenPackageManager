//! `rvn update`: bringing installed packages up to date.
//!
//! Update is a thin decision layer over the install pipeline: it works out
//! what is out of date, then hands those names to the same resolve → fetch →
//! verify → unpack machinery that `install` uses.

use super::{Context, install, remove, sync};
use crate::remove::Options as RemoveOptions;
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
        let found = upgrade::candidates(&ctx.local, &ctx.sync, &ctx.aur, only.map(|t| &t[..]));

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

    let names: Vec<String> = applicable.iter().map(|c| c.name.clone()).collect();
    let result = install::execute(ctx, &names);

    ctx.assume_yes = previously_assumed;
    let outcome = result?;

    // ---- retire replaced packages --------------------------------------
    let mut replaced = Vec::new();
    let superseded: Vec<String> = applicable
        .iter()
        .filter_map(|c| match &c.kind {
            Kind::Replacement { replaces } => Some(replaces.clone()),
            _ => None,
        })
        // Only retire something the successor actually installed over.
        .filter(|old| outcome.installed.iter().any(|new| new != old))
        .collect();

    if !superseded.is_empty() {
        ctx.ui.blank();
        let spinner = ctx
            .ui
            .stage(&format!("retiring {}", superseded.join(", ")));

        // The successor already provides what these offered, so the reverse
        // dependency check would fire spuriously here.
        let plan = crate::remove::plan(
            &ctx.local,
            &superseded,
            RemoveOptions {
                nodeps: true,
                ..Default::default()
            },
        );
        spinner.clear();

        let removed = remove::apply(ctx, &plan)?;
        replaced = removed.removed;
    }

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
        let mut line = format!(
            "{origin}/{} {} {} {}",
            s.bold(&c.name),
            s.dim(&c.installed_version),
            s.glyphs.arrow,
            s.paint(Color::Green, &c.new_version)
        );
        if let Kind::Replacement { replaces } = &c.kind {
            line.push_str(&format!(
                " {}",
                s.paint(Color::Amber, &format!("(replaces {replaces})"))
            ));
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
