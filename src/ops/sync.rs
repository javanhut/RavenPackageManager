//! Refreshing repository databases.

use super::Context;
use crate::config::{Level, Repo};
use crate::db::sync as syncdb;
use crate::fetch;
use std::path::Path;
use std::time::Duration;

/// How old a cached database may be before a refresh is suggested.
pub const STALE_AFTER: Duration = Duration::from_secs(60 * 60 * 24);

/// Whether any configured repo has a missing or stale database.
pub fn needs_refresh(ctx: &Context) -> bool {
    ctx.config.repos.iter().any(|repo| {
        let path = syncdb::db_file(&ctx.config, &repo.name);
        match path.metadata().and_then(|m| m.modified()) {
            Ok(modified) => modified
                .elapsed()
                .map(|age| age > STALE_AFTER)
                .unwrap_or(true),
            Err(_) => true,
        }
    })
}

/// Downloads every configured repository database, verifying each one's
/// signature according to the repository's `SigLevel`.
pub fn refresh(ctx: &mut Context) -> Result<usize, String> {
    if ctx.config.repos.is_empty() {
        return Err("no repositories configured in pacman.conf".into());
    }

    let mut refreshed = 0;
    let mut failures = Vec::new();

    for repo in &ctx.config.repos {
        if repo.servers.is_empty() {
            failures.push(format!("{}: no mirrors configured", repo.name));
            continue;
        }

        let spinner = ctx.ui.stage(&format!("syncing {}", repo.name));
        let urls: Vec<String> = repo
            .servers
            .iter()
            .map(|s| syncdb::db_url(s, &repo.name))
            .collect();
        let dest = syncdb::db_file(&ctx.config, &repo.name);

        let bytes = match fetch::download_with_mirrors(&urls, &dest, None) {
            Ok(bytes) => bytes,
            Err(e) => {
                spinner.fail(&format!("{} failed", repo.name));
                failures.push(format!("{}: {e}", repo.name));
                continue;
            }
        };

        spinner.set_message(&format!("verifying {}", repo.name));
        match verify_database(ctx, repo, &dest) {
            Ok(Verified::Signed) => spinner.succeed(&format!(
                "{} synced {} {}",
                repo.name,
                ctx.ui
                    .style
                    .dim(&format!("({})", crate::ui::theme::bytes(bytes))),
                ctx.ui.style.dim("· signature verified")
            )),
            Ok(Verified::Unsigned) => spinner.succeed(&format!(
                "{} synced {}",
                repo.name,
                ctx.ui
                    .style
                    .dim(&format!("({})", crate::ui::theme::bytes(bytes)))
            )),
            Err(e) => {
                spinner.fail(&format!("{} failed verification", repo.name));
                // A database that cannot be trusted must not be left in place
                // for the next command to pick up.
                let _ = std::fs::remove_file(&dest);
                let _ = std::fs::remove_file(syncdb::db_sig_file(&ctx.config, &repo.name));
                failures.push(format!("{}: {e}", repo.name));
                continue;
            }
        }

        refreshed += 1;
    }

    ctx.reload_sync();

    if refreshed == 0 && !failures.is_empty() {
        return Err(failures.join("\n"));
    }
    for failure in &failures {
        ctx.ui.warn(failure);
    }

    Ok(refreshed)
}

/// Whether a synced database carried a valid signature.
enum Verified {
    Signed,
    Unsigned,
}

/// Checks a freshly downloaded database against its detached signature.
///
/// A tampered database cannot forge package signatures, but it can hide an
/// update or steer a request at a different version, so a repository asking
/// for `DatabaseRequired` must not be silently downgraded.
fn verify_database(ctx: &Context, repo: &Repo, dest: &Path) -> Result<Verified, String> {
    if repo.siglevel.database == Level::Never {
        return Ok(Verified::Unsigned);
    }

    let sig_urls: Vec<String> = repo
        .servers
        .iter()
        .map(|s| syncdb::db_sig_url(s, &repo.name))
        .collect();
    let sig_dest = syncdb::db_sig_file(&ctx.config, &repo.name);
    let _ = std::fs::remove_file(&sig_dest);

    let fetched = fetch::download_with_mirrors(&sig_urls, &sig_dest, None).is_ok();

    if !fetched {
        // Optional means "check it if it exists"; many third-party repos ship
        // no database signature at all.
        return match repo.siglevel.database {
            Level::Required => Err("no database signature is published, but the \
                                    repository is configured as DatabaseRequired"
                .into()),
            _ => Ok(Verified::Unsigned),
        };
    }

    let keyring = ctx
        .keyring
        .as_ref()
        .ok_or("the pacman keyring could not be read, so the database signature \
                cannot be checked")?;

    let data = std::fs::read(dest).map_err(|e| e.to_string())?;
    let signature = std::fs::read(&sig_dest).map_err(|e| e.to_string())?;

    // A signature that is present but invalid is fatal at every level above
    // Never — that is a tampered database, not a missing convenience.
    keyring
        .verify_detached(&data, &signature)
        .map(|_| Verified::Signed)
        .map_err(|e| format!("database {e}"))
}
