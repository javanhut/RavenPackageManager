//! Refreshing repository databases.

use super::Context;
use crate::db::sync as syncdb;
use crate::fetch;
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

/// Downloads every configured repository database.
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

        match fetch::download_with_mirrors(&urls, &dest, None) {
            Ok(bytes) => {
                spinner.succeed(&format!(
                    "{} synced {}",
                    repo.name,
                    ctx.ui
                        .style
                        .dim(&format!("({})", crate::ui::theme::bytes(bytes)))
                ));
                refreshed += 1;
            }
            Err(e) => {
                spinner.fail(&format!("{} failed", repo.name));
                failures.push(format!("{}: {e}", repo.name));
            }
        }
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
