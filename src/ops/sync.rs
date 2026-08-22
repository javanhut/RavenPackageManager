//! Refreshing repository databases.

use super::Context;
use crate::config::{Level, Repo};
use crate::db::sync as syncdb;
use crate::fetch;
use std::path::Path;
use std::time::Duration;

/// How old a cached database may be before a refresh is suggested.
pub const STALE_AFTER: Duration = Duration::from_secs(60 * 60 * 24);

/// How long rvn trusts its note that a repository publishes no database
/// signature before asking the mirrors again.
///
/// Whether a repository signs its databases is close to a permanent property,
/// but not quite one — a repository that starts signing has to be noticed
/// without the administrator knowing to clear anything by hand.
pub const NOSIG_TRUSTED_FOR: Duration = Duration::from_secs(60 * 60 * 24 * 7);

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

    // Checked once, before any download: otherwise every repo fails the same
    // way in turn, each reporting a bare `os error 13` that never mentions the
    // one thing the reader needs to know.
    check_writable(&ctx.config.sync_db_path())?;

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
                // for the next command to pick up, and the next attempt should
                // start from a clean slate rather than from what this one
                // concluded about the repository.
                let _ = std::fs::remove_file(&dest);
                let _ = std::fs::remove_file(syncdb::db_sig_file(&ctx.config, &repo.name));
                let _ = std::fs::remove_file(syncdb::db_nosig_file(&ctx.config, &repo.name));
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

/// Confirms the sync directory can actually be written to.
fn check_writable(dir: &Path) -> Result<(), String> {
    if let Err(e) = std::fs::create_dir_all(dir) {
        return Err(describe_write_failure(dir, &e));
    }

    // Directory permissions alone do not settle it — a read-only mount or a
    // restrictive ACL both pass that check and fail the write.
    let probe = dir.join(".rvn-write-probe");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(describe_write_failure(dir, &e)),
    }
}

fn describe_write_failure(dir: &Path, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "cannot write to {} — rvn needs root to refresh the databases, so run it with sudo",
            dir.display()
        )
    } else {
        format!("cannot write to {}: {e}", dir.display())
    }
}

/// Whether a note that a repository publishes no database signature is recent
/// enough to act on.
///
/// A marker whose timestamp cannot be read, or which claims to be from the
/// future, is treated as absent: the cost of being wrong is one probe, and
/// the cost of trusting a clock glitch is never checking again.
fn marker_is_fresh(marker: &Path) -> bool {
    marker
        .metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age < NOSIG_TRUSTED_FOR)
}

/// Records that a repository publishes no database signature.
///
/// The file's contents are for whoever finds it in the sync directory; only
/// its timestamp is read back. Failing to write it is not an error — the
/// marker is a shortcut, and losing it costs a probe on the next sync.
fn remember_no_signature(marker: &Path, repo: &str) {
    let note = format!(
        "{repo} published no database signature when rvn last checked.\n\
         rvn re-checks after {} days; delete this file to re-check now.\n",
        NOSIG_TRUSTED_FOR.as_secs() / (60 * 60 * 24)
    );
    let _ = std::fs::write(marker, note);
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

    let marker = syncdb::db_nosig_file(&ctx.config, &repo.name);

    // Most repositories, Arch's own included, publish no database signature,
    // and confirming that costs a round trip per mirror for an answer that
    // essentially never changes. `Required` repositories are deliberately
    // exempt: there the answer is fatal, so it is worth re-asking every time
    // rather than holding a failure in place for a week.
    let required = repo.siglevel.database == Level::Required;
    if !required && marker_is_fresh(&marker) {
        return Ok(Verified::Unsigned);
    }

    let sig_urls: Vec<String> = repo
        .servers
        .iter()
        .map(|s| syncdb::db_sig_url(s, &repo.name))
        .collect();
    let sig_dest = syncdb::db_sig_file(&ctx.config, &repo.name);
    let _ = std::fs::remove_file(&sig_dest);

    match fetch::download_optional(&sig_urls, &sig_dest) {
        // The repository signs after all, so any note saying otherwise is
        // wrong and has to go before it is consulted again.
        fetch::Optional::Fetched(_) => {
            let _ = std::fs::remove_file(&marker);
        }
        // Optional means "check it if it exists". Arch's own repositories
        // publish no database signature at all, and many third-party ones
        // follow suit, so this is the ordinary path rather than a fault.
        fetch::Optional::NotPublished => {
            return match repo.siglevel.database {
                Level::Required => Err("no database signature is published, but the \
                                        repository is configured as DatabaseRequired"
                    .into()),
                _ => {
                    remember_no_signature(&marker, &repo.name);
                    Ok(Verified::Unsigned)
                }
            };
        }
        // Not reaching the mirrors is not the same as learning there is no
        // signature: a repository that demands one has to fail here rather
        // than fall through to an unverified database.
        fetch::Optional::Unavailable(e) => {
            return match repo.siglevel.database {
                Level::Required => Err(format!(
                    "the database signature could not be fetched, but the \
                     repository is configured as DatabaseRequired: {e}"
                )),
                _ => Ok(Verified::Unsigned),
            };
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn marker_path(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rvn-nosig-{tag}.db.nosig"));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// Moves a marker's timestamp back by `age`, standing in for the passage
    /// of time without making the test wait for it.
    fn backdate(marker: &Path, age: Duration) {
        let when = std::time::SystemTime::now() - age;
        filetime::set_file_mtime(marker, filetime::FileTime::from_system_time(when)).unwrap();
    }

    #[test]
    fn a_recent_note_saves_the_probe() {
        let marker = marker_path("recent");
        remember_no_signature(&marker, "core");
        assert!(marker_is_fresh(&marker));
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn a_note_past_its_ttl_is_re_checked() {
        // The point of the expiry: a repository that starts signing must be
        // noticed without anyone knowing to delete this file by hand.
        let marker = marker_path("expired");
        remember_no_signature(&marker, "core");
        backdate(&marker, NOSIG_TRUSTED_FOR + Duration::from_secs(60));
        assert!(!marker_is_fresh(&marker));
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn a_note_just_inside_its_ttl_is_still_trusted() {
        let marker = marker_path("boundary");
        remember_no_signature(&marker, "core");
        backdate(&marker, NOSIG_TRUSTED_FOR - Duration::from_secs(60 * 60));
        assert!(marker_is_fresh(&marker));
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn a_missing_note_means_ask_the_mirrors() {
        assert!(!marker_is_fresh(&marker_path("absent")));
    }

    #[test]
    fn a_note_dated_in_the_future_is_not_trusted() {
        // A clock that jumped backwards would otherwise pin the marker as
        // permanently fresh and the repository as permanently unchecked.
        let marker = marker_path("future");
        remember_no_signature(&marker, "core");
        let when = std::time::SystemTime::now() + Duration::from_secs(60 * 60 * 24);
        filetime::set_file_mtime(&marker, filetime::FileTime::from_system_time(when)).unwrap();
        assert!(!marker_is_fresh(&marker));
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn the_note_explains_itself_to_whoever_finds_it() {
        let marker = marker_path("readable");
        remember_no_signature(&marker, "core");
        let note = std::fs::read_to_string(&marker).unwrap();
        assert!(note.contains("core"), "{note}");
        assert!(note.contains("delete this file"), "{note}");
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn an_unwritable_note_is_not_fatal() {
        // The marker is an optimisation; losing it costs a probe, not a sync.
        remember_no_signature(Path::new("/nonexistent/rvn/core.db.nosig"), "core");
    }

    #[test]
    fn a_writable_directory_passes_and_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join("rvn-writable-probe");
        assert!(check_writable(&dir).is_ok());
        assert!(!dir.join(".rvn-write-probe").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unwritable_directory_says_to_use_sudo() {
        // Root can write anywhere, so there is nothing to observe.
        if super::super::is_root() {
            return;
        }
        let message = describe_write_failure(
            Path::new("/var/lib/pacman/sync"),
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        // The bare `os error 13` this replaced never said what to do about it.
        assert!(message.contains("sudo"), "{message}");
        assert!(message.contains("/var/lib/pacman/sync"), "{message}");
    }

    #[test]
    fn other_write_failures_keep_their_own_message() {
        let message = describe_write_failure(
            Path::new("/somewhere"),
            &std::io::Error::from(std::io::ErrorKind::StorageFull),
        );
        assert!(!message.contains("sudo"), "{message}");
    }
}
