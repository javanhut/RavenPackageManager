//! High-level operations, each owning one user-facing command.

pub mod install;
pub mod remove;
pub mod search;
pub mod sync;
pub mod update;

use crate::aur::Aur;
use crate::config::Config;
use crate::db::local::LocalDb;
use crate::db::sync::SyncDb;
use crate::ui::Ui;
use crate::verify::Keyring;
use std::path::PathBuf;

/// Shared state for a single rvn invocation.
pub struct Context {
    pub config: Config,
    pub local: LocalDb,
    pub sync: Vec<SyncDb>,
    pub aur: Aur,
    pub ui: Ui,
    pub keyring: Option<Keyring>,
    /// Skip the AUR entirely.
    pub repo_only: bool,
    /// Resolve and report, but change nothing.
    pub dry_run: bool,
    /// Answer every prompt affirmatively.
    pub assume_yes: bool,
}

impl Context {
    /// Builds a context from a config file path, loading whatever databases
    /// already exist. Missing databases are not an error — the caller can
    /// refresh them.
    pub fn load(config_path: &PathBuf, ui: Ui) -> std::io::Result<Context> {
        let config = Config::load(config_path).unwrap_or_default();
        let local = LocalDb::load(&config.local_db_path());
        let (sync, _missing) = crate::db::sync::load_all(&config);
        let keyring = Keyring::load(&config.gpg_dir).ok();

        Ok(Context {
            config,
            local,
            sync,
            aur: Aur::new(),
            ui,
            keyring,
            repo_only: false,
            dry_run: false,
            assume_yes: false,
        })
    }

    /// Reloads the sync databases after a refresh.
    pub fn reload_sync(&mut self) {
        let (sync, _) = crate::db::sync::load_all(&self.config);
        self.sync = sync;
    }

    /// The first writable cache directory.
    pub fn cache_dir(&self) -> PathBuf {
        self.config
            .cache_dirs
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/var/cache/pacman/pkg"))
    }

    /// Whether the process can write to the install root.
    pub fn can_write_root(&self) -> bool {
        // An unwritable root means every install would fail late; better to
        // say so up front.
        let probe = self.config.db_path.join("local");
        probe
            .metadata()
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
            || is_root()
    }
}

#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc_geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}
