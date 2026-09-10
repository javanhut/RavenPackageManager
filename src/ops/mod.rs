//! High-level operations, each owning one user-facing command.

pub mod install;
pub mod query;
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
use std::sync::OnceLock;

/// Shared state for a single rvn invocation.
pub struct Context {
    pub config: Config,
    pub local: LocalDb,
    pub sync: Vec<SyncDb>,
    pub aur: Aur,
    pub ui: Ui,
    /// Read on first use: only signature checks need it, and parsing
    /// pacman's keyring takes tens of milliseconds every other command
    /// would pay for nothing.
    keyring: OnceLock<Option<Keyring>>,
    /// Skip the AUR entirely.
    pub repo_only: bool,
    /// Resolve and report, but change nothing.
    pub dry_run: bool,
    /// Answer every prompt affirmatively.
    pub assume_yes: bool,
    /// Keep downloaded packages after a successful transaction.
    pub keep_cache: bool,
    /// Refresh stale or missing databases without being asked.
    pub auto_sync: bool,
    /// Upstream commits of the VCS packages rvn has built.
    pub devel: crate::devel::Registry,
    /// Packages to reinstall even if their version already matches.
    pub force_rebuild: Vec<String>,
    /// `rvn --user`: installing into the caller's own prefix. No root, so no
    /// scriptlets and no hooks, and nothing goes through rvnd.
    pub user_prefix: Option<crate::config::UserPrefix>,
}

impl Context {
    /// Builds a context from a config file path, loading whatever databases
    /// already exist. Missing databases are not an error — the caller can
    /// refresh them.
    pub fn load(config_path: &PathBuf, ui: Ui) -> std::io::Result<Context> {
        // A mistyped --config must not silently fall back to defaults that
        // point at the real system databases.
        let config = match Config::load(config_path) {
            Ok(config) => config,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("{}: no such configuration file", config_path.display()),
                ));
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("{}: {e}", config_path.display()),
                ));
            }
        };
        Ok(Self::from_config(config, ui))
    }

    /// A context over an already-built configuration.
    pub fn from_config(config: Config, ui: Ui) -> Context {
        let db_path_for_devel = config.db_path.clone();
        let local = LocalDb::load(&config.local_db_path());
        let (sync, _missing) = crate::db::sync::load_all(&config);

        Context {
            config,
            local,
            sync,
            aur: Aur::new(),
            ui,
            keyring: OnceLock::new(),
            repo_only: false,
            dry_run: false,
            assume_yes: false,
            keep_cache: false,
            auto_sync: true,
            devel: crate::devel::Registry::load(&db_path_for_devel),
            force_rebuild: Vec::new(),
            user_prefix: None,
        }
    }

    /// The pacman keyring, or `None` when it could not be read.
    pub fn keyring(&self) -> Option<&Keyring> {
        self.keyring
            .get_or_init(|| Keyring::load(&self.config.gpg_dir).ok())
            .as_ref()
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
