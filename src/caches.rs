//! The desktop's lookup caches, rebuilt after a transaction that changed
//! what they index.
//!
//! On Arch these are pacman's libalpm hooks (update-desktop-database.hook,
//! 30-update-mime-database.hook), which rvn does not run. Without them a
//! package's files land but the desktop never learns of them: a browser
//! installs and is not the handler for https:// links, so nothing opens them
//! until some unrelated build happens to rewrite mimeinfo.cache.
//!
//!   usr/share/applications/*.desktop   mimeinfo.cache: which application
//!                                      handles a MIME type or URL scheme
//!   usr/share/mime/packages/*.xml      the MIME database: what type a
//!                                      file is
//!
//! Like the hooks, this reads a transaction's file list, not the disk, so a
//! transaction that touched neither directory costs nothing.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

/// Which caches a transaction's files invalidate.
#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub struct Stale {
    pub desktop: bool,
    pub mime: bool,
}

impl Stale {
    /// Marks what the root-relative paths in `files` invalidate. Called once
    /// per package, so one refresh covers the whole transaction.
    pub fn note(&mut self, files: &[String]) {
        for file in files {
            if file.starts_with("usr/share/applications/") && file.ends_with(".desktop") {
                self.desktop = true;
            } else if file.starts_with("usr/share/mime/packages/") && file.ends_with(".xml") {
                self.mime = true;
            }
        }
    }
}

/// Rebuilds each stale cache under `root`. A missing tool or a failed run is
/// a warning: the packages are installed either way, and the next refresh
/// repairs the cache.
pub fn refresh(root: &Path, stale: Stale, warn: &mut impl FnMut(&str)) {
    if stale.desktop {
        run(
            "update-desktop-database",
            &[OsStr::new("-q"), root.join("usr/share/applications").as_os_str()],
            "desktop-file-utils",
            warn,
        );
    }
    if stale.mime {
        run(
            "update-mime-database",
            &[root.join("usr/share/mime").as_os_str()],
            "shared-mime-info",
            warn,
        );
    }
}

fn run(tool: &str, args: &[&OsStr], package: &str, warn: &mut impl FnMut(&str)) {
    match Command::new(tool).args(args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => warn(&format!(
            "{tool} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn(&format!("{tool} is missing (from {package}); desktop caches not refreshed"))
        }
        Err(e) => warn(&format!("could not run {tool}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn a_desktop_entry_marks_the_desktop_database() {
        let mut stale = Stale::default();
        stale.note(&files(&["usr/bin/brave", "usr/share/applications/brave-browser.desktop"]));
        assert_eq!(stale, Stale { desktop: true, mime: false });
    }

    #[test]
    fn a_mime_package_marks_the_mime_database() {
        let mut stale = Stale::default();
        stale.note(&files(&["usr/share/mime/packages/foo.xml"]));
        assert_eq!(stale, Stale { desktop: false, mime: true });
    }

    #[test]
    fn unrelated_files_and_directory_entries_mark_nothing() {
        let mut stale = Stale::default();
        stale.note(&files(&[
            "usr/share/applications/",
            "usr/share/mime/",
            "usr/share/doc/brave/README",
            "usr/share/applications/mimeinfo.cache",
        ]));
        assert_eq!(stale, Stale::default());
    }

    #[test]
    fn notes_accumulate_across_packages() {
        let mut stale = Stale::default();
        stale.note(&files(&["usr/share/applications/a.desktop"]));
        stale.note(&files(&["usr/share/mime/packages/b.xml"]));
        assert_eq!(stale, Stale { desktop: true, mime: true });
    }

    #[test]
    fn nothing_stale_runs_nothing_and_warns_nothing() {
        let mut warned = Vec::new();
        refresh(Path::new("/nonexistent"), Stale::default(), &mut |w| warned.push(w.to_string()));
        assert!(warned.is_empty());
    }
}
