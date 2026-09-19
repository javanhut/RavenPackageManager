//! What the base system provides without rvn having installed it.
//!
//! Raven builds some of what Arch ships as packages into the image itself:
//! `raven-open` is the system's `xdg-open`, `xdg-settings` and `xdg-mime`, so
//! nothing should ever install `xdg-utils` over it. But packages from the
//! repositories still name `xdg-utils` as a dependency (chromium does), and
//! the local database knows nothing of what the image built -- so without
//! this, rvn would pull `xdg-utils` in, find `/usr/bin/xdg-open` already on
//! disk and owned by no package, and refuse the whole installation.
//!
//! A component declares what it stands in for with a file in
//!
//!   usr/share/rvn/provides.d/   shipped by the component itself
//!   etc/rvn/provides.d/         added by the machine's administrator
//!
//! one provision per line, `name` or `name=version`, `#` for comments:
//!
//! ```text
//! # usr/share/rvn/provides.d/raven-open
//! xdg-utils=1.2.1
//! ```
//!
//! A versioned provision satisfies versioned dependencies the way a package's
//! own `provides` does; a bare one satisfies only unversioned dependencies,
//! as in alpm. These are deliberately *not* entries in the local database:
//! that would make `rvn update` offer to "upgrade" them from the repositories,
//! which is exactly the overwrite this exists to prevent.

use std::path::Path;

use crate::pkg::Dep;

/// Directories holding provision files, relative to the install root, in the
/// order they are read.
pub const DIRS: &[&str] = &["usr/share/rvn/provides.d", "etc/rvn/provides.d"];

/// One thing the system provides.
#[derive(Debug, Clone, PartialEq)]
pub struct Provision {
    /// The package name, with its version as an `=` constraint when given.
    pub dep: Dep,
    /// The file that declared it -- named after the component, so it reads
    /// as "provided by raven-open".
    pub by: String,
}

/// Everything the base system provides.
#[derive(Debug, Clone, Default)]
pub struct SystemProvides {
    provisions: Vec<Provision>,
}

impl SystemProvides {
    /// Reads every provision file under `root`. Missing directories and
    /// unreadable files are skipped: a system with none of these files is
    /// simply one where rvn manages everything.
    pub fn load(root: &Path) -> Self {
        let mut provisions = Vec::new();
        for dir in DIRS {
            let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
                continue;
            };
            let mut files: Vec<_> = entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| !n.starts_with('.'))
                })
                .collect();
            // Name order, so the file reported for a provision declared twice
            // does not depend on directory order.
            files.sort();
            for path in files {
                let (Ok(text), Some(by)) = (
                    std::fs::read_to_string(&path),
                    path.file_name().and_then(|n| n.to_str()),
                ) else {
                    continue;
                };
                provisions.extend(parse(&text, by));
            }
        }
        Self { provisions }
    }

    /// A set built from explicit provisions, for tests and callers that
    /// already have them.
    pub fn from(provisions: Vec<Provision>) -> Self {
        Self { provisions }
    }

    /// The provision satisfying `dep`, if the system has one.
    pub fn satisfier(&self, dep: &Dep) -> Option<&Provision> {
        self.provisions
            .iter()
            .find(|p| dep.satisfied_by_provide(&p.dep))
    }

    /// The provision named `name`, whatever its version -- for refusing an
    /// explicit request to install over it.
    pub fn named(&self, name: &str) -> Option<&Provision> {
        self.provisions.iter().find(|p| p.dep.name == name)
    }

    pub fn is_empty(&self) -> bool {
        self.provisions.is_empty()
    }
}

/// The provisions in one file's text.
pub fn parse(text: &str, by: &str) -> Vec<Provision> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty())
        .map(|line| Provision {
            dep: Dep::parse(line),
            by: by.to_owned(),
        })
        // Only `name` and `name=version` provide anything; `name>=1` is a
        // requirement, not a provision, and is ignored rather than guessed at.
        .filter(|p| matches!(&p.dep.constraint, None | Some((crate::pkg::Op::Eq, _))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provides(text: &str) -> SystemProvides {
        SystemProvides::from(parse(text, "raven-open"))
    }

    #[test]
    fn a_versioned_provision_satisfies_versioned_and_bare_dependencies() {
        let sys = provides("# raven-open stands in for these\nxdg-utils=1.2.1\n");
        assert!(sys.satisfier(&Dep::parse("xdg-utils")).is_some());
        assert!(sys.satisfier(&Dep::parse("xdg-utils>=1.1")).is_some());
        assert!(sys.satisfier(&Dep::parse("xdg-utils>=2")).is_none());
        assert_eq!(
            sys.satisfier(&Dep::parse("xdg-utils")).unwrap().by,
            "raven-open"
        );
    }

    #[test]
    fn a_bare_provision_satisfies_only_bare_dependencies() {
        let sys = provides("xdg-utils\n");
        assert!(sys.satisfier(&Dep::parse("xdg-utils")).is_some());
        assert!(sys.satisfier(&Dep::parse("xdg-utils>=1.0")).is_none());
    }

    #[test]
    fn comments_blanks_and_requirements_are_not_provisions() {
        let sys = provides("\n  # a comment\nfoo>=1 \nbar=2 # trailing\n");
        assert!(sys.named("foo").is_none());
        assert!(sys.satisfier(&Dep::parse("bar=2")).is_some());
    }

    #[test]
    fn files_are_read_from_both_directories_under_the_root() {
        let root = std::env::temp_dir().join(format!("rvn-provides-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (dir, name, text) in [
            (
                "usr/share/rvn/provides.d",
                "raven-open",
                "xdg-utils=1.2.1\n",
            ),
            ("etc/rvn/provides.d", "local", "my-tool\n"),
            ("etc/rvn/provides.d", ".hidden", "ignored\n"),
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join(name), text).unwrap();
        }
        let sys = SystemProvides::load(&root);
        assert_eq!(sys.named("xdg-utils").unwrap().by, "raven-open");
        assert_eq!(sys.named("my-tool").unwrap().by, "local");
        assert!(sys.named("ignored").is_none());
        assert!(SystemProvides::load(&root.join("nowhere")).is_empty());
    }
}
