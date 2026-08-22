//! Package install scriptlets (`.INSTALL`).
//!
//! A scriptlet is a bash file defining optional hook functions that run around
//! a transaction. rvn stores it alongside the package record — exactly where
//! pacman keeps it — so removal hooks still work long after installation.
//!
//! A failing scriptlet warns rather than aborting: pacman behaves the same way,
//! and rolling a half-applied transaction back over a failed `post_install`
//! would be worse than continuing.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    PreInstall,
    PostInstall,
    PreUpgrade,
    PostUpgrade,
    PreRemove,
    PostRemove,
}

impl Hook {
    /// The bash function pacman looks for.
    pub fn function(self) -> &'static str {
        match self {
            Hook::PreInstall => "pre_install",
            Hook::PostInstall => "post_install",
            Hook::PreUpgrade => "pre_upgrade",
            Hook::PostUpgrade => "post_upgrade",
            Hook::PreRemove => "pre_remove",
            Hook::PostRemove => "post_remove",
        }
    }

    /// Whether this hook runs before the filesystem is touched.
    pub fn is_pre(self) -> bool {
        matches!(self, Hook::PreInstall | Hook::PreUpgrade | Hook::PreRemove)
    }

    /// The install-time hook for a transaction, which differs for an upgrade.
    pub fn for_install(upgrading: bool, pre: bool) -> Hook {
        match (upgrading, pre) {
            (true, true) => Hook::PreUpgrade,
            (true, false) => Hook::PostUpgrade,
            (false, true) => Hook::PreInstall,
            (false, false) => Hook::PostInstall,
        }
    }
}

/// Whether a scriptlet defines a given hook.
///
/// Checked before spawning bash: most scriptlets define only one or two hooks,
/// and starting a shell for a function that does not exist is pure overhead.
pub fn defines(script: &str, hook: Hook) -> bool {
    let name = hook.function();
    script.lines().map(str::trim).any(|line| {
        // Matches `post_install() {`, `post_install ()`, and `function post_install`.
        line.strip_prefix("function ")
            .unwrap_or(line)
            .trim_start()
            .strip_prefix(name)
            .map(|rest| rest.trim_start().starts_with('('))
            .unwrap_or(false)
    })
}

/// Where a scriptlet is staged inside the install root before it runs.
fn staging_path(root: &Path, package: &str) -> PathBuf {
    root.join(format!("tmp/rvn-scriptlet-{package}"))
}

/// Builds the command that runs one hook.
///
/// When the install root is not `/`, the scriptlet is executed inside it with
/// `chroot`, so a package's own post-install work lands in the target system
/// rather than the host.
pub fn command(
    root: &Path,
    script_in_root: &Path,
    hook: Hook,
    new_version: &str,
    old_version: Option<&str>,
) -> Command {
    // `source` then call: the scriptlet is a library of functions, not a
    // program with a main body.
    let script_arg = format!("/{}", script_in_root.display());
    let mut inline = format!(". {script_arg}; {}", hook.function());
    if let Some(old) = old_version {
        inline.push_str(&format!(" '{new_version}' '{old}'"));
    } else {
        inline.push_str(&format!(" '{new_version}'"));
    }

    if root == Path::new("/") {
        let mut command = Command::new("bash");
        command.arg("-c").arg(inline);
        command
    } else {
        let mut command = Command::new("chroot");
        command.arg(root).arg("bash").arg("-c").arg(inline);
        command
    }
}

#[derive(Debug)]
pub enum Outcome {
    /// The hook ran successfully.
    Ran,
    /// The scriptlet does not define this hook.
    NotDefined,
    /// The hook ran and failed; the message is what it reported.
    Failed(String),
}

/// Runs one hook from a scriptlet.
pub fn run(
    root: &Path,
    package: &str,
    script: &[u8],
    hook: Hook,
    new_version: &str,
    old_version: Option<&str>,
) -> Outcome {
    let text = String::from_utf8_lossy(script);
    if !defines(&text, hook) {
        return Outcome::NotDefined;
    }

    // The scriptlet has to live inside the root for chroot to reach it.
    let staged = staging_path(root, package);
    if let Some(parent) = staged.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return Outcome::Failed("could not stage the scriptlet".into());
        }
    }
    if std::fs::write(&staged, script).is_err() {
        return Outcome::Failed("could not stage the scriptlet".into());
    }

    let relative = staged.strip_prefix(root).unwrap_or(&staged);
    let result = command(root, relative, hook, new_version, old_version).output();
    let _ = std::fs::remove_file(&staged);

    match result {
        Ok(output) if output.status.success() => Outcome::Ran,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("scriptlet failed")
                .trim()
                .to_string();
            Outcome::Failed(message)
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = r#"
post_install() {
    echo "installed $1"
}

function pre_remove () {
    echo "removing $1"
}

post_upgrade() {
  echo "upgraded $1 from $2"
}
"#;

    #[test]
    fn detects_defined_hooks() {
        assert!(defines(SCRIPT, Hook::PostInstall));
        assert!(defines(SCRIPT, Hook::PostUpgrade));
        // Declared with the `function` keyword and a space before `()`.
        assert!(defines(SCRIPT, Hook::PreRemove));

        assert!(!defines(SCRIPT, Hook::PreInstall));
        assert!(!defines(SCRIPT, Hook::PreUpgrade));
        assert!(!defines(SCRIPT, Hook::PostRemove));
    }

    #[test]
    fn does_not_match_a_mere_mention() {
        // A call or comment must not count as a definition.
        let script = "# post_install is intentionally omitted\npre_install() { post_install; }\n";
        assert!(!defines(script, Hook::PostInstall));
        assert!(defines(script, Hook::PreInstall));
    }

    #[test]
    fn picks_the_right_hook_for_the_transaction() {
        assert_eq!(Hook::for_install(false, true), Hook::PreInstall);
        assert_eq!(Hook::for_install(false, false), Hook::PostInstall);
        assert_eq!(Hook::for_install(true, true), Hook::PreUpgrade);
        assert_eq!(Hook::for_install(true, false), Hook::PostUpgrade);
        assert!(Hook::PreInstall.is_pre());
        assert!(!Hook::PostInstall.is_pre());
    }

    #[test]
    fn install_command_passes_only_the_new_version() {
        let command = command(
            Path::new("/"),
            Path::new("tmp/s"),
            Hook::PostInstall,
            "1.2-1",
            None,
        );
        assert_eq!(command.get_program(), "bash");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let inline = args.last().unwrap();
        assert!(inline.contains("post_install '1.2-1'"), "{inline}");
        assert!(!inline.contains("''"), "no empty second argument: {inline}");
    }

    #[test]
    fn upgrade_command_passes_both_versions() {
        let command = command(
            Path::new("/"),
            Path::new("tmp/s"),
            Hook::PostUpgrade,
            "2.0-1",
            Some("1.0-1"),
        );
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        let inline = args.last().unwrap();
        // pacman's order is new then old.
        assert!(inline.contains("post_upgrade '2.0-1' '1.0-1'"), "{inline}");
    }

    #[test]
    fn a_non_root_install_runs_inside_a_chroot() {
        let command = command(
            Path::new("/mnt/target"),
            Path::new("tmp/s"),
            Hook::PostInstall,
            "1.0-1",
            None,
        );
        assert_eq!(command.get_program(), "chroot");
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(args[0], "/mnt/target");
        assert_eq!(args[1], "bash");
    }

    #[test]
    fn undefined_hook_is_skipped_without_running_anything() {
        let root = std::env::temp_dir().join("rvn-scriptlet-skip");
        std::fs::create_dir_all(&root).unwrap();
        let outcome = run(
            &root,
            "demo",
            b"post_install() { exit 1; }",
            Hook::PreRemove,
            "1.0-1",
            None,
        );
        assert!(matches!(outcome, Outcome::NotDefined));
    }

    #[test]
    fn a_defined_hook_runs_and_reports_failure() {
        // Executes for real against `/`, so keep the hooks trivial.
        let root = Path::new("/");

        let ok = run(
            root,
            "rvn-selftest-ok",
            b"post_install() { true; }",
            Hook::PostInstall,
            "1.0-1",
            None,
        );
        assert!(matches!(ok, Outcome::Ran), "{ok:?}");

        let bad = run(
            root,
            "rvn-selftest-bad",
            b"post_install() { echo 'boom' >&2; false; }",
            Hook::PostInstall,
            "1.0-1",
            None,
        );
        match bad {
            Outcome::Failed(message) => assert!(message.contains("boom"), "{message}"),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn the_new_version_reaches_the_hook() {
        let marker = std::env::temp_dir().join("rvn-scriptlet-version");
        let _ = std::fs::remove_file(&marker);
        let script = format!(
            "post_install() {{ printf '%s' \"$1\" > {}; }}",
            marker.display()
        );
        let outcome = run(
            Path::new("/"),
            "rvn-selftest-version",
            script.as_bytes(),
            Hook::PostInstall,
            "3.1-4",
            None,
        );
        assert!(matches!(outcome, Outcome::Ran), "{outcome:?}");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "3.1-4");
    }
}
