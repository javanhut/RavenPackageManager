//! rvnd -- the package manager's privileged worker.
//!
//! Started by raven-init as root. Listens on /run/rvn/ctl, which members of
//! the `wheel` group can open, and runs `rvn --json --yes ...` on their
//! behalf for install, uninstall, update and sync. Which of those need the
//! human who asked to agree to them first is `/etc/raven/rvnd.toml`; every
//! request, permitted or refused, is written to
//! /var/log/raven/rvnd-audit.log. See
//! `rvn::daemon`, and `rvn::policy` for the file.
//!
//!   rvnd [--socket PATH] [--group NAME] [--rvn PATH] [--policy PATH]
//!   rvnd --print-policy

use std::path::PathBuf;

fn main() {
    let mut policy_path = PathBuf::from(rvn::policy::DEFAULT_PATH);
    let mut socket = PathBuf::from(rvn::daemon::SOCKET_PATH);
    let mut group = Some(rvn::daemon::DEFAULT_GROUP.to_string());
    let mut rvn_binary = sibling_rvn(std::env::current_exe().ok());

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => socket = PathBuf::from(args.next().unwrap_or_default()),
            "--group" => {
                let g = args.next().unwrap_or_default();
                group = if g.is_empty() || g == "none" {
                    None
                } else {
                    Some(g)
                };
            }
            "--rvn" => rvn_binary = PathBuf::from(args.next().unwrap_or_default()),
            "--policy" => policy_path = PathBuf::from(args.next().unwrap_or_default()),
            // Writes the shipped policy file, comments and all, so that
            // `rvnd --print-policy | sudo tee /etc/raven/rvnd.toml` gets an
            // administrator a copy to edit that matches the rvnd they are
            // actually running. It needs no root and touches nothing.
            "--print-policy" => {
                print!("{}", rvn::policy::DEFAULT_FILE);
                return;
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: rvnd [--socket PATH] [--group NAME|none] [--rvn PATH] [--policy PATH]\n       rvnd --print-policy"
                );
                return;
            }
            other => {
                eprintln!("rvnd: unknown option {other}");
                std::process::exit(2);
            }
        }
    }

    // Read before the root check and before the socket exists, so that a
    // policy file with a typo in it is reported as a policy file with a typo
    // in it rather than as a daemon that started and then behaved in a way
    // nobody could account for. A file that is present and does not parse
    // stops rvnd: falling back to the defaults would quietly ignore a policy
    // somebody wrote down and believed.
    let policy = match rvn::policy::Policy::load(&policy_path) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("rvnd: {e}");
            std::process::exit(1);
        }
    };

    let config = rvn::daemon::ServerConfig {
        socket,
        group,
        rvn: rvn_binary,
        policy,
    };

    if !rvn::ops::is_root() {
        eprintln!(
            "rvnd: must run as root; it installs packages for the members of {}",
            config.group.as_deref().unwrap_or("its group")
        );
        std::process::exit(1);
    }
    let listener = match rvn::daemon::bind(&config) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("rvnd: cannot bind {}: {e}", config.socket.display());
            std::process::exit(1);
        }
    };
    rvn::daemon::serve(config, listener);
}

/// The rvn installed beside this rvnd, falling back to `/usr/bin/rvn`.
///
/// A fixed `/usr/bin/rvn` meant an rvnd installed to /usr/local by
/// `imlazy install` still ran the packaged rvn, so every fix to the
/// transaction code reached a terminal and never the Store. The two are
/// built together and belong together.
fn sibling_rvn(exe: Option<PathBuf>) -> PathBuf {
    exe.and_then(|exe| exe.parent().map(|dir| dir.join("rvn")))
        .filter(|rvn| rvn.is_file())
        .unwrap_or_else(|| PathBuf::from("/usr/bin/rvn"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rvnd_runs_the_rvn_beside_it() {
        let dir = std::env::temp_dir().join("rvnd-sibling");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rvn"), b"").unwrap();
        assert_eq!(sibling_rvn(Some(dir.join("rvnd"))), dir.join("rvn"));
    }

    #[test]
    fn without_a_sibling_it_falls_back_to_the_packaged_rvn() {
        let dir = std::env::temp_dir().join("rvnd-no-sibling");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            sibling_rvn(Some(dir.join("rvnd"))),
            PathBuf::from("/usr/bin/rvn")
        );
        assert_eq!(sibling_rvn(None), PathBuf::from("/usr/bin/rvn"));
    }
}
