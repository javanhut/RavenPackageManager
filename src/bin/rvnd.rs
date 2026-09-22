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
    let mut rvn_binary = PathBuf::from("/usr/bin/rvn");

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
