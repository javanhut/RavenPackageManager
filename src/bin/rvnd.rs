//! rvnd -- the package manager's privileged worker.
//!
//! Started by raven-init as root. Listens on /run/rvn/ctl, which members of
//! the `wheel` group can open, and runs `rvn --json --yes ...` on their
//! behalf for install, uninstall, update and sync. See `rvn::daemon`.
//!
//!   rvnd [--socket PATH] [--group NAME] [--rvn PATH]

use std::path::PathBuf;

fn main() {
    let mut config = rvn::daemon::ServerConfig {
        socket: PathBuf::from(rvn::daemon::SOCKET_PATH),
        group: Some(rvn::daemon::DEFAULT_GROUP.to_string()),
        rvn: PathBuf::from("/usr/bin/rvn"),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => config.socket = PathBuf::from(args.next().unwrap_or_default()),
            "--group" => {
                let g = args.next().unwrap_or_default();
                config.group = if g.is_empty() || g == "none" { None } else { Some(g) };
            }
            "--rvn" => config.rvn = PathBuf::from(args.next().unwrap_or_default()),
            "-h" | "--help" => {
                eprintln!("usage: rvnd [--socket PATH] [--group NAME|none] [--rvn PATH]");
                return;
            }
            other => {
                eprintln!("rvnd: unknown option {other}");
                std::process::exit(2);
            }
        }
    }
    if !rvn::ops::is_root() {
        eprintln!("rvnd: must run as root; it installs packages for the members of {}", config.group.as_deref().unwrap_or("its group"));
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
