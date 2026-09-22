use clap::{Arg, ArgAction, ArgMatches, Command};
use rvn::ops::{self, Context};
use rvn::ui::Ui;
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_CONFIG: &str = "/etc/pacman.conf";

fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn packages_arg(help: &'static str) -> Arg {
    Arg::new("packages")
        .help(help)
        .required(true)
        .num_args(1..)
        .action(ArgAction::Append)
}

fn cli() -> Command {
    Command::new("rvn")
        .about("raven package manager utility")
        .version(get_version())
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("config")
                .long("config")
                .global(true)
                .value_name("PATH")
                .help("Path to pacman.conf")
                .default_value(DEFAULT_CONFIG),
        )
        .arg(
            Arg::new("repo-only")
                .long("repo-only")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Skip the AUR and use official repositories only"),
        )
        .arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Assume yes for every prompt"),
        )
        .arg(
            Arg::new("keep-cache")
                .long("keep-cache")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Keep downloaded packages instead of clearing them afterwards"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Emit machine-readable JSON events on stdout (for front-ends)"),
        )
        .arg(
            Arg::new("user")
                .long("user")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Install into your own prefix (~/.local/share/rvn/root), without root"),
        )
        .arg(
            Arg::new("no-sync")
                .long("no-sync")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Never refresh repository databases automatically"),
        )
        // Install package
        .subcommand(
            Command::new("install")
                .short_flag('i')
                .about("Installs a package")
                .arg(packages_arg("Package(s) to install"))
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Resolve and show the plan without changing anything"),
                ),
        )
        .subcommand(
            Command::new("uninstall")
                .short_flag('u')
                .about("Uninstalls a package.")
                .arg(packages_arg("Package(s) to uninstall"))
                .arg(
                    Arg::new("cascade")
                        .long("cascade")
                        .action(ArgAction::SetTrue)
                        .help("Also remove packages that depend on the targets"),
                )
                .arg(
                    Arg::new("keep-orphans")
                        .long("keep-orphans")
                        .action(ArgAction::SetTrue)
                        .help("Leave behind dependencies nothing needs any more"),
                )
                .arg(
                    Arg::new("remove-orphans")
                        .long("remove-orphans")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("keep-orphans")
                        .help("Remove orphaned dependencies without asking (needed with --yes)"),
                )
                .arg(
                    Arg::new("nodeps")
                        .long("nodeps")
                        .action(ArgAction::SetTrue)
                        .help("Remove even if it breaks other packages"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Show what would be removed without changing anything"),
                ),
        )
        .subcommand(
            Command::new("update")
                .about("Updates a package.")
                .arg(
                    Arg::new("packages")
                        .help("Package(s) to update; omit to update everything")
                        .num_args(0..)
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("no-refresh")
                        .long("no-refresh")
                        .action(ArgAction::SetTrue)
                        .help("Use the cached databases instead of syncing first"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Show available updates without applying them"),
                ),
        )
        .subcommand(
            Command::new("find")
                .short_flag('f')
                .about("Finds a package in the package repository.")
                .arg(packages_arg("Package name(s) or search term(s)"))
                .arg(
                    Arg::new("limit")
                        .long("limit")
                        .value_name("N")
                        .default_value("20")
                        .help("Maximum results to show"),
                )
                .arg(
                    Arg::new("no-select")
                        .long("no-select")
                        .action(ArgAction::SetTrue)
                        .help("Print results without offering to install them"),
                ),
        )
        .subcommand(
            Command::new("info")
                .about("Shows everything known about a package.")
                .arg(packages_arg("Package(s) to describe")),
        )
        .subcommand(
            Command::new("list")
                .short_flag('l')
                .about("Lists installed packages.")
                .arg(
                    Arg::new("orphans")
                        .long("orphans")
                        .action(ArgAction::SetTrue)
                        .help("Only dependencies nothing needs any more"),
                )
                .arg(
                    Arg::new("foreign")
                        .long("foreign")
                        .action(ArgAction::SetTrue)
                        .help("Only packages no repository carries (AUR or hand-built)"),
                )
                .arg(
                    Arg::new("explicit")
                        .long("explicit")
                        .action(ArgAction::SetTrue)
                        .help("Only packages installed by name"),
                ),
        )
        .subcommand(
            Command::new("owns")
                .short_flag('o')
                .about("Shows which package owns a file.")
                .arg(packages_arg("Path(s) to look up")),
        )
        .subcommand(
            Command::new("files")
                .about("Lists the files an installed package owns.")
                .arg(packages_arg("Package(s) to list")),
        )
        .subcommand(
            Command::new("sync")
                .short_flag('s')
                .about("Refreshes the repository databases."),
        )
        // Review the configuration files an upgrade left unmerged. Bare `rvn
        // config` lists them, because the first thing anyone wants after being
        // told there are three of them is to see which three.
        .subcommand(
            Command::new("config")
                .about("Reviews configuration files an upgrade did not replace (.pacnew).")
                .subcommand(Command::new("list").about("Shows every unmerged configuration file."))
                .subcommand(
                    Command::new("diff")
                        .about("Shows what the package's version would change.")
                        .arg(config_paths_arg()),
                )
                .subcommand(
                    Command::new("merge")
                        .about("Opens both versions in $EDITOR, or vimdiff.")
                        .arg(config_paths_arg()),
                )
                .subcommand(
                    Command::new("accept")
                        .about("Takes the package's version, saving the current one.")
                        .arg(config_paths_arg()),
                )
                .subcommand(
                    Command::new("keep")
                        .about("Discards the package's version and keeps the current one.")
                        .arg(config_paths_arg()),
                ),
        )
        // Bare `rvn cache` reports, because the question that makes somebody
        // type it is "what is in there", and answering it deletes nothing.
        // `clean` is the verb that removes files and it is never guessed at.
        .subcommand(
            Command::new("cache")
                .about("Reports what the package cache holds, and clears what is not needed.")
                .subcommand(
                    Command::new("status")
                        .about("Shows the size of the cache and what is taking it up."),
                )
                .subcommand(
                    Command::new("clean")
                        .about("Keeps the most recent versions of each package and deletes the rest.")
                        .arg(
                            Arg::new("keep")
                                .long("keep")
                                .value_name("N")
                                .default_value("2")
                                .help("Versions of each package to keep (the installed one always stays)"),
                        )
                        .arg(
                            Arg::new("builds")
                                .long("builds")
                                .action(ArgAction::SetTrue)
                                .help("Also delete the AUR build trees: checkouts, edits and downloaded sources"),
                        )
                        .arg(
                            Arg::new("dry-run")
                                .long("dry-run")
                                .action(ArgAction::SetTrue)
                                .help("Show what would be deleted without deleting anything"),
                        ),
                ),
        )
        // Turning a manifest into a package. Not routed through rvnd and not
        // a privileged operation at all: it reads a manifest, stages files
        // into a directory of its own and writes an archive. A build that
        // needed root would be a build that could not be run by the person
        // who wrote the manifest.
        .subcommand(
            Command::new("build")
                .about("Builds a package from a package.toml.")
                .arg(
                    Arg::new("manifests")
                        .help("package.toml file(s), or the directories holding them")
                        .required(true)
                        .num_args(1..)
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("outdir")
                        .long("outdir")
                        .value_name("DIR")
                        .help("Where the finished packages go (default: the working directory)"),
                )
                .arg(
                    Arg::new("no-build")
                        .long("no-build")
                        .action(ArgAction::SetTrue)
                        .help("Package a tree that is already built, rather than running [build]"),
                )
                .arg(
                    Arg::new("srcdir")
                        .long("srcdir")
                        .value_name("DIR")
                        .help("The built source tree the manifest's src paths are relative to"),
                )
                .arg(
                    Arg::new("repo")
                        .long("repo")
                        .value_name("NAME")
                        .help("Also rebuild NAME.db in the output directory"),
                )
                .arg(no_files_arg())
                .arg(sign_arg())
                .arg(no_sign_arg())
                .arg(key_arg()),
        )
        // Named after the tool it replaces, because somebody who has run a
        // repository before will look for exactly this word.
        .subcommand(
            Command::new("repo-add")
                .about("Builds a repository database from a directory of packages.")
                .arg(
                    Arg::new("directory")
                        .help("The directory holding the packages")
                        .required(true)
                        .num_args(1),
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_name("NAME")
                        .help("What to call the repository (default: the directory's name)"),
                )
                .arg(no_files_arg())
                .arg(sign_arg())
                .arg(no_sign_arg())
                .arg(key_arg()),
        )
        // Bare `rvn rollback` reports rather than acting, for the same reason
        // bare `rvn cache` does: the question that makes somebody type it is
        // "what can I go back to", and answering it changes nothing.
        .subcommand(
            Command::new("rollback")
                .about("Reinstalls the previous version of a package from the cache.")
                .arg(
                    Arg::new("packages")
                        .help("The package to roll back; omit to see what can be")
                        .num_args(0..=1)
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Show what would be reinstalled without reinstalling it"),
                ),
        )
        // Not a package operation, and here anyway. See `daemon::Op::Service`
        // for the argument: raven-init's control socket is root-only by
        // design, rvnd is already the root process that brokers verbs for
        // unprivileged front-ends, and a second daemon doing the same job for
        // a second socket would be two policies to keep in step.
        .subcommand(
            Command::new("service")
                .about("Turns one of this machine's own daemons on or off.")
                .long_about(
                    "Turns one of this machine's own daemons on or off.\n\n\
                     Only names a service this machine already ships a definition for, \
                     under /usr/share/raven/services or /etc/raven/init.d. `enable` \
                     starts it now and at every boot, which is what a switch in Raven \
                     Settings does; `start` is this boot only. `status` reads what \
                     raven-init publishes and needs no privilege at all.",
                )
                .arg(
                    Arg::new("action")
                        .help("enable, disable, start, stop, restart or status")
                        .required(true)
                        .value_parser([
                            "enable", "disable", "start", "stop", "restart", "status",
                        ]),
                )
                .arg(
                    Arg::new("service")
                        .help("The service, e.g. faced or fprintd")
                        .required(true),
                ),
        )
}

fn sign_arg() -> Arg {
    Arg::new("sign")
        .long("sign")
        .action(ArgAction::SetTrue)
        .help("Sign what is produced, failing if no key is configured")
}

fn no_sign_arg() -> Arg {
    Arg::new("no-sign")
        .long("no-sign")
        .action(ArgAction::SetTrue)
        .conflicts_with_all(["sign", "key"])
        .help("Do not sign, even though a key is configured")
}

fn key_arg() -> Arg {
    Arg::new("key")
        .long("key")
        .value_name("KEY")
        .help("A gpg key id, or the path to a secret key file; implies --sign")
}

/// The opt-out for the `<repo>.files` database.
///
/// Phrased as an opt-out because `repo-add` writes both databases and a
/// repository missing one of them is the odd one out. See
/// [`rvn::repodb::Files`] for the case where skipping it is the right call.
fn no_files_arg() -> Arg {
    Arg::new("no-files")
        .long("no-files")
        .action(ArgAction::SetTrue)
        .help("Skip NAME.files, the database `pacman -F` reads")
}

/// Whether this run writes the file-list database.
fn files(sub: &ArgMatches) -> rvn::repodb::Files {
    if sub.get_flag("no-files") {
        rvn::repodb::Files::Skip
    } else {
        rvn::repodb::Files::Write
    }
}

/// Which signing rule the flags add up to.
///
/// Signing when a key is configured and nothing was said is deliberate, and
/// it is the same reading the rest of the crate gives a configuration file it
/// finds: somebody who wrote down a signing key wrote down that packages from
/// this machine are signed, and quietly producing unsigned ones would ignore
/// it. `--no-sign` is how that is overridden for one run.
fn signing(sub: &ArgMatches) -> ops::build::Signing {
    if sub.get_flag("no-sign") {
        return ops::build::Signing::Never;
    }
    if let Some(key) = sub.get_one::<String>("key") {
        return ops::build::Signing::Key(key.clone());
    }
    if sub.get_flag("sign") {
        return ops::build::Signing::Required;
    }
    ops::build::Signing::Configured
}

/// The files a `rvn config` verb should act on; all of them when none are
/// named, which is how a review of a machine nobody has looked at starts.
fn config_paths_arg() -> Arg {
    Arg::new("paths")
        .help("File(s) to act on; omit for every one waiting")
        .num_args(0..)
        .action(ArgAction::Append)
}

/// `rvn service`: read what raven-init publishes, or ask somebody with the
/// privilege to change it.
///
/// Three paths, and which one is taken is decided by what the request needs
/// rather than by a flag:
///
///   * `status` reads `/run/raven-init/services/NAME`, which raven-init
///     writes mode 0644 exactly so that this question does not need root.
///     No daemon, no prompt, no socket.
///   * As root -- `sudo rvn service`, or an image build -- the work is done
///     here, against raven-init's own socket.
///   * Otherwise it goes to rvnd, which does the same work and asks the
///     human first if the policy says to. This is the path Raven Settings
///     takes, through `rvn --json`, exactly as Raven Store takes it for an
///     install.
fn service_command(matches: &ArgMatches, action: &str, name: &str) -> Result<(), String> {
    use rvn::daemon::{Reach, Replay, ServiceAction, reach, request, SOCKET_PATH};

    let json = matches.get_flag("json");

    // Checked here as well as in rvnd, which checks everything that reaches
    // it. This one is for the person: a name with a slash or a space in it
    // gets a sentence about the name, rather than a round trip and whatever
    // the daemon makes of it.
    if !rvn::initctl::valid_service_name(name) {
        return Err(format!("refusing service name {name:?}"));
    }

    if action == "status" {
        let path = std::path::Path::new(rvn::initctl::STATUS_DIR)
            .join("services")
            .join(name);
        let text = std::fs::read_to_string(&path).map_err(|_| {
            format!(
                "raven-init says nothing about '{name}'; `rvn service status` reads {}",
                path.display()
            )
        })?;
        if json {
            Ui::json().emit("service", serde_json::json!({ "service": name, "status": text }));
        } else {
            print!("{text}");
        }
        return Ok(());
    }

    let action = match action {
        "enable" => ServiceAction::Enable,
        "disable" => ServiceAction::Disable,
        "start" => ServiceAction::Start,
        "stop" => ServiceAction::Stop,
        "restart" => ServiceAction::Restart,
        other => return Err(format!("no such action '{other}'")),
    };

    if ops::is_root() {
        let ui = if json { Ui::json() } else { Ui::new() };
        let mut failure = None;
        rvn::daemon::run_service(action, name, &mut |kind, message| match kind {
            "failed" => failure = Some(message),
            "info" => ui.info(&message),
            _ => ui.ok(&message),
        });
        return match failure {
            Some(message) => Err(message),
            None => Ok(()),
        };
    }

    let socket_override = std::env::var("RVN_SOCKET").ok();
    let socket = std::path::Path::new(socket_override.as_deref().unwrap_or(SOCKET_PATH));
    match reach(socket) {
        Reach::Ok => {}
        // Unlike an install, there is no in-process fallback to warn about
        // and fall through to: changing a service needs a privileged channel
        // to PID 1, and an unprivileged rvn has none.
        Reach::Absent => {
            return Err(
                "rvnd is not running, so services cannot be changed from here: start it with `sudo raven-rc start rvnd`, or use `sudo raven-rc` in a terminal"
                    .into(),
            );
        }
        Reach::Denied => {
            return Err(format!(
                "not allowed to use rvnd: {} is for members of the {} group; use sudo, or add yourself to the group and log in again",
                SOCKET_PATH,
                rvn::daemon::DEFAULT_GROUP
            ));
        }
        Reach::Other(e) => return Err(format!("rvnd: {e}")),
    }

    let req = rvn::daemon::Request {
        op: Some(rvn::daemon::Op::Service),
        service: Some(name.to_string()),
        action: Some(action),
        ..Default::default()
    };

    if json {
        return request(socket, &req, |line| println!("{line}"));
    }
    let ui = Ui::new();
    let mut replay = Replay::new(&ui, false);
    let result = request(socket, &req, |line| replay.event(line));
    replay.finish();
    result
}

/// Run a privileged operation through rvnd when this process is not root.
///
/// Returns `None` when the operation should run in-process as before: we are
/// root, the caller chose a configuration file of their own (the daemon only
/// ever uses the system's), or there is no daemon to talk to. In the last
/// case the in-process path fails the way it always has, and the hint about
/// the daemon is printed first so the failure explains itself.
///
/// Terminal use is two phases: the daemon runs the operation with
/// `--dry-run` and the plan is shown; then, once the person says yes, it runs
/// for real. Nothing on the wire is interactive, so the question is asked
/// here. `--yes` skips the first phase; `--dry-run` skips the second. In
/// `--json` mode the events are relayed verbatim and there is one phase, as
/// there always was for a front-end.
fn via_daemon(matches: &ArgMatches, sub: &ArgMatches, mut req: rvn::daemon::Request) -> Option<Result<(), String>> {
    use rvn::daemon::{Reach, reach, request, Replay, SOCKET_PATH};

    if ops::is_root() || matches.get_flag("user") {
        return None;
    }
    if matches
        .get_one::<String>("config")
        .is_some_and(|c| c != DEFAULT_CONFIG)
    {
        return None;
    }
    // RVN_SOCKET points a client at another daemon; for development and for
    // tests, which run a stand-in on a temporary socket.
    let socket_override = std::env::var("RVN_SOCKET").ok();
    let socket = std::path::Path::new(socket_override.as_deref().unwrap_or(SOCKET_PATH));
    let json = matches.get_flag("json");
    match reach(socket) {
        Reach::Ok => {}
        Reach::Absent => {
            // In a terminal this is a warning and the in-process path goes
            // on to fail at the first write, with root's advice printed
            // first. A front-end reading JSON has no terminal to read that
            // warning on, so it gets the same advice as the failure itself
            // rather than a later, worse one about a read-only database.
            if json {
                return Some(Err(
                    "rvnd is not running, so installing needs root: start it with `sudo raven-rc start rvnd`, or use `sudo rvn` in a terminal".into(),
                ));
            }
            Ui::new().warn("rvnd is not running, so this needs root: `sudo rvn ...`, or `sudo raven-rc start rvnd`");
            return None;
        }
        Reach::Denied => {
            let msg = format!(
                "not allowed to use rvnd: {} is for members of the {} group; use sudo, or add yourself to the group and log in again",
                SOCKET_PATH,
                rvn::daemon::DEFAULT_GROUP
            );
            return Some(Err(msg));
        }
        Reach::Other(e) => return Some(Err(format!("rvnd: {e}"))),
    }

    req.repo_only = matches.get_flag("repo-only");
    req.keep_cache = matches.get_flag("keep-cache");
    req.no_sync = matches.get_flag("no-sync");
    let dry_run_asked = sub.try_get_one::<bool>("dry-run").ok().flatten().copied() == Some(true);
    let assume_yes = matches.get_flag("yes") || json;

    if json {
        req.dry_run = dry_run_asked;
        return Some(request(socket, &req, |line| println!("{line}")));
    }

    let ui = Ui::new();
    let run = |req: &rvn::daemon::Request, show_banner: bool| -> Result<(), String> {
        let mut replay = Replay::new(&ui, show_banner);
        let result = request(socket, req, |line| replay.event(line));
        replay.finish();
        result
    };

    // Phase one: the plan. Skipped when the answer is already yes, and the
    // only phase when only the plan was asked for. `sync` has no plan.
    let needs_plan = req.op != Some(rvn::daemon::Op::Sync) && (dry_run_asked || !assume_yes);
    if needs_plan {
        req.dry_run = true;
        if let Err(e) = run(&req, true) {
            return Some(Err(e));
        }
        if dry_run_asked {
            return Some(Ok(()));
        }
        // Yes, except for a rollback. Every other question here confirms the
        // thing the person typed, so the default is the answer they have
        // already given; a rollback is a downgrade, which is the direction
        // that surprises people, and `ops::rollback` defaults its own
        // confirmation to no for that reason. Running it through rvnd must
        // not quietly turn that no into a yes.
        let default = req.op != Some(rvn::daemon::Op::Rollback);
        if !ui.confirm("proceed?", default) {
            return Some(Err("cancelled".into()));
        }
    }
    req.dry_run = false;
    Some(run(&req, !needs_plan))
}

fn packages(matches: &ArgMatches) -> Vec<String> {
    matches
        .get_many::<String>("packages")
        .unwrap_or_default()
        .cloned()
        .collect()
}

fn build_context(matches: &ArgMatches, sub: &ArgMatches) -> Result<Context, String> {
    let config_path = PathBuf::from(
        matches
            .get_one::<String>("config")
            .cloned()
            .unwrap_or_else(|| DEFAULT_CONFIG.to_string()),
    );

    let ui = if matches.get_flag("json") {
        Ui::json()
    } else {
        Ui::new()
    };
    let mut ctx = if matches.get_flag("user") {
        // The system configuration for repositories and keys; the user's own
        // directories for everything written.
        let mut config = rvn::config::Config::load(&config_path)
            .map_err(|e| format!("{}: {e}", config_path.display()))?;
        let prefix = rvn::config::UserPrefix::from_env()
            .ok_or("--user needs HOME to be set")?;
        config.use_prefix(&prefix).map_err(|e| format!("cannot create the user prefix: {e}"))?;
        let mut ctx = Context::from_config(config, ui);
        ctx.user_prefix = Some(prefix);
        ctx
    } else {
        Context::load(&config_path, ui).map_err(|e| e.to_string())?
    };
    ctx.repo_only = matches.get_flag("repo-only");
    ctx.assume_yes = matches.get_flag("yes");
    ctx.keep_cache = matches.get_flag("keep-cache");
    ctx.auto_sync = !matches.get_flag("no-sync");
    ctx.dry_run = sub.try_get_one::<bool>("dry-run").ok().flatten().copied() == Some(true);

    if ctx.repo_only {
        ctx.aur = rvn::aur::Aur::offline();
    }

    Ok(ctx)
}

fn main() -> ExitCode {
    let matches = cli().get_matches();

    let result = match matches.subcommand() {
        Some(("install", sub)) => via_daemon(
            &matches,
            sub,
            rvn::daemon::Request {
                op: Some(rvn::daemon::Op::Install),
                packages: packages(sub),
                ..Default::default()
            },
        )
        .unwrap_or_else(|| {
            build_context(&matches, sub).and_then(|mut ctx| {
                ops::install::run(&mut ctx, &packages(sub)).map(|outcome| {
                    if outcome.installed.is_empty() && outcome.skipped.is_empty() {
                        ctx.ui.info("nothing to do");
                    }
                })
            })
        }),

        Some(("find", sub)) => build_context(&matches, sub).and_then(|mut ctx| {
            let limit: usize = sub
                .get_one::<String>("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(20);
            let query = packages(sub).join(" ");
            let hits = ops::search::run(&ctx, &query)?;

            if ctx.ui.is_json() {
                let results: Vec<serde_json::Value> = hits
                    .iter()
                    .take(limit)
                    .map(|h| {
                        let mut v = rvn::ui::json::package(&h.package);
                        v["installed_version"] = serde_json::json!(h.installed_version);
                        v["upgradable"] = serde_json::Value::Bool(h.upgradable);
                        v
                    })
                    .collect();
                ctx.ui.emit(
                    "results",
                    serde_json::json!({ "query": query, "results": results, "total": hits.len() }),
                );
                return Ok(());
            }

            if hits.is_empty() {
                ctx.ui.info(&format!("no packages match {query:?}"));
                return Ok(());
            }

            // Offering the results as a numbered menu turns a search into an
            // install without retyping a package name.
            let selectable = ctx.ui.style.interactive && !ctx.assume_yes && !sub.get_flag("no-select");
            ops::search::print_numbered(&ctx, &hits, limit, selectable);

            if !selectable {
                return Ok(());
            }

            let shown = hits.len().min(limit);
            let answer = ctx
                .ui
                .prompt("install which? (e.g. 1 3, 2-4, ^2, blank to skip)");
            let chosen = ops::search::parse_selection(&answer, shown);
            if chosen.is_empty() {
                return Ok(());
            }

            let targets: Vec<String> = chosen
                .iter()
                .map(|n| hits[n - 1].package.name.clone())
                .collect();
            if let Some(result) = via_daemon(
                &matches,
                sub,
                rvn::daemon::Request {
                    op: Some(rvn::daemon::Op::Install),
                    packages: targets.clone(),
                    ..Default::default()
                },
            ) {
                return result;
            }
            ops::install::run(&mut ctx, &targets).map(|_| ())
        }),

        Some(("info", sub)) => build_context(&matches, sub).and_then(|ctx| {
            if !ctx.ui.is_json() {
                return ops::query::info(&ctx, &packages(sub));
            }
            let mut missing = Vec::new();
            let mut found = Vec::new();
            for name in packages(sub) {
                match ops::query::locate(&ctx, &name) {
                    Some(pkg) => {
                        let mut v = rvn::ui::json::package(&pkg);
                        v["installed_version"] =
                            serde_json::json!(ctx.local.get(&name).map(|p| p.version.clone()));
                        v["required_by"] = serde_json::json!(
                            ctx.local
                                .packages
                                .values()
                                .filter(|p| p.depends.iter().any(|d| pkg.satisfies(d)))
                                .map(|p| p.name.clone())
                                .collect::<Vec<_>>()
                        );
                        found.push(v);
                    }
                    None => missing.push(name),
                }
            }
            ctx.ui
                .emit("packages", serde_json::json!({ "packages": found, "missing": missing }));
            if !missing.is_empty() {
                return Err(format!("no package named {}", missing.join(", ")));
            }
            Ok(())
        }),

        Some(("list", sub)) => build_context(&matches, sub).and_then(|ctx| {
            let filter = rvn::ops::query::ListFilter {
                orphans: sub.get_flag("orphans"),
                foreign: sub.get_flag("foreign"),
                explicit: sub.get_flag("explicit"),
            };
            if ctx.ui.is_json() {
                let installed: Vec<serde_json::Value> = ops::query::installed(&ctx, filter)
                    .into_iter()
                    .map(|pkg| {
                        let mut v = rvn::ui::json::package(pkg);
                        v["aur"] = serde_json::Value::Bool(ops::query::is_foreign(&ctx, pkg));
                        v["explicit"] = serde_json::Value::Bool(
                            pkg.install_reason == rvn::pkg::InstallReason::Explicit,
                        );
                        v
                    })
                    .collect();
                ctx.ui.emit("installed", serde_json::json!({ "packages": installed }));
                return Ok(());
            }
            let count = ops::query::list(&ctx, filter)?;
            if count == 0 {
                ctx.ui.info("nothing matches");
            }
            Ok(())
        }),

        Some(("owns", sub)) => {
            build_context(&matches, sub).and_then(|ctx| ops::query::owns(&ctx, &packages(sub)))
        }

        Some(("files", sub)) => {
            build_context(&matches, sub).and_then(|ctx| ops::query::files(&ctx, &packages(sub)))
        }

        Some(("sync", sub)) => via_daemon(
            &matches,
            sub,
            rvn::daemon::Request {
                op: Some(rvn::daemon::Op::Sync),
                ..Default::default()
            },
        )
        .unwrap_or_else(|| {
            build_context(&matches, sub).and_then(|mut ctx| {
                ctx.ui.banner(&format!("v{}", get_version()));
                ops::sync::refresh(&mut ctx).map(|n| {
                    ctx.ui.ok(&format!("{n} repositories up to date"));
                })
            })
        }),

        Some(("uninstall", sub)) => via_daemon(
            &matches,
            sub,
            rvn::daemon::Request {
                op: Some(rvn::daemon::Op::Uninstall),
                packages: packages(sub),
                cascade: sub.get_flag("cascade"),
                keep_orphans: sub.get_flag("keep-orphans"),
                remove_orphans: sub.get_flag("remove-orphans"),
                nodeps: sub.get_flag("nodeps"),
                ..Default::default()
            },
        )
        .unwrap_or_else(|| {
            build_context(&matches, sub).and_then(|mut ctx| {
                // Removing a package should not leave its dependencies behind,
                // so orphan cleanup is the default rather than a flag to remember.
                // Under --yes it also needs --remove-orphans; see ops::remove.
                let options = rvn::remove::Options {
                    cascade: sub.get_flag("cascade"),
                    recursive: !sub.get_flag("keep-orphans"),
                    nodeps: sub.get_flag("nodeps"),
                    remove_orphans: sub.get_flag("remove-orphans"),
                };
                ops::remove::run(&mut ctx, &packages(sub), options).map(|_| ())
            })
        }),

        Some(("update", sub)) => via_daemon(
            &matches,
            sub,
            rvn::daemon::Request {
                op: Some(rvn::daemon::Op::Update),
                packages: packages(sub),
                no_refresh: sub.get_flag("no-refresh"),
                ..Default::default()
            },
        )
        .unwrap_or_else(|| {
            build_context(&matches, sub).and_then(|mut ctx| {
                let refresh = !sub.get_flag("no-refresh");
                ops::update::run(&mut ctx, &packages(sub), refresh).map(|_| ())
            })
        }),

        // Never through rvnd: `list` and `diff` read files anyone may read and
        // must not need a daemon at all, and the three that write are asking
        // an administrator a question about their own /etc. When that question
        // needs root it says so and names sudo, rather than handing the daemon
        // a file path and a verb that overwrite configuration.
        Some(("config", sub)) => {
            let (verb, args) = match sub.subcommand() {
                Some((verb, args)) => (verb, Some(args)),
                None => ("list", None),
            };
            match ops::config::Action::parse(verb) {
                None => Err(format!("rvn config has no `{verb}`")),
                Some(action) => {
                    // try_get_many, not get_many: `list` declares no paths at
                    // all, and asking a subcommand for an argument it never
                    // defined is a panic rather than an empty answer. Same
                    // reason build_context reaches for --dry-run that way.
                    let paths: Vec<String> = args
                        .and_then(|a| a.try_get_many::<String>("paths").ok().flatten())
                        .unwrap_or_default()
                        .cloned()
                        .collect();
                    build_context(&matches, args.unwrap_or(sub))
                        .and_then(|mut ctx| ops::config::run(&mut ctx, action, &paths))
                }
            }
        }

        // Never through rvnd either, and for the same reason as `config`:
        // `status` reads directories anybody may read, and `clean` is an
        // administrator deciding what to delete from their own disk rather
        // than a package operation the daemon exists to carry out. When it
        // needs root it says so and names sudo.
        Some(("cache", sub)) => {
            let (verb, args) = match sub.subcommand() {
                Some((verb, args)) => (verb, Some(args)),
                None => ("status", None),
            };
            // A `--keep` that is not a number is a mistake worth stopping for:
            // falling back to the default would delete more than the person
            // asked to keep, and they would not find out until it was gone.
            // try_get_one, not get_one: `status` declares neither --keep nor
            // --builds, and asking a subcommand for an argument it never
            // defined is a panic rather than an empty answer. Same reason
            // build_context reaches for --dry-run that way.
            let keep = match args.and_then(|a| a.try_get_one::<String>("keep").ok().flatten()) {
                Some(raw) => raw
                    .parse::<usize>()
                    .map_err(|_| format!("--keep wants a number of versions, not {raw:?}")),
                None => Ok(rvn::cache::DEFAULT_KEEP),
            };
            match (ops::cache::Action::parse(verb), keep) {
                (None, _) => Err(format!("rvn cache has no `{verb}`")),
                (_, Err(message)) => Err(message),
                (Some(action), Ok(keep)) => {
                    let options = ops::cache::Options {
                        keep,
                        builds: args.is_some_and(|a| {
                            a.try_get_one::<bool>("builds").ok().flatten().copied() == Some(true)
                        }),
                    };
                    build_context(&matches, args.unwrap_or(sub))
                        .and_then(|mut ctx| ops::cache::run(&mut ctx, action, &options))
                }
            }
        }

        // Never through rvnd: building a package needs no root, and a daemon
        // that ran arbitrary `[build]` commands as root on request would undo
        // everything the AUR build path (ops::install::build_command) exists
        // to prevent.
        Some(("build", sub)) => {
            let options = ops::build::Options {
                outdir: sub
                    .get_one::<String>("outdir")
                    .map(PathBuf::from)
                    .unwrap_or_default(),
                run_build: !sub.get_flag("no-build"),
                source_dir: sub.get_one::<String>("srcdir").map(PathBuf::from),
                repo: sub.get_one::<String>("repo").cloned(),
                signing: signing(sub),
                files: files(sub),
            };
            let manifests: Vec<String> = sub
                .get_many::<String>("manifests")
                .unwrap_or_default()
                .cloned()
                .collect();
            build_context(&matches, sub)
                .and_then(|mut ctx| ops::build::run(&mut ctx, &manifests, &options))
        }

        Some(("repo-add", sub)) => {
            let directory = PathBuf::from(
                sub.get_one::<String>("directory")
                    .expect("clap requires the directory"),
            );
            let name = sub.get_one::<String>("name").cloned();
            let signing = signing(sub);
            let files = files(sub);
            build_context(&matches, sub).and_then(|mut ctx| {
                ops::build::repo_add(&mut ctx, &directory, name.as_deref(), &signing, files)
            })
        }

        // Rolling back writes to the install root, so it goes through rvnd
        // like every other privileged operation and is audited the same way;
        // `rvn::policy::Class::of` explains why it is classed `repo`.
        //
        // Only the named form does. Bare `rvn rollback` reports what could be
        // rolled back, which is reading two world-readable databases: sending
        // it to the daemon would put an authorization prompt in front of a
        // question, and hold rvnd's transaction lock to answer it.
        Some(("rollback", sub)) => {
            let package = sub
                .get_many::<String>("packages")
                .unwrap_or_default()
                .next()
                .cloned();
            let daemon = package.clone().and_then(|package| {
                via_daemon(
                    &matches,
                    sub,
                    rvn::daemon::Request {
                        op: Some(rvn::daemon::Op::Rollback),
                        packages: vec![package],
                        ..Default::default()
                    },
                )
            });
            daemon.unwrap_or_else(|| {
                build_context(&matches, sub)
                    .and_then(|mut ctx| ops::rollback::run(&mut ctx, package.as_deref()))
            })
        }

        Some(("service", sub)) => {
            let action = sub
                .get_one::<String>("action")
                .expect("required")
                .to_string();
            let name = sub
                .get_one::<String>("service")
                .expect("required")
                .to_string();
            service_command(&matches, &action, &name)
        }

        _ => unreachable!("subcommand_required(true) guarantees a subcommand"),
    };

    match result {
        Ok(()) => {
            if matches.get_flag("json") {
                Ui::json().emit("done", serde_json::json!({}));
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            if matches.get_flag("json") {
                Ui::json().emit("failed", serde_json::json!({ "message": message }));
            } else {
                Ui::new().err(&message);
            }
            ExitCode::FAILURE
        }
    }
}
