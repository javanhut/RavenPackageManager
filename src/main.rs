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

    if ops::is_root() {
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
            if !json {
                Ui::new().warn("rvnd is not running, so this needs root: `sudo rvn ...`, or `sudo raven-rc start rvnd`");
            }
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
        if !ui.confirm("proceed?", true) {
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
    let mut ctx = Context::load(&config_path, ui).map_err(|e| e.to_string())?;
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
                nodeps: sub.get_flag("nodeps"),
                ..Default::default()
            },
        )
        .unwrap_or_else(|| {
            build_context(&matches, sub).and_then(|mut ctx| {
                // Removing a package should not leave its dependencies behind,
                // so orphan cleanup is the default rather than a flag to remember.
                let options = rvn::remove::Options {
                    cascade: sub.get_flag("cascade"),
                    recursive: !sub.get_flag("keep-orphans"),
                    nodeps: sub.get_flag("nodeps"),
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
