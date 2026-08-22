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
                .long("noconfirm")
                .short('y')
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Answer every prompt affirmatively"),
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
                    Arg::new("recursive")
                        .long("recursive")
                        .short('r')
                        .action(ArgAction::SetTrue)
                        .help("Also remove dependencies that become orphaned"),
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
                ),
        )
        .subcommand(
            Command::new("sync")
                .short_flag('s')
                .about("Refreshes the repository databases."),
        )
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

    let mut ctx = Context::load(&config_path, Ui::new()).map_err(|e| e.to_string())?;
    ctx.repo_only = matches.get_flag("repo-only");
    ctx.assume_yes = matches.get_flag("yes");
    ctx.dry_run = sub.try_get_one::<bool>("dry-run").ok().flatten().copied() == Some(true);

    if ctx.repo_only {
        ctx.aur = rvn::aur::Aur::offline();
    }

    Ok(ctx)
}

fn main() -> ExitCode {
    let matches = cli().get_matches();

    let result = match matches.subcommand() {
        Some(("install", sub)) => build_context(&matches, sub).and_then(|mut ctx| {
            ops::install::run(&mut ctx, &packages(sub)).map(|outcome| {
                if outcome.installed.is_empty() && outcome.skipped.is_empty() {
                    ctx.ui.info("nothing to do");
                }
            })
        }),

        Some(("find", sub)) => build_context(&matches, sub).and_then(|ctx| {
            let limit: usize = sub
                .get_one::<String>("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(20);
            let query = packages(sub).join(" ");
            let hits = ops::search::run(&ctx, &query)?;
            if hits.is_empty() {
                ctx.ui.info(&format!("no packages match {query:?}"));
            } else {
                ops::search::print(&ctx, &hits, limit);
            }
            Ok(())
        }),

        Some(("sync", sub)) => build_context(&matches, sub).and_then(|mut ctx| {
            ctx.ui.banner(&format!("v{}", get_version()));
            ops::sync::refresh(&mut ctx).map(|n| {
                ctx.ui.ok(&format!("{n} repositories up to date"));
            })
        }),

        Some(("uninstall", sub)) => build_context(&matches, sub).and_then(|mut ctx| {
            let options = rvn::remove::Options {
                cascade: sub.get_flag("cascade"),
                recursive: sub.get_flag("recursive"),
                nodeps: sub.get_flag("nodeps"),
            };
            ops::remove::run(&mut ctx, &packages(sub), options).map(|_| ())
        }),

        Some(("update", sub)) => build_context(&matches, sub).and_then(|mut ctx| {
            let refresh = !sub.get_flag("no-refresh");
            ops::update::run(&mut ctx, &packages(sub), refresh).map(|_| ())
        }),

        _ => unreachable!("subcommand_required(true) guarantees a subcommand"),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            Ui::new().err(&message);
            ExitCode::FAILURE
        }
    }
}
