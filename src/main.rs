use clap::{Arg, ArgAction, ArgMatches, Command};

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
        // Install package
        .subcommand(
            Command::new("install")
                .short_flag('i')
                .long_flag("install")
                .about("Installs a package")
                .arg(packages_arg("Package(s) to install")),
        )
        .subcommand(
            Command::new("uninstall")
                .short_flag('u')
                .long_flag("uninstall")
                .about("Uninstalls a package.")
                .arg(packages_arg("Package(s) to uninstall")),
        )
        .subcommand(
            Command::new("update")
                .long_flag("update")
                .about("Updates a package.")
                .arg(packages_arg("Package(s) to update")),
        )
        .subcommand(
            Command::new("find")
                .short_flag('f')
                .long_flag("find")
                .about("Finds a package in the package repository.")
                .arg(packages_arg("Package name(s) or search term(s)")),
        )
}

fn packages(matches: &ArgMatches) -> Vec<&str> {
    matches
        .get_many::<String>("packages")
        .unwrap_or_default()
        .map(String::as_str)
        .collect()
}

fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("install", sub)) => {
            println!("install: {}", packages(sub).join(" "));
        }
        Some(("uninstall", sub)) => {
            println!("uninstall: {}", packages(sub).join(" "));
        }
        Some(("update", sub)) => {
            println!("update: {}", packages(sub).join(" "));
        }
        Some(("find", sub)) => {
            println!("find: {}", packages(sub).join(" "));
        }
        _ => unreachable!("subcommand_required(true) guarantees a subcommand"),
    }
}
