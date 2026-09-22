//! The privilege boundary: `rvnd`, and the client side of it in `rvn`.
//!
//! Installing a package needs root. Until now that meant `sudo rvn`, which
//! meant a password for every install, a graphical store that shelled out to
//! sudo, and builds that ran as root because the whole command did. This
//! module is the alternative: one small daemon, started by raven-init, that
//! listens on a socket only members of one group can open, and runs the
//! existing `rvn --json --yes ...` as root on their behalf with the client's
//! connection as its stdout. The client -- an unprivileged `rvn`, or Raven
//! Store -- sends one request line and reads the same event stream `--json`
//! has always produced.
//!
//! What crosses the boundary is deliberately small: an operation name, a
//! package list, and a handful of flags, all validated here before anything
//! is spawned. The configuration file is never the client's to choose; the
//! daemon runs with the system's. AUR packages are built by a dedicated
//! unprivileged account rather than by root; see `build_identity` in
//! `ops::install`.
//!
//! The group is `wheel` by default. Installing packages is root-equivalent
//! (scriptlets run as root), so the group has to be the administrators'
//! group; what this buys is one door instead of a sudo call in every
//! front-end, not less power.
//!
//! # Who may ask, and whether they are asked back
//!
//! For a long time the socket's mode was the whole of the access control, and
//! this comment said so. It was not enough. On a desktop where the one human
//! is in `wheel`, "any process running as a member of wheel" means the web
//! browser, and anything the browser is running, and the postinstall script
//! of the last npm package anybody installed -- each of which could ask this
//! daemon to build an arbitrary PKGBUILD and run its scriptlets as root, with
//! no prompt and no record.
//!
//! So there are now three things in front of a request rather than one.
//!
//!   1. The socket mode, unchanged: the kernel refuses the `connect`.
//!   2. An explicit check that the peer's account is in the group the socket
//!      belongs to. It can only ever refuse what the kernel already let
//!      through -- see `peer_is_in_group` -- and it is here so that the
//!      policy is legible in the code rather than implied by a chmod.
//!   3. The policy in `/etc/raven/rvnd.toml`, read by `policy`, which says
//!      which classes of operation need the human who owns the requesting
//!      session to agree to them. `auth` asks ravend to put that question in
//!      front of them, and remembers the answer for a few minutes the way
//!      sudo does.
//!
//! Every privileged request is written to `/var/log/raven/rvnd-audit.log` by
//! `audit`, with the uid, the pid, what that pid was executing and the
//! package list, whether it was permitted or refused. Nothing else on the
//! machine records what asked for root.
//!
//! The decision happens after `Request::validate` and before the BUSY lock,
//! so that a refusal is a reply on a socket whose request has been read --
//! see the comment on `BUSY` for why that ordering is not optional.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Where rvnd listens. The directory is created by the daemon, mode 0755;
/// the socket inside it is what the group setting applies to.
pub const SOCKET_DIR: &str = "/run/rvn";
pub const SOCKET_PATH: &str = "/run/rvn/ctl";
/// The group whose members may install, remove and update packages.
pub const DEFAULT_GROUP: &str = "wheel";

/// The operations the daemon will run. Everything else rvn does is reading
/// world-readable databases and needs no daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Install,
    Uninstall,
    Update,
    Sync,
    /// Putting one package back to the version before it, from an archive
    /// already in the cache. It is here for the same reason the others are:
    /// it writes to the install root, so without it `rvn rollback` is a
    /// command people reach root for with `sudo` and no audit line is written
    /// about it.
    Rollback,
    /// Turning one of the machine's own daemons on or off.
    ///
    /// The odd one out here, and worth the paragraph: it installs nothing and
    /// never runs rvn at all. It is on this socket because of what it needs
    /// and who needs it. raven-init's control socket is mode 0600 and must
    /// stay that way -- `control.rs` is explicit that an unprivileged session
    /// holding a channel into PID 1 is the thing it must never allow -- so
    /// turning a daemon on has always meant `sudo raven-rc`, typed in a
    /// terminal, by somebody who knew that was the answer.
    ///
    /// That was the whole of how face unlock and the fingerprint reader got
    /// switched on. Raven Settings could see the camera, could see the
    /// binary, and could do nothing but print the command. This daemon
    /// already is what that situation needs: a root process that holds a
    /// privileged channel, checks the peer's group, asks the human through
    /// ravend, and writes down what it did. Adding a second daemon to do the
    /// same four things for a different socket would be two policies to keep
    /// in agreement.
    ///
    /// What it can reach is bounded and fixed: a name is refused unless a
    /// root-owned service definition of that name already exists, either as a
    /// template a package shipped under /usr/share/raven/services or as a
    /// drop-in under /etc/raven/init.d. There is no field here that names a
    /// program, and nothing a client sends becomes one.
    Service,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Install => "install",
            Op::Uninstall => "uninstall",
            Op::Update => "update",
            Op::Sync => "sync",
            Op::Rollback => "rollback",
            Op::Service => "service",
        }
    }
}

/// What to do to a service, for [`Op::Service`].
///
/// Five verbs and not raven-init's full set, because these are the five a
/// settings panel has a switch for. There is no `reload`: reloading is how
/// several of these are carried out, which is init's business and not a
/// client's, and a verb that only made init re-read its files would be a verb
/// whose effect nobody could see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAction {
    /// Run it now and at every boot. What a switch being turned on means.
    Enable,
    /// Stop it now and leave it stopped at the next boot. A switch turned off.
    Disable,
    /// Run it now; say nothing about the next boot.
    Start,
    /// Stop it now; say nothing about the next boot.
    Stop,
    Restart,
}

impl ServiceAction {
    fn as_str(self) -> &'static str {
        match self {
            ServiceAction::Enable => "enable",
            ServiceAction::Disable => "disable",
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
        }
    }
}

/// What a validated request turns out to be: a run of rvn, or a service verb
/// that never goes near it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The argv to hand rvn, as root.
    Rvn(Vec<String>),
    Service {
        action: ServiceAction,
        name: String,
    },
}

impl Plan {
    /// The line written to rvnd's log and shown in messages.
    pub fn describe(&self) -> String {
        match self {
            Plan::Rvn(argv) => format!("rvn {}", argv.join(" ")),
            Plan::Service { action, name } => format!("service {} {name}", action.as_str()),
        }
    }

    /// The argv, for a plan that has one. Only the rvn half of `handle` and
    /// the tests below ever ask.
    #[cfg(test)]
    pub fn argv(&self) -> &[String] {
        match self {
            Plan::Rvn(argv) => argv,
            Plan::Service { .. } => &[],
        }
    }
}

/// One request line. Flags are named rather than passed as argv so the
/// daemon can refuse anything it does not recognise; a package list is
/// validated to package-name characters so nothing in it can ever be read as
/// an option by the rvn it spawns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Request {
    pub op: Option<Op>,
    #[serde(default)]
    pub packages: Vec<String>,
    /// Resolve and report; change nothing. The client's first phase.
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub repo_only: bool,
    #[serde(default)]
    pub keep_cache: bool,
    #[serde(default)]
    pub no_sync: bool,
    // uninstall
    #[serde(default)]
    pub cascade: bool,
    #[serde(default)]
    pub keep_orphans: bool,
    /// The client showed the orphans from its dry run and the user agreed.
    /// Every daemon run is `--yes`, so without this an orphan sweep is refused.
    #[serde(default)]
    pub remove_orphans: bool,
    #[serde(default)]
    pub nodeps: bool,
    // update
    #[serde(default)]
    pub no_refresh: bool,
    // service
    /// The service to act on. Only read for `Op::Service`.
    #[serde(default)]
    pub service: Option<String>,
    /// What to do to it. Only read for `Op::Service`.
    #[serde(default)]
    pub action: Option<ServiceAction>,
}

/// A package name as pacman allows it: lowercase letters, digits and a few
/// punctuation marks, never starting with a dash. A version suffix as in
/// `foo>=1.2` is allowed through, since rvn's own parser handles it.
pub fn valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name.len() <= 255
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._+-<>=:~".contains(c))
}

impl Request {
    /// What the daemon will do for this request, or why it refused.
    ///
    /// Pure, so that every refusal in it can be tested without a socket, a
    /// root process or a machine that happens to have the right files. The
    /// checks that must look at the filesystem -- whether a service is one
    /// this machine actually ships a definition for -- are deliberately not
    /// here; they are in `service_definition_path`, called from `handle`
    /// after this has established that the *shape* of the request is
    /// acceptable.
    pub fn validate(&self) -> Result<Plan, String> {
        let op = self.op.ok_or("request has no op")?;
        for name in &self.packages {
            if !valid_package_name(name) {
                return Err(format!("refusing package name {name:?}"));
            }
        }

        if op == Op::Service {
            let action = self.action.ok_or("a service request needs an action")?;
            let name = self
                .service
                .as_deref()
                .ok_or("a service request needs a service")?;
            // The same rule rvn applies before it promotes a template, and it
            // has to hold here for a second reason: this name is about to be
            // joined to a directory path and written into a request line that
            // PID 1 parses by whitespace.
            if !crate::initctl::valid_service_name(name) {
                return Err(format!("refusing service name {name:?}"));
            }
            if !self.packages.is_empty() {
                return Err("a service request names no packages".into());
            }
            return Ok(Plan::Service {
                action,
                name: name.to_string(),
            });
        }

        match op {
            Op::Install if self.packages.is_empty() => return Err("install needs packages".into()),
            Op::Uninstall if self.packages.is_empty() => {
                return Err("uninstall needs packages".into());
            }
            Op::Sync if self.dry_run => return Err("sync has no dry run".into()),
            // The bare form of `rvn rollback` only reports, needs no root and
            // is never sent here, so a rollback request without a package is
            // a request that would do nothing but hold the daemon's lock.
            Op::Rollback if self.packages.len() != 1 => {
                return Err("rollback names exactly one package".into());
            }
            // Returned above; this arm exists so that adding an op to the
            // enum fails to compile here rather than falling through into an
            // argv for rvn.
            Op::Service => unreachable!("handled above"),
            _ => {}
        }

        let mut argv = vec!["--json".to_string(), "--yes".to_string()];
        if self.repo_only {
            argv.push("--repo-only".into());
        }
        if self.keep_cache {
            argv.push("--keep-cache".into());
        }
        if self.no_sync {
            argv.push("--no-sync".into());
        }
        argv.push(op.as_str().into());
        if self.dry_run {
            argv.push("--dry-run".into());
        }
        match op {
            Op::Uninstall => {
                if self.cascade {
                    argv.push("--cascade".into());
                }
                if self.keep_orphans {
                    argv.push("--keep-orphans".into());
                }
                if self.remove_orphans {
                    argv.push("--remove-orphans".into());
                }
                if self.nodeps {
                    argv.push("--nodeps".into());
                }
            }
            Op::Update if self.no_refresh => argv.push("--no-refresh".into()),
            _ => {}
        }
        argv.extend(self.packages.iter().cloned());
        Ok(Plan::Rvn(argv))
    }
}

/// The root-owned file that defines `name`, or `None` when this machine has
/// no such service.
///
/// This is the whole of what bounds [`Op::Service`]. A client may ask for any
/// name that survives `valid_service_name`; it gets an answer only for one
/// that some package already put a definition on disk for. Both directories
/// are root's: a drop-in under /etc/raven/init.d was copied there by an
/// install running as root or by an administrator, and a template under
/// /usr/share/raven/services arrived inside a signed package. Neither is
/// writable by the session asking, so a name cannot be made to mean a service
/// of the caller's own design.
///
/// The drop-in is checked first because it is the one init actually reads.
fn service_definition_path(name: &str) -> Option<PathBuf> {
    if !crate::initctl::valid_service_name(name) {
        return None;
    }
    let dropin = Path::new(DROPIN_DIR).join(format!("{name}.toml"));
    if dropin.is_file() {
        return Some(dropin);
    }
    let template = Path::new(crate::initctl::TEMPLATE_DIR).join(format!("{name}.toml"));
    template.is_file().then_some(template)
}

/// Where raven-init reads service definitions from at boot.
const DROPIN_DIR: &str = "/etc/raven/init.d";

// ----------------------------------------------------------------------------
// Server
// ----------------------------------------------------------------------------

/// How the daemon is configured, from rvnd's command line.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub socket: PathBuf,
    /// Group given the socket, or `None` to leave it as created (tests).
    ///
    /// It is also the group a peer must belong to. One field for both,
    /// because a daemon whose socket is owned by one group and whose check
    /// names another has a policy nobody can read off the machine.
    pub group: Option<String>,
    /// The rvn binary to run as root.
    pub rvn: PathBuf,
    /// What needs a human's agreement, read once at startup so a malformed
    /// file stops rvnd rather than surfacing mid-transaction.
    pub policy: crate::policy::Policy,
}

/// Pid, uid and gid of the peer, from SO_PEERCRED.
///
/// The kernel fills this in at `connect` time from the credentials the peer
/// had then, so unlike anything in the request it cannot be chosen by the
/// client. All three are used: the uid and gid to decide, the pid to find the
/// session to prompt and the executable to write down.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

unsafe extern "C" {
    fn getsockopt(fd: i32, level: i32, name: i32, value: *mut Ucred, len: *mut u32) -> i32;
}

fn peer_cred(stream: &UnixStream) -> Option<Ucred> {
    use std::os::fd::AsRawFd;
    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;
    let mut cred = Ucred::default();
    let mut len = std::mem::size_of::<Ucred>() as u32;
    // SAFETY: the buffer is a properly sized, writable `ucred`, and the
    // kernel writes at most `len` bytes into it.
    let rc = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            &mut cred,
            &mut len,
        )
    };
    (rc == 0).then_some(cred)
}

/// The account name for a uid, from /etc/passwd. `None` for an unknown uid.
fn user_name(uid: u32) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|line| {
        let mut f = line.split(':');
        let name = f.next()?;
        f.next();
        let id: u32 = f.next()?.parse().ok()?;
        (id == uid).then(|| name.to_string())
    })
}

/// The gid and member list of a group, from /etc/group.
fn group_entry(name: &str) -> Option<(u32, Vec<String>)> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|line| {
        let mut f = line.split(':');
        if f.next()? != name {
            return None;
        }
        f.next(); // the password field, "x" on every machine that has shadow
        let gid: u32 = f.next()?.parse().ok()?;
        let members = f
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|member| !member.is_empty())
            .map(str::to_string)
            .collect();
        Some((gid, members))
    })
}

/// The gid of a group, from /etc/group.
fn group_id(name: &str) -> Option<u32> {
    group_entry(name).map(|(gid, _)| gid)
}

/// Whether the peer's account belongs to the group the socket is owned by.
///
/// This cannot let anybody in who was not already let in: the kernel checked
/// the connecting process's real group membership against the socket's mode
/// before `accept` ever returned, and this check can only refuse on top of
/// that. It is worth having anyway, for two reasons.
///
/// It is where the policy is written down. "Only administrators may install
/// packages" being enforced solely by a chmod in `bind` means the next person
/// to read this file has to infer the rule from a permission bit, and the
/// version of that rule that ends up in somebody's head is the one that gets
/// changed by accident.
///
/// And it follows /etc/group rather than the process's credentials, so it is
/// the stricter of the two in the direction that matters. A person removed
/// from `wheel` five minutes ago still has running processes carrying the old
/// supplementary group, and the kernel will happily let those connect; this
/// refuses them. The reverse -- somebody added to the group who has not
/// logged in again -- never reaches here, because the kernel refused the
/// connect first.
///
/// Membership is the primary gid or an entry in the group's member list,
/// which is the same pair of places `id -nG` looks.
fn peer_is_in_group(cred: &Ucred, user: Option<&str>, group: &str) -> bool {
    let Some((gid, members)) = group_entry(group) else {
        // No such group. `bind` refuses to start without it, so reaching
        // here means /etc/group changed under a running daemon; refusing is
        // the only answer that does not invent a permission.
        return false;
    };
    if cred.gid == gid {
        return true;
    }
    user.is_some_and(|name| members.iter().any(|member| member == name))
}

fn emit_line(stream: &mut UnixStream, event: &str, payload: serde_json::Value) {
    let mut v = payload;
    if let serde_json::Value::Object(map) = &mut v {
        map.insert("event".into(), serde_json::Value::String(event.into()));
    }
    let _ = writeln!(stream, "{v}");
    let _ = stream.flush();
}

/// Append one decision to the audit log, or say why it could not be.
///
/// A log that cannot be written never stops a transaction: `/var` being full
/// is a bad day, and a package manager that refuses to work on a bad day is a
/// worse one. The warning is what an administrator should alert on -- see the
/// `audit` module for the argument.
fn write_audit(config: &ServerConfig, event: &crate::audit::Event, who: &str) {
    let log = &config.policy.audit_log;
    if let Err(e) = crate::audit::record(log, event, crate::audit::now_unix()) {
        eprintln!(
            "rvnd: WARNING: {who}: cannot write the audit log at {}: {e}",
            log.display()
        );
    }
}

/// Bind the socket, set its group and mode, and return the listener.
pub fn bind(config: &ServerConfig) -> std::io::Result<UnixListener> {
    if let Some(dir) = config.socket.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o755)).ok();
    }
    if config.socket.exists() {
        std::fs::remove_file(&config.socket)?;
    }
    let listener = UnixListener::bind(&config.socket)?;
    // Group-gated: owner root, group rw, nobody else. Set before the group so
    // there is no window where "everyone" could connect.
    std::fs::set_permissions(
        &config.socket,
        std::os::unix::fs::PermissionsExt::from_mode(0o660),
    )?;
    if let Some(group) = &config.group {
        let gid = group_id(group).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no such group: {group}"),
            )
        })?;
        std::os::unix::fs::chown(&config.socket, None, Some(gid))?;
    }
    Ok(listener)
}

/// Serve forever. One transaction at a time: a second client while one is
/// running is told so at once rather than queued behind it, because the thing
/// it would wait on is a package install of unknown length.
pub fn serve(config: ServerConfig, listener: UnixListener) -> ! {
    eprintln!("rvnd: listening on {}", config.socket.display());
    // The policy is the interesting half of what this daemon is, and the
    // failure it has is being quietly different from what somebody believes.
    // Saying it once at startup means `journalctl -u rvnd | head` answers
    // "does this machine prompt?" without anyone having to read a file.
    eprintln!(
        "rvnd: policy from {}: query={} repo={} aur={}, {} when nothing can be asked, \
         authorization remembered for {}s, audit log {}",
        config.policy.source.display(),
        config.policy.query.as_str(),
        config.policy.repo.as_str(),
        config.policy.aur.as_str(),
        match config.policy.on_auth_unavailable {
            crate::policy::Unavailable::Allow => "allowing",
            crate::policy::Unavailable::Deny => "refusing",
        },
        config.policy.auth_cache_seconds,
        config.policy.audit_log.display()
    );
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("rvnd: accept: {e}");
                continue;
            }
        };
        let config = config.clone();
        std::thread::spawn(move || handle(&config, stream));
    }
    unreachable!("incoming() never ends")
}

/// The one-transaction-at-a-time lock. Taken only once a request has been
/// read and validated: a refusal must be a reply, and a reply written to a
/// socket whose request is still unread is turned into a reset by the
/// kernel, which the client sees as the daemon hanging up. A connection that
/// only probes and says nothing never takes it at all.
static BUSY: Mutex<()> = Mutex::new(());

/// Prompts that have been answered and still count, keyed on the session they
/// were answered in. See `auth::Cache`; the lifetime of this is the
/// lifetime of the daemon, so restarting rvnd asks everybody again.
static AUTH_CACHE: crate::auth::Cache = crate::auth::Cache::new();

/// What to do with one request, and what to write down about it.
struct Decision {
    allowed: bool,
    /// The `auth=` field of the audit line: the one word that says how this
    /// was settled.
    how: &'static str,
    /// Why. The refusal the client is given, or the note beside an allow.
    reason: String,
    /// Something the client should be told even though it went ahead.
    warning: Option<String>,
}

impl Decision {
    fn allow(how: &'static str, reason: impl Into<String>) -> Decision {
        Decision {
            allowed: true,
            how,
            reason: reason.into(),
            warning: None,
        }
    }

    fn refuse(how: &'static str, reason: impl Into<String>) -> Decision {
        Decision {
            allowed: false,
            how,
            reason: reason.into(),
            warning: None,
        }
    }
}

/// What a request needing authorization gets when no prompt could be raised.
///
/// One place, because there are two ways to arrive at it -- a prompt that
/// could not be sent, and a caller with no session on a machine where
/// nothing was listening to prompt anyway -- and a machine that allows one
/// while refusing the other is answering the same question twice.
fn unavailable(config: &ServerConfig, why: &str) -> Decision {
    use crate::policy::Unavailable;
    match config.policy.on_auth_unavailable {
        Unavailable::Allow => Decision {
            allowed: true,
            how: "unavailable",
            reason: format!("nothing could be asked: {why}"),
            warning: Some(format!(
                "rvnd could not ask anyone to authorize this and let it through anyway: {why}. \
                 Set on_auth_unavailable = \"deny\" in {} once prompts work on this machine.",
                config.policy.source.display()
            )),
        },
        Unavailable::Deny => Decision::refuse(
            "unavailable",
            format!(
                "this needs someone to authorize it and nothing could be asked ({why}); \
                 {} says to refuse when that happens",
                config.policy.source.display()
            ),
        ),
    }
}

/// Whether this peer may have this request, and how that was settled.
///
/// Every input is something rvnd established for itself -- the credentials
/// the kernel attached to the connection, `/etc/group`, `/proc`, and the
/// policy file -- except `request`, whose only contribution is which
/// operation was asked for and whether it promised `--repo-only`.
fn decide(
    config: &ServerConfig,
    cred: &Ucred,
    user: Option<&str>,
    request: &Request,
    class: crate::policy::Class,
    session: Option<crate::auth::Session>,
) -> Decision {
    use crate::policy::Rule;

    // Root is already root. It has no need of this daemon at all, and a
    // prompt asking the superuser to confirm that it is the superuser would
    // be pure ceremony -- the kind that teaches people to click yes.
    if cred.uid == 0 {
        return Decision::allow("root", "the peer is root");
    }

    if let Some(group) = &config.group
        && !peer_is_in_group(cred, user, group)
    {
        return Decision::refuse(
            "group",
            format!(
                "installing packages is for members of the {group} group, and this account is not in it"
            ),
        );
    }

    let rule = config.policy.rule(class);
    match rule {
        Rule::Allow => Decision::allow("not-required", "policy does not require authorization"),
        Rule::Deny => Decision::refuse(
            "policy",
            format!(
                "{} operations are switched off on this machine ({} = \"deny\" in {})",
                class.as_str(),
                class.as_str(),
                config.policy.source.display()
            ),
        ),
        Rule::Auth => {
            // No session means the process that asked is gone -- /proc has
            // nothing to read. There is nobody left to put a prompt in front
            // of and nobody waiting for the answer, so this is a refusal and
            // deliberately not the `on_auth_unavailable` case: that setting
            // is about a missing *mechanism*, and treating a missing asker as
            // a missing mechanism would make "exit quickly" the way past it.
            //
            // Unless there is no mechanism either, which is checked first.
            // Refusing here while the identical request from a caller whose
            // session did resolve is waved through by `on_auth_unavailable`
            // is not one policy, it is two answers to one question, settled
            // by whether /proc still had a session leader to read -- and the
            // one it refuses is the desktop, where every process descends
            // from a service and the message reads as a bug in the store.
            // The probe asks about the socket and never about the caller, so
            // exiting quickly is no way past this: a caller that stays alive
            // gets the same answer.
            let Some(session) = session else {
                if let Err(why) = crate::auth::reachable(&config.policy.auth_socket) {
                    return unavailable(config, &why);
                }
                return Decision::refuse(
                    "session",
                    "the process that asked is no longer there to be asked back",
                );
            };
            if AUTH_CACHE.allows(session, config.policy.auth_cache_seconds) {
                return Decision::allow("cached", "authorized recently in this session");
            }
            let verdict = crate::auth::ask(
                &config.policy.auth_socket,
                session,
                cred.pid,
                request.op.map_or("", |op| op.as_str()),
                class.as_str(),
                &request.packages,
                config.policy.auth_timeout_seconds,
            );
            match verdict {
                crate::auth::Verdict::Granted => {
                    AUTH_CACHE.record(session);
                    Decision::allow("prompt", "authorized by the session's owner")
                }
                crate::auth::Verdict::Denied(why) => {
                    Decision::refuse("denied", format!("not authorized: {why}"))
                }
                crate::auth::Verdict::Unavailable(why) => unavailable(config, &why),
            }
        }
    }
}

/// One connection: read the request, validate it, decide whether this peer
/// may have it, run rvn with the socket as its stdout, wait.
fn handle(config: &ServerConfig, mut stream: UnixStream) {
    let cred = peer_cred(&stream);
    let uid = cred.map(|c| c.uid);
    let user = uid.and_then(user_name);
    let who = user
        .clone()
        .unwrap_or_else(|| format!("uid {}", uid.map_or(-1, |u| u as i64)));

    let mut line = String::new();
    {
        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("rvnd: {who}: clone: {e}");
                return;
            }
        });
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            // A probe (`rvn` checking whether the daemon is there) connects
            // and says nothing. Not an error, not a transaction.
            return;
        }
    }
    let request: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            // Something that is not even a request was sent to a socket that
            // grants root. There is no operation to name and no package list,
            // but the uid and the exe are exactly what somebody would want to
            // know afterwards, so the line goes in with what there is.
            let reason = format!("bad request: {e}");
            let exe = cred.and_then(|c| crate::auth::exe_of(c.pid));
            write_audit(
                config,
                &crate::audit::Event {
                    decision: "refused",
                    auth: "malformed",
                    uid,
                    user: user.as_deref(),
                    gid: cred.map(|c| c.gid),
                    pid: cred.map(|c| c.pid),
                    exe: exe.as_deref(),
                    reason: Some(&reason),
                    ..Default::default()
                },
                &who,
            );
            eprintln!("rvnd: {who}: refused: {reason}");
            emit_line(
                &mut stream,
                "failed",
                serde_json::json!({ "message": reason }),
            );
            return;
        }
    };
    // Everything the audit log records about the caller, gathered once. The
    // executable path and the session both come out of /proc and both can
    // have vanished between the connect and now, so each is an Option rather
    // than something to fail on.
    let exe = cred.and_then(|c| crate::auth::exe_of(c.pid));
    let session = cred.and_then(|c| crate::auth::Session::of(c.uid, c.pid));
    let class = request
        .op
        .map(|op| crate::policy::Class::of(op, request.repo_only, request.dry_run));
    let mut audit = crate::audit::Event {
        op: request.op.map_or("", |op| op.as_str()),
        class: class.map_or("", |class| class.as_str()),
        rule: class.map_or("", |class| config.policy.rule(class).as_str()),
        uid,
        user: user.as_deref(),
        gid: cred.map(|c| c.gid),
        pid: cred.map(|c| c.pid),
        session: session.map(|s| s.leader),
        exe: exe.as_deref(),
        packages: &request.packages,
        ..Default::default()
    };

    let plan = match request.validate() {
        Ok(plan) => plan,
        Err(e) => {
            // A request that does not even parse into an argv is still a
            // request for root that something on this machine made, and it
            // is the shape of request worth noticing in a log.
            audit.decision = "refused";
            audit.auth = "malformed";
            audit.reason = Some(&e);
            write_audit(config, &audit, &who);
            eprintln!("rvnd: {who}: refused: {e}");
            emit_line(&mut stream, "failed", serde_json::json!({ "message": e }));
            return;
        }
    };

    // ---- authorization --------------------------------------------------
    // Before the BUSY lock, so a refusal is a reply rather than a hang-up,
    // and after validate() so the audit line can say what was being asked
    // for. See the comment on BUSY for why the first of those matters.
    let Some(cred) = cred else {
        let reason = "rvnd cannot read the credentials of the process that connected to it";
        audit.decision = "refused";
        audit.auth = "peer";
        audit.reason = Some(reason);
        write_audit(config, &audit, &who);
        eprintln!("rvnd: {who}: refused: {reason}");
        emit_line(
            &mut stream,
            "failed",
            serde_json::json!({ "message": reason }),
        );
        return;
    };
    // `validate` refuses a request with no op, so this is always Some by now.
    // The fallback is the class that asks for the most rather than a panic,
    // because a daemon everything installs through is the wrong place to
    // discover that an assumption has stopped holding.
    let class = class.unwrap_or(crate::policy::Class::Aur);
    let decision = decide(config, &cred, user.as_deref(), &request, class, session);

    audit.class = class.as_str();
    audit.rule = config.policy.rule(class).as_str();
    audit.auth = decision.how;
    audit.decision = if decision.allowed {
        "allowed"
    } else {
        "refused"
    };
    audit.reason = Some(&decision.reason);
    write_audit(config, &audit, &who);

    if !decision.allowed {
        eprintln!(
            "rvnd: {who}: refused ({}): {}",
            decision.how, decision.reason
        );
        emit_line(
            &mut stream,
            "failed",
            serde_json::json!({ "message": decision.reason }),
        );
        return;
    }
    if let Some(warning) = decision.warning {
        // On the daemon's own log because that is what an administrator
        // greps, and on the client's stream because the person who is about
        // to get the package deserves to know nobody was asked.
        eprintln!("rvnd: WARNING: {who}: {warning}");
        emit_line(
            &mut stream,
            "warn",
            serde_json::json!({ "message": warning }),
        );
    }

    // A service verb never runs rvn: it is a handful of lines on raven-init's
    // control socket, which this process can open and the caller cannot.
    //
    // Deliberately before the BUSY lock, and not under it. BUSY exists so
    // that two transactions cannot unpack into the same install root at once,
    // and a service verb does not touch it -- it writes at most one file into
    // /etc/raven/init.d and then talks to PID 1, which serialises its own
    // callers. Taking the lock would mean that turning the fingerprint reader
    // on during a Store install failed with "another rvn transaction is
    // running", which is both untrue of what was being asked and exactly the
    // kind of thing this verb exists to stop happening to somebody at a
    // switch.
    if let Plan::Service { action, name } = plan {
        eprintln!("rvnd: {who}: service {} {name}", action.as_str());
        run_service(action, &name, &mut |kind, message| {
            emit_line(&mut stream, kind, serde_json::json!({ "message": message }));
        });
        return;
    }

    let Ok(_guard) = BUSY.try_lock() else {
        eprintln!("rvnd: {who}: busy, refused: {}", plan.describe());
        emit_line(
            &mut stream,
            "failed",
            serde_json::json!({ "message": "another rvn transaction is running; try again when it finishes" }),
        );
        return;
    };
    eprintln!("rvnd: {who}: {}", plan.describe());

    let Plan::Rvn(argv) = plan else {
        unreachable!("the service plan returned above");
    };

    let stdout = match stream.try_clone() {
        Ok(s) => Stdio::from(std::os::fd::OwnedFd::from(s)),
        Err(e) => {
            emit_line(
                &mut stream,
                "failed",
                serde_json::json!({ "message": format!("socket: {e}") }),
            );
            return;
        }
    };
    let mut cmd = Command::new(&config.rvn);
    cmd.args(&argv)
        .stdin(Stdio::null())
        .stdout(stdout)
        // rvn's own stderr is quiet in --json mode; what does reach it is a
        // crash, which belongs in the daemon's log, not in the event stream.
        .stderr(Stdio::inherit())
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("HOME", "/root")
        .env("LANG", "C.UTF-8");
    // Who asked. This is no longer a build identity: AUR builds run as the
    // dedicated `raven-build` account and nothing in rvn reads this variable
    // any more (see `build_identity` in ops::install). It is still set
    // because a package's scriptlets inherit this environment, and a
    // scriptlet that wants to know which human a transaction came from finds
    // the answer in the same place it would under `sudo`.
    if let Some(user) = &user {
        cmd.env("SUDO_USER", user);
    }
    match cmd.status() {
        Ok(status) => {
            eprintln!("rvnd: {who}: rvn exited {status}");
            if !status.success() {
                // rvn emits `failed` itself; this is for the case where it
                // could not even get that far.
                emit_line(
                    &mut stream,
                    "exit",
                    serde_json::json!({ "code": status.code().unwrap_or(-1) }),
                );
            }
        }
        Err(e) => {
            eprintln!("rvnd: {who}: cannot run {}: {e}", config.rvn.display());
            emit_line(
                &mut stream,
                "failed",
                serde_json::json!({ "message": format!("rvnd cannot run rvn: {e}") }),
            );
        }
    }
}

/// Carries out one service verb against raven-init, reporting as it goes.
///
/// # Why this is more than one line per verb
///
/// Because "turn face unlock on" is three different situations on three
/// machines, and a switch in a settings panel is one switch.
///
/// A machine imaged from this tree has `faced` in its init.toml and running:
/// the verb is `start` and nothing else is needed. A machine that installed
/// raven-faced through a version of rvn that only copied the template has a
/// drop-in raven-init has never read, because drop-ins are read at boot: the
/// verb fails with "no such service" until init is told to reload. A machine
/// that got the binary some other way has a template and no drop-in at all.
///
/// Each of those needed a different command typed in a terminal, and the
/// hardest part was working out which. So this function makes the definition
/// true before it acts on it -- promote the template if it has to, reload if
/// init does not know the name -- and the client sends the same request in
/// every case.
///
/// Every step that changes something says so on the stream. A person who
/// turns a switch on and is told "face unlock is running" has been told the
/// truth; one who is told nothing has to go and look.
pub fn run_service(action: ServiceAction, name: &str, report: &mut dyn FnMut(&str, String)) {
    let socket = Path::new(crate::initctl::SOCKET_PATH);

    let ok = |report: &mut dyn FnMut(&str, String), message: String| report("ok", message);
    let failed = |report: &mut dyn FnMut(&str, String), message: String| report("failed", message);

    let Some(definition) = service_definition_path(name) else {
        failed(
            report,
            format!(
                "this machine has no service definition for '{name}' \
                 (nothing in {DROPIN_DIR} or {})",
                crate::initctl::TEMPLATE_DIR
            ),
        );
        return;
    };

    if !crate::initctl::reachable(socket) {
        // rvnd is running, so raven-init started it -- but it is not
        // answering. Worth saying plainly rather than as a socket error: the
        // person reading it is looking at a switch that did not move.
        failed(
            report,
            format!(
                "raven-init is not answering on {}, so services cannot be changed",
                crate::initctl::SOCKET_PATH
            ),
        );
        return;
    }

    // Stopping and disabling act on what is already there; only the verbs
    // that turn something on have to make the definition real first.
    if matches!(
        action,
        ServiceAction::Enable | ServiceAction::Start | ServiceAction::Restart
    ) && let Err(e) = ensure_defined(report, socket, name, &definition)
    {
        failed(report, e);
        return;
    }

    match action {
        ServiceAction::Enable => {
            // Enable before start: if the start fails, the machine is still
            // one that has been told to run this at boot, which is what the
            // person asked for and is recoverable by rebooting. The other
            // order leaves a daemon running that nothing will start again.
            if let Err(e) = crate::initctl::enable(socket, name) {
                failed(report, format!("cannot enable '{name}': {e}"));
                return;
            }
            match crate::initctl::start(socket, name) {
                Ok(_) => ok(report, format!("'{name}' is running, and will start at boot")),
                Err(e) => failed(
                    report,
                    format!(
                        "'{name}' will start at boot, but did not start now: {e} \
                         \u{2014} `raven-rc status {name}` says more"
                    ),
                ),
            }
        }
        ServiceAction::Disable => {
            // A stop that fails because it was not running is the state being
            // asked for, so it is not reported: what matters is that it is
            // stopped and stays stopped, and `disable` below is the half that
            // can fail in a way the person needs to know about.
            let _ = crate::initctl::stop(socket, name);
            match crate::initctl::disable(socket, name) {
                Ok(_) => ok(
                    report,
                    format!("'{name}' is stopped, and will not start at boot"),
                ),
                Err(e) => failed(report, format!("cannot disable '{name}': {e}")),
            }
        }
        ServiceAction::Start => match crate::initctl::start(socket, name) {
            Ok(_) => ok(report, format!("'{name}' is running")),
            Err(e) => failed(report, format!("cannot start '{name}': {e}")),
        },
        ServiceAction::Stop => match crate::initctl::stop(socket, name) {
            Ok(_) => ok(report, format!("'{name}' is stopped")),
            Err(e) => failed(report, format!("cannot stop '{name}': {e}")),
        },
        ServiceAction::Restart => match crate::initctl::ask(socket, "restart", Some(name)) {
            Ok(_) => ok(report, format!("'{name}' has been restarted")),
            Err(e) => failed(report, format!("cannot restart '{name}': {e}")),
        },
    }
}

/// Makes sure raven-init knows about `name` before a verb is sent for it.
///
/// Two things can be missing, and they are missing on different machines.
/// The drop-in may not exist, because the definition is still the inert
/// template a package shipped; it is copied, which is exactly what
/// `ops::install::activate_service_templates` does at install time and is
/// here for the machines that installed before it did. And init may not have
/// read the drop-in, because it reads that directory once, at boot.
///
/// `status` is the question that distinguishes them, and it is asked rather
/// than assumed: a reload is cheap but not free -- it re-reads every file in
/// the directory and re-synthesises the services that live in no file -- and
/// doing it on every switch would make a panel that polls into a panel that
/// reloads PID 1 several times a minute.
fn ensure_defined(
    report: &mut dyn FnMut(&str, String),
    socket: &Path,
    name: &str,
    definition: &Path,
) -> Result<(), String> {
    let dropin = Path::new(DROPIN_DIR).join(format!("{name}.toml"));
    if !dropin.is_file() {
        std::fs::create_dir_all(DROPIN_DIR)
            .map_err(|e| format!("cannot create {DROPIN_DIR}: {e}"))?;
        std::fs::copy(definition, &dropin).map_err(|e| {
            format!(
                "cannot install {} as {}: {e}",
                definition.display(),
                dropin.display()
            )
        })?;
        report(
            "info",
            format!("installed the service definition for '{name}'"),
        );
    }

    if crate::initctl::status(socket, name).is_ok() {
        return Ok(());
    }
    // Either the name is genuinely unknown or the drop-in postdates the boot.
    // A reload settles it, and a `start` that still fails afterwards reports
    // init's own words.
    crate::initctl::reload(socket)
        .map(|_| ())
        .map_err(|e| format!("raven-init did not reload its configuration: {e}"))
}

// ----------------------------------------------------------------------------
// Client
// ----------------------------------------------------------------------------

/// Whether a daemon is reachable at `socket`. Distinguishes "no daemon" from
/// "not allowed", since the two need different advice.
#[derive(Debug, PartialEq, Eq)]
pub enum Reach {
    Ok,
    Absent,
    Denied,
    Other(String),
}

pub fn reach(socket: &Path) -> Reach {
    match UnixStream::connect(socket) {
        Ok(_) => Reach::Ok,
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => Reach::Absent,
            std::io::ErrorKind::PermissionDenied => Reach::Denied,
            _ => Reach::Other(e.to_string()),
        },
    }
}

/// Send one request and hand every event line to `sink` as it arrives.
/// Returns when the daemon closes the connection. The result is what the
/// stream said: `done` is Ok, `failed` carries its message, and a stream that
/// ends with neither is an error too, since the worker died mid-way.
pub fn request(socket: &Path, req: &Request, mut sink: impl FnMut(&str)) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("rvnd: {e}"))?;
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    writeln!(stream, "{line}").map_err(|e| format!("rvnd: {e}"))?;
    stream.flush().ok();
    let reader = BufReader::new(stream);
    let mut outcome: Option<Result<(), String>> = None;
    for line in reader.lines() {
        let line = line.map_err(|e| format!("rvnd: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            match v["event"].as_str() {
                Some("done") => outcome = Some(Ok(())),
                Some("failed") => {
                    outcome = Some(Err(v["message"]
                        .as_str()
                        .unwrap_or("rvn failed")
                        .to_string()))
                }
                Some("exit") if outcome.is_none() => {
                    outcome = Some(Err(format!(
                        "rvn exited with status {}",
                        v["code"].as_i64().unwrap_or(-1)
                    )))
                }
                _ => {}
            }
        }
        sink(&line);
    }
    outcome.unwrap_or_else(|| Err("rvnd closed the connection without a result".into()))
}

/// Turns the daemon's event stream back into the terminal interface, so an
/// install through rvnd looks exactly like one run as root.
pub struct Replay<'a> {
    ui: &'a crate::ui::Ui,
    spinner: Option<crate::ui::spinner::Spinner>,
    progress: HashMap<String, crate::ui::progress::Progress>,
    /// The apply phase follows a plan phase that already showed the masthead.
    show_banner: bool,
}

impl<'a> Replay<'a> {
    pub fn new(ui: &'a crate::ui::Ui, show_banner: bool) -> Self {
        Replay {
            ui,
            spinner: None,
            progress: HashMap::new(),
            show_banner,
        }
    }

    fn message(&self, f: impl FnOnce()) {
        match &self.spinner {
            Some(s) => s.suspend(f),
            None => f(),
        }
    }

    pub fn event(&mut self, line: &str) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            return;
        };
        let text = |key: &str| v[key].as_str().unwrap_or("").to_string();
        match v["event"].as_str().unwrap_or("") {
            "banner" => {
                if self.show_banner {
                    self.ui.banner(&text("version"));
                }
            }
            // A live stage sends `stage` when it starts AND again on every
            // change of message, with nothing to tell the two apart. Updating
            // the running spinner rather than replacing it is what makes the
            // settle below land on the same line the work was announced on;
            // replacing it left the previous one unsettled, which is why an
            // install through rvnd used to show a column of spinners that
            // never resolved.
            //
            // `ok` is still honoured on `stage` for a daemon older than this
            // client: rvnd runs whichever rvn is installed, which is not
            // necessarily the binary the person typed.
            "stage" => match v["ok"].as_bool() {
                None => match &self.spinner {
                    Some(s) => s.set_message(&text("message")),
                    None => self.spinner = Some(self.ui.stage(&text("message"))),
                },
                Some(ok) => self.settle(ok, &text("message")),
            },
            // How a stage actually ends. Nothing emitted `stage` with an `ok`
            // field, so until this arm existed every spinner started and none
            // of them ever finished.
            "stage_done" => self.settle(v["ok"].as_bool().unwrap_or(true), &text("message")),
            "progress" => {
                let label = text("label");
                let total = v["total"].as_u64().unwrap_or(0);
                let done = v["done"].as_u64().unwrap_or(0);
                let unit = text("unit");
                let bar = self.progress.entry(label.clone()).or_insert_with(|| {
                    if unit == "bytes" {
                        self.ui.progress(&label, total)
                    } else {
                        let noun: &'static str = Box::leak(unit.into_boxed_str());
                        self.ui.counter(&label, total, noun)
                    }
                });
                let detail = text("detail");
                if !detail.is_empty() {
                    bar.set_detail(&detail);
                }
                bar.set(done);
            }
            "progress_done" => match self.progress.remove(&text("label")) {
                Some(bar) => bar.finish(&text("message")),
                None => self.ui.ok(&text("message")),
            },
            "ok" => self.message(|| self.ui.ok(&text("message"))),
            "err" => self.message(|| self.ui.err(&text("message"))),
            "warn" => self.message(|| self.ui.warn(&text("message"))),
            "info" => self.message(|| self.ui.info(&text("message"))),
            "step" => self.message(|| self.ui.step(&text("message"))),
            "detail" => self.message(|| self.ui.detail(&text("message"))),
            "tree" => {
                let items: Vec<String> = v["items"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|i| i.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                self.message(|| self.ui.tree(&items));
            }
            // The transaction summary. Unlike every other event here it is
            // the ONLY thing emitted -- `ops::install::show_plan` returns
            // early in JSON mode rather than painting as well -- so without
            // this arm a person installing through rvnd was asked "proceed?"
            // about a plan they had never been shown.
            "plan" => self.message(|| self.show_plan(&v)),
            // The same gap, in `ops::update::show_candidates`.
            "updates" => self.message(|| self.show_updates(&v)),

            // Everything below is deliberately not rendered, and the list is
            // spelled out rather than left to a bare wildcard so that the
            // next event added to this crate has an obvious place to be
            // considered against. Anyone adding one: the question is not
            // "does Replay know this name", it is "does the operation that
            // emits it ALSO paint the same thing through ui.ok/warn/tree" --
            // because in JSON mode those become `ok`/`warn`/`tree` events,
            // which are relayed above. An arm here for an event that is
            // already accompanied by text would print everything twice.
            //
            // The request's own result, read by `request()` rather than
            // shown:
            "done" | "failed" | "exit" => {}
            // Data for a front-end, emitted by read-only operations that
            // never reach the daemon at all:
            //
            // `service` is `rvn service status` in --json mode: raven-init's
            // own status text, handed to a settings panel that will lay it
            // out itself. The terminal form of that command prints the same
            // text directly and never becomes an event, so an arm that
            // rendered this would only ever double it. Every service verb
            // that *changes* something reports through `ok`, `info` and
            // `failed`, which are relayed above.
            "packages" | "installed" | "results" | "service" => {}
            // Emitted alongside the text that describes them, so relaying
            // them would duplicate it: the removal plan paints itself in
            // JSON mode (unlike the install plan above), the pacnew warning
            // is printed from the install loop, and the rest announce
            // themselves through a spinner or a warning first.
            "removal_plan"
            | "pacnew"
            | "transaction_hook"
            | "build_tree_handover"
            | "rollback_plan"
            | "rollback_done" => {}
            // Emitted only by commands that do not go through rvnd, so these
            // never arrive on this socket: `rvn build`, `rvn repo-add`,
            // `rvn cache`, `rvn config`, and the bare reporting form of
            // `rvn rollback`, which needs no root and is run in-process.
            "built" | "repo_db" | "cache" | "cache_clean" | "pacnew_diff" | "pacnew_refused"
            | "pacnew_resolved" | "rollback_available" => {}
            // An rvn newer than this client, which is possible whenever the
            // daemon's binary and the caller's differ. Silence is right:
            // the transaction is rvn's to run, and the event stream is not
            // the place to complain about vocabulary.
            _ => {}
        }
    }

    /// Ends the running stage, or reports the verdict on its own if the
    /// stream never announced a stage to end.
    fn settle(&mut self, ok: bool, message: &str) {
        match (self.spinner.take(), ok) {
            (Some(s), true) => s.succeed(message),
            (Some(s), false) => s.fail(message),
            (None, true) => self.ui.ok(message),
            (None, false) => self.ui.err(message),
        }
    }

    /// Repaints `ops::install`'s transaction summary from the `plan` event.
    ///
    /// The wording and the layout are that function's, copied rather than
    /// shared because the two sides hold different things: it has the
    /// resolved packages, and this has only what the event carries. If one
    /// changes, the other is meant to change with it -- which is the price of
    /// a daemon whose client is the same terminal interface.
    fn show_plan(&self, v: &serde_json::Value) {
        use crate::ui::theme::{Color, bytes, bytes_signed};
        let s = &self.ui.style;
        let entries = v["install"].as_array().cloned().unwrap_or_default();

        let render = |p: &serde_json::Value| {
            let origin = s.paint(
                if p["aur"].as_bool().unwrap_or(false) {
                    Color::Cyan
                } else {
                    Color::Violet
                },
                p["origin"].as_str().unwrap_or(""),
            );
            let name = s.bold(p["name"].as_str().unwrap_or(""));
            let version = s.paint(Color::Green, p["version"].as_str().unwrap_or(""));
            match p["installed_version"].as_str() {
                Some(old) => format!(
                    "{origin}/{name} {} {} {version}",
                    s.dim(old),
                    s.glyphs.arrow
                ),
                None => format!("{origin}/{name} {version}"),
            }
        };

        self.ui.blank();

        let (explicit, implicit): (Vec<_>, Vec<_>) = entries
            .iter()
            .partition(|p| p["explicit"].as_bool().unwrap_or(false));

        if !explicit.is_empty() {
            self.ui.step("packages requested");
            self.ui
                .tree(&explicit.iter().map(|p| render(p)).collect::<Vec<_>>());
        }
        if !implicit.is_empty() {
            self.ui.step(&format!("dependencies ({})", implicit.len()));
            self.ui
                .tree(&implicit.iter().map(|p| render(p)).collect::<Vec<_>>());
        }

        let replacing = v["replacing"].as_array().cloned().unwrap_or_default();
        if !replacing.is_empty() {
            self.ui.step(&format!("replacing ({})", replacing.len()));
            self.ui.tree(
                &replacing
                    .iter()
                    .map(|r| {
                        format!(
                            "{} {} {}",
                            s.bold(r["old"].as_str().unwrap_or("")),
                            s.glyphs.arrow,
                            s.paint(Color::Green, r["new"].as_str().unwrap_or(""))
                        )
                    })
                    .collect::<Vec<_>>(),
            );
        }

        self.ui.blank();
        let aur = v["build_from_source"].as_u64().unwrap_or(0);
        self.ui.info(&format!(
            "download {}   installed size {}{}",
            s.bold(&bytes(v["download_size"].as_u64().unwrap_or(0))),
            s.bold(&bytes_signed(
                v["installed_size_delta"].as_i64().unwrap_or(0)
            )),
            if aur > 0 {
                format!(
                    "   {} to build from source",
                    s.paint(Color::Cyan, &aur.to_string())
                )
            } else {
                String::new()
            }
        ));
        self.ui.blank();
    }

    /// Repaints `ops::update`'s candidate list from the `updates` event.
    fn show_updates(&self, v: &serde_json::Value) {
        use crate::ui::theme::{Color, bytes};
        let s = &self.ui.style;

        let render = |c: &serde_json::Value| {
            let kind = c["kind"].as_str().unwrap_or("");
            let origin = s.paint(
                if c["aur"].as_bool().unwrap_or(false) {
                    Color::Cyan
                } else {
                    Color::Violet
                },
                c["origin"].as_str().unwrap_or(""),
            );
            let name = s.bold(c["name"].as_str().unwrap_or(""));
            let installed = s.dim(c["installed_version"].as_str().unwrap_or(""));
            // A devel package's "new version" is not known until it is built,
            // so only the installed one is shown.
            let mut line = if kind == "devel" {
                format!("{origin}/{name} {installed}")
            } else {
                format!(
                    "{origin}/{name} {installed} {} {}",
                    s.glyphs.arrow,
                    s.paint(Color::Green, c["new_version"].as_str().unwrap_or(""))
                )
            };
            match kind {
                "replacement" => line.push_str(&format!(
                    " {}",
                    s.paint(
                        Color::Amber,
                        &format!("(replaces {})", c["replaces"].as_str().unwrap_or(""))
                    )
                )),
                "devel" => line.push_str(&format!(
                    " {}",
                    s.paint(Color::Cyan, "(upstream moved — rebuild)")
                )),
                _ => {}
            }
            line
        };

        let applicable = v["candidates"].as_array().cloned().unwrap_or_default();
        let downgrades = v["downgrades"].as_array().cloned().unwrap_or_default();

        self.ui.blank();

        if !applicable.is_empty() {
            self.ui
                .step(&format!("updates to apply ({})", applicable.len()));
            self.ui
                .tree(&applicable.iter().map(&render).collect::<Vec<_>>());

            self.ui.blank();
            let aur = applicable
                .iter()
                .filter(|c| c["aur"].as_bool().unwrap_or(false))
                .count();
            self.ui.info(&format!(
                "download {}{}",
                s.bold(&bytes(v["download_size"].as_u64().unwrap_or(0))),
                if aur > 0 {
                    format!(
                        "   {} to rebuild from source",
                        s.paint(Color::Cyan, &aur.to_string())
                    )
                } else {
                    String::new()
                }
            ));
        }

        if !downgrades.is_empty() {
            self.ui.blank();
            self.ui.warn(&format!(
                "{} installed package{} newer than the repositories carry (skipped):",
                downgrades.len(),
                if downgrades.len() == 1 {
                    " is"
                } else {
                    "s are"
                }
            ));
            self.ui
                .tree(&downgrades.iter().map(render).collect::<Vec<_>>());
            self.ui
                .info("install a specific version explicitly to move backwards");
        }

        self.ui.blank();
    }

    /// Settle anything still animating, so a stream that ended without a
    /// closing stage leaves a clean terminal.
    pub fn finish(mut self) {
        if let Some(s) = self.spinner.take() {
            s.clear();
        }
        self.progress.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    /// Every event name `ui::Ui::emit` or `ui::json::emit` is called with
    /// anywhere in this crate, and therefore every name that can reach
    /// `Replay::event` over the socket.
    ///
    /// Kept beside the test that regenerates it from the source below. It is
    /// here so that `Replay`'s match can be read against a list rather than
    /// against a grep somebody has to think to run -- the gap this closes is
    /// that `stage_done` went unhandled for as long as it existed, which
    /// meant no spinner in an rvnd-driven transaction ever settled.
    ///
    /// Three names are not in it and are handled all the same: `done`,
    /// `failed` and `exit` also come from the daemon's own `emit_line`, and
    /// the six message kinds -- ok, err, warn, info, step, detail -- come out
    /// of `ui::json::message`, which is called with a variable.
    const UI_EVENTS: &[&str] = &[
        "banner",
        "build_tree_handover",
        "built",
        "cache",
        "cache_clean",
        "done",
        "failed",
        "installed",
        "packages",
        "pacnew",
        "pacnew_diff",
        "pacnew_refused",
        "pacnew_resolved",
        "plan",
        "progress",
        "progress_done",
        "removal_plan",
        "repo_db",
        "results",
        "rollback_available",
        "rollback_done",
        "rollback_plan",
        "service",
        "stage",
        "stage_done",
        "transaction_hook",
        "tree",
        "updates",
    ];

    /// Every string literal passed as the first argument to an `emit(` call
    /// in `src`, read out of the source itself.
    fn emitted_in_the_source() -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        let mut stack = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                // Spelled in two pieces so that this scanner does not find
                // itself: the needle must not appear verbatim in the source
                // it is about to read.
                let needle = concat!("emit", "(");
                for (at, _) in text.match_indices(needle) {
                    // The name may sit on the next line, which is how every
                    // multi-line event in this crate is written.
                    let rest = text[at + needle.len()..].trim_start();
                    // Anything else is a definition or a forwarded variable.
                    let Some(rest) = rest.strip_prefix('"') else {
                        continue;
                    };
                    let Some(end) = rest.find('"') else {
                        continue;
                    };
                    names.push(rest[..end].to_string());
                }
            }
        }
        names.sort();
        names.dedup();
        names
    }

    /// The audit itself: adding an event to this crate without deciding what
    /// `Replay` should do with it fails here.
    ///
    /// "Do nothing" is a perfectly good decision and several events have it,
    /// but it has to be written down in the match rather than fallen into,
    /// because the failure mode is silent -- a client driving rvn through
    /// rvnd simply never sees something a client running it directly does.
    #[test]
    fn every_event_the_crate_emits_is_accounted_for_in_replay() {
        let found = emitted_in_the_source();
        // A test binary run away from its source proves nothing here; it must
        // not fail either.
        if found.is_empty() {
            return;
        }
        let known: Vec<String> = UI_EVENTS.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            found, known,
            "the events this crate emits have changed; \
             decide what Replay::event should do with each new one, add it to \
             the match (doing nothing is fine, if it is written down), and \
             list it here"
        );
    }

    /// Regression: a stage used to be torn down and restarted on every change
    /// of its message, and `stage_done` -- the only thing that ever settles
    /// one -- had no arm at all, so an install through rvnd showed a stream
    /// of spinners and never a single completed step.
    #[test]
    fn a_stage_is_updated_in_place_and_settled_by_stage_done() {
        let ui = crate::ui::Ui::plain();
        let mut replay = Replay::new(&ui, false);

        replay.event(r#"{"event":"stage","message":"resolving"}"#);
        assert!(replay.spinner.is_some(), "a stage starts a spinner");

        replay.event(r#"{"event":"stage","message":"resolving — huginn"}"#);
        assert!(
            replay.spinner.is_some(),
            "a change of message updates the running spinner rather than replacing it"
        );

        replay.event(r#"{"event":"stage_done","message":"resolved","ok":true,"ms":9}"#);
        assert!(replay.spinner.is_none(), "stage_done settles the spinner");

        // A verdict with no stage in front of it is still reported, which is
        // what `Ui::ok`/`Ui::err` do when there was no spinner to settle.
        replay.event(r#"{"event":"stage_done","message":"failed","ok":false}"#);
        assert!(replay.spinner.is_none());
    }

    /// Every name in the vocabulary, through `Replay`, to prove the match
    /// reads each one without reaching for a field that is not there.
    #[test]
    fn replay_survives_every_event_name_with_an_empty_payload() {
        let ui = crate::ui::Ui::plain();
        let mut replay = Replay::new(&ui, false);
        for event in UI_EVENTS
            .iter()
            .chain(["exit", "ok", "err", "warn", "info", "step", "detail"].iter())
        {
            replay.event(&format!(r#"{{"event":"{event}"}}"#));
        }
        replay.finish();
    }

    #[test]
    fn package_names_are_checked() {
        for ok in [
            "seatd",
            "libinput",
            "brave-bin",
            "python-freetype-py",
            "foo>=1.2",
            "lib32-x",
            "a_b",
        ] {
            assert!(valid_package_name(ok), "{ok}");
        }
        for bad in ["", "-y", "--config", "a b", "x;rm", "../etc", "a$b"] {
            assert!(!valid_package_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn requests_become_a_fixed_argv() {
        let r = Request {
            op: Some(Op::Install),
            packages: vec!["seatd".into(), "libinput".into()],
            dry_run: true,
            repo_only: true,
            ..Default::default()
        };
        assert_eq!(
            r.validate().unwrap().argv(),
            vec![
                "--json",
                "--yes",
                "--repo-only",
                "install",
                "--dry-run",
                "seatd",
                "libinput"
            ]
        );
        let r = Request {
            op: Some(Op::Uninstall),
            packages: vec!["foo".into()],
            cascade: true,
            keep_orphans: true,
            ..Default::default()
        };
        assert_eq!(
            r.validate().unwrap().argv(),
            vec![
                "--json",
                "--yes",
                "uninstall",
                "--cascade",
                "--keep-orphans",
                "foo"
            ]
        );
        let r = Request {
            op: Some(Op::Uninstall),
            packages: vec!["foo".into()],
            remove_orphans: true,
            ..Default::default()
        };
        assert_eq!(
            r.validate().unwrap().argv(),
            vec!["--json", "--yes", "uninstall", "--remove-orphans", "foo"]
        );
        let r = Request {
            op: Some(Op::Sync),
            ..Default::default()
        };
        assert_eq!(r.validate().unwrap().argv(), vec!["--json", "--yes", "sync"]);
        let r = Request {
            op: Some(Op::Update),
            no_refresh: true,
            ..Default::default()
        };
        assert_eq!(
            r.validate().unwrap().argv(),
            vec!["--json", "--yes", "update", "--no-refresh"]
        );
        let r = Request {
            op: Some(Op::Rollback),
            packages: vec!["huginn".into()],
            ..Default::default()
        };
        assert_eq!(
            r.validate().unwrap().argv(),
            vec!["--json", "--yes", "rollback", "huginn"]
        );
        let r = Request {
            op: Some(Op::Rollback),
            packages: vec!["huginn".into()],
            dry_run: true,
            ..Default::default()
        };
        assert_eq!(
            r.validate().unwrap().argv(),
            vec!["--json", "--yes", "rollback", "--dry-run", "huginn"]
        );
    }

    #[test]
    fn a_service_request_becomes_a_service_plan() {
        let r = Request {
            op: Some(Op::Service),
            service: Some("faced".into()),
            action: Some(ServiceAction::Enable),
            ..Default::default()
        };
        assert_eq!(
            r.validate().unwrap(),
            Plan::Service {
                action: ServiceAction::Enable,
                name: "faced".into(),
            }
        );
        // And it never produces an argv, because nothing runs rvn for it.
        assert!(r.validate().unwrap().argv().is_empty());
    }

    /// The request goes out as one line of JSON and comes back as one line of
    /// text that PID 1 splits on whitespace. A name that could put a second
    /// word on that line is refused here, before anything holds a socket to
    /// init.
    #[test]
    fn a_service_request_is_refused_before_it_can_reach_init() {
        let service = |name: &str| Request {
            op: Some(Op::Service),
            service: Some(name.into()),
            action: Some(ServiceAction::Start),
            ..Default::default()
        };
        assert!(service("faced").validate().is_ok());
        assert!(service("faced stop").validate().is_err());
        assert!(service("../../etc/shadow").validate().is_err());
        assert!(service("").validate().is_err());

        // Both halves are required: an action with nothing to act on, and a
        // service with nothing to do to it, are each a request that would be
        // authorized and then mean nothing.
        assert!(
            Request {
                op: Some(Op::Service),
                action: Some(ServiceAction::Start),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Request {
                op: Some(Op::Service),
                service: Some("faced".into()),
                ..Default::default()
            }
            .validate()
            .is_err()
        );

        // A service request carries no package list. Refusing one that does
        // is not about what the list could do -- nothing reads it on this
        // path -- but about not authorizing a request whose two halves say
        // different things.
        assert!(
            Request {
                op: Some(Op::Service),
                service: Some("faced".into()),
                action: Some(ServiceAction::Start),
                packages: vec!["linux".into()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }

    /// The bound on this class: a name is answered for only if root already
    /// put a definition of it on disk.
    #[test]
    fn only_a_service_this_machine_defines_can_be_named() {
        // Nothing ships a definition called this, whatever machine the suite
        // is running on.
        assert!(service_definition_path("definitely-not-a-raven-service").is_none());
        // And a name that could escape the directory never gets as far as
        // looking.
        assert!(service_definition_path("../../etc/shadow").is_none());
    }

    #[test]
    fn a_service_action_is_named_on_the_wire_and_in_the_log() {
        let plan = Plan::Service {
            action: ServiceAction::Enable,
            name: "faced".into(),
        };
        assert_eq!(plan.describe(), "service enable faced");
        // The wire form is the lowercase word, which is what a front-end
        // writing JSON by hand would guess.
        let r: Request = serde_json::from_str(
            r#"{"op":"service","service":"faced","action":"enable"}"#,
        )
        .expect("parses");
        assert_eq!(r.action, Some(ServiceAction::Enable));
        assert_eq!(r.op, Some(Op::Service));
    }

    /// A rollback is one package or it is nothing. The bare form reports and
    /// is never sent here, and rolling several packages back at once is not
    /// something the command offers, so a request for it would produce an
    /// argv rvn would reject after the daemon had already granted root.
    #[test]
    fn a_rollback_names_exactly_one_package() {
        for packages in [vec![], vec!["a".to_string(), "b".to_string()]] {
            assert!(
                Request {
                    op: Some(Op::Rollback),
                    packages,
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn bad_requests_are_refused_before_anything_runs() {
        assert!(Request::default().validate().is_err());
        assert!(
            Request {
                op: Some(Op::Install),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Request {
                op: Some(Op::Install),
                packages: vec!["--config".into()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Request {
                op: Some(Op::Sync),
                dry_run: true,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        // The wire format has no way to name a config file at all.
        let r: Result<Request, _> =
            serde_json::from_str(r#"{"op":"install","packages":["x"],"config":"/tmp/evil"}"#);
        assert!(r.is_ok(), "unknown fields are ignored, not honoured");
        assert_eq!(
            r.unwrap().validate().unwrap().argv(),
            vec!["--json", "--yes", "install", "x"]
        );
    }

    /// Every test that stands a daemon up shares two process-wide things --
    /// the BUSY lock and the authorization cache -- so they run one at a
    /// time. Without this, one test's transaction makes another's request
    /// come back "another rvn transaction is running", and one test's
    /// answered prompt authorizes another test's install.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    /// A daemon on a temporary socket with a stand-in rvn, plus somewhere to
    /// put its audit log. Every test here works in its own directory under
    /// the system temp dir and writes nothing to the machine's own /var or
    /// /run.
    struct Harness {
        dir: PathBuf,
        socket: PathBuf,
        audit: PathBuf,
    }

    impl Harness {
        fn start(name: &str, mut policy: crate::policy::Policy) -> Harness {
            let dir = std::env::temp_dir().join(format!(
                "rvnd-test-{}-{name}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).unwrap();
            let fake = dir.join("rvn");
            std::fs::write(
                &fake,
                "#!/bin/sh\n\
                 echo \"{\\\"event\\\":\\\"banner\\\",\\\"version\\\":\\\"test\\\"}\"\n\
                 echo \"{\\\"event\\\":\\\"info\\\",\\\"message\\\":\\\"args: $*\\\"}\"\n\
                 echo \"{\\\"event\\\":\\\"info\\\",\\\"message\\\":\\\"requester: ${SUDO_USER:-none}\\\"}\"\n\
                 case \"$*\" in *fail*) echo \"{\\\"event\\\":\\\"failed\\\",\\\"message\\\":\\\"as asked\\\"}\"; exit 1;; esac\n\
                 echo \"{\\\"event\\\":\\\"done\\\"}\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();

            let audit = dir.join("rvnd.log");
            policy.audit_log = audit.clone();
            policy.source = dir.join("rvnd.toml");
            let config = ServerConfig {
                socket: dir.join("ctl"),
                group: None,
                rvn: fake,
                policy,
            };
            let listener = bind(&config).unwrap();
            let socket = config.socket.clone();
            std::thread::spawn(move || serve(config, listener));
            Harness { dir, socket, audit }
        }

        /// Send a request and collect every event line it produced.
        fn send(&self, req: &Request) -> (Result<(), String>, Vec<String>) {
            let mut lines = Vec::new();
            let outcome = request(&self.socket, req, |l| lines.push(l.to_string()));
            (outcome, lines)
        }

        fn audit_log(&self) -> String {
            std::fs::read_to_string(&self.audit).unwrap_or_default()
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    /// A policy with nothing to connect to, so `auth` is always the
    /// "unavailable" path -- which is the state of every machine whose
    /// ravend does not answer authorization prompts yet.
    fn no_prompt_available() -> crate::policy::Policy {
        crate::policy::Policy {
            auth_socket: std::env::temp_dir().join("rvnd-test-no-such-authorize.sock"),
            ..crate::policy::Policy::default()
        }
    }

    /// End to end without root: a daemon on a temporary socket, a stand-in
    /// rvn that prints what it was asked and a scripted event stream, and the
    /// real client.
    #[test]
    fn a_request_round_trips_through_the_daemon() {
        let _serialised = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        AUTH_CACHE.clear();
        let h = Harness::start("roundtrip", no_prompt_available());

        assert_eq!(reach(&h.socket), Reach::Ok);

        let req = Request {
            op: Some(Op::Install),
            packages: vec!["seatd".into()],
            dry_run: true,
            ..Default::default()
        };
        let (outcome, lines) = h.send(&req);
        outcome.expect("succeeds");
        let joined = lines.join("\n");
        assert!(
            joined.contains("args: --json --yes install --dry-run seatd"),
            "{joined}"
        );
        // rvnd tells rvn who asked, for the scriptlets that inherit it.
        let me = std::env::var("USER").unwrap_or_default();
        if !me.is_empty() {
            assert!(joined.contains(&format!("requester: {me}")), "{joined}");
        }

        let req = Request {
            op: Some(Op::Install),
            packages: vec!["fail".into()],
            ..Default::default()
        };
        let (outcome, _) = h.send(&req);
        assert_eq!(outcome.unwrap_err(), "as asked");

        // A refused request never reaches the stand-in.
        let req = Request {
            op: Some(Op::Install),
            packages: vec!["--config".into()],
            ..Default::default()
        };
        let (outcome, lines) = h.send(&req);
        let err = outcome.unwrap_err();
        assert!(err.contains("refusing"), "{err}");
        assert!(!lines.iter().any(|l| l.contains("args:")), "{lines:?}");

        assert_eq!(reach(&h.dir.join("nowhere")), Reach::Absent);
    }

    /// Every request that reaches the daemon leaves a line behind, including
    /// the one that was thrown out before an argv existed for it.
    #[test]
    fn every_request_is_written_down_including_the_refused_ones() {
        let _serialised = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        AUTH_CACHE.clear();
        let h = Harness::start("audit", no_prompt_available());

        h.send(&Request {
            op: Some(Op::Sync),
            ..Default::default()
        })
        .0
        .expect("a sync is a query and needs nobody's agreement");
        h.send(&Request {
            op: Some(Op::Install),
            packages: vec!["--config".into()],
            ..Default::default()
        })
        .0
        .unwrap_err();

        let log = h.audit_log();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "{log}");

        assert!(
            lines[0].contains("] [RVND] allowed op=sync class=query rule=allow auth=not-required"),
            "{log}"
        );
        assert!(
            lines[0].contains(&format!("pid={}", std::process::id())),
            "{log}"
        );
        // The exe path is this test binary, read from /proc.
        assert!(lines[0].contains("exe=\"/"), "{log}");

        assert!(lines[1].contains("refused op=install"), "{log}");
        assert!(lines[1].contains("auth=malformed"), "{log}");
        assert!(lines[1].contains("packages=--config"), "{log}");

        // A line that is not a request at all still leaves a record, with
        // whatever there was to record.
        {
            use std::io::Write as _;
            let mut raw = UnixStream::connect(&h.socket).unwrap();
            writeln!(raw, "this is not json").unwrap();
            let mut reply = String::new();
            raw.read_to_string(&mut reply).ok();
            assert!(reply.contains("bad request"), "{reply}");
        }
        let log = h.audit_log();
        assert_eq!(log.lines().count(), 3, "{log}");
        assert!(
            log.lines().nth(2).unwrap().contains("refused op=- class=-"),
            "{log}"
        );

        // A probe -- a connection that says nothing -- is not a request and
        // must not fill the log with noise.
        assert_eq!(reach(&h.socket), Reach::Ok);
        assert_eq!(h.audit_log().lines().count(), 3, "{}", h.audit_log());
    }

    /// The uncomfortable default, pinned down so nobody changes it by
    /// accident: with nothing able to raise a prompt, the transaction goes
    /// ahead, the client is told, and the log says `auth=unavailable`.
    #[test]
    fn an_unaskable_prompt_allows_loudly_by_default() {
        let _serialised = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        AUTH_CACHE.clear();
        let h = Harness::start("unavailable-allow", no_prompt_available());

        let (outcome, lines) = h.send(&Request {
            op: Some(Op::Install),
            packages: vec!["brave-bin".into()],
            ..Default::default()
        });
        outcome.expect("the desktop keeps working");
        let joined = lines.join("\n");
        assert!(
            joined.contains("could not ask anyone to authorize"),
            "{joined}"
        );
        assert!(joined.contains("\"event\":\"warn\""), "{joined}");

        let log = h.audit_log();
        assert!(
            log.contains("allowed op=install class=aur rule=auth auth=unavailable"),
            "{log}"
        );
    }

    /// And the other half of that setting: once an administrator has decided
    /// prompts work on this machine, the same request is refused with a
    /// message that names the file they would change to undo it.
    #[test]
    fn an_unaskable_prompt_refuses_when_the_policy_says_so() {
        let _serialised = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        AUTH_CACHE.clear();
        let h = Harness::start(
            "unavailable-deny",
            crate::policy::Policy {
                on_auth_unavailable: crate::policy::Unavailable::Deny,
                ..no_prompt_available()
            },
        );

        let (outcome, lines) = h.send(&Request {
            op: Some(Op::Install),
            packages: vec!["brave-bin".into()],
            ..Default::default()
        });
        let err = outcome.unwrap_err();
        assert!(err.contains("needs someone to authorize it"), "{err}");
        assert!(err.contains("rvnd.toml"), "{err}");
        assert!(!lines.iter().any(|l| l.contains("args:")), "{lines:?}");
        assert!(
            h.audit_log()
                .contains("refused op=install class=aur rule=auth auth=unavailable")
        );

        // The plan phase must still work, or the terminal client can never
        // show anybody the plan they are being asked to authorize.
        let (outcome, lines) = h.send(&Request {
            op: Some(Op::Install),
            packages: vec!["brave-bin".into()],
            dry_run: true,
            ..Default::default()
        });
        outcome.expect("a dry run is a query");
        assert!(lines.iter().any(|l| l.contains("args:")), "{lines:?}");
    }

    /// A caller whose session cannot be resolved, on a machine where nothing
    /// is listening for prompts.
    ///
    /// This is every graphical session on a machine whose init leaves its
    /// services in session 0: the store's `rvn` is in a session whose leader
    /// is pid 0 and `/proc` has nothing to read for it. Refusing it while the
    /// same request from a terminal -- which has a session leader, finds no
    /// ravend, and is allowed by `on_auth_unavailable` -- goes through is the
    /// split this checks against.
    #[test]
    fn no_session_and_no_ravend_is_a_missing_mechanism_not_a_missing_asker() {
        let policy = crate::policy::Policy {
            auth_socket: std::env::temp_dir().join("rvnd-no-such-ravend.sock"),
            ..crate::policy::Policy::default()
        };
        std::fs::remove_file(&policy.auth_socket).ok();
        let config = ServerConfig {
            socket: PathBuf::from("/nonexistent/ctl"),
            group: None,
            rvn: PathBuf::from("/nonexistent/rvn"),
            policy,
        };
        let request = Request {
            op: Some(Op::Install),
            packages: vec!["brave-bin".into()],
            ..Default::default()
        };
        let cred = Ucred {
            pid: std::process::id() as i32,
            uid: 1000,
            gid: 1000,
        };

        let decision = decide(
            &config,
            &cred,
            Some("someone"),
            &request,
            crate::policy::Class::Aur,
            None,
        );
        assert!(decision.allowed, "{}", decision.reason);
        assert_eq!(decision.how, "unavailable");
        assert!(decision.warning.is_some(), "an allow nobody authorized says so");
    }

    /// The same caller, on a machine where a ravend *is* listening.
    ///
    /// Here the mechanism exists and the only thing missing is somebody to
    /// prompt, so the refusal stands: a process that exits the moment it has
    /// asked must not be a way past a prompt that could have been raised.
    #[test]
    fn no_session_with_a_ravend_listening_is_still_refused() {
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("rvnd-nosession-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prompt = dir.join("authorize.sock");
        std::fs::remove_file(&prompt).ok();
        let _listener = UnixListener::bind(&prompt).unwrap();

        let config = ServerConfig {
            socket: PathBuf::from("/nonexistent/ctl"),
            group: None,
            rvn: PathBuf::from("/nonexistent/rvn"),
            policy: crate::policy::Policy {
                auth_socket: prompt,
                ..crate::policy::Policy::default()
            },
        };
        let request = Request {
            op: Some(Op::Install),
            packages: vec!["brave-bin".into()],
            ..Default::default()
        };
        let cred = Ucred {
            pid: std::process::id() as i32,
            uid: 1000,
            gid: 1000,
        };

        let decision = decide(
            &config,
            &cred,
            Some("someone"),
            &request,
            crate::policy::Class::Aur,
            None,
        );
        assert!(!decision.allowed, "{}", decision.reason);
        assert_eq!(decision.how, "session");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The prompt itself, against a stand-in ravend: one request is asked,
    /// answered and remembered, and the next request in the same session is
    /// not asked again.
    #[test]
    fn an_answered_prompt_runs_the_transaction_and_counts_for_the_session() {
        use std::os::unix::net::UnixListener;

        let _serialised = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        AUTH_CACHE.clear();

        let dir = std::env::temp_dir().join(format!("rvnd-prompt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prompt = dir.join("authorize.sock");
        std::fs::remove_file(&prompt).ok();
        let listener = UnixListener::bind(&prompt).unwrap();

        let asked = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let recorded = std::sync::Arc::clone(&asked);
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let mut conn = conn;
                let mut header = [0u8; 4];
                if conn.read_exact(&mut header).is_err() {
                    continue;
                }
                let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
                if conn.read_exact(&mut body).is_err() {
                    continue;
                }
                if let Ok(value) = serde_json::from_slice(&body) {
                    recorded.lock().unwrap().push(value);
                }
                let reply = br#"{"response":"granted"}"#;
                let _ = conn.write_all(&(reply.len() as u32).to_be_bytes());
                let _ = conn.write_all(reply);
            }
        });

        let h = Harness::start(
            "prompt",
            crate::policy::Policy {
                auth_socket: prompt.clone(),
                auth_timeout_seconds: 5,
                ..crate::policy::Policy::default()
            },
        );

        let req = Request {
            op: Some(Op::Install),
            packages: vec!["brave-bin".into()],
            ..Default::default()
        };
        let (outcome, lines) = h.send(&req);
        outcome.expect("granted");
        assert!(lines.iter().any(|l| l.contains("args:")), "{lines:?}");

        let (outcome, _) = h.send(&req);
        outcome.expect("granted again, without asking again");

        let asked = asked.lock().unwrap();
        assert_eq!(
            asked.len(),
            1,
            "the second request reused the answer: {asked:?}"
        );
        assert_eq!(asked[0]["request"], "authorize");
        assert_eq!(asked[0]["class"], "aur");
        assert_eq!(asked[0]["action"], "install");
        assert_eq!(asked[0]["packages"][0], "brave-bin");

        let log = h.audit_log();
        assert!(
            log.contains("allowed op=install class=aur rule=auth auth=prompt"),
            "{log}"
        );
        assert!(
            log.contains("allowed op=install class=aur rule=auth auth=cached"),
            "{log}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A prompt that was answered "no" is a refusal, and nothing runs.
    #[test]
    fn a_declined_prompt_refuses() {
        use std::os::unix::net::UnixListener;

        let _serialised = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        AUTH_CACHE.clear();

        let dir = std::env::temp_dir().join(format!("rvnd-declined-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prompt = dir.join("authorize.sock");
        std::fs::remove_file(&prompt).ok();
        let listener = UnixListener::bind(&prompt).unwrap();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let mut conn = conn;
                let mut header = [0u8; 4];
                if conn.read_exact(&mut header).is_err() {
                    continue;
                }
                let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
                let _ = conn.read_exact(&mut body);
                let reply = br#"{"response":"denied","reason":"the prompt was dismissed"}"#;
                let _ = conn.write_all(&(reply.len() as u32).to_be_bytes());
                let _ = conn.write_all(reply);
            }
        });

        let h = Harness::start(
            "declined",
            crate::policy::Policy {
                auth_socket: prompt,
                auth_timeout_seconds: 5,
                ..crate::policy::Policy::default()
            },
        );

        let (outcome, lines) = h.send(&Request {
            op: Some(Op::Uninstall),
            packages: vec!["seatd".into()],
            ..Default::default()
        });
        let err = outcome.unwrap_err();
        assert!(err.contains("the prompt was dismissed"), "{err}");
        assert!(!lines.iter().any(|l| l.contains("args:")), "{lines:?}");
        assert!(
            h.audit_log()
                .contains("refused op=uninstall class=repo rule=auth auth=denied")
        );

        // A refusal is not remembered: the next request asks again.
        let (outcome, _) = h.send(&Request {
            op: Some(Op::Uninstall),
            packages: vec!["seatd".into()],
            ..Default::default()
        });
        assert!(outcome.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A policy of "deny" refuses without asking anybody anything, and says
    /// which file said so.
    #[test]
    fn a_class_switched_off_is_refused_without_a_prompt() {
        let _serialised = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        AUTH_CACHE.clear();
        let h = Harness::start(
            "denied-class",
            crate::policy::Policy {
                aur: crate::policy::Rule::Deny,
                repo: crate::policy::Rule::Allow,
                ..no_prompt_available()
            },
        );

        let (outcome, _) = h.send(&Request {
            op: Some(Op::Install),
            packages: vec!["brave-bin".into()],
            ..Default::default()
        });
        let err = outcome.unwrap_err();
        assert!(err.contains("aur operations are switched off"), "{err}");
        assert!(err.contains("rvnd.toml"), "{err}");

        // ...while the class the same policy allows still runs, untouched.
        let (outcome, lines) = h.send(&Request {
            op: Some(Op::Install),
            packages: vec!["seatd".into()],
            repo_only: true,
            ..Default::default()
        });
        outcome.expect("repo = allow");
        assert!(lines.iter().any(|l| l.contains("--repo-only")), "{lines:?}");
        assert!(
            h.audit_log()
                .contains("allowed op=install class=repo rule=allow auth=not-required")
        );
    }

    /// The group check can only ever refuse somebody the socket mode already
    /// let through, so what matters is that it reads /etc/group the way
    /// `id -nG` does and refuses a group that is not there at all.
    #[test]
    fn group_membership_is_the_primary_gid_or_the_member_list() {
        let text = std::fs::read_to_string("/etc/group").unwrap_or_default();
        let Some((name, gid)) = text.lines().find_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?.to_string();
            f.next();
            let gid: u32 = f.next()?.parse().ok()?;
            Some((name, gid))
        }) else {
            return; // A machine with no /etc/group has nothing to assert.
        };

        let cred = Ucred {
            pid: 0,
            uid: 12345,
            gid,
        };
        assert!(peer_is_in_group(&cred, None, &name), "primary gid counts");

        let elsewhere = Ucred {
            gid: gid.wrapping_add(4242),
            ..cred
        };
        assert!(
            !peer_is_in_group(&elsewhere, Some("nobody-by-this-name"), &name),
            "neither the gid nor the member list"
        );
        assert!(
            !peer_is_in_group(&cred, None, "a-group-that-does-not-exist"),
            "a group that is not there is not a group anybody is in"
        );
    }
}
