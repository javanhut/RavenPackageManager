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
//! daemon runs with the system's. The build identity for AUR packages is the
//! requesting user, the same account `sudo rvn` would have used, so build
//! trees and caches stay owned by a person.
//!
//! The group is `wheel` by default. Installing packages is root-equivalent
//! (hooks run as root), so the group has to be the administrators' group;
//! what this buys is one auditable door and no password ceremony, not less
//! power. The socket file's mode is the whole of the access control: the
//! kernel refuses the connect, and there is nothing to bypass.

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
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Install => "install",
            Op::Uninstall => "uninstall",
            Op::Update => "update",
            Op::Sync => "sync",
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
    #[serde(default)]
    pub nodeps: bool,
    // update
    #[serde(default)]
    pub no_refresh: bool,
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
    /// The argv the daemon hands to rvn for this request, or why it refused.
    pub fn validate(&self) -> Result<Vec<String>, String> {
        let op = self.op.ok_or("request has no op")?;
        for name in &self.packages {
            if !valid_package_name(name) {
                return Err(format!("refusing package name {name:?}"));
            }
        }
        match op {
            Op::Install if self.packages.is_empty() => return Err("install needs packages".into()),
            Op::Uninstall if self.packages.is_empty() => {
                return Err("uninstall needs packages".into())
            }
            Op::Sync if self.dry_run => return Err("sync has no dry run".into()),
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
                if self.nodeps {
                    argv.push("--nodeps".into());
                }
            }
            Op::Update if self.no_refresh => argv.push("--no-refresh".into()),
            _ => {}
        }
        argv.extend(self.packages.iter().cloned());
        Ok(argv)
    }
}

// ----------------------------------------------------------------------------
// Server
// ----------------------------------------------------------------------------

/// How the daemon is configured, from rvnd's command line.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub socket: PathBuf,
    /// Group given the socket, or `None` to leave it as created (tests).
    pub group: Option<String>,
    /// The rvn binary to run as root.
    pub rvn: PathBuf,
}

/// Uid and gid of the peer, from SO_PEERCRED.
#[repr(C)]
#[derive(Default)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

unsafe extern "C" {
    fn getsockopt(fd: i32, level: i32, name: i32, value: *mut Ucred, len: *mut u32) -> i32;
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
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
    (rc == 0).then_some(cred.uid)
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

/// The gid of a group, from /etc/group.
fn group_id(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|line| {
        let mut f = line.split(':');
        (f.next()? == name).then(|| f.nth(1)?.parse().ok())?
    })
}

fn emit_line(stream: &mut UnixStream, event: &str, payload: serde_json::Value) {
    let mut v = payload;
    if let serde_json::Value::Object(map) = &mut v {
        map.insert("event".into(), serde_json::Value::String(event.into()));
    }
    let _ = writeln!(stream, "{v}");
    let _ = stream.flush();
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

/// One connection: read the request, validate it, run rvn with the socket
/// as its stdout, wait.
fn handle(config: &ServerConfig, mut stream: UnixStream) {
    let uid = peer_uid(&stream);
    let user = uid.and_then(user_name);
    let who = user.clone().unwrap_or_else(|| format!("uid {}", uid.map_or(-1, |u| u as i64)));

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
            emit_line(&mut stream, "failed", serde_json::json!({ "message": format!("bad request: {e}") }));
            return;
        }
    };
    let argv = match request.validate() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("rvnd: {who}: refused: {e}");
            emit_line(&mut stream, "failed", serde_json::json!({ "message": e }));
            return;
        }
    };

    let Ok(_guard) = BUSY.try_lock() else {
        eprintln!("rvnd: {who}: busy, refused: rvn {}", argv.join(" "));
        emit_line(
            &mut stream,
            "failed",
            serde_json::json!({ "message": "another rvn transaction is running; try again when it finishes" }),
        );
        return;
    };
    eprintln!("rvnd: {who}: rvn {}", argv.join(" "));

    let stdout = match stream.try_clone() {
        Ok(s) => Stdio::from(std::os::fd::OwnedFd::from(s)),
        Err(e) => {
            emit_line(&mut stream, "failed", serde_json::json!({ "message": format!("socket: {e}") }));
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
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C.UTF-8");
    // AUR builds run as the requester, the account `sudo rvn` would have
    // built as; see `build_identity` in ops::install.
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
            "stage" => match v["ok"].as_bool() {
                None => {
                    if let Some(s) = self.spinner.take() {
                        s.clear();
                    }
                    self.spinner = Some(self.ui.stage(&text("message")));
                }
                Some(true) => match self.spinner.take() {
                    Some(s) => s.succeed(&text("message")),
                    None => self.ui.ok(&text("message")),
                },
                Some(false) => match self.spinner.take() {
                    Some(s) => s.fail(&text("message")),
                    None => self.ui.err(&text("message")),
                },
            },
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
            // done / failed / exit are the request's result, handled by the
            // caller; data events (packages, installed, results) belong to
            // the read-only operations that never come this way.
            _ => {}
        }
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
    use super::*;

    #[test]
    fn package_names_are_checked() {
        for ok in ["seatd", "libinput", "brave-bin", "python-freetype-py", "foo>=1.2", "lib32-x", "a_b"] {
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
            r.validate().unwrap(),
            vec!["--json", "--yes", "--repo-only", "install", "--dry-run", "seatd", "libinput"]
        );
        let r = Request {
            op: Some(Op::Uninstall),
            packages: vec!["foo".into()],
            cascade: true,
            keep_orphans: true,
            ..Default::default()
        };
        assert_eq!(
            r.validate().unwrap(),
            vec!["--json", "--yes", "uninstall", "--cascade", "--keep-orphans", "foo"]
        );
        let r = Request { op: Some(Op::Sync), ..Default::default() };
        assert_eq!(r.validate().unwrap(), vec!["--json", "--yes", "sync"]);
        let r = Request { op: Some(Op::Update), no_refresh: true, ..Default::default() };
        assert_eq!(r.validate().unwrap(), vec!["--json", "--yes", "update", "--no-refresh"]);
    }

    #[test]
    fn bad_requests_are_refused_before_anything_runs() {
        assert!(Request::default().validate().is_err());
        assert!(Request { op: Some(Op::Install), ..Default::default() }.validate().is_err());
        assert!(Request {
            op: Some(Op::Install),
            packages: vec!["--config".into()],
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(Request { op: Some(Op::Sync), dry_run: true, ..Default::default() }
            .validate()
            .is_err());
        // The wire format has no way to name a config file at all.
        let r: Result<Request, _> = serde_json::from_str(r#"{"op":"install","packages":["x"],"config":"/tmp/evil"}"#);
        assert!(r.is_ok(), "unknown fields are ignored, not honoured");
        assert_eq!(r.unwrap().validate().unwrap(), vec!["--json", "--yes", "install", "x"]);
    }

    /// End to end without root: a daemon on a temporary socket, a stand-in
    /// rvn that prints what it was asked and a scripted event stream, and the
    /// real client.
    #[test]
    fn a_request_round_trips_through_the_daemon() {
        let dir = std::env::temp_dir().join(format!("rvnd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("rvn");
        std::fs::write(
            &fake,
            "#!/bin/sh\n\
             echo \"{\\\"event\\\":\\\"banner\\\",\\\"version\\\":\\\"test\\\"}\"\n\
             echo \"{\\\"event\\\":\\\"info\\\",\\\"message\\\":\\\"args: $*\\\"}\"\n\
             echo \"{\\\"event\\\":\\\"info\\\",\\\"message\\\":\\\"builder: ${SUDO_USER:-none}\\\"}\"\n\
             case \"$*\" in *fail*) echo \"{\\\"event\\\":\\\"failed\\\",\\\"message\\\":\\\"as asked\\\"}\"; exit 1;; esac\n\
             echo \"{\\\"event\\\":\\\"done\\\"}\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

        let config = ServerConfig {
            socket: dir.join("ctl"),
            group: None,
            rvn: fake,
        };
        let listener = bind(&config).unwrap();
        let socket = config.socket.clone();
        std::thread::spawn(move || serve(config, listener));

        assert_eq!(reach(&socket), Reach::Ok);

        let mut lines = Vec::new();
        let req = Request {
            op: Some(Op::Install),
            packages: vec!["seatd".into()],
            dry_run: true,
            ..Default::default()
        };
        request(&socket, &req, |l| lines.push(l.to_string())).expect("succeeds");
        let joined = lines.join("\n");
        assert!(joined.contains("args: --json --yes install --dry-run seatd"), "{joined}");
        // The requester is the build identity, resolved from the peer uid.
        let me = std::env::var("USER").unwrap_or_default();
        if !me.is_empty() {
            assert!(joined.contains(&format!("builder: {me}")), "{joined}");
        }

        let req = Request {
            op: Some(Op::Install),
            packages: vec!["fail".into()],
            ..Default::default()
        };
        let err = request(&socket, &req, |_| {}).unwrap_err();
        assert_eq!(err, "as asked");

        // A refused request never reaches the stand-in.
        let mut lines = Vec::new();
        let req = Request {
            op: Some(Op::Install),
            packages: vec!["--config".into()],
            ..Default::default()
        };
        let err = request(&socket, &req, |l| lines.push(l.to_string())).unwrap_err();
        assert!(err.contains("refusing"), "{err}");
        assert!(!lines.iter().any(|l| l.contains("args:")), "{lines:?}");

        assert_eq!(reach(&dir.join("nowhere")), Reach::Absent);
        std::fs::remove_dir_all(&dir).ok();
    }
}
