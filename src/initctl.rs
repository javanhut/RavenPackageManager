//! Asking raven-init to load and run what an install just put on disk.
//!
//! # The gap this closes
//!
//! `ops::install::activate_service_templates` copies a package's service
//! definition out of `/usr/share/raven/services` and into
//! `/etc/raven/init.d`, which is the directory raven-init folds into its
//! service list. It reads that directory exactly once, at boot. So installing
//! a daemon produced a definition nothing had read, a service `raven-rc
//! start` reported as "no such service", and a settings panel that could see
//! the hardware, could see the binary, and found no daemon running -- which
//! looks exactly like a daemon that crashed.
//!
//! The fix is one line of socket traffic at the end of an install: tell init
//! the directory changed. Everything needed to do that was already here.
//! `rvn` performing an install is running as root -- either because somebody
//! typed `sudo rvn`, or because `rvnd` spawned it -- and root is the whole of
//! what `/run/raven-init.sock` requires.
//!
//! # Why a client here rather than running raven-rc
//!
//! `raven-rc` is this socket's other client and it would have worked. It is
//! not used because an install would then depend on a binary from a different
//! package being present and on its exit codes, to send four verbs over a
//! protocol that is one line of text. The socket is the interface raven-init
//! documents; `raven-rc` is a front-end for it, and so is this.
//!
//! # What it will not do
//!
//! Nothing here is reachable by an unprivileged caller. The socket is mode
//! 0600 and owned by root: init's `control` module is explicit that handing
//! an unprivileged session a channel into PID 1 is the thing it must never
//! do, and this does not change that. What `rvnd` adds on top (see
//! `daemon::Op::Service`) is a *daemon* that holds the root end and answers a
//! fixed, validated set of questions -- the same shape as every other
//! privileged verb on this system.
//!
//! An install into a `--root` that is not `/` never speaks to init at all:
//! the services being defined there belong to that tree, and the init running
//! on this machine is not supervising it.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Where raven-init listens. Mode 0600, owned by root.
pub const SOCKET_PATH: &str = "/run/raven-init.sock";

/// Where init publishes the answers to `list` and `status NAME`, mode 0644,
/// for readers that have no business holding the socket. Nothing here reads
/// it -- rvn already knows what it installed -- but it is named because it is
/// the half of this interface an unprivileged front-end may use, and a reader
/// looking for "how does Settings know" should find the answer next to the
/// part that needs root.
pub const STATUS_DIR: &str = "/run/raven-init";

/// The inert service definitions a package may ship.
pub const TEMPLATE_DIR: &str = "/usr/share/raven/services";

/// How long to wait on a socket that has accepted us.
///
/// `reload` re-reads every file in `/etc/raven/init.d` and `start` watches a
/// just-started service for a moment before answering, so this is not a
/// round-trip time; it is the point past which PID 1 is assumed to be wedged
/// and an install should stop waiting for it. Init's own readiness timeouts
/// run to 30 seconds (`faced`), so this has to clear that with room.
const TIMEOUT: Duration = Duration::from_secs(45);

/// A service name as init will accept it, and as it appears in a file name
/// under `/etc/raven/init.d`.
///
/// Deliberately stricter than "not empty": this string is written into a
/// request line that a root process parses by whitespace, and it is joined to
/// a directory path by every caller that looks a template up. A name with a
/// space in it would become two words and a different verb's target; one with
/// a slash or a `..` in it would name a file outside the directory. Neither
/// can be spelled here.
pub fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && name != "."
        && name != ".."
}

/// Whether init is listening.
///
/// A connection that is refused means no init on this socket -- a container,
/// a build chroot, a machine running something else as PID 1 -- and every
/// caller here treats that as "there is nothing to tell", not as a failure.
/// A connection refused for *permission* is the other case and is equally not
/// an error to report at every call site: an unprivileged `rvn` cannot reload
/// init and never could.
pub fn reachable(socket: &Path) -> bool {
    UnixStream::connect(socket).is_ok()
}

/// Send one verb, with an optional target, and return init's reply.
///
/// The protocol is one line of request, then response text until the server
/// closes the stream. An `error:` prefix on the reply is init's way of
/// refusing, and it is turned into an `Err` here so a caller does not have to
/// remember to look: a reply that arrived is not the same as a thing that
/// happened.
pub fn ask(socket: &Path, verb: &str, target: Option<&str>) -> Result<String, String> {
    if let Some(name) = target
        && !valid_service_name(name)
    {
        return Err(format!("refusing service name {name:?}"));
    }

    let mut stream =
        UnixStream::connect(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();

    let line = match target {
        Some(name) => format!("{verb} {name}\n"),
        None => format!("{verb}\n"),
    };
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("cannot send `{verb}` to raven-init: {e}"))?;
    stream.flush().ok();

    let mut reply = String::new();
    let mut reader = BufReader::new(stream);
    loop {
        let mut chunk = String::new();
        match reader.read_line(&mut chunk) {
            Ok(0) => break,
            Ok(_) => reply.push_str(&chunk),
            Err(e) => return Err(format!("cannot read raven-init's reply: {e}")),
        }
        // A reply longer than this is init describing something that is not
        // the answer to any verb sent from here.
        if reply.len() > 64 * 1024 {
            break;
        }
    }

    if let Some(rest) = reply.trim_start().strip_prefix("error:") {
        return Err(rest.trim().to_string());
    }
    Ok(reply)
}

/// Re-read `/etc/raven/init.toml` and every drop-in under
/// `/etc/raven/init.d`, so a definition that arrived since boot exists.
pub fn reload(socket: &Path) -> Result<String, String> {
    ask(socket, "reload", None)
}

pub fn start(socket: &Path, name: &str) -> Result<String, String> {
    ask(socket, "start", Some(name))
}

pub fn stop(socket: &Path, name: &str) -> Result<String, String> {
    ask(socket, "stop", Some(name))
}

/// Run it at every boot from now on. This rewrites the `enabled` key in
/// whichever file defines the service; it does not start anything.
pub fn enable(socket: &Path, name: &str) -> Result<String, String> {
    ask(socket, "enable", Some(name))
}

pub fn disable(socket: &Path, name: &str) -> Result<String, String> {
    ask(socket, "disable", Some(name))
}

/// What init says about one service, or `Err` when it does not have it.
pub fn status(socket: &Path, name: &str) -> Result<String, String> {
    ask(socket, "status", Some(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Stands in for init: reads the one request line, writes `reply`, and
    /// closes -- which is what ends the client's read.
    fn fake_init(dir: &Path, reply: &'static str) -> (std::path::PathBuf, std::thread::JoinHandle<String>) {
        let socket = dir.join("init.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut request = String::new();
            reader.read_line(&mut request).expect("read");
            let mut stream = stream;
            stream.write_all(reply.as_bytes()).expect("write");
            request
        });
        (socket, handle)
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rvn-initctl-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn a_name_that_could_change_the_verb_is_refused() {
        assert!(valid_service_name("faced"));
        assert!(valid_service_name("avahi-daemon"));
        assert!(valid_service_name("os-release-guard"));
        // A space makes the rest of the line a second word init would read as
        // its own target.
        assert!(!valid_service_name("faced stop"));
        // A path is how a name reaches a file outside the template directory.
        assert!(!valid_service_name("../../etc/shadow"));
        assert!(!valid_service_name("a/b"));
        assert!(!valid_service_name(".."));
        assert!(!valid_service_name(""));
        // Leading dash: an argument, not a name.
        assert!(!valid_service_name("-rf"));
    }

    #[test]
    fn a_verb_and_its_target_go_out_as_one_line() {
        let dir = tempdir();
        let (socket, server) = fake_init(&dir, "Started faced\n");

        let reply = start(&socket, "faced").expect("started");
        assert_eq!(reply, "Started faced\n");
        assert_eq!(server.join().expect("joined"), "start faced\n");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_verb_with_no_target_carries_no_second_word() {
        let dir = tempdir();
        let (socket, server) = fake_init(&dir, "Reloaded\n");

        reload(&socket).expect("reloaded");
        assert_eq!(server.join().expect("joined"), "reload\n");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Init refuses in the body of a reply that arrived intact, so a client
    /// that only checked for an I/O error would report success.
    #[test]
    fn an_error_reply_is_an_error() {
        let dir = tempdir();
        let (socket, server) = fake_init(&dir, "error: no such service 'faced'\n");

        let why = start(&socket, "faced").expect_err("refused");
        assert_eq!(why, "no such service 'faced'");
        server.join().expect("joined");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nothing_listening_is_not_a_panic() {
        let dir = tempdir();
        let socket = dir.join("absent.sock");
        assert!(!reachable(&socket));
        assert!(reload(&socket).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
