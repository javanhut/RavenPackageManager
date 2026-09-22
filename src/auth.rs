//! Asking the human whether they meant it.
//!
//! `policy` decides that a request needs a person to agree to it. This is how
//! the person is found and asked, and how their answer is remembered for a
//! while afterwards.
//!
//! # Why rvnd cannot ask by itself
//!
//! rvnd is a daemon with no terminal and no screen. The thing that knows
//! which screen a given session is on, and already holds this account's
//! password and its fingerprint policy, is `ravend` -- RavenLogin's login
//! daemon, which started the session in the first place. RavenLogin's own
//! protocol even has a name for this permission already: a `FingerPolicy`
//! carries a `sudo` flag, "in place of the password sudo asks for", which is
//! this same question at a different door.
//!
//! What rvnd cannot do is use ravend's existing verify socket. That socket is
//! deliberately built so it can only ever be asked about the account that
//! owns the connection, resolved from `SO_PEERCRED` -- its own comments
//! explain that a socket anyone may connect to is a password oracle unless it
//! can only be asked about the asker. The connection here would be rvnd's, so
//! it would be asking about root. What is needed is the other kind of socket:
//! one that only root may open, where the caller names the session to prompt.
//!
//! # The protocol
//!
//! Framing is RavenLogin's: a 4-byte big-endian length, then that many bytes
//! of JSON. One request, one reply, connection closed. rvnd sends
//!
//! ```text
//! {"request":"authorize",
//!  "uid":1000,"pid":4242,
//!  "session":{"leader":1200,"started":88231},
//!  "action":"install","class":"aur",
//!  "packages":["brave-bin"],
//!  "timeout_seconds":120}
//! ```
//!
//! and reads back exactly one of
//!
//! ```text
//! {"response":"granted"}
//! {"response":"denied","reason":"..."}
//! {"response":"unavailable","reason":"..."}
//! ```
//!
//! Everything in the request is something rvnd established for itself from
//! `SO_PEERCRED` and `/proc`; nothing in it was asserted by the client. In
//! particular there is no free-text field for the client to put words in. It
//! would be a genuinely useful field -- "Raven Store: install Brave" reads
//! better than "install brave-bin" -- and it is left out because a prompt
//! that displays text an unprivileged caller chose is a prompt that can be
//! made to read "System update required" by the thing asking for root.
//!
//! # What each failure means
//!
//! The distinction that matters most in this file is between a prompt that
//! was *refused* and one that could not be *raised*, because the policy's
//! fallback for the second is, by default, to allow the request.
//!
//!   - Nothing is listening, or the conversation broke: `Unavailable`. The
//!     mechanism is missing and `on_auth_unavailable` decides.
//!   - Something answered and said no: `Denied`. A refusal.
//!   - Something answered and then said nothing until the timeout expired:
//!     `Denied`. The mechanism exists and the human did not use it; treating
//!     an ignored prompt as an absent one would make ignoring the prompt the
//!     way to grant root.
//!
//! # The cache
//!
//! An answer is remembered against the *session* it was given in, the way
//! sudo remembers a password against a terminal, so that installing four
//! packages in a row is one prompt. A session here is the POSIX session the
//! requesting process belongs to: its leader's pid, which for anything inside
//! a graphical session is the process the compositor was started from, and
//! the leader's start time, because a pid on its own is reused and an
//! inherited answer would be somebody else's.
//!
//! It is deliberately not keyed on the uid. Two terminals in one session
//! sharing an answer is the point; a background daemon running as the same
//! human, in no session of its own, sharing that answer is exactly the attack
//! this whole change exists to stop.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The largest reply this will read, matching RavenLogin's own cap. Small on
/// purpose: the biggest legitimate message is a sentence, and the cap is what
/// makes a length prefix corrupted to 4 GiB close the connection instead of
/// asking the allocator for 4 GiB.
const MAX_MESSAGE: usize = 64 * 1024;

/// How much longer than the prompt's own deadline to wait on the socket.
///
/// ravend is told how long the human has and is expected to answer by then;
/// this slack is only so that a reply sent at the last moment is read rather
/// than raced, and so that the timeout that fires is ravend's considered one
/// and not ours.
const SOCKET_SLACK: Duration = Duration::from_secs(5);

/// The session a request came from.
///
/// `leader` alone would do if pids were not reused. They are, so the leader's
/// start time comes along: together they name one session for as long as it
/// exists and can never be confused with the next one to get that pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub uid: u32,
    pub leader: i32,
    pub leader_started: u64,
}

impl Session {
    /// The session process `pid` belongs to, for a peer whose uid is `uid`.
    ///
    /// `None` when `/proc` will not say -- the process exited between the
    /// `connect` and this call, which is the ordinary case rather than an
    /// exceptional one. A caller that cannot establish a session cannot cache
    /// an answer for it and must prompt every time, which is the safe way for
    /// this to degrade.
    pub fn of(uid: u32, pid: i32) -> Option<Session> {
        let leader = stat_field(pid, SESSION_FIELD)?.parse().ok()?;
        // A process whose session leader has exited belongs to an orphaned
        // session whose leader pid may already have been handed out again.
        // Reading the start time from the leader is what makes that visible:
        // no leader, no session, no cache entry.
        let leader_started = stat_field(leader, STARTTIME_FIELD)?.parse().ok()?;
        Some(Session {
            uid,
            leader,
            leader_started,
        })
    }
}

/// Index of `session` among the fields of /proc/<pid>/stat that follow the
/// command name, and of `starttime`. The file's fields are numbered from 1
/// with `pid` first and `comm` second, so a field's index here is its number
/// minus three.
const SESSION_FIELD: usize = 3;
const STARTTIME_FIELD: usize = 19;

/// One field of /proc/<pid>/stat, counted from the field after the command.
///
/// Split on the LAST `)` rather than parsed field by field, because the
/// second field is the executable's name in parentheses and an executable is
/// free to be called `evil) 1 2 3 (`. Every /proc/<pid>/stat parser that has
/// ever been wrong has been wrong here.
fn stat_field(pid: i32, index: usize) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &text[text.rfind(')')? + 1..];
    tail.split_whitespace().nth(index).map(str::to_string)
}

/// What `pid` was executing, from /proc/<pid>/exe.
///
/// `read_link` is `readlink(2)`: it reads the link's own target and never
/// opens it, which is what this has to be. rvnd is root and the pid belongs
/// to somebody else, so opening the target would be root following a path of
/// another user's choosing.
///
/// The answer is for the audit log and for nothing else. By the time it is
/// read the process may have exec'd something different or exited and had its
/// pid reused; the kernel appends " (deleted)" for a binary that has been
/// unlinked; and a path is not an identity in any case. It is a lead for a
/// human reading the log afterwards.
pub fn exe_of(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// What came back from the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The human agreed.
    Granted,
    /// The human declined, or did not answer in time.
    Denied(String),
    /// There was nobody to ask. `policy.on_auth_unavailable` decides.
    Unavailable(String),
}

/// Ask ravend to put the question to the owner of `session`.
///
/// Blocking, with the socket's own deadline set a little beyond the one the
/// request carries, so that the timeout which fires is the considered one at
/// the other end.
pub fn ask(
    socket: &Path,
    session: Session,
    pid: i32,
    action: &str,
    class: &str,
    packages: &[String],
    timeout_seconds: u64,
) -> Verdict {
    let deadline = Duration::from_secs(timeout_seconds) + SOCKET_SLACK;
    let stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(e) => {
            return Verdict::Unavailable(format!("{}: {e}", socket.display()));
        }
    };
    if stream.set_read_timeout(Some(deadline)).is_err()
        || stream.set_write_timeout(Some(deadline)).is_err()
    {
        return Verdict::Unavailable("cannot put a deadline on the authorization socket".into());
    }

    let request = serde_json::json!({
        "request": "authorize",
        "uid": session.uid,
        "pid": pid,
        "session": { "leader": session.leader, "started": session.leader_started },
        "action": action,
        "class": class,
        "packages": packages,
        "timeout_seconds": timeout_seconds,
    });

    match exchange(stream, &request.to_string()) {
        Ok(reply) => interpret(&reply),
        // A deadline that expired with no reply is the human ignoring the
        // prompt, which is a refusal. Everything else is a mechanism that
        // broke mid-sentence.
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Verdict::Denied("the request was not answered in time".into())
        }
        Err(e) => Verdict::Unavailable(format!("{}: {e}", socket.display())),
    }
}

/// One length-prefixed message out, one back.
fn exchange(mut stream: UnixStream, request: &str) -> std::io::Result<String> {
    let bytes = request.as_bytes();
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("reply of {length} bytes is beyond the {MAX_MESSAGE} byte limit"),
        ));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    String::from_utf8(body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// The verdict a reply carries.
///
/// A reply this does not understand is `Unavailable` rather than `Denied`: it
/// means a ravend newer or older than this rvnd, which is a broken mechanism
/// and not a human's answer, and the policy's fallback is where that belongs.
fn interpret(reply: &str) -> Verdict {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(reply) else {
        return Verdict::Unavailable("the reply was not JSON".into());
    };
    let reason = || {
        value["reason"]
            .as_str()
            .unwrap_or("no reason given")
            .to_string()
    };
    match value["response"].as_str() {
        Some("granted") => Verdict::Granted,
        Some("denied") => Verdict::Denied(reason()),
        Some("unavailable") => Verdict::Unavailable(reason()),
        Some(other) => Verdict::Unavailable(format!("unknown reply {other:?}")),
        None => Verdict::Unavailable("the reply named no response".into()),
    }
}

/// Answered prompts, and when they stop counting.
///
/// A `Vec` rather than a map because it holds one entry per session that has
/// authorized something recently, which on a desktop is one or two, and
/// because a `Vec` can be built in a `const fn` and so can live in a `static`
/// beside the daemon's other one.
pub struct Cache {
    entries: Mutex<Vec<(Session, Instant)>>,
}

impl Default for Cache {
    fn default() -> Cache {
        Cache::new()
    }
}

impl Cache {
    pub const fn new() -> Cache {
        Cache {
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Whether this session has an answer that still counts.
    ///
    /// Expired entries are dropped on the way past, which is the only place
    /// they are ever dropped -- there is no sweeper, because the list is
    /// short and a session that never comes back costs two words until the
    /// next one does.
    pub fn allows(&self, session: Session, ttl_seconds: u64) -> bool {
        if ttl_seconds == 0 {
            return false;
        }
        let ttl = Duration::from_secs(ttl_seconds);
        let Ok(mut entries) = self.entries.lock() else {
            // A poisoned lock means a previous holder panicked. The safe
            // reading of "I cannot tell whether this was authorized" is that
            // it was not.
            return false;
        };
        entries.retain(|(_, when)| when.elapsed() < ttl);
        entries.iter().any(|(held, _)| *held == session)
    }

    /// Remember that this session agreed, starting the clock again.
    pub fn record(&self, session: Session) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let now = Instant::now();
        match entries.iter_mut().find(|(held, _)| *held == session) {
            Some(entry) => entry.1 = now,
            None => entries.push((session, now)),
        }
    }

    /// Forget everything. Only the tests need it -- `daemon`'s as well as
    /// this module's, because the daemon's cache is a `static` shared by
    /// every test in the binary. A running daemon's cache is emptied by time
    /// or by rvnd restarting.
    #[cfg(test)]
    pub(crate) fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(leader: i32, started: u64) -> Session {
        Session {
            uid: 1000,
            leader,
            leader_started: started,
        }
    }

    #[test]
    fn this_process_has_a_session_and_an_exe() {
        let pid = std::process::id() as i32;
        let found = Session::of(1000, pid).expect("/proc says what session this is");
        assert!(found.leader > 0);
        // The test binary is a real file, so its path comes back.
        let exe = exe_of(pid).expect("/proc says what this is running");
        assert!(exe.starts_with('/'), "{exe}");
    }

    /// A peer that exited between the connect and the lookup is the ordinary
    /// case, not an exceptional one, and it must come back as "no session"
    /// rather than as anything that could be mistaken for one.
    #[test]
    fn a_pid_that_is_not_there_has_no_session() {
        // Pid 0 is never a process; /proc/0 does not exist.
        assert_eq!(Session::of(1000, 0), None);
        assert_eq!(exe_of(0), None);
    }

    #[test]
    fn an_answer_counts_for_its_session_and_no_other() {
        let cache = Cache::new();
        cache.record(session(100, 5));
        assert!(cache.allows(session(100, 5), 300));
        // Same leader pid, different process behind it: not the same session.
        assert!(!cache.allows(session(100, 6), 300));
        assert!(!cache.allows(session(101, 5), 300));
        // A zero timeout is "ask every time", not "cache forever".
        assert!(!cache.allows(session(100, 5), 0));
        cache.clear();
        assert!(!cache.allows(session(100, 5), 300));
    }

    #[test]
    fn replies_are_read_and_anything_unexpected_is_an_absence() {
        assert_eq!(interpret(r#"{"response":"granted"}"#), Verdict::Granted);
        assert_eq!(
            interpret(r#"{"response":"denied","reason":"not now"}"#),
            Verdict::Denied("not now".into())
        );
        assert!(matches!(
            interpret(r#"{"response":"unavailable","reason":"no session"}"#),
            Verdict::Unavailable(_)
        ));
        // A ravend that speaks a dialect this one does not is a missing
        // mechanism, not a refusal.
        assert!(matches!(
            interpret(r#"{"response":"maybe"}"#),
            Verdict::Unavailable(_)
        ));
        assert!(matches!(interpret("not json"), Verdict::Unavailable(_)));
        assert!(matches!(interpret("{}"), Verdict::Unavailable(_)));
    }

    #[test]
    fn nothing_listening_is_unavailable_rather_than_denied() {
        let nowhere = std::env::temp_dir().join("rvnd-authorize-that-is-not-there.sock");
        std::fs::remove_file(&nowhere).ok();
        let verdict = ask(&nowhere, session(1, 1), 1, "install", "aur", &[], 1);
        assert!(matches!(verdict, Verdict::Unavailable(_)), "{verdict:?}");
    }

    /// The whole conversation against a stand-in ravend, so the framing is
    /// pinned down for whoever writes the other half.
    #[test]
    fn a_prompt_is_one_framed_message_each_way() {
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("rvnd-auth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("authorize.sock");
        std::fs::remove_file(&path).ok();
        let listener = UnixListener::bind(&path).unwrap();

        let seen = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut body).unwrap();
            let reply = br#"{"response":"granted"}"#;
            stream
                .write_all(&(reply.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(reply).unwrap();
            String::from_utf8(body).unwrap()
        });

        let verdict = ask(
            &path,
            session(1200, 88231),
            4242,
            "install",
            "aur",
            &["brave-bin".to_string()],
            5,
        );
        assert_eq!(verdict, Verdict::Granted);

        let request: serde_json::Value = serde_json::from_str(&seen.join().unwrap()).unwrap();
        assert_eq!(request["request"], "authorize");
        assert_eq!(request["uid"], 1000);
        assert_eq!(request["pid"], 4242);
        assert_eq!(request["session"]["leader"], 1200);
        assert_eq!(request["session"]["started"], 88231);
        assert_eq!(request["class"], "aur");
        assert_eq!(request["packages"][0], "brave-bin");

        std::fs::remove_dir_all(&dir).ok();
    }
}
