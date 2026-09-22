//! HTTP downloads with mirror failover and progress reporting.
//!
//! `file://` is served from the filesystem rather than through ureq, which
//! refuses the scheme outright ("http: invalid format"). That matters because
//! a repository built by `rvn repo-add` into a directory is the ordinary way
//! to try RavenLinux's own packages before anything is published, and
//! `Server = file:///srv/raven` in `pacman.conf` is how pacman has always
//! spelled it. The branch lives inside [`stream_to`] so that mirror failover,
//! the `.part`-then-rename dance, progress accounting and the absent-quorum
//! rule in [`download_optional`] all keep working without knowing about it.

use crate::ui::progress::Progress;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const USER_AGENT: &str = concat!("rvn/", env!("CARGO_PKG_VERSION"));

#[derive(Debug)]
pub enum FetchError {
    /// Every mirror was tried and none served the file.
    AllMirrorsFailed { url: String, attempts: Vec<String> },
    Io(io::Error),
    Status { url: String, code: u16 },
    /// The connection failed before any status was returned.
    Transport { url: String, reason: String },
    /// The server sent fewer bytes than it promised.
    Truncated {
        url: String,
        expected: u64,
        received: u64,
    },
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::AllMirrorsFailed { url, attempts } => {
                write!(f, "all mirrors failed for {url}")?;
                for a in attempts {
                    write!(f, "\n    {a}")?;
                }
                Ok(())
            }
            FetchError::Io(e) => write!(f, "{e}"),
            FetchError::Status { url, code } => write!(f, "{url} returned HTTP {code}"),
            FetchError::Transport { url, reason } => write!(f, "{url}: {reason}"),
            FetchError::Truncated {
                url,
                expected,
                received,
            } => write!(
                f,
                "{url} ended early: expected {expected} bytes, received {received}"
            ),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<io::Error> for FetchError {
    fn from(e: io::Error) -> Self {
        FetchError::Io(e)
    }
}

/// How long a mirror may sit on an accepted connection before it is written
/// off. Without this, a server that completes the handshake and then goes
/// quiet holds the whole command open forever — a mirrorlist of any size
/// reliably contains a few.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

/// How many mirrors are asked for a file the repository may not publish at
/// all. A mirrorlist can hold well over a hundred servers, and walking every
/// one of them to learn that none carries the file costs minutes.
pub const OPTIONAL_MIRROR_LIMIT: usize = 3;

/// How many mirrors must independently answer "no such file" before rvn
/// concludes it is not published, rather than that one mirror is behind.
const ABSENT_QUORUM: usize = 2;

/// The whole exchange for an optional file, which is small by definition.
const OPTIONAL_TIMEOUT: Duration = Duration::from_secs(10);

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .user_agent(USER_AGENT)
        .timeout_connect(Some(Duration::from_secs(15)))
        // This bounds the wait for response headers, not for the body: a
        // large package over a slow link is slow but healthy, and cutting it
        // off at a fixed deadline would break exactly the downloads that
        // matter most.
        .timeout_recv_response(Some(RESPONSE_TIMEOUT))
        .build()
        .into()
}

/// A stricter agent for the small files rvn is only probing for, where any
/// delay at all is better spent on the next mirror.
fn probe_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .user_agent(USER_AGENT)
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_global(Some(OPTIONAL_TIMEOUT))
        .build()
        .into()
}

/// The scheme a repository served straight out of a directory uses.
const FILE_SCHEME: &str = "file://";

/// Whether this URL names a path on this machine rather than a server.
///
/// Compared case-insensitively because a scheme is case-insensitive in the
/// URL grammar, and somebody hand-editing `pacman.conf` may well write
/// `FILE://`.
fn is_file_url(url: &str) -> bool {
    url.len() >= FILE_SCHEME.len() && url[..FILE_SCHEME.len()].eq_ignore_ascii_case(FILE_SCHEME)
}

/// Decodes the `%XX` escapes a URL may carry, as bytes.
///
/// A `Server =` line is usually written with none, but the other half of
/// every URL rvn builds is a filename out of a repository database, and a
/// path with a space in it has to arrive as `%20` to be a URL at all. A `%`
/// that does not begin a valid escape is left alone rather than rejected,
/// because it is far more likely to be a literal character in a filename
/// than a truncated escape.
///
/// Bytes rather than a `String`, because a path on Linux is bytes: decoding
/// through UTF-8 would replace anything an escape sequence produced that is
/// not valid UTF-8, and then look for a file under a name nothing has.
fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let hex = |b: u8| (b as char).to_digit(16);
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(&hi), Some(&lo)) => match (hex(hi), hex(lo)) {
                (Some(hi), Some(lo)) => {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// The path a `file://` URL names, or why rvn will not read it.
///
/// The two refusals are not paranoia about the operator's own `Server =`
/// line. Every URL rvn fetches is that line joined to a filename taken out of
/// a repository database, and the database is the half rvn did not write: a
/// `%FILENAME%` of `../../../etc/shadow` would otherwise walk straight out of
/// the directory being served and hand its contents to the verifier as though
/// it were a package. Rejecting any `..` component — after decoding, so an
/// escaped `%2e%2e` is caught too — keeps every read inside the directory the
/// operator pointed at. A non-local authority is refused because `file://` to
/// another host is not a thing rvn can honour, and quietly reading the local
/// path of that name instead would be worse than saying so.
fn file_path(url: &str) -> Result<PathBuf, FetchError> {
    let rest = &url[FILE_SCHEME.len()..];
    // `file:///srv/raven` is the ordinary spelling: empty authority, then an
    // absolute path. `file://localhost/srv/raven` means the same thing.
    let path = match rest.find('/') {
        Some(slash) => {
            let authority = &rest[..slash];
            if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
                return Err(FetchError::Transport {
                    url: url.to_string(),
                    reason: format!("file:// cannot reach the host {authority:?}"),
                });
            }
            &rest[slash..]
        }
        None => {
            return Err(FetchError::Transport {
                url: url.to_string(),
                reason: "file:// URL has no path".into(),
            });
        }
    };

    use std::os::unix::ffi::OsStringExt;
    let path = PathBuf::from(std::ffi::OsString::from_vec(percent_decode(path)));
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(FetchError::Transport {
            url: url.to_string(),
            reason: "refusing a file:// path that climbs out of its directory with ..".into(),
        });
    }

    Ok(path)
}

/// Copies a local file into `sink`, reporting bytes the way a download does.
///
/// A missing file is reported as HTTP 404 rather than as an I/O error, which
/// looks like a lie and is not: [`download_optional`] decides whether a
/// repository publishes a `.db.sig` at all by counting how many mirrors
/// answered "no such file", and a local repository that ships no signature
/// has to be able to give that same answer or every sync of it would stall on
/// "could not establish". Every other I/O failure — a directory without
/// permission to read it, a disk error — leaves the question genuinely open
/// and is reported as a transport failure, exactly as a refused connection is.
fn copy_local<W: Write>(
    url: &str,
    sink: &mut W,
    mut on_bytes: impl FnMut(u64),
) -> Result<u64, FetchError> {
    let path = file_path(url)?;

    let local = |e: io::Error| -> FetchError {
        if e.kind() == io::ErrorKind::NotFound {
            FetchError::Status {
                url: url.to_string(),
                code: 404,
            }
        } else {
            FetchError::Transport {
                url: url.to_string(),
                reason: e.to_string(),
            }
        }
    };

    // Followed rather than inspected, because `repo-add` publishes `<repo>.db`
    // as a symlink to `<repo>.db.tar.gz` and refusing symlinks would make
    // every repository this crate writes unreadable by it.
    let meta = std::fs::metadata(&path).map_err(local)?;
    if !meta.is_file() {
        // A directory or a device node is not a failure to serve the file; it
        // is the file not being there in any sense rvn can use, and reading
        // /dev/zero would never end.
        return Err(FetchError::Status {
            url: url.to_string(),
            code: 404,
        });
    }
    // Remembered before the copy for the same reason the Content-Length is:
    // a file being rewritten underneath us — `rvn repo-add` regenerating the
    // database while a sync reads it — must not be renamed into place short.
    let expected = meta.len();

    let mut file = std::fs::File::open(&path).map_err(local)?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        sink.write_all(&buffer[..n])?;
        total += n as u64;
        on_bytes(n as u64);
    }

    if total != expected {
        return Err(FetchError::Truncated {
            url: url.to_string(),
            expected,
            received: total,
        });
    }

    Ok(total)
}

/// Streams `url` into `sink`, reporting bytes as they arrive.
fn stream_to<W: Write>(
    agent: &ureq::Agent,
    url: &str,
    sink: &mut W,
    mut on_bytes: impl FnMut(u64),
) -> Result<u64, FetchError> {
    // Decided here rather than at each call site so that every caller —
    // mirror failover, the optional-file probe, `get_string` — gets local
    // repositories for free and none of them has to learn a second code path.
    if is_file_url(url) {
        return copy_local(url, sink, on_bytes);
    }

    // A refused connection and a 404 are different problems, and reporting a
    // timeout as "HTTP 0" sends the reader looking in the wrong place.
    let mut response = agent.get(url).call().map_err(|e| match &e {
        ureq::Error::StatusCode(code) => FetchError::Status {
            url: url.to_string(),
            code: *code,
        },
        other => FetchError::Transport {
            url: url.to_string(),
            reason: other.to_string(),
        },
    })?;

    // Remembered before the body is consumed, so a short read is detectable.
    let expected: Option<u64> = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok());

    let mut reader = response.body_mut().as_reader();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        sink.write_all(&buffer[..n])?;
        total += n as u64;
        on_bytes(n as u64);
    }

    // A connection that drops cleanly mid-transfer otherwise looks like a
    // complete download, and the truncated file would be renamed into place.
    if let Some(expected) = expected {
        if total != expected {
            return Err(FetchError::Truncated {
                url: url.to_string(),
                expected,
                received: total,
            });
        }
    }

    Ok(total)
}

/// Downloads a URL into memory.
pub fn get_bytes(url: &str) -> Result<Vec<u8>, FetchError> {
    let mut out = Vec::new();
    stream_to(&agent(), url, &mut out, |_| {})?;
    Ok(out)
}

/// Downloads a URL as text.
pub fn get_string(url: &str) -> Result<String, FetchError> {
    let bytes = get_bytes(url)?;
    String::from_utf8(bytes)
        .map_err(|e| FetchError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))
}

/// Downloads to `dest`, trying each mirror in turn until one succeeds.
///
/// The write goes to a `.part` file that is renamed on success, so an
/// interrupted download never leaves a truncated package in the cache.
pub fn download_with_mirrors(
    urls: &[String],
    dest: &Path,
    progress: Option<&mut Progress>,
) -> Result<u64, FetchError> {
    if urls.is_empty() {
        return Err(FetchError::AllMirrorsFailed {
            url: dest.display().to_string(),
            attempts: vec!["no mirrors configured".into()],
        });
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let agent = agent();
    let mut attempts = Vec::new();
    let mut progress = progress;

    // A `.part` beside the target, named after it, so two concurrent
    // downloads cannot tread on each other's temporary file.
    let mut part = dest.as_os_str().to_os_string();
    part.push(".part");
    let part = std::path::PathBuf::from(part);

    for url in urls {
        let file = std::fs::File::create(&part)?;
        let mut writer = io::BufWriter::new(file);

        // Bytes counted for a mirror that then fails have to be taken back,
        // or a failover would push the bar past 100% and skew the rate.
        let mut attempt_bytes = 0u64;
        let result = match progress.as_deref_mut() {
            Some(p) => stream_to(&agent, url, &mut writer, |n| {
                attempt_bytes += n;
                p.advance(n);
            }),
            None => stream_to(&agent, url, &mut writer, |n| attempt_bytes += n),
        };

        match result {
            Ok(total) => {
                writer.flush()?;
                drop(writer);
                std::fs::rename(&part, dest)?;
                return Ok(total);
            }
            Err(e) => {
                drop(writer);
                let _ = std::fs::remove_file(&part);
                if let Some(p) = progress.as_deref_mut() {
                    p.rewind(attempt_bytes);
                }
                attempts.push(format!("{url}: {e}"));
            }
        }
    }

    Err(FetchError::AllMirrorsFailed {
        url: dest
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        attempts,
    })
}

/// The outcome of looking for a file a repository may or may not publish.
#[derive(Debug)]
pub enum Optional {
    Fetched(u64),
    /// Mirrors agreed there is no such file. Nothing is wrong; the repository
    /// simply does not publish it.
    NotPublished,
    /// No mirror answered, so nothing at all was established. This is not the
    /// same as `NotPublished`, and a caller that requires the file must treat
    /// it as a failure rather than as a licence to continue unverified.
    Unavailable(FetchError),
}

/// Downloads a file that a repository may legitimately not publish.
///
/// Arch's official repositories, for one, ship no `$repo.db.sig`. Asking a
/// full mirrorlist for a file no mirror carries costs a round trip per server
/// — minutes across a hundred mirrors, and unbounded against one that accepts
/// the connection and then goes silent. A few mirrors agreeing the file is
/// absent settles the question.
pub fn download_optional(urls: &[String], dest: &Path) -> Optional {
    if urls.is_empty() {
        return Optional::Unavailable(FetchError::AllMirrorsFailed {
            url: dest.display().to_string(),
            attempts: vec!["no mirrors configured".into()],
        });
    }

    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Optional::Unavailable(FetchError::Io(e));
        }
    }

    let agent = probe_agent();
    let mut part = dest.as_os_str().to_os_string();
    part.push(".part");
    let part = std::path::PathBuf::from(part);

    let mut absent = 0usize;
    let mut attempts = Vec::new();

    for url in urls.iter().take(OPTIONAL_MIRROR_LIMIT) {
        let file = match std::fs::File::create(&part) {
            Ok(file) => file,
            Err(e) => return Optional::Unavailable(FetchError::Io(e)),
        };
        let mut writer = io::BufWriter::new(file);

        match stream_to(&agent, url, &mut writer, |_| {}) {
            Ok(total) => {
                let renamed = writer
                    .flush()
                    .and_then(|_| {
                        drop(writer);
                        std::fs::rename(&part, dest)
                    });
                return match renamed {
                    Ok(()) => Optional::Fetched(total),
                    Err(e) => Optional::Unavailable(FetchError::Io(e)),
                };
            }
            Err(e) => {
                drop(writer);
                let _ = std::fs::remove_file(&part);
                // A 404 is the mirror answering the question, not failing to.
                // Every other error leaves the question open.
                if matches!(&e, FetchError::Status { code, .. } if *code == 404 || *code == 410) {
                    absent += 1;
                    if absent >= ABSENT_QUORUM {
                        return Optional::NotPublished;
                    }
                }
                attempts.push(format!("{url}: {e}"));
            }
        }
    }

    // A single 404 with nothing to corroborate it is still the only answer
    // anyone gave, and refusing to act on it would strand repositories served
    // by one mirror.
    if absent > 0 {
        return Optional::NotPublished;
    }

    Optional::Unavailable(FetchError::AllMirrorsFailed {
        url: dest
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        attempts,
    })
}

/// Whether a cached file can be reused, based on the expected size.
pub fn cached_ok(path: &Path, expected_size: u64) -> bool {
    match std::fs::metadata(path) {
        // A zero expected size means the database did not say, so trust
        // nothing and re-download.
        Ok(meta) => expected_size > 0 && meta.len() == expected_size,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mirror_list_is_an_error() {
        let dest = std::env::temp_dir().join("rvn-no-mirrors.pkg");
        let err = download_with_mirrors(&[], &dest, None).unwrap_err();
        assert!(matches!(err, FetchError::AllMirrorsFailed { .. }));
    }

    #[test]
    fn cached_ok_requires_a_known_size_match() {
        let path = std::env::temp_dir().join("rvn-cache-probe");
        std::fs::write(&path, b"0123456789").unwrap();

        assert!(cached_ok(&path, 10));
        assert!(!cached_ok(&path, 9));
        // Size 0 means "unknown", which must not count as a cache hit.
        assert!(!cached_ok(&path, 0));
        assert!(!cached_ok(Path::new("/nonexistent/rvn"), 10));
    }

    #[test]
    fn an_optional_file_needs_at_least_one_mirror() {
        let dest = std::env::temp_dir().join("rvn-optional-no-mirrors.sig");
        match download_optional(&[], &dest) {
            Optional::Unavailable(_) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn an_unreachable_mirror_is_not_read_as_a_missing_file() {
        // Regression: treating "could not ask" as "there is none" would let a
        // network outage silently downgrade a DatabaseRequired repository to
        // an unverified database. Port 1 refuses immediately.
        let dest = std::env::temp_dir().join("rvn-optional-unreachable.sig");
        let urls = vec![
            "http://127.0.0.1:1/core.db.sig".to_string(),
            "http://127.0.0.1:1/core.db.sig".to_string(),
        ];
        match download_optional(&urls, &dest) {
            Optional::Unavailable(_) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
        // A failed probe must not leave its scratch file behind.
        assert!(!dest.with_extension("sig.part").exists());
    }

    #[test]
    fn optional_probes_stop_well_short_of_a_full_mirrorlist() {
        // The whole point of the probe: a mirrorlist can hold a hundred-odd
        // servers, and a file none of them carries must not cost a round trip
        // to each one.
        assert!(OPTIONAL_MIRROR_LIMIT <= 5);
        assert!(ABSENT_QUORUM <= OPTIONAL_MIRROR_LIMIT);
    }

    /// A directory of this run's own, so the file:// tests cannot collide
    /// with each other or with a previous run left behind.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-file-url-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_file_url_is_recognised_whatever_its_case() {
        assert!(is_file_url("file:///srv/raven/raven.db"));
        assert!(is_file_url("FILE:///srv/raven/raven.db"));
        assert!(!is_file_url("https://example.invalid/raven.db"));
        assert!(!is_file_url("file:/srv/raven"));
    }

    #[test]
    fn a_file_url_resolves_to_its_path() {
        assert_eq!(
            file_path("file:///srv/raven/raven.db").unwrap(),
            Path::new("/srv/raven/raven.db")
        );
        // localhost is the spelling of "this machine" the URL grammar allows.
        assert_eq!(
            file_path("file://localhost/srv/raven/raven.db").unwrap(),
            Path::new("/srv/raven/raven.db")
        );
        // A space in a directory name arrives escaped or it is not a URL.
        assert_eq!(
            file_path("file:///srv/my%20repo/raven.db").unwrap(),
            Path::new("/srv/my repo/raven.db")
        );
    }

    #[test]
    fn a_file_url_may_not_climb_out_of_its_directory() {
        // Regression: the filename half of every URL comes out of a
        // repository database, so `%FILENAME%` is attacker-controlled for any
        // repository rvn did not build itself.
        for url in [
            "file:///srv/raven/../../etc/shadow",
            // The same attack spelled in escapes, which is why decoding has
            // to happen before the check rather than after it.
            "file:///srv/raven/%2e%2e/%2e%2e/etc/shadow",
        ] {
            match file_path(url) {
                Err(FetchError::Transport { reason, .. }) => assert!(reason.contains("..")),
                other => panic!("expected a refusal for {url}, got {other:?}"),
            }
        }
        // A file:// URL naming another host is refused rather than silently
        // read from this one.
        assert!(matches!(
            file_path("file://elsewhere.invalid/srv/raven.db"),
            Err(FetchError::Transport { .. })
        ));
    }

    #[test]
    fn a_local_repository_downloads_like_any_mirror() {
        let dir = scratch("download");
        let source = dir.join("widget-1.0-1-x86_64.pkg.tar.zst");
        std::fs::write(&source, b"not really a package, but it is bytes").unwrap();

        let dest = dir.join("cached.pkg.tar.zst");
        let url = format!("file://{}", source.display());
        let total = download_with_mirrors(&[url], &dest, None).unwrap();

        assert_eq!(total, 37);
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"not really a package, but it is bytes"
        );
        // The same .part-then-rename contract every other download honours.
        assert!(!dest.with_extension("tar.zst.part").exists());
    }

    #[test]
    fn a_missing_local_file_fails_over_to_the_next_mirror() {
        let dir = scratch("failover");
        let real = dir.join("raven.db");
        std::fs::write(&real, b"database").unwrap();

        let dest = dir.join("fetched.db");
        let urls = vec![
            format!("file://{}", dir.join("absent.db").display()),
            format!("file://{}", real.display()),
        ];
        assert_eq!(download_with_mirrors(&urls, &dest, None).unwrap(), 8);
        assert_eq!(std::fs::read(&dest).unwrap(), b"database");
    }

    #[test]
    fn an_absent_local_signature_reads_as_not_published() {
        // A directory-served repository ships no `<repo>.db.sig`, exactly as
        // Arch's own repositories do not. Reporting that as "could not ask"
        // would strand every local repository at sync time, so a missing
        // local file has to answer the question the way a 404 does.
        let dir = scratch("optional");
        let dest = dir.join("raven.db.sig");
        let urls = vec![format!("file://{}", dir.join("raven.db.sig").display())];
        match download_optional(&urls, &dest) {
            Optional::NotPublished => {}
            other => panic!("expected NotPublished, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_is_not_a_file_to_fetch() {
        let dir = scratch("directory");
        let dest = dir.join("out");
        let urls = vec![format!("file://{}", dir.display())];
        match download_optional(&urls, &dest) {
            Optional::NotPublished => {}
            other => panic!("expected NotPublished, got {other:?}"),
        }
    }

    #[test]
    fn error_display_lists_attempts() {
        let err = FetchError::AllMirrorsFailed {
            url: "go.pkg.tar.zst".into(),
            attempts: vec!["https://a: 404".into(), "https://b: timeout".into()],
        };
        let text = err.to_string();
        assert!(text.contains("go.pkg.tar.zst"));
        assert!(text.contains("https://a: 404"));
        assert!(text.contains("https://b: timeout"));
    }
}
