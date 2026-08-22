//! HTTP downloads with mirror failover and progress reporting.

use crate::ui::progress::Progress;
use std::io::{self, Read, Write};
use std::path::Path;
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

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .user_agent(USER_AGENT)
        .timeout_connect(Some(Duration::from_secs(15)))
        .build()
        .into()
}

/// Streams `url` into `sink`, reporting bytes as they arrive.
fn stream_to<W: Write>(
    agent: &ureq::Agent,
    url: &str,
    sink: &mut W,
    mut on_bytes: impl FnMut(u64),
) -> Result<u64, FetchError> {
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
