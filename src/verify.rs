//! Integrity and authenticity checks for downloaded packages.
//!
//! Two independent checks apply: the SHA-256 recorded in the sync database,
//! and the detached PGP signature published alongside the package. Which of
//! them is mandatory is governed by the repo's `SigLevel`.

use crate::config::Level;
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug)]
pub enum VerifyError {
    ChecksumMismatch { expected: String, actual: String },
    /// A signature was required by SigLevel but no `.sig` was available.
    SignatureMissing,
    /// The signature parsed but no key in the keyring validated it.
    SignatureInvalid(String),
    /// The signing key is not in the keyring.
    UnknownKey(String),
    Keyring(String),
    Io(io::Error),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::ChecksumMismatch { expected, actual } => write!(
                f,
                "checksum mismatch (expected {}, got {})",
                &expected[..expected.len().min(16)],
                &actual[..actual.len().min(16)]
            ),
            VerifyError::SignatureMissing => write!(f, "required signature is missing"),
            VerifyError::SignatureInvalid(e) => write!(f, "signature is not valid: {e}"),
            VerifyError::UnknownKey(id) => write!(f, "signed by unknown key {id}"),
            VerifyError::Keyring(e) => write!(f, "keyring unusable: {e}"),
            VerifyError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<io::Error> for VerifyError {
    fn from(e: io::Error) -> Self {
        VerifyError::Io(e)
    }
}

/// Streams a file through SHA-256 without loading it into memory.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let mut reader = io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Compares a file against an expected SHA-256, case-insensitively.
pub fn check_sha256(path: &Path, expected: &str) -> Result<(), VerifyError> {
    let actual = sha256_file(path)?;
    if actual.eq_ignore_ascii_case(expected.trim()) {
        Ok(())
    } else {
        Err(VerifyError::ChecksumMismatch {
            expected: expected.to_string(),
            actual,
        })
    }
}

/// GnuPG's local "ring trust" packet, which is not part of the OpenPGP
/// transferable-key format.
const TAG_RING_TRUST: u8 = 12;

/// Removes GnuPG's ring-trust packets from a keyring.
///
/// `pubring.gpg` on disk is not quite what `gpg --export` emits: GnuPG
/// interleaves tag-12 trust packets recording its own view of each key. A
/// strict OpenPGP parser reads one as the end of the current transferable key
/// and starts a new one, so every key arrives stripped of its user IDs and,
/// crucially, its subkeys — and no error is raised to say so. Since Arch
/// packages are signed by a packager's signing subkey, the result is that
/// every package looks as though it were signed by a key nobody holds.
fn strip_trust_packets(data: &[u8]) -> Cow<'_, [u8]> {
    let Some(spans) = packet_spans(data) else {
        // Not walkable at the packet level. Hand the original bytes to the
        // real parser and let it report the problem, rather than inventing a
        // truncated keyring here.
        return Cow::Borrowed(data);
    };

    if !spans.iter().any(|(tag, _, _)| *tag == TAG_RING_TRUST) {
        return Cow::Borrowed(data);
    }

    let mut out = Vec::with_capacity(data.len());
    for (tag, start, end) in spans {
        if tag != TAG_RING_TRUST {
            out.extend_from_slice(&data[start..end]);
        }
    }
    Cow::Owned(out)
}

/// Walks OpenPGP packet headers, yielding `(tag, start, end)` for each packet.
///
/// Returns `None` the moment the stream stops looking like a packet sequence,
/// so a malformed keyring is passed through untouched rather than silently
/// rewritten into something else.
fn packet_spans(data: &[u8]) -> Option<Vec<(u8, usize, usize)>> {
    let mut spans = Vec::new();
    let mut i = 0usize;

    while i < data.len() {
        let start = i;
        let header = data[i];
        // Bit 7 is set on every packet header; without it this is not a packet
        // stream and guessing further would be worse than giving up.
        if header & 0x80 == 0 {
            return None;
        }
        i += 1;

        let (tag, len) = if header & 0x40 == 0 {
            // Old format: a four-bit tag and a two-bit length type.
            let tag = (header & 0x3f) >> 2;
            let len = match header & 0x03 {
                0 => be_bytes(data, &mut i, 1)?,
                1 => be_bytes(data, &mut i, 2)?,
                2 => be_bytes(data, &mut i, 4)?,
                // An indeterminate length runs to the end of the stream, which
                // a keyring never uses and this walker cannot bound.
                _ => return None,
            };
            (tag, len)
        } else {
            // New format: a six-bit tag and a self-describing length.
            let tag = header & 0x3f;
            let first = *data.get(i)?;
            i += 1;
            let len = if first < 192 {
                u64::from(first)
            } else if first < 224 {
                let second = *data.get(i)?;
                i += 1;
                ((u64::from(first) - 192) << 8) + u64::from(second) + 192
            } else if first == 255 {
                be_bytes(data, &mut i, 4)?
            } else {
                // Partial body lengths belong to streamed data, not keyrings.
                return None;
            };
            (tag, len)
        };

        let end = i.checked_add(usize::try_from(len).ok()?)?;
        if end > data.len() {
            return None;
        }
        i = end;
        spans.push((tag, start, end));
    }

    Some(spans)
}

/// Reads `n` big-endian bytes as a length, advancing the cursor.
fn be_bytes(data: &[u8], i: &mut usize, n: usize) -> Option<u64> {
    let bytes = data.get(*i..i.checked_add(n)?)?;
    *i += n;
    Some(bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

/// Whether a signature's named issuer is this key or one of its subkeys.
fn names_key(key: &SignedPublicKey, issuers: &[String]) -> bool {
    let known = |fp: String| issuers.iter().any(|i| fp.eq_ignore_ascii_case(&i[..]));
    known(key.fingerprint().to_string())
        || key
            .public_subkeys
            .iter()
            .any(|sub| known(sub.fingerprint().to_string()))
}

/// The public keys trusted for package signatures.
#[derive(Debug)]
pub struct Keyring {
    keys: Vec<SignedPublicKey>,
}

impl Keyring {
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// How many subkeys the keyring holds. A keyring that parses into keys but
    /// no subkeys is the signature of a stripped parse, not of a real keyring.
    pub fn subkey_count(&self) -> usize {
        self.keys.iter().map(|k| k.public_subkeys.len()).sum()
    }

    /// Loads keys from raw OpenPGP bytes (a `pubring.gpg`).
    ///
    /// Individual malformed keys are skipped rather than failing the whole
    /// keyring; a real pacman keyring accumulates revoked and odd entries.
    pub fn from_bytes(data: &[u8]) -> Result<Keyring, VerifyError> {
        let data = strip_trust_packets(data);
        let keys: Vec<SignedPublicKey> =
            SignedPublicKey::from_bytes_many(io::Cursor::new(data.as_ref()))
                .map_err(|e| VerifyError::Keyring(e.to_string()))?
                .flatten()
                .collect();
        Ok(Keyring { keys })
    }

    /// Loads pacman's keyring from a GPG home directory.
    pub fn load(gpg_dir: &Path) -> Result<Keyring, VerifyError> {
        // Modern GnuPG splits keys into a keybox, but pacman keeps a legacy
        // `pubring.gpg` alongside it for exactly this kind of consumer.
        let pubring = gpg_dir.join("pubring.gpg");
        let data = std::fs::read(&pubring).map_err(|e| {
            VerifyError::Keyring(format!("{}: {}", pubring.display(), e))
        })?;
        Keyring::from_bytes(&data)
    }

    /// Verifies `data` against a detached signature, trying the key whose
    /// fingerprint the signature names before falling back to a full scan.
    pub fn verify_detached(&self, data: &[u8], signature: &[u8]) -> Result<String, VerifyError> {
        if self.keys.is_empty() {
            return Err(VerifyError::Keyring("no keys loaded".into()));
        }

        let signatures: Vec<DetachedSignature> =
            DetachedSignature::from_bytes_many(io::Cursor::new(signature))
                .map_err(|e| VerifyError::SignatureInvalid(e.to_string()))?
                .flatten()
                .collect();

        if signatures.is_empty() {
            return Err(VerifyError::SignatureInvalid("no signature packets".into()));
        }

        let mut last_error: Option<VerifyError> = None;

        for sig in &signatures {
            let issuers: Vec<String> = sig
                .signature
                .issuer_fingerprint()
                .iter()
                .map(|f| f.to_string())
                .collect();

            // A signature names the key that made it, which for an Arch
            // package is a packager's signing subkey rather than their primary
            // key. Comparing only primary fingerprints matches nothing.
            let named: Vec<&SignedPublicKey> = self
                .keys
                .iter()
                .filter(|key| names_key(key, &issuers))
                .collect();

            // Knowing which key signed something makes searching the rest of
            // the keyring pointless: if the named key does not verify the
            // payload, no other key will, and every extra candidate means
            // hashing the whole package again to reach the same answer. Only a
            // signature that names nobody justifies trying everything.
            let candidates: Vec<&SignedPublicKey> = if !named.is_empty() {
                named
            } else if issuers.is_empty() {
                self.keys.iter().collect()
            } else {
                // Holding none of the named keys is a different problem from
                // holding one that disagrees, and wants a different fix.
                last_error = Some(VerifyError::UnknownKey(issuers.join(", ")));
                continue;
            };

            for key in candidates {
                if sig.verify(key, data).is_ok() {
                    return Ok(key.fingerprint().to_string());
                }
                // Subkeys sign packages far more often than primary keys do.
                for subkey in &key.public_subkeys {
                    if sig.verify(subkey, data).is_ok() {
                        return Ok(key.fingerprint().to_string());
                    }
                }
            }

            last_error = Some(VerifyError::SignatureInvalid(if issuers.is_empty() {
                "the signature names no key and matched none".to_string()
            } else {
                // The signing key is trusted, so the content is what changed.
                format!(
                    "the content does not match the signature made by {}",
                    issuers.join(", ")
                )
            }));
        }

        Err(last_error
            .unwrap_or_else(|| VerifyError::SignatureInvalid("no matching key".into())))
    }
}

/// The outcome of verifying one package file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// Checksum matched and a signature was validated.
    ChecksumAndSignature { key: String },
    /// Checksum matched; no signature was required.
    ChecksumOnly,
    /// Verification was skipped entirely (`SigLevel = Never`, no checksum).
    Skipped,
}

/// Runs the full check for a downloaded package or database.
///
/// `signature` is the contents of the `.sig` file, when one was fetched.
pub fn verify_package(
    path: &Path,
    expected_sha256: Option<&str>,
    signature: Option<&[u8]>,
    keyring: Option<&Keyring>,
    level: Level,
) -> Result<Verified, VerifyError> {
    if let Some(expected) = expected_sha256 {
        check_sha256(path, expected)?;
    }

    if level == Level::Never {
        return Ok(if expected_sha256.is_some() {
            Verified::ChecksumOnly
        } else {
            Verified::Skipped
        });
    }

    match signature {
        Some(sig) => {
            let keyring = keyring.ok_or_else(|| VerifyError::Keyring("not loaded".into()))?;
            let data = std::fs::read(path)?;
            let key = keyring.verify_detached(&data, sig)?;
            Ok(Verified::ChecksumAndSignature { key })
        }
        None if level == Level::Required => Err(VerifyError::SignatureMissing),
        None => Ok(if expected_sha256.is_some() {
            Verified::ChecksumOnly
        } else {
            Verified::Skipped
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(tag: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rvn-verify-{tag}"));
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// The SHA-256 of "hello", as a known-good vector.
    const HELLO_SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn hashes_match_known_vector() {
        let path = temp_file("hello", b"hello");
        assert_eq!(sha256_file(&path).unwrap(), HELLO_SHA);
        assert!(check_sha256(&path, HELLO_SHA).is_ok());
        // Uppercase digests from a database must still match.
        assert!(check_sha256(&path, &HELLO_SHA.to_uppercase()).is_ok());
    }

    #[test]
    fn checksum_mismatch_is_reported_with_both_values() {
        let path = temp_file("mismatch", b"hello");
        let err = check_sha256(&path, &"0".repeat(64)).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
        match err {
            VerifyError::ChecksumMismatch { actual, .. } => assert_eq!(actual, HELLO_SHA),
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[test]
    fn siglevel_never_skips_signature_checks() {
        let path = temp_file("never", b"hello");
        let result =
            verify_package(&path, Some(HELLO_SHA), None, None, Level::Never).unwrap();
        assert_eq!(result, Verified::ChecksumOnly);
    }

    #[test]
    fn siglevel_required_rejects_a_missing_signature() {
        let path = temp_file("required", b"hello");
        let err =
            verify_package(&path, Some(HELLO_SHA), None, None, Level::Required).unwrap_err();
        assert!(matches!(err, VerifyError::SignatureMissing));
    }

    #[test]
    fn siglevel_optional_accepts_a_missing_signature() {
        let path = temp_file("optional", b"hello");
        let result =
            verify_package(&path, Some(HELLO_SHA), None, None, Level::Optional).unwrap();
        assert_eq!(result, Verified::ChecksumOnly);
    }

    #[test]
    fn a_bad_checksum_fails_before_any_signature_work() {
        let path = temp_file("early-exit", b"hello");
        // No keyring is supplied, so reaching the signature stage would panic
        // on the unwrap path; a checksum failure must short-circuit first.
        let err = verify_package(&path, Some(&"a".repeat(64)), Some(b"junk"), None, Level::Required)
            .unwrap_err();
        assert!(matches!(err, VerifyError::ChecksumMismatch { .. }));
    }

    #[test]
    fn a_tampered_payload_is_not_reported_as_an_unknown_key() {
        // Regression: a valid key whose signature no longer matches the data
        // was reported as "unknown key", pointing at the wrong problem.
        let error = VerifyError::SignatureInvalid(
            "the content does not match the signature made by ABC".into(),
        );
        let text = error.to_string();
        assert!(text.contains("does not match"), "{text}");
        assert!(!text.contains("unknown"), "{text}");
    }

    #[test]
    fn empty_keyring_is_rejected_rather_than_silently_passing() {
        let keyring = Keyring { keys: Vec::new() };
        assert!(keyring.is_empty());
        let err = keyring.verify_detached(b"data", b"sig").unwrap_err();
        assert!(matches!(err, VerifyError::Keyring(_)));
    }

    #[test]
    fn garbage_signature_bytes_do_not_panic() {
        let keyring = Keyring {
            keys: Vec::new(),
        };
        assert!(keyring.verify_detached(b"data", b"not a signature").is_err());
    }

    /// Builds an old-format packet, the shape GnuPG writes trust packets in.
    fn old_packet(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80 | (tag << 2)];
        out.push(body.len() as u8);
        out.extend_from_slice(body);
        out
    }

    /// Builds a new-format packet using the two-byte length encoding.
    fn new_packet_two_byte_len(tag: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len();
        assert!((192..8384).contains(&len));
        let encoded = len - 192;
        let mut out = vec![0xc0 | tag];
        out.push(((encoded >> 8) + 192) as u8);
        out.push((encoded & 0xff) as u8);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn ring_trust_packets_are_removed_and_nothing_else_is() {
        // Regression: GnuPG interleaves these in pubring.gpg, and a parser
        // that takes one as the end of a key drops every subkey that follows.
        // Arch packages are signed by subkeys, so this made every package look
        // as though it were signed by a key nobody has.
        let mut ring = Vec::new();
        ring.extend(old_packet(6, b"primary key"));
        ring.extend(old_packet(TAG_RING_TRUST, b"gnupg local state"));
        ring.extend(old_packet(13, b"user id"));
        ring.extend(old_packet(TAG_RING_TRUST, b"more local state"));
        ring.extend(old_packet(14, b"signing subkey"));

        let stripped = strip_trust_packets(&ring);
        assert!(matches!(stripped, Cow::Owned(_)), "trust packets were present");

        let tags: Vec<u8> = packet_spans(&stripped)
            .unwrap()
            .into_iter()
            .map(|(tag, _, _)| tag)
            .collect();
        assert_eq!(tags, vec![6, 13, 14]);

        // The surviving packets must come through byte for byte.
        assert!(stripped.windows(14).any(|w| w == b"signing subkey"));
        assert!(!stripped.windows(17).any(|w| w == b"gnupg local state"));
    }

    #[test]
    fn a_keyring_without_trust_packets_is_left_alone() {
        let ring = [old_packet(6, b"primary"), old_packet(14, b"subkey")].concat();
        // Borrowed rather than rebuilt: an export from `gpg --export` already
        // has the right shape and must not be copied for nothing.
        assert!(matches!(strip_trust_packets(&ring), Cow::Borrowed(_)));
    }

    #[test]
    fn new_format_lengths_are_walked_correctly() {
        let body = vec![b'x'; 500];
        let mut ring = new_packet_two_byte_len(6, &body);
        ring.extend(old_packet(TAG_RING_TRUST, b"trust"));
        let spans = packet_spans(&ring).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0], (6, 0, 503));
        assert_eq!(spans[1].0, TAG_RING_TRUST);
    }

    #[test]
    fn a_stream_that_is_not_packets_is_passed_through_untouched() {
        // Better to let the real parser report a bad keyring than to rewrite
        // bytes we do not understand.
        let junk = b"not an openpgp packet stream at all";
        assert!(matches!(strip_trust_packets(junk), Cow::Borrowed(_)));
        assert!(packet_spans(junk).is_none());
    }

    #[test]
    fn a_packet_claiming_more_bytes_than_exist_is_rejected() {
        // Old format, one-byte length of 200, with only 3 bytes following.
        let truncated = vec![0x98, 200, 1, 2, 3];
        assert!(packet_spans(&truncated).is_none());
        assert!(matches!(strip_trust_packets(&truncated), Cow::Borrowed(_)));
    }

    #[test]
    fn indeterminate_and_partial_lengths_are_declined() {
        // Neither appears in a keyring, and neither can be bounded here.
        assert!(packet_spans(&[0x83, 1, 2, 3]).is_none()); // old, indeterminate
        assert!(packet_spans(&[0xc6, 230, 1, 2]).is_none()); // new, partial body
    }

    /// The real keyring is the case that broke; check it when it is present.
    #[test]
    fn the_system_keyring_parses_with_its_subkeys_intact() {
        let dir = Path::new("/etc/pacman.d/gnupg");
        if !dir.join("pubring.gpg").exists() {
            return;
        }
        let Ok(keyring) = Keyring::load(dir) else {
            return; // Unreadable without privileges on some systems.
        };
        assert!(!keyring.is_empty());
        assert!(
            keyring.subkey_count() > 0,
            "every subkey was dropped: {} keys, 0 subkeys",
            keyring.len()
        );
    }

    #[test]
    fn missing_keyring_file_is_an_error_not_a_pass() {
        let err = Keyring::load(Path::new("/nonexistent/rvn/gnupg")).unwrap_err();
        assert!(matches!(err, VerifyError::Keyring(_)));
    }
}
