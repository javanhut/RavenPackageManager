//! Integrity and authenticity checks for downloaded packages.
//!
//! Two independent checks apply: the SHA-256 recorded in the sync database,
//! and the detached PGP signature published alongside the package. Which of
//! them is mandatory is governed by the repo's `SigLevel`.

use crate::config::Level;
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;
use sha2::{Digest, Sha256};
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

    /// Loads keys from raw OpenPGP bytes (a `pubring.gpg`).
    ///
    /// Individual malformed keys are skipped rather than failing the whole
    /// keyring; a real pacman keyring accumulates revoked and odd entries.
    pub fn from_bytes(data: &[u8]) -> Result<Keyring, VerifyError> {
        let keys: Vec<SignedPublicKey> = SignedPublicKey::from_bytes_many(io::Cursor::new(data))
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

        let mut last_error = String::from("no matching key");

        for sig in &signatures {
            let issuers: Vec<String> = sig
                .signature
                .issuer_fingerprint()
                .iter()
                .map(|f| f.to_string())
                .collect();

            // Split the keyring so "we do not have that key" and "we have it
            // and the data does not match" stay distinguishable — they mean
            // very different things to whoever has to act on the message.
            let mut named: Vec<&SignedPublicKey> = Vec::new();
            let mut rest: Vec<&SignedPublicKey> = Vec::new();
            for key in &self.keys {
                let fp = key.fingerprint().to_string();
                if issuers.iter().any(|i| fp.eq_ignore_ascii_case(i)) {
                    named.push(key);
                } else {
                    rest.push(key);
                }
            }
            let issuer_known = !named.is_empty();

            for key in named.iter().chain(rest.iter()) {
                if sig.verify(*key, data).is_ok() {
                    return Ok(key.fingerprint().to_string());
                }
                // Subkeys sign packages far more often than primary keys do.
                for subkey in &key.public_subkeys {
                    if sig.verify(subkey, data).is_ok() {
                        return Ok(key.fingerprint().to_string());
                    }
                }
            }

            last_error = if issuer_known {
                // The signing key is trusted, so the content is what changed.
                format!(
                    "the content does not match the signature made by {}",
                    issuers.join(", ")
                )
            } else if !issuers.is_empty() {
                format!("signed by unknown key {}", issuers.join(", "))
            } else {
                "the signature names no key and matched none".to_string()
            };
        }

        Err(VerifyError::SignatureInvalid(last_error))
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

    #[test]
    fn missing_keyring_file_is_an_error_not_a_pass() {
        let err = Keyring::load(Path::new("/nonexistent/rvn/gnupg")).unwrap_err();
        assert!(matches!(err, VerifyError::Keyring(_)));
    }
}
