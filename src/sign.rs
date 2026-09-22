//! Making the detached signatures [`crate::verify`] checks.
//!
//! rvn has verified PGP signatures since it existed and has never made one.
//! That was fine while every package came from a mirror somebody else signs,
//! and stops being fine the moment rvn builds packages of its own: a
//! repository of RavenLinux's userland that nothing signs is a repository
//! where a machine in the middle can replace `rvn` itself, and
//! [`crate::ops::sync::verify_database`] already has the code to refuse that
//! if only somebody would sign the database.
//!
//! # Why this shells out to gpg
//!
//! The `pgp` crate is already a dependency and does support signing.
//! [`crate::verify`] uses its `SignedPublicKey` and `DetachedSignature` for
//! the verifying half, and the symmetric change would be to read a
//! `SignedSecretKey` here. It is not a contained change, and the reason is
//! not the API: it is that reading a secret key means rvn holds private key
//! material, which means rvn owns unlocking it, which means rvn owns
//! passphrase prompting, passphrase caching, and being the process a
//! passphrase is typed into. That is a security surface this crate has never
//! had, added for a command that runs on a build machine.
//!
//! `gpg` already owns all of it, including `gpg-agent` and whatever pinentry
//! the machine is set up with, and it is installed anywhere a package is
//! being built. So rvn names a key and hands gpg a file. The private key
//! never enters this process, and rvn never writes one anywhere.
//!
//! # Naming a key
//!
//! `key` is either a key identifier gpg already knows -- a fingerprint, a
//! key id, an email address -- or a path to an exported secret key file. The
//! second form is what a CI runner has: a key file the pipeline dropped on
//! disk, with no keyring around it. For that case rvn imports it into a
//! GNUPGHOME of its own, made 0700, used for the one signature and removed
//! afterwards, so signing never modifies the keyring the person who ran the
//! command uses for anything else.
//!
//! A passphrase-protected key file is refused rather than prompted for: rvn
//! would have to pass the passphrase to gpg, which means rvn would have to
//! have it. Use an agent-backed key identifier for that, which is the case
//! gpg handles properly.

use crate::toml::Document;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the signing configuration lives, relative to the install root.
///
/// Under `etc/rvn` beside `provides.d` and `hooks.d`, which is the directory
/// rvn already owns. It is optional and absent on every machine that is not
/// building packages, which is almost all of them.
pub const CONFIG: &str = "etc/rvn/build.toml";

#[derive(Debug)]
pub enum Error {
    /// gpg is not installed.
    MissingProgram,
    /// The configured key file is not there.
    NoSuchKey { key: String },
    /// gpg refused, with what it said.
    Refused { message: String },
    Io {
        doing: String,
        source: std::io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingProgram => write!(
                f,
                "gpg is not installed, and signing needs it — install gnupg, or build without --sign"
            ),
            Error::NoSuchKey { key } => write!(
                f,
                "{key} is neither a key gpg knows nor a file on disk — check `[sign] key` in /{CONFIG}, or pass --key"
            ),
            Error::Refused { message } => write!(f, "gpg refused to sign: {message}"),
            Error::Io { doing, source } => write!(f, "{doing}: {source}"),
        }
    }
}

fn io(doing: impl Into<String>) -> impl FnOnce(std::io::Error) -> Error {
    let doing = doing.into();
    move |source| Error::Io { doing, source }
}

/// A configured signing key.
///
/// `key` is a name, never key material: a gpg identifier or a path. Nothing
/// secret is held here, which is why it is safe for this to be `Debug`.
#[derive(Debug)]
pub struct Signer {
    /// What was configured: a gpg key identifier, or a path to a key file.
    key: String,
    /// Where the setting came from, for saying so when a signature fails.
    pub source: String,
}

impl Signer {
    /// A signer for a key named on the command line.
    pub fn named(key: &str) -> Signer {
        Signer {
            key: key.to_string(),
            source: "--key".to_string(),
        }
    }

    /// The signer `etc/rvn/build.toml` configures, if it configures one.
    ///
    /// Absent is not an error and never will be: a machine that installs
    /// packages has no reason to have this file, and a build that was not
    /// asked to sign does not need it either. A file that is *present* and
    /// does not parse is an error, for the reason stated in
    /// [`crate::toml`] -- falling back to "do not sign" would quietly ignore
    /// a policy somebody wrote down, and the packages would ship unsigned.
    pub fn configured(root: &Path) -> Result<Option<Signer>, String> {
        let path = root.join(CONFIG);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };

        let document = Document::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        for section in document.sections() {
            if section.name.is_empty() && section.is_empty() {
                continue;
            }
            if section.name != "sign" {
                return Err(format!(
                    "{}: line {}: [{}] is not a section this file has; it has [sign]",
                    path.display(),
                    section.line,
                    section.name
                ));
            }
            for key in section.keys() {
                if key != "key" {
                    return Err(format!(
                        "{}: line {}: `{key}` is not a key [sign] has; it has `key`",
                        path.display(),
                        section.line_of(key)
                    ));
                }
            }
        }

        let Some(section) = document.section("sign") else {
            return Ok(None);
        };
        let Some(value) = section.get("key") else {
            return Ok(None);
        };
        let key = value.as_str().ok_or_else(|| {
            format!(
                "{}: line {}: `key` is a string — a gpg key id, or the path to a secret key file",
                path.display(),
                section.line_of("key")
            )
        })?;

        Ok(Some(Signer {
            key: key.to_string(),
            source: path.display().to_string(),
        }))
    }

    /// Signs `path`, writing `<path>.sig` beside it.
    ///
    /// The signature is binary rather than armoured, because that is what
    /// [`crate::verify::Keyring::verify_detached`] reads and what mirrors
    /// serve: a `.sig` next to a package is the raw packet stream.
    pub fn sign(&self, path: &Path) -> Result<PathBuf, Error> {
        let signature = PathBuf::from(format!("{}.sig", path.display()));
        // Removed first: gpg refuses to write over an existing output file,
        // and a stale signature from a previous build of the same version is
        // worse than none -- it verifies, against the wrong bytes.
        let _ = std::fs::remove_file(&signature);

        let key_file = Path::new(&self.key);
        if key_file.is_file() {
            let home = EphemeralHome::create(path)?;
            home.import(key_file)?;
            run(Command::new("gpg")
                .args(["--homedir".as_ref(), home.dir.as_os_str()])
                .args(["--batch", "--yes", "--quiet", "--detach-sign", "--no-armor"])
                .arg("--output")
                .arg(&signature)
                .arg(path))?;
        } else {
            if self.key.contains('/') {
                // A value with a slash in it was meant to be a path, so
                // saying "gpg does not know that key" would send the reader
                // looking in the wrong place.
                return Err(Error::NoSuchKey {
                    key: self.key.clone(),
                });
            }
            run(Command::new("gpg")
                .args(["--batch", "--yes", "--detach-sign", "--no-armor"])
                .args(["--local-user", &self.key])
                .arg("--output")
                .arg(&signature)
                .arg(path))?;
        }

        Ok(signature)
    }
}

/// Runs gpg and turns a refusal into something a person can act on.
fn run(command: &mut Command) -> Result<(), Error> {
    let output = command.output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::MissingProgram
        } else {
            Error::Io {
                doing: "running gpg".to_string(),
                source: e,
            }
        }
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with("gpg: Warning"))
            .unwrap_or("no output")
            .to_string();
        return Err(Error::Refused { message });
    }
    Ok(())
}

/// A GNUPGHOME that exists for one signature.
///
/// It is made beside the file being signed rather than in /tmp: the build
/// output directory is already a place this process is writing to, and a
/// world-writable /tmp is the wrong place to put a directory a secret key is
/// about to be imported into -- the same argument
/// [`crate::scriptlet::staging_dir`] makes about staging scriptlets.
struct EphemeralHome {
    dir: PathBuf,
}

impl EphemeralHome {
    fn create(beside: &Path) -> Result<EphemeralHome, Error> {
        let parent = beside.parent().unwrap_or(Path::new("."));
        let dir = parent.join(format!(".rvn-signing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(io("creating a keyring for signing"))?;
        // Set immediately after creation rather than at create time, and then
        // set rather than assumed: gpg refuses to use a homedir anybody else
        // can read, and so should rvn.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(io("securing the keyring for signing"))?;
        Ok(EphemeralHome { dir })
    }

    fn import(&self, key: &Path) -> Result<(), Error> {
        run(Command::new("gpg")
            .args(["--homedir".as_ref(), self.dir.as_os_str()])
            .args(["--batch", "--quiet", "--import"])
            .arg(key))
    }
}

impl Drop for EphemeralHome {
    /// Removed whichever way signing ended. What is in here is a copy of a
    /// secret key, so it is not left behind for a failed build to leak.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-sign-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp dir");
        dir
    }

    #[test]
    fn no_configuration_file_is_not_an_error() {
        let dir = temp_dir("absent");
        assert!(
            Signer::configured(&dir)
                .expect("an absent file is fine")
                .is_none(),
            "a machine that installs packages has no build.toml and must not need one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_configured_key_is_read_and_a_broken_file_stops_the_build() {
        let dir = temp_dir("config");
        let config = dir.join(CONFIG);
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();

        std::fs::write(&config, "[sign]\nkey = \"0xDEADBEEF\"\n").unwrap();
        let signer = Signer::configured(&dir)
            .unwrap()
            .expect("a key is configured");
        assert_eq!(signer.key, "0xDEADBEEF");
        assert!(signer.source.ends_with(CONFIG));

        // A present file that does not parse, or that says something this
        // does not understand, is refused by name rather than treated as "do
        // not sign" -- the packages would ship unsigned and nobody would be
        // told.
        for (text, says) in [
            ("[sign]\nkey = \"a\"\nkeys = \"b\"\n", "`keys` is not a key"),
            ("[signing]\nkey = \"a\"\n", "[signing] is not a section"),
            ("[sign]\nkey = 7\n", "`key` is a string"),
            ("[sign]\nkey = \n", "line 2"),
        ] {
            std::fs::write(&config, text).unwrap();
            let e = Signer::configured(&dir).expect_err("this file should be refused");
            assert!(e.contains(says), "{text:?} -> {e}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reference file shipped in the repository at `etc/rvn/build.toml`.
    const SHIPPED: &str = include_str!("../etc/rvn/build.toml");

    #[test]
    fn the_shipped_reference_file_parses_and_describes_the_default() {
        // Two things are being checked and both have bitten this project's
        // configuration files before. The first is that the file parses at
        // all: it is written by hand, nothing reads it in the test suite
        // otherwise, and a stray character in it would only be discovered by
        // whoever copied it to /etc. The second is that what it describes
        // with everything commented out is what the code actually does with
        // no file at all -- a reference file that documents a default the
        // code does not have is worse than no reference file.
        let document = Document::parse(SHIPPED).expect("the shipped file should parse");
        let section = document
            .section("sign")
            .expect("the shipped file should carry the [sign] header, so the name is discoverable");
        assert!(
            section.is_empty(),
            "every key in the reference file is commented out, so copying it changes nothing"
        );

        let dir = temp_dir("shipped");
        let config = dir.join(CONFIG);
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, SHIPPED).unwrap();
        assert!(
            Signer::configured(&dir).unwrap().is_none(),
            "the shipped file must mean the same as no file: nothing is signed until a key is named"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_path_that_is_not_there_says_so_rather_than_blaming_gpg() {
        let dir = temp_dir("missing");
        let target = dir.join("package.pkg.tar.zst");
        std::fs::write(&target, b"not really a package").unwrap();

        let signer = Signer::named("/no/such/key.asc");
        let e = signer
            .sign(&target)
            .expect_err("a missing key file should fail");
        assert!(
            matches!(e, Error::NoSuchKey { .. }),
            "a path that is not there is a missing key, not a gpg refusal: {e}"
        );
        assert!(e.to_string().contains("neither a key gpg knows nor a file"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
