//! What a package expects the *system* to do at install time.
//!
//! Arch packages do not create their users or seed /etc themselves -- they
//! ship declarations and expect the distribution to act on them:
//!
//!   usr/lib/sysusers.d/*.conf   accounts the package's daemons run as
//!   usr/lib/tmpfiles.d/*.conf   files copied from /usr/share/factory into /etc
//!
//! On Arch both are processed by systemd. Raven has no systemd, so before this
//! module existed the declarations were silently ignored: `rvn install` put
//! the binaries on disk and the daemon then died on its missing user or its
//! missing config, and the person at the keyboard was told to fix it by hand.
//! An installation is supposed to do that part itself.
//!
//! Only the subset packages actually rely on is implemented: `u`/`u!`, `g`
//! and `m` lines from sysusers.d, and `C`/`C+` (copy from factory if missing)
//! and `d` (create directory) from tmpfiles.d. Everything else in those
//! formats is about boot-time state, which is init's business, not the
//! package manager's.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// What was done, so the UI can say so.
#[derive(Debug, Default, PartialEq)]
pub struct Applied {
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub memberships: Vec<(String, String)>,
    pub copied: Vec<String>,
    pub directories: Vec<String>,
}

impl Applied {
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
            && self.groups.is_empty()
            && self.memberships.is_empty()
            && self.copied.is_empty()
            && self.directories.is_empty()
    }
}

/// Processes the sysusers.d and tmpfiles.d fragments among `files`, which are
/// the root-relative paths one package just installed.
///
/// Failures are reported, not fatal: the package's files are already on disk
/// and registered, and un-installing them because a duplicate uid was declared
/// would be a worse outcome than a warning.
pub fn apply(root: &Path, files: &[String], warn: &mut impl FnMut(&str)) -> Applied {
    let mut applied = Applied::default();

    for file in files {
        if file.starts_with("usr/lib/sysusers.d/")
            && file.ends_with(".conf")
            && let Ok(text) = std::fs::read_to_string(root.join(file))
        {
            apply_sysusers(root, &text, &mut applied, warn);
        }
    }
    // Users first, then files: a `C` copy may carry ownership of a user the
    // same package declared.
    for file in files {
        if file.starts_with("usr/lib/tmpfiles.d/")
            && file.ends_with(".conf")
            && let Ok(text) = std::fs::read_to_string(root.join(file))
        {
            apply_tmpfiles(root, &text, &mut applied, warn);
        }
    }

    applied
}

/// Splits a sysusers/tmpfiles line into fields, honouring double quotes --
/// the GECOS field is routinely `"System Message Bus"`.
fn fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn apply_sysusers(root: &Path, text: &str, applied: &mut Applied, warn: &mut impl FnMut(&str)) {
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f = fields(line);
        match f.first().map(String::as_str) {
            // `u!` is a user with a locked password -- which is the only kind
            // rvn creates anyway, so the two spellings act the same here.
            Some("u") | Some("u!") if f.len() >= 2 => {
                let name = &f[1];
                let uid = f.get(2).map(String::as_str).unwrap_or("-");
                let gecos = f.get(3).map(String::as_str).unwrap_or("-");
                let home = f.get(4).map(String::as_str).unwrap_or("-");
                match ensure_user(root, name, uid, gecos, home) {
                    Ok(true) => applied.users.push(name.clone()),
                    Ok(false) => {}
                    Err(e) => warn(&format!("sysusers: could not create user {name}: {e}")),
                }
            }
            Some("g") if f.len() >= 2 => {
                let name = &f[1];
                let gid = f.get(2).map(String::as_str).unwrap_or("-");
                match ensure_group(root, name, gid) {
                    Ok(Some(_)) => applied.groups.push(name.clone()),
                    Ok(None) => {}
                    Err(e) => warn(&format!("sysusers: could not create group {name}: {e}")),
                }
            }
            Some("m") if f.len() >= 3 => {
                let (user, group) = (&f[1], &f[2]);
                match add_membership(root, user, group) {
                    Ok(true) => applied.memberships.push((user.clone(), group.clone())),
                    Ok(false) => {}
                    Err(e) => {
                        warn(&format!("sysusers: could not add {user} to {group}: {e}"))
                    }
                }
            }
            // `r` (uid ranges) and anything unrecognised: not needed by the
            // packages this exists for.
            _ => {}
        }
    }
}

/// The passwd/group/shadow files under an install root.
fn db(root: &Path, name: &str) -> PathBuf {
    root.join("etc").join(name)
}

fn read_db(root: &Path, name: &str) -> String {
    std::fs::read_to_string(db(root, name)).unwrap_or_default()
}

fn append_db(root: &Path, name: &str, line: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join("etc"))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(db(root, name))?;
    // The last line of a hand-edited passwd does not always end in a newline,
    // and appending straight after it would splice two entries into one.
    let existing = read_db(root, name);
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file)?;
    }
    writeln!(file, "{line}")
}

fn name_exists(content: &str, name: &str) -> bool {
    content
        .lines()
        .any(|l| l.split(':').next() == Some(name))
}

fn ids_in_use(content: &str, field: usize) -> HashSet<u32> {
    content
        .lines()
        .filter_map(|l| l.split(':').nth(field))
        .filter_map(|id| id.parse().ok())
        .collect()
}

/// System accounts get 100-999, allocated downward -- the same range
/// sysusers.d(5) documents, well clear of both the fixed low uids and the
/// first login user at 1000.
fn free_system_id(used: &HashSet<u32>) -> Option<u32> {
    (100..=999).rev().find(|id| !used.contains(id))
}

fn parse_or_free(spec: &str, used: &HashSet<u32>) -> Option<u32> {
    if spec == "-" {
        free_system_id(used)
    } else {
        // `uid:gid` appears occasionally; the uid half is what names the user.
        spec.split(':').next()?.parse().ok()
    }
}

/// Days since the epoch, for the shadow "last changed" field.
fn today() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(0)
}

fn ensure_group(root: &Path, name: &str, gid_spec: &str) -> std::io::Result<Option<u32>> {
    let group = read_db(root, "group");
    if name_exists(&group, name) {
        return Ok(None);
    }
    let used = ids_in_use(&group, 2);
    let gid = parse_or_free(gid_spec, &used).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no free gid in 100-999")
    })?;
    append_db(root, "group", &format!("{name}:x:{gid}:"))?;
    Ok(Some(gid))
}

fn ensure_user(
    root: &Path,
    name: &str,
    uid_spec: &str,
    gecos: &str,
    home: &str,
) -> std::io::Result<bool> {
    let passwd = read_db(root, "passwd");
    if name_exists(&passwd, name) {
        return Ok(false);
    }

    // A sysusers `u` line declares the group of the same name with it.
    let gid = match ensure_group(root, name, uid_spec)? {
        Some(gid) => gid,
        None => read_db(root, "group")
            .lines()
            .find(|l| l.split(':').next() == Some(name))
            .and_then(|l| l.split(':').nth(2))
            .and_then(|g| g.parse().ok())
            .unwrap_or(65534),
    };

    let used = ids_in_use(&passwd, 2);
    let uid = parse_or_free(uid_spec, &used).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no free uid in 100-999")
    })?;

    let gecos = if gecos == "-" { name } else { gecos };
    let home = if home == "-" { "/" } else { home };

    append_db(
        root,
        "passwd",
        &format!("{name}:x:{uid}:{gid}:{gecos}:{home}:/bin/false"),
    )?;
    // Locked: these accounts exist to own processes and files, not to log in.
    append_db(root, "shadow", &format!("{name}:!:{}:0:99999:7:::", today()))?;
    Ok(true)
}

fn add_membership(root: &Path, user: &str, group: &str) -> std::io::Result<bool> {
    let content = read_db(root, "group");
    let mut changed = false;
    let mut out = String::new();
    for line in content.lines() {
        if line.split(':').next() == Some(group) {
            let members = line.rsplit(':').next().unwrap_or("");
            let already = members.split(',').any(|m| m == user);
            if !already {
                let sep = if members.is_empty() { "" } else { "," };
                out.push_str(&format!("{line}{sep}{user}\n"));
                changed = true;
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if changed {
        std::fs::write(db(root, "group"), out)?;
    }
    Ok(changed)
}

fn apply_tmpfiles(root: &Path, text: &str, applied: &mut Applied, warn: &mut impl FnMut(&str)) {
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f = fields(line);
        let (Some(kind), Some(target)) = (f.first(), f.get(1)) else {
            continue;
        };
        let relative = target.trim_start_matches('/');

        match kind.as_str() {
            // Copy into place if nothing is there yet. The source is the
            // seventh field when given, and /usr/share/factory/<target>
            // otherwise -- which is where Arch ships every default it used
            // to write into /etc directly.
            "C" | "C+" => {
                let destination = root.join(relative);
                if destination.exists() {
                    continue;
                }
                let source = match f.get(6).filter(|s| *s != "-") {
                    Some(src) => root.join(src.trim_start_matches('/')),
                    None => root.join("usr/share/factory").join(relative),
                };
                if !source.exists() {
                    continue;
                }
                if let Err(e) = copy_recursive(&source, &destination) {
                    warn(&format!("tmpfiles: could not copy {target}: {e}"));
                } else {
                    applied.copied.push(target.clone());
                }
            }
            "d" | "D" => {
                let destination = root.join(relative);
                if destination.is_dir() {
                    continue;
                }
                if let Err(e) = std::fs::create_dir_all(&destination) {
                    warn(&format!("tmpfiles: could not create {target}: {e}"));
                    continue;
                }
                if let Some(mode) = f.get(2).filter(|m| *m != "-")
                    && let Ok(bits) = u32::from_str_radix(mode, 8)
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &destination,
                        std::fs::Permissions::from_mode(bits),
                    );
                }
                applied.directories.push(target.clone());
            }
            // f, w, L, r, z and friends manage boot-time state; init's job.
            _ => {}
        }
    }
}

fn copy_recursive(source: &Path, destination: &Path) -> std::io::Result<()> {
    if source.is_dir() {
        std::fs::create_dir_all(destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_recursive(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, destination)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rvn-hooks-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        dir
    }

    fn no_warn() -> impl FnMut(&str) {
        |m: &str| panic!("unexpected warning: {m}")
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    /// dbus's actual fragment: the daemon dies at boot without its uid, which
    /// is exactly what happened when /etc/passwd lost the entry.
    #[test]
    fn a_sysusers_fragment_creates_the_user_group_and_shadow_entry() {
        let root = root("sysusers-u");
        write(&root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
        write(&root, "etc/group", "root:x:0:\n");
        write(
            &root,
            "usr/lib/sysusers.d/dbus.conf",
            "# comment\nu dbus 81 \"System Message Bus\"\n",
        );

        let applied = apply(&root, &["usr/lib/sysusers.d/dbus.conf".into()], &mut no_warn());

        assert_eq!(applied.users, vec!["dbus"]);
        let passwd = std::fs::read_to_string(root.join("etc/passwd")).unwrap();
        assert!(passwd.contains("dbus:x:81:81:System Message Bus:/:/bin/false"), "{passwd}");
        assert!(passwd.starts_with("root:"), "existing entries survive: {passwd}");
        let shadow = std::fs::read_to_string(root.join("etc/shadow")).unwrap();
        assert!(shadow.starts_with("dbus:!:"), "locked, not passwordless: {shadow}");
    }

    #[test]
    fn an_existing_user_is_left_exactly_alone() {
        let root = root("sysusers-existing");
        write(&root, "etc/passwd", "dbus:x:81:81:Bus:/:/bin/false\n");
        write(&root, "etc/group", "dbus:x:81:\n");
        write(&root, "usr/lib/sysusers.d/dbus.conf", "u dbus 81\n");

        let applied = apply(&root, &["usr/lib/sysusers.d/dbus.conf".into()], &mut no_warn());

        assert!(applied.is_empty());
        assert_eq!(
            std::fs::read_to_string(root.join("etc/passwd")).unwrap(),
            "dbus:x:81:81:Bus:/:/bin/false\n"
        );
    }

    /// A `-` uid means "any free system id"; a fixed one that is already taken
    /// must not create a second user with the same number.
    #[test]
    fn a_dash_uid_allocates_from_the_system_range() {
        let root = root("sysusers-dash");
        write(&root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
        write(&root, "etc/group", "root:x:0:\n");
        write(&root, "usr/lib/sysusers.d/x.conf", "u! avahi - - /var/run/avahi\n");

        let applied = apply(&root, &["usr/lib/sysusers.d/x.conf".into()], &mut no_warn());

        assert_eq!(applied.users, vec!["avahi"]);
        let passwd = std::fs::read_to_string(root.join("etc/passwd")).unwrap();
        let uid: u32 = passwd
            .lines()
            .find(|l| l.starts_with("avahi:"))
            .and_then(|l| l.split(':').nth(2))
            .unwrap()
            .parse()
            .unwrap();
        assert!((100..=999).contains(&uid), "system range, got {uid}");
        assert!(passwd.contains(":/var/run/avahi:"));
    }

    #[test]
    fn membership_lines_extend_the_group() {
        let root = root("sysusers-m");
        write(&root, "etc/group", "audio:x:11:raven\nvideo:x:12:\n");
        write(
            &root,
            "usr/lib/sysusers.d/x.conf",
            "m pulse audio\nm pulse video\nm raven audio\n",
        );

        let applied = apply(&root, &["usr/lib/sysusers.d/x.conf".into()], &mut no_warn());

        // raven was already in audio, so only the two new memberships count.
        assert_eq!(applied.memberships.len(), 2);
        let group = std::fs::read_to_string(root.join("etc/group")).unwrap();
        assert!(group.contains("audio:x:11:raven,pulse"), "{group}");
        assert!(group.contains("video:x:12:pulse"), "{group}");
    }

    /// openssh's actual tmpfiles fragment: without the factory copies there is
    /// no /etc/ssh/sshd_config and sshd refuses to start.
    #[test]
    fn tmpfiles_copies_factory_defaults_only_where_nothing_exists() {
        let root = root("tmpfiles-c");
        write(&root, "usr/share/factory/etc/ssh/sshd_config", "Port 22\n");
        write(&root, "usr/share/factory/etc/pam.d/sshd", "auth required\n");
        // The operator already has their own pam file; it must survive.
        write(&root, "etc/pam.d/sshd", "mine\n");
        write(
            &root,
            "usr/lib/tmpfiles.d/openssh.conf",
            "C /etc/pam.d/sshd\nC /etc/ssh/sshd_config\n\nd /etc/ssh/sshd_config.d\n",
        );

        let applied = apply(&root, &["usr/lib/tmpfiles.d/openssh.conf".into()], &mut no_warn());

        assert_eq!(applied.copied, vec!["/etc/ssh/sshd_config"]);
        assert_eq!(applied.directories, vec!["/etc/ssh/sshd_config.d"]);
        assert_eq!(std::fs::read_to_string(root.join("etc/ssh/sshd_config")).unwrap(), "Port 22\n");
        assert_eq!(
            std::fs::read_to_string(root.join("etc/pam.d/sshd")).unwrap(),
            "mine\n",
            "an existing file is never overwritten"
        );
        assert!(root.join("etc/ssh/sshd_config.d").is_dir());
    }

    #[test]
    fn quoted_fields_hold_together() {
        assert_eq!(
            fields(r#"u dbus 81 "System Message Bus" /"#),
            vec!["u", "dbus", "81", "System Message Bus", "/"]
        );
    }
}
