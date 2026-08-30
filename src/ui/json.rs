//! Machine-readable event stream, enabled by `rvn --json`.
//!
//! Every line on stdout is one JSON object with an `event` field. A graphical
//! front-end (Raven Store) runs `rvn --json ...` as a child, reads the lines
//! as they arrive, and renders them — the same spinner/progress/message
//! vocabulary the terminal shows, just without the terminal.
//!
//! Human-readable text is never mixed into the stream: in JSON mode all the
//! usual stderr painting is suppressed, and stdout carries only events.

use crate::pkg::Package;
use crate::upgrade::Candidate;
use serde_json::{Value, json};
use std::io::Write;

/// Writes one event line. Serialisation failures are impossible for the
/// values built here, and a closed pipe simply means nobody is listening.
pub fn emit(event: &str, mut payload: Value) {
    if let Value::Object(map) = &mut payload {
        map.insert("event".into(), Value::String(event.to_string()));
    } else {
        payload = json!({ "event": event, "value": payload });
    }
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{payload}");
    let _ = out.flush();
}

/// A message-style event: `ok`, `warn`, `err`, `info`, `step`, `detail`.
pub fn message(kind: &str, text: &str) {
    emit(kind, json!({ "message": text }));
}

pub fn package(pkg: &Package) -> Value {
    let deps = |list: &[crate::pkg::Dep]| -> Vec<String> {
        list.iter().map(|d| d.to_string()).collect()
    };
    json!({
        "name": pkg.name,
        "version": pkg.version,
        "description": pkg.description,
        "url": pkg.url,
        "origin": pkg.origin.label(),
        "aur": pkg.origin.is_aur(),
        "licenses": pkg.licenses,
        "groups": pkg.groups,
        "depends": deps(&pkg.depends),
        "optdepends": deps(&pkg.optdepends),
        "provides": deps(&pkg.provides),
        "conflicts": deps(&pkg.conflicts),
        "download_size": pkg.csize,
        "installed_size": pkg.isize,
        "popularity": pkg.popularity,
        "out_of_date": pkg.out_of_date,
        "packager": pkg.packager,
    })
}

pub fn candidate(c: &Candidate) -> Value {
    use crate::upgrade::Kind;
    let (kind, replaces) = match &c.kind {
        Kind::Upgrade => ("upgrade", None),
        Kind::Replacement { replaces } => ("replacement", Some(replaces.clone())),
        Kind::Downgrade => ("downgrade", None),
        Kind::Devel => ("devel", None),
    };
    json!({
        "name": c.name,
        "installed_version": c.installed_version,
        "new_version": c.new_version,
        "origin": c.origin.label(),
        "aur": c.origin.is_aur(),
        "kind": kind,
        "replaces": replaces,
        "download_size": c.download_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::Origin;

    #[test]
    fn package_serialises_the_fields_a_store_needs() {
        let pkg = Package {
            name: "ripgrep".into(),
            version: "15.2.0-1".into(),
            description: "grep, but fast".into(),
            origin: Origin::Repo("extra".into()),
            csize: 1400,
            ..Default::default()
        };
        let v = package(&pkg);
        assert_eq!(v["name"], "ripgrep");
        assert_eq!(v["origin"], "extra");
        assert_eq!(v["aur"], false);
        assert_eq!(v["download_size"], 1400);
    }
}
