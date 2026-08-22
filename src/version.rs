//! Faithful port of alpm's `rpmvercmp` / `alpm_pkg_vercmp`.
//!
//! Getting this wrong silently corrupts upgrade decisions, so it mirrors the C
//! implementation byte for byte rather than trying to be clever.

use std::cmp::Ordering;

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

fn is_alpha(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Compares two version segments the way RPM (and therefore pacman) does:
/// separator runs must match in length, numeric segments outrank alpha ones,
/// and leading zeros are insignificant.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let one = a.as_bytes();
    let two = b.as_bytes();
    let (mut i, mut j) = (0usize, 0usize);

    while i < one.len() && j < two.len() {
        let (sep_i, sep_j) = (i, j);
        while i < one.len() && !is_alnum(one[i]) {
            i += 1;
        }
        while j < two.len() && !is_alnum(two[j]) {
            j += 1;
        }

        // Ran off the end of either string: the tail rules below decide.
        if i >= one.len() || j >= two.len() {
            break;
        }

        // Differing separator run lengths are themselves a verdict.
        if (i - sep_i) != (j - sep_j) {
            return (i - sep_i).cmp(&(j - sep_j));
        }

        let start_i = i;
        let start_j = j;
        let isnum = is_digit(one[start_i]);

        if isnum {
            while i < one.len() && is_digit(one[i]) {
                i += 1;
            }
            while j < two.len() && is_digit(two[j]) {
                j += 1;
            }
        } else {
            while i < one.len() && is_alpha(one[i]) {
                i += 1;
            }
            while j < two.len() && is_alpha(two[j]) {
                j += 1;
            }
        }

        let mut seg_a = &one[start_i..i];
        let mut seg_b = &two[start_j..j];

        // `two` had no segment of this type at all: numeric beats nothing,
        // alpha loses to nothing.
        if seg_b.is_empty() {
            return if isnum {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        if isnum {
            while seg_a.first() == Some(&b'0') {
                seg_a = &seg_a[1..];
            }
            while seg_b.first() == Some(&b'0') {
                seg_b = &seg_b[1..];
            }
            if seg_a.len() != seg_b.len() {
                return seg_a.len().cmp(&seg_b.len());
            }
        }

        match seg_a.cmp(seg_b) {
            Ordering::Equal => {}
            other => return other,
        }
    }

    let a_done = i >= one.len();
    let b_done = j >= two.len();

    if a_done && b_done {
        Ordering::Equal
    } else if (a_done && !is_alpha(two[j])) || (!a_done && is_alpha(one[i])) {
        // A trailing alpha segment never beats an empty string: 1.0a < 1.0.
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// A package version split into its `epoch:version-release` parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub epoch: String,
    pub version: String,
    pub release: Option<String>,
    raw: String,
}

impl Version {
    pub fn parse(raw: &str) -> Version {
        // An epoch is a run of digits followed by ':'; anything else is part
        // of the version proper.
        let digits = raw.bytes().take_while(|b| b.is_ascii_digit()).count();
        let (epoch, rest) = if raw.as_bytes().get(digits) == Some(&b':') {
            (raw[..digits].to_string(), &raw[digits + 1..])
        } else {
            ("0".to_string(), raw)
        };

        // The release is whatever follows the *last* hyphen.
        let (version, release) = match rest.rfind('-') {
            Some(idx) => (rest[..idx].to_string(), Some(rest[idx + 1..].to_string())),
            None => (rest.to_string(), None),
        };

        Version {
            epoch,
            version,
            release,
            raw: raw.to_string(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match rpmvercmp(&self.epoch, &other.epoch) {
            Ordering::Equal => {}
            other => return other,
        }
        match rpmvercmp(&self.version, &other.version) {
            Ordering::Equal => {}
            other => return other,
        }
        // Releases only participate when both sides declare one, so that
        // `1.0` and `1.0-2` compare equal like pacman treats them.
        match (&self.release, &other.release) {
            (Some(a), Some(b)) => rpmvercmp(a, b),
            _ => Ordering::Equal,
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compares two raw version strings, as `vercmp(1)` would.
pub fn vercmp(a: &str, b: &str) -> Ordering {
    Version::parse(a).cmp(&Version::parse(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    fn c(a: &str, b: &str) -> Ordering {
        vercmp(a, b)
    }

    #[test]
    fn equality() {
        assert_eq!(c("1.0", "1.0"), Equal);
        assert_eq!(c("1.0-1", "1.0-1"), Equal);
        assert_eq!(c("0:1.0", "1.0"), Equal);
    }

    #[test]
    fn basic_ordering() {
        assert_eq!(c("1.0", "1.1"), Less);
        assert_eq!(c("1.1", "1.0"), Greater);
        assert_eq!(c("1.0.1", "1.0"), Greater);
        assert_eq!(c("2.0", "10.0"), Less);
    }

    #[test]
    fn leading_zeros_are_insignificant() {
        assert_eq!(c("1.007", "1.7"), Equal);
        assert_eq!(c("1.0010", "1.10"), Equal);
    }

    #[test]
    fn numeric_beats_alpha() {
        assert_eq!(c("1.5", "1.b"), Greater);
        assert_eq!(c("1.b", "1.5"), Less);
    }

    #[test]
    fn trailing_alpha_loses_to_empty() {
        assert_eq!(c("1.0a", "1.0"), Less);
        assert_eq!(c("1.0", "1.0a"), Greater);
        assert_eq!(c("1.0rc1", "1.0"), Less);
    }

    #[test]
    fn release_only_counts_when_both_present() {
        assert_eq!(c("1.0-1", "1.0-2"), Less);
        assert_eq!(c("1.0-2", "1.0-1"), Greater);
        assert_eq!(c("1.0", "1.0-5"), Equal);
        assert_eq!(c("1.0-5", "1.0"), Equal);
    }

    #[test]
    fn epoch_dominates() {
        assert_eq!(c("1:1.0", "2.0"), Greater);
        assert_eq!(c("1.0", "1:0.1"), Less);
        assert_eq!(c("2:1.0-1", "1:9.9-9"), Greater);
    }

    #[test]
    fn separator_runs_matter() {
        assert_eq!(c("1..0", "1.0"), Greater);
        assert_eq!(c("1.0", "1..0"), Less);
    }

    #[test]
    fn parses_parts() {
        let v = Version::parse("3:1.2.3-4");
        assert_eq!(v.epoch, "3");
        assert_eq!(v.version, "1.2.3");
        assert_eq!(v.release.as_deref(), Some("4"));

        // A colon that isn't preceded solely by digits is not an epoch.
        let v = Version::parse("1.2-3");
        assert_eq!(v.epoch, "0");
        assert_eq!(v.version, "1.2");
        assert_eq!(v.release.as_deref(), Some("3"));
    }

    #[test]
    fn real_world_samples() {
        assert_eq!(c("1.0.2-1", "1.0.10-1"), Less);
        assert_eq!(c("6.6.1.arch1-1", "6.6.2.arch1-1"), Less);
        assert_eq!(c("1.0beta", "1.0"), Less);
        assert_eq!(c("20240101-1", "20231231-1"), Greater);
    }
}
