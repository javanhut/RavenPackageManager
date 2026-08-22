//! Unified search across official repositories and the AUR.

use super::Context;
use crate::pkg::Package;
use crate::ui::theme::Color;
use std::cmp::Ordering;

/// A search hit, annotated with what rvn knows about it locally.
#[derive(Debug, Clone)]
pub struct Hit {
    pub package: Package,
    pub installed_version: Option<String>,
    /// A locally installed copy older than this result.
    pub upgradable: bool,
    score: u32,
}

/// Ranks a package against a query. Lower is better.
///
/// Exact name matches must always float to the top; the AUR otherwise drowns
/// short queries in fuzzy description hits.
fn score(pkg: &Package, query: &str) -> u32 {
    let name = pkg.name.to_lowercase();
    let query = query.to_lowercase();

    let base = if name == query {
        0
    } else if name.starts_with(&query) {
        10
    } else if name.contains(&query) {
        20
    } else if pkg.description.to_lowercase().contains(&query) {
        30
    } else {
        40
    };

    // Within a tier, official repositories outrank the AUR.
    base + if pkg.origin.is_aur() { 1 } else { 0 }
}

/// Runs a search and returns ranked hits.
pub fn run(ctx: &Context, query: &str) -> Result<Vec<Hit>, String> {
    let mut hits: Vec<Hit> = Vec::new();
    let needle = query.to_lowercase();

    for db in &ctx.sync {
        for pkg in &db.packages {
            if pkg.name.to_lowercase().contains(&needle)
                || pkg.description.to_lowercase().contains(&needle)
            {
                hits.push(make_hit(ctx, pkg.clone(), query));
            }
        }
    }

    if !ctx.repo_only {
        match ctx.aur.search(query) {
            Ok(aur_hits) => {
                for pkg in aur_hits {
                    // A package present in an official repo wins; do not list
                    // the AUR copy as well.
                    if hits.iter().any(|h| h.package.name == pkg.name) {
                        continue;
                    }
                    hits.push(make_hit(ctx, pkg, query));
                }
            }
            Err(e) => ctx.ui.warn(&format!("AUR search unavailable: {e}")),
        }
    }

    hits.sort_by(|a, b| {
        a.score
            .cmp(&b.score)
            // More popular AUR packages first, then alphabetically.
            .then_with(|| {
                b.package
                    .popularity
                    .partial_cmp(&a.package.popularity)
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| a.package.name.cmp(&b.package.name))
    });

    Ok(hits)
}

fn make_hit(ctx: &Context, package: Package, _query: &str) -> Hit {
    let installed = ctx.local.get(&package.name);
    let installed_version = installed.map(|p| p.version.clone());
    let upgradable = installed
        .map(|p| crate::version::vercmp(&package.version, &p.version) == Ordering::Greater)
        .unwrap_or(false);
    let score = score(&package, _query);

    Hit {
        package,
        installed_version,
        upgradable,
        score,
    }
}

/// Prints search results to stdout, so they stay pipeable.
pub fn print(ctx: &Context, hits: &[Hit], limit: usize) {
    print_numbered(ctx, hits, limit, false)
}

/// Prints results, optionally with selection numbers.
pub fn print_numbered(ctx: &Context, hits: &[Hit], limit: usize, numbered: bool) {
    let s = &ctx.ui.style;

    for (index, hit) in hits.iter().take(limit).enumerate() {
        let pkg = &hit.package;
        let origin = s.paint(
            if pkg.origin.is_aur() {
                Color::Cyan
            } else {
                Color::Violet
            },
            pkg.origin.label(),
        );
        let name = s.bold(&pkg.name);
        let version = s.paint(Color::Green, &pkg.version);

        let mut tags = Vec::new();
        if let Some(installed) = &hit.installed_version {
            if hit.upgradable {
                tags.push(s.paint(
                    Color::Amber,
                    &format!("[installed: {installed} {} upgradable]", s.glyphs.arrow),
                ));
            } else {
                tags.push(s.paint(Color::Slate, "[installed]"));
            }
        }
        if pkg.out_of_date {
            tags.push(s.paint(Color::Red, "[out of date]"));
        }
        if pkg.popularity > 0.0 {
            tags.push(s.dim(&format!("({:.1})", pkg.popularity)));
        }

        let prefix = if numbered {
            format!("{} ", s.paint(Color::Amber, &format!("{:>2}", index + 1)))
        } else {
            String::new()
        };
        println!("{prefix}{origin}/{name} {version} {}", tags.join(" "));
        if !pkg.description.is_empty() {
            println!("    {}", s.dim(&pkg.description));
        }
    }

    if hits.len() > limit {
        println!(
            "{}",
            s.dim(&format!(
                "  … {} more results, refine the query to narrow them",
                hits.len() - limit
            ))
        );
    }
}

/// Parses a yay-style selection over `count` numbered results.
///
/// Accepts individual numbers, inclusive ranges (`2-4`), and exclusions
/// (`^3`, `^2-4`). Exclusions apply to everything selected so far, or to the
/// whole list when nothing was selected explicitly — so `^2` means "all but
/// the second". Out-of-range and unparseable entries are ignored rather than
/// failing the whole selection.
pub fn parse_selection(input: &str, count: usize) -> Vec<usize> {
    let mut included: Vec<usize> = Vec::new();
    let mut excluded: Vec<usize> = Vec::new();
    let mut saw_include = false;

    let expand = |token: &str| -> Vec<usize> {
        match token.split_once('-') {
            Some((from, to)) => {
                let (Ok(from), Ok(to)) = (from.trim().parse::<usize>(), to.trim().parse::<usize>())
                else {
                    return Vec::new();
                };
                let (low, high) = if from <= to { (from, to) } else { (to, from) };
                (low..=high).collect()
            }
            None => token.trim().parse::<usize>().map(|n| vec![n]).unwrap_or_default(),
        }
    };

    for token in input.split([' ', ',']).filter(|t| !t.trim().is_empty()) {
        match token.strip_prefix('^') {
            Some(rest) => excluded.extend(expand(rest)),
            None => {
                saw_include = true;
                included.extend(expand(token));
            }
        }
    }

    // A selection made only of exclusions starts from everything.
    if !saw_include && !excluded.is_empty() {
        included = (1..=count).collect();
    }

    let mut chosen: Vec<usize> = included
        .into_iter()
        .filter(|n| *n >= 1 && *n <= count && !excluded.contains(n))
        .collect();

    chosen.sort_unstable();
    chosen.dedup();
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::Origin;

    fn pkg(name: &str, description: &str, origin: Origin) -> Package {
        Package {
            name: name.into(),
            version: "1.0-1".into(),
            description: description.into(),
            origin,
            ..Default::default()
        }
    }

    #[test]
    fn exact_name_match_outranks_everything() {
        let exact = pkg("go", "the go compiler", Origin::Repo("extra".into()));
        let prefix = pkg("golang-tools", "tools", Origin::Repo("extra".into()));
        let desc = pkg("vim", "editor with go support", Origin::Repo("extra".into()));

        assert!(score(&exact, "go") < score(&prefix, "go"));
        assert!(score(&prefix, "go") < score(&desc, "go"));
    }

    #[test]
    fn repos_outrank_aur_at_the_same_tier() {
        let repo = pkg("spotify", "music", Origin::Repo("extra".into()));
        let aur = pkg("spotify", "music", Origin::Aur);
        assert!(score(&repo, "spotify") < score(&aur, "spotify"));
    }

    #[test]
    fn parses_individual_numbers_and_ranges() {
        assert_eq!(parse_selection("1 3 5", 10), vec![1, 3, 5]);
        assert_eq!(parse_selection("2-4", 10), vec![2, 3, 4]);
        assert_eq!(parse_selection("1,3", 10), vec![1, 3]);
        assert_eq!(parse_selection("1 2-4 7", 10), vec![1, 2, 3, 4, 7]);
        // A reversed range still means the same span.
        assert_eq!(parse_selection("4-2", 10), vec![2, 3, 4]);
    }

    #[test]
    fn exclusions_subtract_from_everything_when_alone() {
        assert_eq!(parse_selection("^2", 4), vec![1, 3, 4]);
        assert_eq!(parse_selection("^2-3", 5), vec![1, 4, 5]);
    }

    #[test]
    fn exclusions_subtract_from_an_explicit_selection() {
        assert_eq!(parse_selection("1-5 ^3", 10), vec![1, 2, 4, 5]);
    }

    #[test]
    fn out_of_range_and_junk_are_ignored() {
        assert_eq!(parse_selection("0 1 99", 3), vec![1]);
        assert_eq!(parse_selection("abc 2 !!", 3), vec![2]);
        // Duplicates collapse.
        assert_eq!(parse_selection("2 2 2", 3), vec![2]);
    }

    #[test]
    fn empty_selection_chooses_nothing() {
        assert!(parse_selection("", 5).is_empty());
        assert!(parse_selection("   ", 5).is_empty());
    }

    #[test]
    fn scoring_is_case_insensitive() {
        let p = pkg("Firefox", "browser", Origin::Repo("extra".into()));
        assert_eq!(score(&p, "firefox"), score(&p, "FIREFOX"));
        assert_eq!(score(&p, "firefox"), 0);
    }
}
