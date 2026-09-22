//! The subset of TOML that rvn's own configuration is written in.
//!
//! rvn reads pacman's configuration, which is INI, and pacman's databases,
//! which are `%KEY%` records. Neither of those is a format anybody would
//! choose today, and neither is what the rest of Raven's system configuration
//! is written in: `/etc/raven/login.toml` and `/etc/raven/time.toml` are TOML,
//! so the files rvn owns are TOML too. An administrator should not have to
//! learn a second syntax to configure the same machine.
//!
//! This is deliberately not an implementation of TOML. It reads `[section]`
//! headers, `key = value`, quoted strings, `true`/`false`, whole numbers,
//! inline tables, and lists of those -- including a list written across
//! several lines, because a hook that triggers on twenty paths has to be
//! readable. Everything else it refuses by name and on the right line: dotted
//! keys, arrays of tables, floats and dates all produce an error that says
//! what was found rather than quietly parsing into something else.
//!
//! Inline tables were not here to begin with, and the reason they are now is
//! worth recording: `rvn build` reads the package manifests in
//! RavenLinux/packages, and those were written long before this parser
//! existed. Their `[install]` section is
//! `files = [{ src = "...", dest = "...", mode = 755 }]` and their `[build]`
//! section is `env = { CGO_ENABLED = "0" }`. Refusing that syntax would have
//! meant rewriting forty manifests to suit the parser, which is the wrong way
//! round: the manifests are the thing that already exists and the thing a
//! person edits. Arrays of tables are still refused, because nothing writes
//! them and `[[...]]` and `[...]` differ by one character that changes the
//! meaning entirely.
//!
//! Why not the `toml` crate. This crate has no `libc` either: `geteuid`,
//! `SO_PEERCRED`, the /etc/passwd reader, the OpenPGP packet walker in
//! `verify` and the binary index format in `db::index` are all hand-written,
//! because a package manager is the thing that has to keep working when the
//! machine it manages is half-upgraded, and every crate under it is another
//! way for that to stop being true. A full parser would buy syntax nobody
//! writing a hook file needs. This is about two hundred lines and it is
//! exercised by the tests at the bottom of this file.
//!
//! Being strict is the point rather than a limitation. A file that is present
//! but does not parse is a hard error for every caller: falling back to a
//! default would quietly ignore a policy somebody wrote down and believed,
//! which is the one failure a configuration file must never have.

use std::fmt;

/// An inline `{ key = value, ... }` table.
///
/// Entries keep the order they were written in, the way [`Section`] does, so
/// a message about an unrecognised key can name them in the order the reader
/// sees them on the line.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Table {
    entries: Vec<(String, Value)>,
}

impl Table {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// Every key set here, in the order they were written -- for telling
    /// somebody which of their keys is not one this file understands.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(name, _)| name.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A value one of rvn's configuration files can hold.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Boolean(bool),
    Array(Vec<Value>),
    Table(Table),
}

impl Value {
    /// What to call this in a message the person who wrote the file will
    /// read, phrased to fit "expected a string, found ...".
    pub fn kind(&self) -> &'static str {
        match self {
            Value::String(_) => "a string",
            Value::Integer(_) => "a number",
            Value::Boolean(_) => "true or false",
            Value::Array(_) => "a list",
            Value::Table(_) => "a { key = value } table",
        }
    }

    pub fn as_table(&self) -> Option<&Table> {
        match self {
            Value::Table(table) => Some(table),
            _ => None,
        }
    }

    /// The value as a list of inline tables.
    ///
    /// A bare table counts as a list of one, for the same reason
    /// [`Value::as_strings`] accepts a bare string: somebody writing a
    /// manifest with a single installed file should not have to wrap it in
    /// brackets to say so, and there is no other reading of it.
    pub fn as_tables(&self) -> Option<Vec<&Table>> {
        match self {
            Value::Table(table) => Some(vec![table]),
            Value::Array(items) => items.iter().map(Value::as_table).collect(),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(flag) => Some(*flag),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(number) => Some(*number),
            _ => None,
        }
    }

    /// The value as a list of strings.
    ///
    /// A bare string counts as a list of one. `packages = "linux"` is what a
    /// person writes when they mean one package, and refusing it so they
    /// write `["linux"]` instead would be pedantry with nothing behind it --
    /// there is no other reading of it to be confused with.
    pub fn as_strings(&self) -> Option<Vec<String>> {
        match self {
            Value::String(text) => Some(vec![text.clone()]),
            Value::Array(items) => items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect(),
            _ => None,
        }
    }
}

/// Where a file stopped making sense, and why.
///
/// The line number is carried separately from the message so a caller can
/// prefix the file's path without the result reading as two sentences: what
/// every caller prints is "<path>: line 7: <message>".
#[derive(Debug, PartialEq)]
pub struct Error {
    pub line: usize,
    pub message: String,
}

impl Error {
    fn at(line: usize, message: impl Into<String>) -> Error {
        Error {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

/// One `key = value` and the line it was written on, kept so an error about
/// the value points at the value rather than at the section header.
#[derive(Debug)]
struct Entry {
    key: String,
    line: usize,
    value: Value,
}

/// One `[section]` and everything set under it.
#[derive(Debug)]
pub struct Section {
    pub name: String,
    /// The line the header is on, or 0 for the unnamed section a file's first
    /// keys land in when it has no header at all.
    pub line: usize,
    entries: Vec<Entry>,
}

impl Section {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| &entry.value)
    }

    /// The line `key` was set on, falling back to the section header so an
    /// error about a *missing* key still points somewhere real.
    pub fn line_of(&self, key: &str) -> usize {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.line)
            .unwrap_or(self.line)
    }

    /// Every key set here, in the order they were written -- for telling
    /// somebody which of their keys is not one this file understands.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.key.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A parsed configuration file.
#[derive(Debug)]
pub struct Document {
    sections: Vec<Section>,
}

impl Document {
    /// Reads `text`, or says where it stopped making sense.
    pub fn parse(text: &str) -> Result<Document, Error> {
        parse(text)
    }

    /// The section called `name`, or the unnamed one for `""`.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.name == name)
    }

    /// Every section, the unnamed one first. Callers walk this to refuse a
    /// section they do not recognise rather than ignoring it.
    pub fn sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter()
    }

    /// Whether the file set nothing at all -- comments and blank lines only.
    pub fn is_empty(&self) -> bool {
        self.sections.iter().all(Section::is_empty)
    }
}

fn parse(text: &str) -> Result<Document, Error> {
    let lines: Vec<&str> = text.lines().collect();
    // The unnamed section always exists, so a file whose keys come before any
    // header has somewhere to put them and `sections.last_mut()` never fails.
    let mut document = Document {
        sections: vec![Section {
            name: String::new(),
            line: 0,
            entries: Vec::new(),
        }],
    };

    let mut index = 0;
    while index < lines.len() {
        let number = index + 1;
        let line = strip_comment(lines[index]).trim();
        index += 1;

        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix('[') {
            if rest.starts_with('[') {
                return Err(Error::at(
                    number,
                    "arrays of tables ([[...]]) are not part of the TOML rvn reads; write one file per thing instead",
                ));
            }
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| Error::at(number, "a section header ends with `]`"))?
                .trim();
            let name = parse_key(name, number)?;
            if document.section(&name).is_some() {
                return Err(Error::at(
                    number,
                    format!("[{name}] appears twice; everything it sets belongs under one header"),
                ));
            }
            document.sections.push(Section {
                name,
                line: number,
                entries: Vec::new(),
            });
            continue;
        }

        let Some((key, rest)) = line.split_once('=') else {
            return Err(Error::at(
                number,
                "expected `key = value` or a [section] header",
            ));
        };
        let key = parse_key(key.trim(), number)?;

        // A list or an inline table may be spread over as many lines as it
        // needs; anything else is one line by construction, and an unbalanced
        // `[` or `{` on a line that is neither is a syntax error either way.
        // The manifests this has to read write one installed file per line
        // inside a list, so the two nest.
        let mut text = rest.trim().to_string();
        while open_depth(&text) > 0 {
            if index >= lines.len() {
                return Err(Error::at(
                    number,
                    "a list or inline table that is never closed with `]` or `}`",
                ));
            }
            text.push(' ');
            text.push_str(strip_comment(lines[index]).trim());
            index += 1;
        }

        let value = parse_value(&text, number)?;
        let section = document
            .sections
            .last_mut()
            .expect("the unnamed section is always present");
        if section.get(&key).is_some() {
            return Err(Error::at(
                number,
                format!("`{key}` is set twice in the same section"),
            ));
        }
        section.entries.push(Entry {
            key,
            line: number,
            value,
        });
    }

    Ok(document)
}

/// A bare or quoted key, refusing the dotted form by name so somebody who
/// wrote `hook.exec` is told what to write instead.
fn parse_key(text: &str, line: usize) -> Result<String, Error> {
    if text.is_empty() {
        return Err(Error::at(line, "a key with no name"));
    }
    if text.starts_with('"') || text.starts_with('\'') {
        let (key, rest) = parse_string(text, line)?;
        if !rest.trim().is_empty() {
            return Err(Error::at(line, "a quoted key ends at its closing quote"));
        }
        return Ok(key);
    }
    if text.contains('.') {
        return Err(Error::at(
            line,
            format!(
                "dotted keys are not part of the TOML rvn reads; write `[{}]` as a section header instead",
                text.replace('.', "] [")
            ),
        ));
    }
    if !text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(Error::at(
            line,
            format!("`{text}` is not a key: letters, digits, `-` and `_`, or a quoted string"),
        ));
    }
    Ok(text.to_string())
}

fn parse_value(text: &str, line: usize) -> Result<Value, Error> {
    let (value, rest) = parse_one(text, line)?;
    if !rest.trim().is_empty() {
        return Err(Error::at(
            line,
            format!("`{}` is left over after the value", rest.trim()),
        ));
    }
    Ok(value)
}

/// One value and whatever follows it, so lists can be walked element by
/// element without a tokeniser.
fn parse_one(text: &str, line: usize) -> Result<(Value, &str), Error> {
    let text = text.trim_start();
    let Some(first) = text.chars().next() else {
        return Err(Error::at(line, "a value is missing"));
    };

    if first == '"' || first == '\'' {
        let (string, rest) = parse_string(text, line)?;
        return Ok((Value::String(string), rest));
    }

    if first == '[' {
        let mut rest = &text[1..];
        let mut items = Vec::new();
        loop {
            rest = rest.trim_start();
            if let Some(after) = rest.strip_prefix(']') {
                return Ok((Value::Array(items), after));
            }
            let (item, tail) = parse_one(rest, line)?;
            items.push(item);
            rest = tail.trim_start();
            if let Some(after) = rest.strip_prefix(',') {
                rest = after;
                continue;
            }
            if let Some(after) = rest.strip_prefix(']') {
                return Ok((Value::Array(items), after));
            }
            return Err(Error::at(line, "expected `,` or `]` in a list"));
        }
    }

    if first == '{' {
        let mut rest = &text[1..];
        let mut table = Table::default();
        loop {
            rest = rest.trim_start();
            if let Some(after) = rest.strip_prefix('}') {
                return Ok((Value::Table(table), after));
            }
            // The key runs to the `=`, which is the only thing that can
            // separate it from its value inside braces. Splitting on it here
            // rather than scanning for a key token keeps `parse_key` -- and
            // so the refusal of dotted keys -- the single place a key is
            // understood, inside a table as well as at the top level.
            let Some((key, after_key)) = rest.split_once('=') else {
                return Err(Error::at(
                    line,
                    "expected `key = value` or `}` in an inline table",
                ));
            };
            let key = parse_key(key.trim(), line)?;
            if table.get(&key).is_some() {
                return Err(Error::at(
                    line,
                    format!("`{key}` is set twice in the same inline table"),
                ));
            }
            let (value, tail) = parse_one(after_key, line)?;
            table.entries.push((key, value));
            rest = tail.trim_start();
            if let Some(after) = rest.strip_prefix(',') {
                rest = after;
                continue;
            }
            if let Some(after) = rest.strip_prefix('}') {
                return Ok((Value::Table(table), after));
            }
            return Err(Error::at(line, "expected `,` or `}` in an inline table"));
        }
    }

    let end = text.find([',', ']', '}', ' ', '\t']).unwrap_or(text.len());
    let (token, rest) = text.split_at(end);
    let value = match token {
        "true" => Value::Boolean(true),
        "false" => Value::Boolean(false),
        _ => match token.parse::<i64>() {
            Ok(number) => Value::Integer(number),
            Err(_) => {
                return Err(Error::at(
                    line,
                    format!(
                        "`{token}` is not a value rvn reads: quote it for a string, or write true, false, a whole number, or a list of those in [ ]"
                    ),
                ));
            }
        },
    };
    Ok((value, rest))
}

/// A basic `"..."` or literal `'...'` string, and the text after it.
fn parse_string(text: &str, line: usize) -> Result<(String, &str), Error> {
    let quote = text.chars().next().expect("caller checked for a quote");
    let literal = quote == '\'';
    let mut out = String::new();
    let mut chars = text.char_indices().skip(1);

    while let Some((offset, c)) = chars.next() {
        if c == quote {
            return Ok((out, &text[offset + c.len_utf8()..]));
        }
        if c == '\\' && !literal {
            let Some((_, escaped)) = chars.next() else {
                break;
            };
            match escaped {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                other => {
                    return Err(Error::at(
                        line,
                        format!(
                            "`\\{other}` is not an escape rvn reads: `\\\\`, `\\\"`, `\\n`, `\\t` and `\\r` are, and a literal 'single-quoted' string needs none of them"
                        ),
                    ));
                }
            }
            continue;
        }
        out.push(c);
    }

    Err(Error::at(line, "a string that is never closed"))
}

/// Everything before an unquoted `#`.
///
/// Quoted because a comment character inside a string is just a character:
/// `paths = ["etc/#keep"]` is a path, not half a line.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (offset, c) in line.char_indices() {
        match quote {
            Some(open) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && open == '"' {
                    escaped = true;
                } else if c == open {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '#' => return &line[..offset],
                _ => {}
            },
        }
    }
    line
}

/// How many lists and inline tables are still open at the end of this text,
/// so a value that runs onto the next line can be recognised without parsing
/// it twice.
///
/// Both bracket kinds are counted together rather than separately: the only
/// question being asked is whether the value has finished, and a list of
/// inline tables -- which is what a manifest's `files` key is -- closes both
/// kinds on its way back to zero.
fn open_depth(text: &str) -> i32 {
    let mut depth = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        match quote {
            Some(open) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' && open == '"' {
                    escaped = true;
                } else if c == open {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                _ => {}
            },
        }
    }
    depth
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> Document {
        Document::parse(text).expect("this file should parse")
    }

    #[test]
    fn a_file_of_sections_keys_and_lists_reads_back() {
        let doc = parsed(
            "# a hook, as one would be written\n\
             \n\
             [trigger]\n\
             when = \"pre-transaction\"\n\
             operations = [\"install\", \"update\"]\n\
             \n\
             [run]\n\
             exec = '/usr/lib/rvn/snapshot'\n\
             abort_on_fail = true\n\
             keep = 3\n",
        );

        let trigger = doc.section("trigger").unwrap();
        assert_eq!(
            trigger.get("when").unwrap().as_str(),
            Some("pre-transaction")
        );
        assert_eq!(
            trigger.get("operations").unwrap().as_strings().unwrap(),
            vec!["install".to_string(), "update".to_string()]
        );
        let run = doc.section("run").unwrap();
        assert_eq!(
            run.get("exec").unwrap().as_str(),
            Some("/usr/lib/rvn/snapshot")
        );
        assert_eq!(run.get("abort_on_fail").unwrap().as_bool(), Some(true));
        assert_eq!(run.get("keep").unwrap().as_integer(), Some(3));
        // The line number is what an error about a value points at.
        assert_eq!(trigger.line_of("operations"), 5);
        assert!(doc.section("nothing").is_none());
    }

    #[test]
    fn a_list_may_run_over_as_many_lines_as_it_needs() {
        let doc = parsed("paths = [\n  \"etc/**\",   # the whole of /etc\n  \"boot/**\",\n]\n");
        assert_eq!(
            doc.section("")
                .unwrap()
                .get("paths")
                .unwrap()
                .as_strings()
                .unwrap(),
            vec!["etc/**".to_string(), "boot/**".to_string()]
        );
    }

    #[test]
    fn a_hash_inside_a_string_is_not_a_comment() {
        let doc = parsed("paths = [\"etc/#keep\"] # but this one is\n");
        assert_eq!(
            doc.section("")
                .unwrap()
                .get("paths")
                .unwrap()
                .as_strings()
                .unwrap(),
            vec!["etc/#keep".to_string()]
        );
    }

    #[test]
    fn a_lone_string_counts_as_a_list_of_one() {
        let doc = parsed("packages = \"linux\"\n");
        assert_eq!(
            doc.section("")
                .unwrap()
                .get("packages")
                .unwrap()
                .as_strings()
                .unwrap(),
            vec!["linux".to_string()]
        );
    }

    #[test]
    fn escapes_are_the_ones_a_path_needs_and_no_others() {
        let doc = parsed("a = \"one\\ttwo\\n\"\nb = 'no \\escape here'\n");
        let root = doc.section("").unwrap();
        assert_eq!(root.get("a").unwrap().as_str(), Some("one\ttwo\n"));
        assert_eq!(root.get("b").unwrap().as_str(), Some("no \\escape here"));

        let e = Document::parse("a = \"\\q\"\n").unwrap_err();
        assert!(e.message.contains("\\q"), "{e}");
    }

    #[test]
    fn the_syntax_rvn_does_not_read_is_refused_by_name_and_line() {
        for (text, expected_line, says) in [
            ("[[hook]]\n", 1, "arrays of tables"),
            ("\n\nhook.exec = \"x\"\n", 3, "dotted keys"),
            ("[a]\nx = 1\nx = 2\n", 3, "set twice"),
            ("[a]\n[a]\n", 2, "appears twice"),
            ("x = \n", 1, "missing"),
            ("x = 1.5\n", 1, "not a value rvn reads"),
            ("x = \"unclosed\n", 1, "never closed"),
            ("x = [1, 2\n", 1, "never closed with `]`"),
            ("[section\n", 1, "ends with `]`"),
            ("nonsense\n", 1, "expected `key = value`"),
        ] {
            let e = Document::parse(text).unwrap_err();
            assert_eq!(e.line, expected_line, "{text:?} -> {e}");
            assert!(e.message.contains(says), "{text:?} -> {e}");
        }
    }

    #[test]
    fn a_manifests_install_table_reads_back_as_written() {
        // Copied from RavenLinux/packages/raven/rvn/package.toml, which is
        // the shape this had to learn to read: a list of inline tables, one
        // per line, with a bare number for the mode.
        let doc = parsed(
            "[install]\n\
             files = [\n\
             \x20   { src = \"target/release/rvn\",  dest = \"/usr/bin/rvn\",  mode = 755 },\n\
             \x20   { src = \"target/release/rvnd\", dest = \"/usr/bin/rvnd\", mode = 755 }\n\
             ]\n\
             symlinks = []\n",
        );

        let files = doc
            .section("install")
            .unwrap()
            .get("files")
            .unwrap()
            .as_tables()
            .unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(
            files[0].get("src").unwrap().as_str(),
            Some("target/release/rvn")
        );
        assert_eq!(
            files[1].get("dest").unwrap().as_str(),
            Some("/usr/bin/rvnd")
        );
        assert_eq!(files[0].get("mode").unwrap().as_integer(), Some(755));
        assert_eq!(files[0].keys().collect::<Vec<_>>(), ["src", "dest", "mode"]);
        // An empty list is still a list, not a missing key: a manifest that
        // says outright it installs no symlinks means something different
        // from one that forgot to mention them.
        assert_eq!(
            doc.section("install")
                .unwrap()
                .get("symlinks")
                .unwrap()
                .as_strings()
                .unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_inline_table_stands_alone_and_may_run_over_lines() {
        // `[build] env = { ... }`, the other inline table the manifests use.
        let doc = parsed("env = {\n  CGO_ENABLED = \"0\",\n  GOOS = \"linux\",\n}\n");
        let env = doc.section("").unwrap().get("env").unwrap();
        assert_eq!(
            env.as_table().unwrap().get("GOOS").unwrap().as_str(),
            Some("linux")
        );
        // A bare table counts as a list of one, as a bare string does.
        assert_eq!(env.as_tables().unwrap().len(), 1);
        assert_eq!(env.kind(), "a { key = value } table");

        for (text, says) in [
            (
                "x = { a = 1, a = 2 }\n",
                "set twice in the same inline table",
            ),
            ("x = { a = 1 b = 2 }\n", "expected `,` or `}`"),
            ("x = { a }\n", "expected `key = value` or `}`"),
            ("x = { a = 1\n", "never closed with `]` or `}`"),
        ] {
            let e = Document::parse(text).unwrap_err();
            assert!(e.message.contains(says), "{text:?} -> {e}");
        }
    }

    #[test]
    fn a_file_of_nothing_but_comments_is_empty_rather_than_an_error() {
        // How a shipped hook is switched off: the same name, no directives.
        let doc = parsed("# deliberately does nothing\n\n");
        assert!(doc.is_empty());
        assert!(!parsed("x = 1\n").is_empty());
    }
}
