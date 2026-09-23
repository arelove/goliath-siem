//! Detection values and their wildcard semantics.
//!
//! A value in a detection map is a YAML scalar, and a string scalar is a
//! pattern: `*` stands for any run of characters, `?` for exactly one.
//!
//! # Escaping
//!
//! The Sigma escaping rule is narrow and easy to get wrong. A backslash escapes
//! only `*`, `?`, and another backslash, and is consumed doing so. Before
//! anything else it is a literal backslash, which is what makes Windows paths
//! readable:
//!
//! | Written | Means |
//! | --- | --- |
//! | `C:\Windows` | the literal text `C:\Windows` |
//! | `\*` | a literal asterisk, backslash consumed |
//! | `\\` | a literal backslash |
//! | `\\*` | a literal backslash, then a wildcard |
//!
//! The second and fourth rows are the trap. Someone writing `C:\Users\*` for
//! "anything under that directory" gets the literal text `C:\Users*`, which
//! matches no real path. The intended pattern is `C:\Users\\*`.

use serde::{Deserialize, Serialize};

/// One element of a parsed string pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternPart {
    /// Text that must appear exactly.
    Literal(String),
    /// `*` - any run of characters, including none.
    AnySequence,
    /// `?` - exactly one character.
    AnyChar,
}

/// A parsed string value.
///
/// Parsing happens once, when a rule loads, so that matching never reinterprets
/// escapes on the per-event path.
///
/// The text as written is kept beside the parts. Modifiers that give the value
/// a meaning other than a wildcard pattern, such as `re`, need it: parsing is
/// lossy for them, since the `*` in `a.*b` would become a wildcard, and `\\d`
/// and `\d` would both become the same literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pattern {
    source: String,
    parts: Vec<PatternPart>,
}

impl Pattern {
    /// Parses a string value into a pattern, resolving escapes.
    pub fn parse(source: &str) -> Self {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut chars = source.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '\\' => match chars.peek() {
                    // A backslash escapes only these three, and is consumed.
                    Some(&escaped @ ('*' | '?' | '\\')) => {
                        literal.push(escaped);
                        chars.next();
                    }
                    // Before anything else it is a literal backslash, which is
                    // what lets Windows paths be written plainly.
                    _ => literal.push('\\'),
                },
                '*' | '?' => {
                    if !literal.is_empty() {
                        parts.push(PatternPart::Literal(std::mem::take(&mut literal)));
                    }
                    parts.push(if ch == '*' {
                        PatternPart::AnySequence
                    } else {
                        PatternPart::AnyChar
                    });
                }
                other => literal.push(other),
            }
        }

        if !literal.is_empty() {
            parts.push(PatternPart::Literal(literal));
        }

        Self {
            source: source.to_owned(),
            parts,
        }
    }

    /// Builds a pattern from parts.
    ///
    /// Adjacent literals are merged, empty literals dropped, and runs of `*`
    /// collapsed, none of which changes what the pattern matches. The source
    /// text is written with escapes such that parsing it gives the same parts.
    pub fn from_parts(parts: impl IntoIterator<Item = PatternPart>) -> Self {
        let mut normalized: Vec<PatternPart> = Vec::new();
        for part in parts {
            match (normalized.last_mut(), part) {
                (_, PatternPart::Literal(text)) if text.is_empty() => {}
                (Some(PatternPart::Literal(previous)), PatternPart::Literal(text)) => {
                    previous.push_str(&text);
                }
                (Some(PatternPart::AnySequence), PatternPart::AnySequence) => {}
                (_, part) => normalized.push(part),
            }
        }

        let mut source = String::new();
        for part in &normalized {
            match part {
                PatternPart::Literal(text) => {
                    for ch in text.chars() {
                        if matches!(ch, '*' | '?' | '\\') {
                            source.push('\\');
                        }
                        source.push(ch);
                    }
                }
                PatternPart::AnySequence => source.push('*'),
                PatternPart::AnyChar => source.push('?'),
            }
        }

        Self {
            source,
            parts: normalized,
        }
    }

    /// Returns the value as written in the rule, before escapes were resolved.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the pattern's elements in order.
    pub fn parts(&self) -> &[PatternPart] {
        &self.parts
    }

    /// Returns the text this pattern matches, if it contains no wildcards.
    ///
    /// The match engine indexes literals in a hash set and prefilters them
    /// through a bloom filter. A pattern with wildcards cannot be indexed that
    /// way and has to be evaluated, so this distinction decides which of two
    /// very different cost paths a predicate takes.
    pub fn as_literal(&self) -> Option<&str> {
        match self.parts.as_slice() {
            [PatternPart::Literal(text)] => Some(text),
            [] => Some(""),
            _ => None,
        }
    }

    /// Reports whether the pattern contains no wildcards.
    pub fn is_literal(&self) -> bool {
        self.as_literal().is_some()
    }

    /// Reports whether `candidate` matches this pattern.
    ///
    /// Comparison is case sensitive. Case folding is a backend concern driven
    /// by the `cased` modifier, not a property of the pattern.
    ///
    /// The candidate is event data and therefore attacker controlled, so the
    /// cost is bounded by the product of pattern and candidate length whatever
    /// the number of wildcards. Trying every split at every `*` would be
    /// exponential in the number of wildcards: `*a*a*a*a*a*b` against a hundred
    /// `a` characters took thirty seconds that way.
    ///
    /// Only the most recent `*` ever needs revisiting. Whatever an earlier one
    /// could absorb, the later one can absorb instead, so a failure after the
    /// latest `*` is retried by letting that `*` take one more character.
    pub fn matches(&self, candidate: &str) -> bool {
        let parts = self.parts.as_slice();
        // Byte offsets, always on character boundaries.
        let mut part = 0;
        let mut pos = 0;
        // The part after the latest `*`, and where that `*` stopped absorbing.
        let mut resume: Option<(usize, usize)> = None;

        loop {
            if let Some(current) = parts.get(part) {
                let advanced = match current {
                    PatternPart::AnySequence => {
                        resume = Some((part + 1, pos));
                        Some(pos)
                    }
                    PatternPart::AnyChar => candidate[pos..]
                        .chars()
                        .next()
                        .map(|ch| pos + ch.len_utf8()),
                    PatternPart::Literal(text) => candidate[pos..]
                        .starts_with(text.as_str())
                        .then(|| pos + text.len()),
                };
                if let Some(next) = advanced {
                    part += 1;
                    pos = next;
                    continue;
                }
            } else if pos == candidate.len() {
                return true;
            }

            // Mismatch: let the latest `*` absorb one more character.
            let Some((after_star, absorbed)) = resume else {
                return false;
            };
            let Some(ch) = candidate[absorbed..].chars().next() else {
                return false;
            };
            let absorbed = absorbed + ch.len_utf8();
            resume = Some((after_star, absorbed));
            part = after_star;
            pos = absorbed;
        }
    }
}

/// A value on the right-hand side of a detection map entry.
///
/// `f64` makes [`Eq`] unavailable, so only [`PartialEq`] is derived.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// A string, parsed as a pattern.
    String(Pattern),
    /// An integer.
    Integer(i64),
    /// A floating point number.
    Float(f64),
    /// A boolean, as used by the `exists` modifier.
    Boolean(bool),
    /// YAML `null` - the field must be absent or null.
    Null,
}

impl Value {
    /// Builds a string value by parsing `source` as a pattern.
    pub fn string(source: &str) -> Self {
        Self::String(Pattern::parse(source))
    }

    /// Returns the pattern, if this is a string value.
    pub fn as_pattern(&self) -> Option<&Pattern> {
        match self {
            Self::String(pattern) => Some(pattern),
            _ => None,
        }
    }

    /// Reports whether this value can be looked up by equality.
    ///
    /// Anything indexable goes into the predicate index; anything else is
    /// evaluated per event.
    pub fn is_indexable(&self) -> bool {
        match self {
            Self::String(pattern) => pattern.is_literal(),
            Self::Integer(_) | Self::Boolean(_) | Self::Null => true,
            // Float equality is not a sound index key.
            Self::Float(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_one_literal() {
        let pattern = Pattern::parse("powershell.exe");
        assert_eq!(pattern.as_literal(), Some("powershell.exe"));
        assert!(pattern.is_literal());
    }

    #[test]
    fn wildcards_split_the_pattern() {
        let pattern = Pattern::parse(r"*\powershell.exe");
        assert_eq!(
            pattern.parts(),
            [
                PatternPart::AnySequence,
                PatternPart::Literal(r"\powershell.exe".to_owned())
            ]
        );
        assert!(!pattern.is_literal());
    }

    #[test]
    fn a_backslash_before_ordinary_text_stays_literal() {
        // This is what lets Windows paths be written without doubling.
        let pattern = Pattern::parse(r"C:\Windows\System32");
        assert_eq!(pattern.as_literal(), Some(r"C:\Windows\System32"));
    }

    #[test]
    fn a_backslash_escapes_only_wildcards_and_itself() {
        assert_eq!(Pattern::parse(r"\*").as_literal(), Some("*"));
        assert_eq!(Pattern::parse(r"\?").as_literal(), Some("?"));
        assert_eq!(Pattern::parse(r"\\").as_literal(), Some(r"\"));
    }

    #[test]
    fn a_lone_backslash_before_a_wildcard_escapes_it() {
        // The trap. Someone writing this means "anything under that directory".
        // What they get is the literal text `C:\Users*`: the backslash escaped
        // the wildcard and was consumed with it, leaving a pattern that matches
        // no real path.
        let escaped = Pattern::parse(r"C:\Users\*");
        assert_eq!(escaped.as_literal(), Some(r"C:\Users*"));
        assert!(!escaped.matches(r"C:\Users\adam"));

        // The intended pattern doubles the separator.
        let intended = Pattern::parse(r"C:\Users\\*");
        assert!(!intended.is_literal());
        assert!(intended.matches(r"C:\Users\adam"));
    }

    #[test]
    fn matches_leading_and_trailing_wildcards() {
        let pattern = Pattern::parse("*powershell*");
        assert!(pattern.matches(r"c:\windows\powershell.exe"));
        assert!(pattern.matches("powershell"));
        assert!(!pattern.matches("cmd.exe"));
    }

    #[test]
    fn question_mark_matches_exactly_one_character() {
        let pattern = Pattern::parse("cmd?.exe");
        assert!(pattern.matches("cmd1.exe"));
        assert!(!pattern.matches("cmd.exe"), "one character is required");
        assert!(
            !pattern.matches("cmd12.exe"),
            "only one character is allowed"
        );
    }

    #[test]
    fn matching_backtracks_across_wildcards() {
        let pattern = Pattern::parse("*a*b");
        assert!(pattern.matches("xxaybzzb"));
        assert!(!pattern.matches("xxayb_"));
    }

    #[test]
    fn matching_is_case_sensitive() {
        // Case folding belongs to the `cased` modifier, not to the pattern.
        assert!(!Pattern::parse("powershell.exe").matches("PowerShell.exe"));
    }

    #[test]
    fn an_empty_pattern_matches_only_an_empty_string() {
        let pattern = Pattern::parse("");
        assert_eq!(pattern.as_literal(), Some(""));
        assert!(pattern.matches(""));
        assert!(!pattern.matches("x"));
    }

    #[test]
    fn a_lone_wildcard_matches_anything() {
        let pattern = Pattern::parse("*");
        assert!(pattern.matches(""));
        assert!(pattern.matches("anything at all"));
    }

    #[test]
    fn literal_values_are_indexable_and_wildcards_are_not() {
        assert!(Value::string("powershell.exe").is_indexable());
        assert!(!Value::string("*powershell*").is_indexable());

        assert!(Value::Integer(4_688).is_indexable());
        assert!(Value::Boolean(true).is_indexable());
        assert!(Value::Null.is_indexable());
        assert!(
            !Value::Float(1.5).is_indexable(),
            "float equality is not a sound index key"
        );
    }

    #[test]
    fn keeps_the_text_as_written() {
        // What a `re` value needs: parsing alone loses the distinction.
        let pattern = Pattern::parse(r"\\d+ a.*b");
        assert_eq!(pattern.source(), r"\\d+ a.*b");
        assert_eq!(
            Pattern::parse(r"\\d").parts(),
            Pattern::parse(r"\d").parts(),
            "the parts alone cannot tell these apart"
        );
    }

    #[test]
    fn from_parts_normalizes_without_changing_meaning() {
        let pattern = Pattern::from_parts([
            PatternPart::AnySequence,
            PatternPart::AnySequence,
            PatternPart::Literal("a".to_owned()),
            PatternPart::Literal(String::new()),
            PatternPart::Literal("b".to_owned()),
            PatternPart::AnyChar,
        ]);
        assert_eq!(
            pattern.parts(),
            [
                PatternPart::AnySequence,
                PatternPart::Literal("ab".to_owned()),
                PatternPart::AnyChar,
            ]
        );
    }

    #[test]
    fn from_parts_writes_a_source_that_parses_back() {
        let built = Pattern::from_parts([
            PatternPart::Literal(r"C:\Users\".to_owned()),
            PatternPart::AnySequence,
            PatternPart::Literal(r"*?\".to_owned()),
            PatternPart::AnyChar,
        ]);
        assert_eq!(Pattern::parse(built.source()).parts(), built.parts());
    }

    #[test]
    fn many_wildcards_against_a_long_candidate_stay_fast() {
        // Exponential with naive backtracking; this would not finish.
        let pattern = Pattern::parse("*a*a*a*a*a*a*a*a*b");
        let candidate = "a".repeat(100_000);
        assert!(!pattern.matches(&candidate));
        assert!(pattern.matches(&(candidate + "b")));
    }

    /// Tries every split at every `*`: exponential, but obviously correct.
    fn reference_matches(parts: &[PatternPart], candidate: &str) -> bool {
        let Some((first, rest)) = parts.split_first() else {
            return candidate.is_empty();
        };
        match first {
            PatternPart::Literal(text) => candidate
                .strip_prefix(text.as_str())
                .is_some_and(|tail| reference_matches(rest, tail)),
            PatternPart::AnyChar => {
                let mut chars = candidate.chars();
                chars.next().is_some() && reference_matches(rest, chars.as_str())
            }
            PatternPart::AnySequence => candidate
                .char_indices()
                .map(|(at, _)| at)
                .chain([candidate.len()])
                .any(|at| reference_matches(rest, &candidate[at..])),
        }
    }

    /// Every string over `alphabet` up to `max_len` characters.
    fn all_strings(alphabet: &[char], max_len: usize) -> Vec<String> {
        let mut all = vec![String::new()];
        let mut previous = vec![String::new()];
        for _ in 0..max_len {
            let next: Vec<String> = previous
                .iter()
                .flat_map(|prefix| alphabet.iter().map(move |ch| format!("{prefix}{ch}")))
                .collect();
            all.extend(next.iter().cloned());
            previous = next;
        }
        all
    }

    #[test]
    fn agrees_with_the_reference_on_every_short_input() {
        // Patterns over `*`, `?`, and literals of one or two characters,
        // against every candidate over the same letters plus a multibyte one.
        let patterns = all_strings(&['a', 'b', '*', '?'], 5);
        let candidates = all_strings(&['a', 'b', '\u{e9}'], 6);
        for source in &patterns {
            let pattern = Pattern::parse(source);
            for candidate in &candidates {
                assert_eq!(
                    pattern.matches(candidate),
                    reference_matches(pattern.parts(), candidate),
                    "pattern {source:?} against {candidate:?}"
                );
            }
        }
    }

    #[test]
    fn matching_handles_multibyte_characters() {
        let pattern = Pattern::parse("?_suffix");
        assert!(
            pattern.matches("\u{1F600}_suffix"),
            "one char, not one byte"
        );
    }
}
