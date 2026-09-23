//! Case folding for case insensitive comparison.
//!
//! Sigma compares strings without regard to case unless a rule says otherwise,
//! and the streaming engine and the `ClickHouse` backend must agree on what that
//! means for every character. This module is the single definition both use;
//! see `docs/adr/0012-sigma-field-mapping.md`.
//!
//! The folding is Unicode **simple** case folding: one character in, one
//! character out, no dependence on locale. Two consequences are deliberate:
//!
//! - `ß` does not fold to `ss`. Full folding would make it do so, and would let
//!   a string change length, which a byte offset or a prefix check cannot
//!   survive.
//! - Turkish dotted capital `İ` does not fold to `i`. The mapping that does so
//!   is a locale rule, and a rule must not match differently depending on the
//!   language of the server it runs on.

use std::borrow::Cow;

use icu_casemap::CaseMapper;

/// Folds `text` for case insensitive comparison.
///
/// Returns the input unchanged, without allocating, when folding would not
/// change it, which is the common case for already lower case event data.
///
/// # Examples
///
/// ```
/// use goliath_rule::fold;
///
/// assert_eq!(fold(r"C:\Windows\System32\CMD.EXE"), r"c:\windows\system32\cmd.exe");
/// assert_eq!(fold("ΣΊΣΥΦΟΣ"), fold("σίσυφος"));
/// ```
pub fn fold(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        return if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(text.to_ascii_lowercase())
        } else {
            Cow::Borrowed(text)
        };
    }

    let mapper = CaseMapper::new();
    let first_change = text
        .char_indices()
        .find(|&(_, ch)| mapper.simple_fold(ch) != ch);

    match first_change {
        None => Cow::Borrowed(text),
        Some((at, _)) => {
            let mut folded = String::with_capacity(text.len());
            folded.push_str(&text[..at]);
            folded.extend(text[at..].chars().map(|ch| mapper.simple_fold(ch)));
            Cow::Owned(folded)
        }
    }
}

/// Appends the folded form of `text` to `out`.
///
/// The same folding as [`fold`], for callers that reuse one buffer across
/// many values instead of allocating per value.
pub fn fold_into(text: &str, out: &mut String) {
    if text.is_ascii() {
        let start = out.len();
        out.push_str(text);
        out[start..].make_ascii_lowercase();
    } else {
        let mapper = CaseMapper::new();
        out.extend(text.chars().map(|ch| mapper.simple_fold(ch)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_shortcut_agrees_with_unicode_simple_folding() {
        // The shortcut is only correct because simple folding maps no ASCII
        // character other than A to Z, and maps those to a to z.
        let mapper = CaseMapper::new();
        for byte in 0_u8..=127 {
            let ch = char::from(byte);
            assert_eq!(
                mapper.simple_fold(ch),
                ch.to_ascii_lowercase(),
                "character {byte}"
            );
        }
    }

    #[test]
    fn fold_into_appends_the_same_folding() {
        for text in ["PowerShell.EXE", "\u{3a3}\u{3c2}", "\u{212a}elvin", ""] {
            let mut out = String::from("prefix:");
            fold_into(text, &mut out);
            assert_eq!(out, format!("prefix:{}", fold(text)));
        }
    }

    #[test]
    fn ascii_folds_to_lower_case() {
        assert_eq!(fold("PowerShell.EXE"), "powershell.exe");
    }

    #[test]
    fn unchanged_text_is_borrowed() {
        assert!(matches!(fold(r"c:\windows\cmd.exe"), Cow::Borrowed(_)));
        assert!(matches!(fold(""), Cow::Borrowed(_)));
    }

    #[test]
    fn every_greek_sigma_folds_to_the_same_character() {
        // Capital, medial, and final sigma.
        assert_eq!(fold("\u{3a3}"), "\u{3c3}");
        assert_eq!(fold("\u{3c2}"), "\u{3c3}");
    }

    #[test]
    fn compatibility_characters_fold_to_their_letters() {
        // Kelvin sign and long s: visually unusual spellings that should not
        // let a value slip past a rule.
        assert_eq!(fold("\u{212a}"), "k");
        assert_eq!(fold("\u{17f}"), "s");
    }

    #[test]
    fn sharp_s_keeps_its_length() {
        // Full folding would give "ss"; simple folding never changes length.
        assert_eq!(fold("\u{df}"), "\u{df}");
        assert_eq!(fold("\u{1e9e}"), "\u{df}");
    }

    #[test]
    fn folding_ignores_locale() {
        // Turkish dotted capital I folds to `i` only under a Turkish locale
        // rule, which is exactly what must not apply.
        assert_eq!(fold("\u{130}"), "\u{130}");
        // And dotless small i is its own letter, not a variant of `i`.
        assert_eq!(fold("\u{131}"), "\u{131}");
    }

    #[test]
    fn folding_is_idempotent() {
        for text in ["MiXeD", "\u{3a3}\u{3c2}", "\u{212a}elvin", "\u{1e9e}"] {
            let once = fold(text).into_owned();
            assert_eq!(fold(&once), once.as_str());
        }
    }
}
