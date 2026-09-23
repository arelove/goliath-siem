//! Sigma value transformations: `windash`, `utf16`, `base64`, and friends.
//!
//! Each transformation rewrites the rule's value before comparison, and some
//! turn one value into several. They run once, at load time, so that nothing
//! of them is left for an execution path to do per event.
//!
//! The output must agree byte for byte with pySigma, the reference
//! implementation, or a rule would match differently here than everywhere
//! else it runs. The expected values in the tests were produced by pySigma's
//! algorithm.

use goliath_sigma::{Modifier, PatternPart};

/// Why a chain of transformations cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransformError {
    /// The chain is not meaningful, with the reason.
    Invalid(&'static str),
    /// The value expands into more variants than a rule may carry.
    TooManyVariants(usize),
}

/// Upper bound on the variants one value may expand into.
///
/// `windash` multiplies variants by five for every dash it finds, so a value
/// with many options grows fast. 625 allows four, more than any rule in the
/// `SigmaHQ` repository uses.
pub(crate) const MAX_VARIANTS: usize = 625;

/// The characters `windash` treats as interchangeable option prefixes: hyphen,
/// slash, en dash, em dash, and horizontal bar.
const DASHES: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

/// The result of applying transformations to one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Transformed {
    /// The variants; the value matches if any does.
    pub(crate) variants: Vec<Vec<PatternPart>>,
    /// Whether an encoding was applied. Encoded text is compared with regard
    /// to case, because case carries information in base64.
    pub(crate) encoded: bool,
}

enum Stage {
    Text(Vec<PatternPart>),
    Bytes(Vec<u8>),
}

/// Applies `transforms`, in order, to a value.
pub(crate) fn apply(
    value: &[PatternPart],
    transforms: &[&Modifier],
) -> Result<Transformed, TransformError> {
    let mut stages = vec![Stage::Text(value.to_vec())];
    let mut encoded = false;

    for modifier in transforms {
        let mut next = Vec::new();
        for stage in stages {
            match modifier {
                Modifier::WinDash => match stage {
                    Stage::Text(parts) => {
                        next.extend(windash(&parts)?.into_iter().map(Stage::Text));
                    }
                    Stage::Bytes(_) => {
                        return Err(TransformError::Invalid(
                            "windash applies to text, so it must come before any encoding",
                        ));
                    }
                },
                Modifier::Utf16 | Modifier::Utf16Le | Modifier::Utf16Be => match stage {
                    Stage::Text(parts) => {
                        next.push(Stage::Bytes(utf16(modifier, &literal(&parts)?)));
                    }
                    Stage::Bytes(_) => {
                        return Err(TransformError::Invalid(
                            "a value cannot be encoded as UTF-16 twice",
                        ));
                    }
                },
                Modifier::Base64 => next.push(Stage::Text(vec![PatternPart::Literal(base64(
                    &bytes(stage)?,
                ))])),
                Modifier::Base64Offset => next.extend(
                    base64_offsets(&bytes(stage)?)
                        .into_iter()
                        .map(|text| Stage::Text(vec![PatternPart::Literal(text)])),
                ),
                _ => return Err(TransformError::Invalid("not a transformation")),
            }
        }
        if matches!(modifier, Modifier::Base64 | Modifier::Base64Offset) {
            encoded = true;
        }
        if next.len() > MAX_VARIANTS {
            return Err(TransformError::TooManyVariants(next.len()));
        }
        stages = next;
    }

    let variants = stages
        .into_iter()
        .map(|stage| match stage {
            Stage::Text(parts) => Ok(parts),
            Stage::Bytes(_) => Err(TransformError::Invalid(
                "a UTF-16 encoding must be followed by base64 or base64offset",
            )),
        })
        .collect::<Result<_, _>>()?;

    Ok(Transformed { variants, encoded })
}

/// The text of a value without wildcards.
fn literal(parts: &[PatternPart]) -> Result<String, TransformError> {
    let mut text = String::new();
    for part in parts {
        match part {
            PatternPart::Literal(literal) => text.push_str(literal),
            PatternPart::AnySequence | PatternPart::AnyChar => {
                return Err(TransformError::Invalid(
                    "an encoding cannot preserve wildcards; escape them or remove them",
                ));
            }
        }
    }
    Ok(text)
}

fn bytes(stage: Stage) -> Result<Vec<u8>, TransformError> {
    match stage {
        Stage::Text(parts) => Ok(literal(&parts)?.into_bytes()),
        Stage::Bytes(bytes) => Ok(bytes),
    }
}

fn utf16(modifier: &Modifier, text: &str) -> Vec<u8> {
    let units = text.encode_utf16();
    match modifier {
        Modifier::Utf16Be => units.flat_map(u16::to_be_bytes).collect(),
        // `utf16` is little endian after a byte order mark, as Python writes it.
        Modifier::Utf16 => [0xFF, 0xFE]
            .into_iter()
            .chain(units.flat_map(u16::to_le_bytes))
            .collect(),
        _ => units.flat_map(u16::to_le_bytes).collect(),
    }
}

/// Every spelling of a value with each option dash replaced by each of
/// [`DASHES`].
///
/// An option dash is a `-` or `/` that follows a non-word character, or the
/// start, and precedes a word character, as in pySigma. A wildcard counts as
/// a non-word character, as it does in the text pySigma operates on.
///
/// The number of variants is checked before any is built, so a value with
/// many dashes is refused without first being expanded.
fn windash(parts: &[PatternPart]) -> Result<Vec<Vec<PatternPart>>, TransformError> {
    enum Token {
        Char(char),
        Wildcard(PatternPart),
    }

    let is_word = |ch: char| ch.is_alphanumeric() || ch == '_';

    let tokens: Vec<Token> = parts
        .iter()
        .flat_map(|part| match part {
            PatternPart::Literal(text) => text.chars().map(Token::Char).collect::<Vec<_>>(),
            wildcard => vec![Token::Wildcard(wildcard.clone())],
        })
        .collect();

    let option_dash = |index: usize| {
        let Token::Char('-' | '/') = tokens[index] else {
            return false;
        };
        let after_non_word =
            index == 0 || !matches!(tokens[index - 1], Token::Char(ch) if is_word(ch));
        let before_word = matches!(tokens.get(index + 1), Some(Token::Char(ch)) if is_word(*ch));
        after_non_word && before_word
    };
    let dashes: Vec<usize> = (0..tokens.len()).filter(|&i| option_dash(i)).collect();

    let count = u32::try_from(dashes.len())
        .ok()
        .and_then(|exponent| DASHES.len().checked_pow(exponent))
        .unwrap_or(usize::MAX);
    if count > MAX_VARIANTS {
        return Err(TransformError::TooManyVariants(count));
    }

    let mut variants = vec![Vec::new()];
    let mut next_dash = dashes.iter().peekable();
    for (index, token) in tokens.iter().enumerate() {
        let choices: Vec<PatternPart> = if next_dash.next_if(|&&dash| dash == index).is_some() {
            DASHES
                .iter()
                .map(|dash| PatternPart::Literal(dash.to_string()))
                .collect()
        } else {
            match token {
                Token::Char(ch) => vec![PatternPart::Literal(ch.to_string())],
                Token::Wildcard(wildcard) => vec![wildcard.clone()],
            }
        };
        variants = variants
            .into_iter()
            .flat_map(|prefix: Vec<PatternPart>| {
                choices.iter().map(move |choice| {
                    let mut extended = prefix.clone();
                    extended.push(choice.clone());
                    extended
                })
            })
            .collect();
    }

    Ok(variants
        .into_iter()
        .map(|parts| goliath_sigma::Pattern::from_parts(parts).parts().to_vec())
        .collect())
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 0x3F) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The base64 text of `bytes` at each of the three alignments it can have
/// inside a longer encoded string, trimmed to the characters that do not
/// depend on the surrounding bytes.
fn base64_offsets(bytes: &[u8]) -> Vec<String> {
    const STARTS: [usize; 3] = [0, 2, 3];
    // Characters to drop from the end, by (length + offset) % 3.
    const TRIMS: [usize; 3] = [0, 3, 2];

    (0..3)
        .map(|offset| {
            let mut shifted = vec![b' '; offset];
            shifted.extend_from_slice(bytes);
            let encoded = base64(&shifted);
            let end = encoded
                .len()
                .saturating_sub(TRIMS[(bytes.len() + offset) % 3]);
            encoded
                .get(STARTS[offset]..end)
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(text: &str) -> Vec<PatternPart> {
        vec![PatternPart::Literal(text.to_owned())]
    }

    fn texts(transformed: &Transformed) -> Vec<String> {
        transformed
            .variants
            .iter()
            .map(|parts| match parts.as_slice() {
                [PatternPart::Literal(text)] => text.clone(),
                other => panic!("expected one literal, got {other:?}"),
            })
            .collect()
    }

    #[test]
    fn base64_matches_the_reference() {
        let out = apply(&lit("ping"), &[&Modifier::Base64]).expect("applies");
        assert_eq!(texts(&out), ["cGluZw=="]);
        assert!(out.encoded);
        assert_eq!(base64(b"hello world"), "aGVsbG8gd29ybGQ=");
        assert_eq!(base64(b"/c:"), "L2M6");
        assert_eq!(base64(b""), "");
    }

    #[test]
    fn base64offset_matches_the_reference() {
        let cases: [(&str, [&str; 3]); 3] = [
            ("/c:", ["L2M6", "9jO", "vYz"]),
            ("ping", ["cGluZ", "Bpbm", "waW5n"]),
            (
                "hello world",
                ["aGVsbG8gd29ybG", "hlbGxvIHdvcmxk", "oZWxsbyB3b3JsZ"],
            ),
        ];
        for (value, expected) in cases {
            let out = apply(&lit(value), &[&Modifier::Base64Offset]).expect("applies");
            assert_eq!(texts(&out), expected, "value {value:?}");
        }
    }

    #[test]
    fn utf16_variants_match_the_reference() {
        let encode = |modifier: Modifier| {
            texts(&apply(&lit("ping"), &[&modifier, &Modifier::Base64]).expect("applies"))
        };
        assert_eq!(encode(Modifier::Utf16Le), ["cABpAG4AZwA="]);
        assert_eq!(encode(Modifier::Utf16), ["//5wAGkAbgBnAA=="]);
        assert_eq!(encode(Modifier::Utf16Be), ["AHAAaQBuAGc="]);

        let out =
            apply(&lit("IEX"), &[&Modifier::Utf16Le, &Modifier::Base64Offset]).expect("applies");
        assert_eq!(texts(&out), ["SQBFAFgA", "kARQBYA", "JAEUAWA"]);
    }

    #[test]
    fn utf16_alone_is_refused() {
        assert!(matches!(
            apply(&lit("ping"), &[&Modifier::Utf16Le]),
            Err(TransformError::Invalid(_))
        ));
    }

    #[test]
    fn encodings_refuse_wildcards() {
        let wildcard = vec![
            PatternPart::Literal("a".to_owned()),
            PatternPart::AnySequence,
        ];
        assert!(apply(&wildcard, &[&Modifier::Base64]).is_err());
    }

    #[test]
    fn windash_replaces_option_dashes() {
        let out = apply(&lit(" -enc "), &[&Modifier::WinDash]).expect("applies");
        assert_eq!(
            texts(&out),
            [
                " -enc ",
                " /enc ",
                " \u{2013}enc ",
                " \u{2014}enc ",
                " \u{2015}enc "
            ]
        );
        assert!(!out.encoded);
    }

    #[test]
    fn windash_leaves_other_dashes_alone() {
        // Inside a word, before a space, and before a wildcard.
        for value in ["a-b", "a - b"] {
            let out = apply(&lit(value), &[&Modifier::WinDash]).expect("applies");
            assert_eq!(texts(&out), [value]);
        }
        let before_wildcard = vec![
            PatternPart::Literal(" -".to_owned()),
            PatternPart::AnySequence,
        ];
        let out = apply(&before_wildcard, &[&Modifier::WinDash]).expect("applies");
        assert_eq!(out.variants.len(), 1);
    }

    #[test]
    fn windash_treats_a_wildcard_as_a_non_word_character() {
        let parts = vec![
            PatternPart::AnySequence,
            PatternPart::Literal("-x".to_owned()),
        ];
        let out = apply(&parts, &[&Modifier::WinDash]).expect("applies");
        assert_eq!(out.variants.len(), 5);
        assert_eq!(
            out.variants[1],
            [
                PatternPart::AnySequence,
                PatternPart::Literal("/x".to_owned())
            ]
        );
    }

    #[test]
    fn windash_multiplies_and_is_bounded() {
        let four = apply(&lit("-a -b -c -d"), &[&Modifier::WinDash]).expect("applies");
        assert_eq!(four.variants.len(), 625);
        assert_eq!(
            apply(&lit("-a -b -c -d -e"), &[&Modifier::WinDash]),
            Err(TransformError::TooManyVariants(3125))
        );
        // Refused by counting, not by building: this would be 5^200 variants.
        let many = "-a ".repeat(200);
        assert_eq!(
            apply(&lit(&many), &[&Modifier::WinDash]),
            Err(TransformError::TooManyVariants(usize::MAX))
        );
    }

    #[test]
    fn windash_then_base64offset_encodes_every_spelling() {
        let out =
            apply(&lit("-enc"), &[&Modifier::WinDash, &Modifier::Base64Offset]).expect("applies");
        assert_eq!(out.variants.len(), 15);
        assert!(out.encoded);
    }

    #[test]
    fn windash_after_an_encoding_is_refused() {
        assert!(apply(&lit("-a"), &[&Modifier::Utf16Le, &Modifier::WinDash]).is_err());
    }
}
