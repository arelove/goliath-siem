//! Literals a regular expression cannot match without.
//!
//! A regular expression has no literal the engine's automata could find, so
//! without help a rule that tests one is evaluated on every event of its
//! class, and the expression is run each time. Most expressions in practice
//! do require some text, such as `powershell` in `\\(powershell|pwsh)\.exe`.
//! This module finds a set of literals, one of which every match contains,
//! so the engine can wake the rule only when one of them is found and skip
//! the expression when none is.
//!
//! The literals are folded, and the engine looks for them in the folded texts
//! of the tested fields. That is sound whatever the expression's case
//! sensitivity: simple case folding maps each character to one character, so
//! if a value contains a literal, its folded text contains the folded literal.
//! Under `(?i)` the parser turns a letter into a class of its case variants,
//! and a class counts as a literal character only when every character in it
//! folds to the same one.
//!
//! The analysis may give up on any expression, and then the rule simply has
//! no trigger. It must never claim a literal that some match lacks; the
//! engine would then miss that match.

use goliath_rule::fold;
use goliath_sigma::RegexFlags;
use regex_syntax::ParserBuilder;
use regex_syntax::hir::{Class, Hir, HirKind};

/// Literals shorter than this are found in nearly every text, so they would
/// wake a rule about as often as having no trigger, while costing the
/// automaton a report at almost every position.
const SHORTEST_USEFUL: usize = 3;

/// A set larger than this costs more to look for than it saves.
const MOST_ALTERNATIVES: usize = 32;

/// A class with more characters than this is not a case variant set.
const LARGEST_CASE_CLASS: u32 = 4;

/// Returns folded literals, one of which the folded text of every match of
/// `pattern` contains, or `None` if no useful set is known.
pub(crate) fn required_literals(pattern: &str, flags: RegexFlags) -> Option<Vec<String>> {
    let hir = ParserBuilder::new()
        .case_insensitive(flags.case_insensitive)
        .multi_line(flags.multiline)
        .dot_matches_new_line(flags.dot_all)
        .build()
        .parse(pattern)
        .ok()?;
    let mut literals = required(&hir)?;
    if literals
        .iter()
        .any(|literal| literal.len() < SHORTEST_USEFUL)
    {
        return None;
    }
    literals.sort_unstable();
    literals.dedup();
    Some(literals)
}

/// A set of folded literals, one of which every match of `hir` contains.
fn required(hir: &Hir) -> Option<Vec<String>> {
    if let Some(texts) = exact(hir) {
        return texts.iter().all(|text| !text.is_empty()).then_some(texts);
    }
    match hir.kind() {
        HirKind::Repetition(repetition) if repetition.min >= 1 => required(&repetition.sub),
        HirKind::Capture(capture) => required(&capture.sub),
        HirKind::Concat(parts) => concat(parts),
        HirKind::Alternation(branches) => {
            let mut all = Vec::new();
            for branch in branches {
                all.extend(required(branch)?);
                if all.len() > MOST_ALTERNATIVES {
                    return None;
                }
            }
            Some(all)
        }
        _ => None,
    }
}

/// The best requirement of a sequence. Adjacent parts that match exactly
/// one of a few texts join into runs, which every match contains as one
/// piece: `\\(powershell|pwsh)\.exe` requires `\powershell.exe` or
/// `\pwsh.exe`. Any other part may contribute its own requirement.
fn concat(parts: &[Hir]) -> Option<Vec<String>> {
    let mut candidates: Vec<Vec<String>> = Vec::new();
    let mut run = vec![String::new()];
    let flush = |run: &mut Vec<String>, candidates: &mut Vec<Vec<String>>| {
        let done = std::mem::replace(run, vec![String::new()]);
        if done.iter().all(|text| !text.is_empty()) {
            candidates.push(done);
        }
    };
    for part in parts {
        match exact(part) {
            Some(texts) if run.len() * texts.len() <= MOST_ALTERNATIVES => {
                run = cross(&run, &texts);
            }
            Some(texts) => {
                flush(&mut run, &mut candidates);
                run = texts;
            }
            None => {
                flush(&mut run, &mut candidates);
                if let Some(requirement) = required(part) {
                    candidates.push(requirement);
                }
            }
        }
    }
    flush(&mut run, &mut candidates);
    candidates.into_iter().min_by_key(|set| cost(set))
}

/// Every text of `left` followed by every text of `right`.
fn cross(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .flat_map(|first| right.iter().map(move |second| format!("{first}{second}")))
        .collect()
}

/// The folded texts `hir` can match, when there are only a few of them and
/// nothing else: literals, classes of case variants of one character, and
/// sequences and alternations of those.
fn exact(hir: &Hir) -> Option<Vec<String>> {
    match hir.kind() {
        HirKind::Literal(_) | HirKind::Class(_) => character_text(hir).map(|text| vec![text]),
        HirKind::Capture(capture) => exact(&capture.sub),
        HirKind::Concat(parts) => {
            let mut texts = vec![String::new()];
            for part in parts {
                let next = exact(part)?;
                if texts.len() * next.len() > MOST_ALTERNATIVES {
                    return None;
                }
                texts = cross(&texts, &next);
            }
            Some(texts)
        }
        HirKind::Alternation(branches) => {
            let mut all = Vec::new();
            for branch in branches {
                all.extend(exact(branch)?);
                if all.len() > MOST_ALTERNATIVES {
                    return None;
                }
            }
            Some(all)
        }
        _ => None,
    }
}

/// How often a set is expected to be found: the engine's trigger heuristic,
/// where a literal counts inversely to the square of its length.
fn cost(set: &[String]) -> u64 {
    set.iter()
        .map(|literal| {
            let length = literal.len().max(1) as u64;
            1_000_000 / (length * length)
        })
        .sum()
}

/// The folded text of a literal, or of a class of case variants of one
/// character.
fn character_text(hir: &Hir) -> Option<String> {
    match hir.kind() {
        HirKind::Literal(literal) => {
            let literal = std::str::from_utf8(&literal.0).ok()?;
            Some(fold(literal).into_owned())
        }
        HirKind::Class(Class::Unicode(class)) => {
            let size: u32 = class
                .ranges()
                .iter()
                .map(|range| u32::from(range.end()) - u32::from(range.start()) + 1)
                .sum();
            if size > LARGEST_CASE_CLASS {
                return None;
            }
            same_folding(
                class
                    .ranges()
                    .iter()
                    .flat_map(|range| range.start()..=range.end()),
            )
        }
        HirKind::Class(Class::Bytes(class)) => {
            let size: u32 = class
                .ranges()
                .iter()
                .map(|range| u32::from(range.end()) - u32::from(range.start()) + 1)
                .sum();
            if size > LARGEST_CASE_CLASS {
                return None;
            }
            let mut bytes = class
                .ranges()
                .iter()
                .flat_map(|range| range.start()..=range.end());
            // A byte class stands for characters only where it is ASCII.
            if bytes.any(|byte| !byte.is_ascii()) {
                return None;
            }
            same_folding(
                class
                    .ranges()
                    .iter()
                    .flat_map(|range| range.start()..=range.end())
                    .map(char::from),
            )
        }
        _ => None,
    }
}

/// The one folded character every character of `chars` folds to, if there
/// is one.
fn same_folding(chars: impl Iterator<Item = char>) -> Option<String> {
    let mut folded: Option<String> = None;
    for ch in chars {
        let this = fold(ch.encode_utf8(&mut [0; 4])).into_owned();
        match &folded {
            None => folded = Some(this),
            Some(first) if *first == this => {}
            Some(_) => return None,
        }
    }
    folded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literals(pattern: &str) -> Option<Vec<String>> {
        required_literals(pattern, RegexFlags::default())
    }

    fn insensitive(pattern: &str) -> Option<Vec<String>> {
        required_literals(
            pattern,
            RegexFlags {
                case_insensitive: true,
                ..RegexFlags::default()
            },
        )
    }

    #[allow(clippy::unnecessary_wraps)] // Compared with optional results.
    fn set(items: &[&str]) -> Option<Vec<String>> {
        let mut items: Vec<String> = items.iter().map(|&item| item.to_owned()).collect();
        items.sort_unstable();
        Some(items)
    }

    #[test]
    fn a_plain_literal_is_required_folded() {
        assert_eq!(literals("PowerShell"), set(&["powershell"]));
    }

    #[test]
    fn alternatives_join_their_neighbours() {
        assert_eq!(
            literals(r"\\(powershell|pwsh)\.exe"),
            set(&[r"\powershell.exe", r"\pwsh.exe"])
        );
        assert_eq!(
            literals("(mimikatz|sekurlsa)"),
            set(&["mimikatz", "sekurlsa"])
        );
    }

    #[test]
    fn alternations_without_exact_texts_still_require_one_branch() {
        assert_eq!(
            literals(r"(mimikatz\d|sekurlsa\w)"),
            set(&["mimikatz", "sekurlsa"])
        );
    }

    #[test]
    fn the_rarest_part_of_a_sequence_is_chosen() {
        // `.exe` is shorter than `rundll32`, so it is expected more often.
        assert_eq!(literals(r"rundll32.+\.exe"), set(&["rundll32"]));
    }

    #[test]
    fn case_insensitive_letters_are_classes_of_variants() {
        assert_eq!(insensitive("MiMiKaTz"), set(&["mimikatz"]));
        assert_eq!(literals("(?i)sekurlsa::"), set(&["sekurlsa::"]));
    }

    #[test]
    fn a_class_of_different_letters_ends_a_run() {
        assert_eq!(literals("abc[xy]defgh"), set(&["defgh"]));
    }

    #[test]
    fn optional_parts_are_not_required() {
        assert_eq!(literals("(mimikatz)?x"), None);
        assert_eq!(literals("(mimikatz)*"), None);
        assert_eq!(literals("(mimikatz)+"), set(&["mimikatz"]));
        assert_eq!(literals("(mimikatz){0,3}"), None);
    }

    #[test]
    fn a_branch_without_a_literal_spoils_the_alternation() {
        assert_eq!(literals(r"(mimikatz|\d+)"), None);
    }

    #[test]
    fn short_literals_are_not_worth_a_trigger() {
        assert_eq!(literals(r"-e\s"), None);
        assert_eq!(literals("(ab|cde)"), None);
    }

    #[test]
    fn anything_else_gives_up() {
        assert_eq!(literals(r"\w+"), None);
        assert_eq!(literals("."), None);
        assert_eq!(literals("^$"), None);
        assert_eq!(literals("(unclosed"), None);
    }

    #[test]
    fn look_arounds_split_runs() {
        assert_eq!(literals(r"\bcertutil\b"), set(&["certutil"]));
    }

    #[test]
    fn non_ascii_case_variants_fold_together() {
        // Kelvin sign and K fold to k; a class of those is one character.
        assert_eq!(insensitive("\u{212a}elvin"), set(&["kelvin"]));
        assert_eq!(
            insensitive("\u{3a3}\u{3a3}\u{3a3}"),
            set(&["\u{3c3}\u{3c3}\u{3c3}"])
        );
    }
}
