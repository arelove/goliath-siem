//! The condition expression AST.

use serde::{Deserialize, Serialize};

use crate::span::Span;

/// How many of the targeted search identifiers must match.
///
/// Sigma defines exactly these two. Other counts are rejected at parse time by
/// [`ConditionError::UnsupportedQuantifier`](crate::ConditionError::UnsupportedQuantifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Quantifier {
    /// `1 of` - at least one of the targets matches.
    Any,
    /// `all of` - every target matches.
    All,
}

/// What a quantifier applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// `them` - every search identifier defined by the rule.
    Them,
    /// A pattern over identifier names, such as `selection_*`.
    Pattern(String),
}

impl Target {
    /// Reports whether `identifier` is covered by this target.
    ///
    /// [`Them`](Target::Them) covers everything. A pattern matches with `*`
    /// standing for any run of characters, including none.
    pub fn matches(&self, identifier: &str) -> bool {
        match self {
            Self::Them => true,
            Self::Pattern(pattern) => wildcard_matches(pattern, identifier),
        }
    }
}

/// A parsed Sigma condition.
///
/// Every node carries the source range it was parsed from, so that a later
/// check - such as an identifier the detection block never defines - can point
/// at the offending characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    /// A reference to one search identifier.
    Identifier {
        /// The identifier name.
        name: String,
        /// Where it appeared.
        span: Span,
    },

    /// A quantifier over several search identifiers.
    Quantified {
        /// How many targets must match.
        quantifier: Quantifier,
        /// Which identifiers are targeted.
        target: Target,
        /// Where the whole expression appeared.
        span: Span,
    },

    /// Logical negation.
    Not {
        /// The negated expression.
        operand: Box<Condition>,
        /// Where the whole expression appeared.
        span: Span,
    },

    /// Conjunction of two or more operands.
    And {
        /// The conjoined expressions.
        operands: Vec<Condition>,
        /// Where the whole expression appeared.
        span: Span,
    },

    /// Disjunction of two or more operands.
    Or {
        /// The disjoined expressions.
        operands: Vec<Condition>,
        /// Where the whole expression appeared.
        span: Span,
    },
}

impl Condition {
    /// Returns the source range this node was parsed from.
    pub fn span(&self) -> Span {
        match self {
            Self::Identifier { span, .. }
            | Self::Quantified { span, .. }
            | Self::Not { span, .. }
            | Self::And { span, .. }
            | Self::Or { span, .. } => *span,
        }
    }

    /// Visits every node in the tree, parents before children.
    pub fn walk<'a>(&'a self, visit: &mut impl FnMut(&'a Self)) {
        visit(self);
        match self {
            Self::Identifier { .. } | Self::Quantified { .. } => {}
            Self::Not { operand, .. } => operand.walk(visit),
            Self::And { operands, .. } | Self::Or { operands, .. } => {
                for operand in operands {
                    operand.walk(visit);
                }
            }
        }
    }

    /// Returns every identifier named directly, with its span, in source order.
    ///
    /// Identifiers reached through a quantifier are not included: those are
    /// patterns, and resolving them needs the rule's detection block.
    pub fn named_identifiers(&self) -> Vec<(&str, Span)> {
        let mut found = Vec::new();
        self.walk(&mut |node| {
            if let Self::Identifier { name, span } = node {
                found.push((name.as_str(), *span));
            }
        });
        found
    }

    /// Returns every quantifier target, with its span, in source order.
    pub fn quantifier_targets(&self) -> Vec<(&Target, Span)> {
        let mut found = Vec::new();
        self.walk(&mut |node| {
            if let Self::Quantified { target, span, .. } = node {
                found.push((target, *span));
            }
        });
        found
    }
}

/// Matches `candidate` against a pattern in which `*` stands for any run of
/// characters, including none.
///
/// Iterative with backtracking rather than recursive: patterns come from rule
/// files, and a recursive matcher can be driven to overflow the stack by a
/// pattern of many wildcards.
fn wildcard_matches(pattern: &str, candidate: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let candidate: Vec<char> = candidate.chars().collect();

    let (mut p, mut c) = (0_usize, 0_usize);
    // Where to resume if the current wildcard turns out to have consumed too
    // little. `None` means no wildcard has been seen yet, so failure is final.
    let mut resume: Option<(usize, usize)> = None;

    while c < candidate.len() {
        if p < pattern.len() && pattern[p] == '*' {
            // Try the shortest match first, and record where to backtrack to.
            p += 1;
            resume = Some((p, c));
        } else if p < pattern.len() && pattern[p] == candidate[c] {
            p += 1;
            c += 1;
        } else if let Some((wildcard_end, consumed)) = resume {
            // Let the wildcard consume one more character and retry.
            p = wildcard_end;
            c = consumed + 1;
            resume = Some((wildcard_end, c));
        } else {
            return false;
        }
    }

    pattern[p..].iter().all(|&ch| ch == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_match_any_run_including_none() {
        assert!(wildcard_matches("selection_*", "selection_"));
        assert!(wildcard_matches("selection_*", "selection_process"));
        assert!(!wildcard_matches("selection_*", "selection"));

        assert!(wildcard_matches("*", ""));
        assert!(wildcard_matches("*", "anything"));
    }

    #[test]
    fn wildcards_match_in_the_middle_and_at_the_start() {
        assert!(wildcard_matches("*_filter", "network_filter"));
        assert!(wildcard_matches("sel*ion", "selection"));
        assert!(!wildcard_matches("sel*ion", "selects"));
    }

    #[test]
    fn matching_backtracks_when_a_wildcard_consumed_too_little() {
        // The first `*` must give up `ab` before `abc` can match the tail.
        assert!(wildcard_matches("a*c", "abbbc"));
        assert!(wildcard_matches("*abc", "xxabcabc"));
        assert!(!wildcard_matches("a*c", "abbb"));
    }

    #[test]
    fn literal_patterns_need_an_exact_match() {
        assert!(wildcard_matches("selection", "selection"));
        assert!(!wildcard_matches("selection", "selection_1"));
        assert!(!wildcard_matches("selection", "Selection"));
    }

    #[test]
    fn them_covers_every_identifier() {
        assert!(Target::Them.matches("selection"));
        assert!(Target::Them.matches("filter_admin"));
    }

    #[test]
    fn many_wildcards_do_not_overflow_the_stack() {
        let pattern = "*".repeat(2_000);
        let candidate = "a".repeat(2_000);
        assert!(wildcard_matches(&pattern, &candidate));
    }
}
