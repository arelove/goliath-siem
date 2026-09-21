//! Recursive descent parser for Sigma condition expressions.
//!
//! Precedence, loosest first: `or`, `and`, `not`. Parentheses group.

use crate::condition::{Condition, Quantifier, Target};
use crate::error::ConditionError;
use crate::lexer::{Token, TokenKind, tokenize};
use crate::span::Span;

/// Parses a Sigma condition expression.
///
/// # Errors
///
/// Returns the first syntax error, carrying a span into `source`.
///
/// # Examples
///
/// ```
/// use goliath_sigma::{Condition, parse_condition};
///
/// let condition = parse_condition("selection and not filter")?;
/// let names: Vec<_> = condition.named_identifiers().iter().map(|(n, _)| *n).collect();
/// assert_eq!(names, ["selection", "filter"]);
/// # Ok::<(), goliath_sigma::ConditionError>(())
/// ```
pub fn parse_condition(source: &str) -> Result<Condition, ConditionError> {
    let tokens = tokenize(source)?;
    if tokens.is_empty() {
        return Err(ConditionError::Empty);
    }

    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
        end: source.len(),
    };
    let condition = parser.parse_or()?;

    match parser.peek() {
        None => Ok(condition),
        Some(token) if token.kind == TokenKind::Pipe => {
            Err(ConditionError::AggregationUnsupported {
                span: Span::new(token.span.start, source.len()),
            })
        }
        Some(token) => Err(ConditionError::UnexpectedToken {
            expected: "the end of the condition",
            found: token.kind.describe(),
            span: token.span,
        }),
    }
}

struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
    /// Byte length of the source, used to point at the end on truncated input.
    end: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn advance(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.position);
        if token.is_some() {
            self.position += 1;
        }
        token
    }

    /// Consumes the next token if it is `expected`, and fails otherwise.
    fn expect(
        &mut self,
        expected: &TokenKind,
        described: &'static str,
    ) -> Result<Span, ConditionError> {
        match self.peek() {
            Some(token) if &token.kind == expected => {
                let span = token.span;
                self.position += 1;
                Ok(span)
            }
            Some(token) => Err(ConditionError::UnexpectedToken {
                expected: described,
                found: token.kind.describe(),
                span: token.span,
            }),
            None => Err(ConditionError::UnexpectedEnd {
                expected: described,
                span: Span::empty_at(self.end),
            }),
        }
    }

    fn parse_or(&mut self) -> Result<Condition, ConditionError> {
        let first = self.parse_and()?;
        let mut operands = vec![first];

        while self.peek().is_some_and(|t| t.kind == TokenKind::Or) {
            self.position += 1;
            operands.push(self.parse_and()?);
        }

        Ok(Self::fold(operands, |operands, span| Condition::Or {
            operands,
            span,
        }))
    }

    fn parse_and(&mut self) -> Result<Condition, ConditionError> {
        let first = self.parse_not()?;
        let mut operands = vec![first];

        while self.peek().is_some_and(|t| t.kind == TokenKind::And) {
            self.position += 1;
            operands.push(self.parse_not()?);
        }

        Ok(Self::fold(operands, |operands, span| Condition::And {
            operands,
            span,
        }))
    }

    fn parse_not(&mut self) -> Result<Condition, ConditionError> {
        let Some(token) = self.peek() else {
            return Err(ConditionError::UnexpectedEnd {
                expected: "an expression",
                span: Span::empty_at(self.end),
            });
        };

        if token.kind == TokenKind::Not {
            let start = token.span;
            self.position += 1;
            let operand = self.parse_not()?;
            let span = start.merge(operand.span());
            return Ok(Condition::Not {
                operand: Box::new(operand),
                span,
            });
        }

        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Condition, ConditionError> {
        let Some(token) = self.peek().cloned() else {
            return Err(ConditionError::UnexpectedEnd {
                expected: "an expression",
                span: Span::empty_at(self.end),
            });
        };

        match token.kind {
            TokenKind::LParen => {
                self.position += 1;
                let inner = self.parse_or()?;
                match self.peek() {
                    Some(close) if close.kind == TokenKind::RParen => {
                        self.position += 1;
                        Ok(inner)
                    }
                    Some(other) => Err(ConditionError::UnexpectedToken {
                        expected: "`)`",
                        found: other.kind.describe(),
                        span: other.span,
                    }),
                    None => Err(ConditionError::UnclosedGroup { span: token.span }),
                }
            }

            TokenKind::All => {
                self.position += 1;
                self.parse_quantified(Quantifier::All, token.span)
            }

            TokenKind::Number(value) => {
                self.position += 1;
                if value != 1 {
                    return Err(ConditionError::UnsupportedQuantifier {
                        value,
                        span: token.span,
                    });
                }
                self.parse_quantified(Quantifier::Any, token.span)
            }

            TokenKind::Identifier(name) => {
                self.position += 1;
                Ok(Condition::Identifier {
                    name,
                    span: token.span,
                })
            }

            _ => Err(ConditionError::UnexpectedToken {
                expected: "an expression",
                found: token.kind.describe(),
                span: token.span,
            }),
        }
    }

    /// Parses the `of <target>` tail of a quantifier, given its leading span.
    fn parse_quantified(
        &mut self,
        quantifier: Quantifier,
        start: Span,
    ) -> Result<Condition, ConditionError> {
        self.expect(&TokenKind::Of, "`of`")?;

        let Some(token) = self.advance().cloned() else {
            return Err(ConditionError::UnexpectedEnd {
                expected: "`them` or an identifier pattern",
                span: Span::empty_at(self.end),
            });
        };

        let target = match token.kind {
            TokenKind::Them => Target::Them,
            TokenKind::Identifier(pattern) => Target::Pattern(pattern),
            other => {
                return Err(ConditionError::UnexpectedToken {
                    expected: "`them` or an identifier pattern",
                    found: other.describe(),
                    span: token.span,
                });
            }
        };

        Ok(Condition::Quantified {
            quantifier,
            target,
            span: start.merge(token.span),
        })
    }

    /// Collapses a single operand to itself, and several into a combining node.
    ///
    /// Without this, `selection` would parse as `Or([And([selection])])`, and
    /// every consumer would have to see through the wrapping.
    fn fold(
        mut operands: Vec<Condition>,
        combine: impl FnOnce(Vec<Condition>, Span) -> Condition,
    ) -> Condition {
        if operands.len() == 1 {
            return operands.remove(0);
        }

        let span = operands
            .iter()
            .map(Condition::span)
            .reduce(Span::merge)
            .unwrap_or_else(|| Span::empty_at(0));

        combine(operands, span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(condition: &Condition) -> Vec<String> {
        condition
            .named_identifiers()
            .iter()
            .map(|(n, _)| (*n).to_owned())
            .collect()
    }

    #[test]
    fn a_lone_identifier_is_not_wrapped() {
        let condition = parse_condition("selection").expect("parse");
        assert!(matches!(condition, Condition::Identifier { .. }));
        assert_eq!(names(&condition), ["selection"]);
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // a or b and c parses as a or (b and c)
        let condition = parse_condition("a or b and c").expect("parse");

        let Condition::Or { operands, .. } = &condition else {
            panic!("expected a top-level or, got {condition:?}");
        };
        assert_eq!(operands.len(), 2);
        assert!(matches!(operands[0], Condition::Identifier { .. }));
        assert!(matches!(operands[1], Condition::And { .. }));
    }

    #[test]
    fn not_binds_tighter_than_and() {
        // not a and b parses as (not a) and b
        let condition = parse_condition("not a and b").expect("parse");

        let Condition::And { operands, .. } = &condition else {
            panic!("expected a top-level and, got {condition:?}");
        };
        assert!(matches!(operands[0], Condition::Not { .. }));
        assert!(matches!(operands[1], Condition::Identifier { .. }));
    }

    #[test]
    fn parentheses_override_precedence() {
        let condition = parse_condition("(a or b) and c").expect("parse");
        let Condition::And { operands, .. } = &condition else {
            panic!("expected a top-level and, got {condition:?}");
        };
        assert!(matches!(operands[0], Condition::Or { .. }));
    }

    #[test]
    fn chained_operators_flatten_into_one_node() {
        let condition = parse_condition("a and b and c and d").expect("parse");
        let Condition::And { operands, .. } = &condition else {
            panic!("expected a top-level and, got {condition:?}");
        };
        assert_eq!(operands.len(), 4, "chains should flatten, not nest");
    }

    #[test]
    fn negation_stacks() {
        let condition = parse_condition("not not a").expect("parse");
        let Condition::Not { operand, .. } = &condition else {
            panic!("expected a not, got {condition:?}");
        };
        assert!(matches!(**operand, Condition::Not { .. }));
    }

    #[test]
    fn parses_the_common_selection_filter_shape() {
        let condition = parse_condition("selection and not filter").expect("parse");
        assert_eq!(names(&condition), ["selection", "filter"]);
    }

    #[test]
    fn parses_quantifiers() {
        let any = parse_condition("1 of selection_*").expect("parse");
        assert!(matches!(
            any,
            Condition::Quantified {
                quantifier: Quantifier::Any,
                target: Target::Pattern(_),
                ..
            }
        ));

        let all = parse_condition("all of them").expect("parse");
        assert!(matches!(
            all,
            Condition::Quantified {
                quantifier: Quantifier::All,
                target: Target::Them,
                ..
            }
        ));
    }

    #[test]
    fn quantifiers_combine_with_operators() {
        let condition = parse_condition("1 of selection_* and not 1 of filter_*").expect("parse");

        let targets = condition.quantifier_targets();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].0, &Target::Pattern("selection_*".to_owned()));
        assert_eq!(targets[1].0, &Target::Pattern("filter_*".to_owned()));
    }

    #[test]
    fn rejects_counts_other_than_one() {
        let err = parse_condition("2 of them").expect_err("`2 of` has no defined meaning");
        assert!(matches!(
            err,
            ConditionError::UnsupportedQuantifier { value: 2, .. }
        ));
    }

    #[test]
    fn rejects_aggregation_rather_than_ignoring_it() {
        // Dropping the aggregation would turn a threshold rule into one that
        // fires on every event, which is worse than refusing the rule.
        let source = "selection | count() by User > 5";
        let err = parse_condition(source).expect_err("aggregation must be refused");

        let ConditionError::AggregationUnsupported { span } = err else {
            panic!("expected an aggregation error, got {err:?}");
        };
        assert_eq!(span.slice(source), Some("| count() by User > 5"));
    }

    #[test]
    fn reports_an_unclosed_group_at_the_opening_paren() {
        let source = "(a or b";
        let err = parse_condition(source).expect_err("unclosed group");

        let ConditionError::UnclosedGroup { span } = err else {
            panic!("expected an unclosed group error, got {err:?}");
        };
        assert_eq!(span, Span::new(0, 1));
    }

    #[test]
    fn reports_a_dangling_operator_at_the_end_of_input() {
        let source = "selection and";
        let err = parse_condition(source).expect_err("dangling operator");

        let ConditionError::UnexpectedEnd { expected, span } = err else {
            panic!("expected an end-of-input error, got {err:?}");
        };
        assert_eq!(expected, "an expression");
        assert_eq!(span, Span::empty_at(source.len()));
    }

    #[test]
    fn reports_trailing_input_at_the_offending_token() {
        let source = "selection filter";
        let err = parse_condition(source).expect_err("two expressions with no operator");

        let ConditionError::UnexpectedToken { span, .. } = err else {
            panic!("expected an unexpected token error, got {err:?}");
        };
        assert_eq!(span.slice(source), Some("filter"));
    }

    #[test]
    fn rejects_an_empty_condition() {
        assert_eq!(parse_condition("").unwrap_err(), ConditionError::Empty);
        assert_eq!(parse_condition("   ").unwrap_err(), ConditionError::Empty);
    }

    #[test]
    fn spans_locate_each_identifier_in_the_source() {
        let source = "selection and not filter";
        let condition = parse_condition(source).expect("parse");

        for (name, span) in condition.named_identifiers() {
            assert_eq!(
                span.slice(source),
                Some(name),
                "span must cover its own identifier"
            );
        }
    }

    #[test]
    fn deeply_nested_groups_do_not_overflow_the_stack() {
        let depth = 500;
        let source = format!("{}a{}", "(".repeat(depth), ")".repeat(depth));
        let condition = parse_condition(&source).expect("parse");
        assert_eq!(names(&condition), ["a"]);
    }
}
