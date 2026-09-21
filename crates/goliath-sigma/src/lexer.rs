//! Tokenizer for Sigma condition expressions.

use crate::error::ConditionError;
use crate::span::Span;

/// A token in a Sigma condition expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// What the token is.
    pub kind: TokenKind,
    /// Where it came from in the source condition.
    pub span: Span,
}

/// The kinds of token a Sigma condition can contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    /// A search identifier, or a pattern over identifiers when it contains `*`.
    Identifier(String),
    /// An unsigned integer, as used in the `1 of` quantifier.
    Number(u64),
    /// The `and` operator.
    And,
    /// The `or` operator.
    Or,
    /// The `not` operator.
    Not,
    /// The `of` keyword of a quantifier.
    Of,
    /// The `them` keyword, naming every search identifier in the rule.
    Them,
    /// The `all` quantifier.
    All,
    /// An opening parenthesis.
    LParen,
    /// A closing parenthesis.
    RParen,
    /// The `|` that introduces a legacy aggregation expression.
    Pipe,
}

impl TokenKind {
    /// Returns the name used when reporting this kind in an error message.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Identifier(_) => "an identifier",
            Self::Number(_) => "a number",
            Self::And => "`and`",
            Self::Or => "`or`",
            Self::Not => "`not`",
            Self::Of => "`of`",
            Self::Them => "`them`",
            Self::All => "`all`",
            Self::LParen => "`(`",
            Self::RParen => "`)`",
            Self::Pipe => "`|`",
        }
    }
}

/// Splits a condition expression into tokens.
///
/// Keywords are recognized case-insensitively. The Sigma specification writes
/// them in lower case, but rules in the wild do not always comply, and a
/// capitalized `AND` is never a plausible search identifier.
///
/// # Errors
///
/// Returns [`ConditionError::UnexpectedCharacter`] at the first byte that
/// cannot begin a token.
pub fn tokenize(source: &str) -> Result<Vec<Token>, ConditionError> {
    let mut tokens = Vec::new();
    let mut chars = source.char_indices().peekable();

    while let Some(&(offset, ch)) = chars.peek() {
        match ch {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::LParen,
                    span: Span::new(offset, offset + 1),
                });
            }
            ')' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::RParen,
                    span: Span::new(offset, offset + 1),
                });
            }
            '|' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::Pipe,
                    span: Span::new(offset, offset + 1),
                });
                // Everything after `|` is a legacy aggregation expression, whose
                // grammar is not ours. Lexing it would fail on characters that
                // are valid there, reporting a stray `>` instead of the real
                // problem. Stop here and let the parser refuse the whole tail.
                break;
            }
            c if is_word_char(c) => {
                let mut end = offset;
                while let Some(&(next_offset, next_ch)) = chars.peek() {
                    if is_word_char(next_ch) {
                        end = next_offset + next_ch.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }

                let span = Span::new(offset, end);
                let word = source.get(offset..end).unwrap_or_default();
                tokens.push(Token {
                    kind: classify(word),
                    span,
                });
            }
            _ => {
                return Err(ConditionError::UnexpectedCharacter {
                    character: ch,
                    span: Span::new(offset, offset + ch.len_utf8()),
                });
            }
        }
    }

    Ok(tokens)
}

/// Reports whether a character can appear inside an identifier or number.
///
/// Sigma search identifiers are alphanumeric with underscores; `*` additionally
/// appears in the identifier patterns used by quantifiers.
fn is_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '*'
}

/// Turns a word into a keyword, a number, or an identifier.
fn classify(word: &str) -> TokenKind {
    match word.to_ascii_lowercase().as_str() {
        "and" => TokenKind::And,
        "or" => TokenKind::Or,
        "not" => TokenKind::Not,
        "of" => TokenKind::Of,
        "them" => TokenKind::Them,
        "all" => TokenKind::All,
        _ => word.parse::<u64>().map_or_else(
            |_| TokenKind::Identifier(word.to_owned()),
            TokenKind::Number,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<TokenKind> {
        tokenize(source)
            .expect("tokenize")
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    #[test]
    fn splits_a_simple_condition() {
        assert_eq!(
            kinds("selection and not filter"),
            [
                TokenKind::Identifier("selection".to_owned()),
                TokenKind::And,
                TokenKind::Not,
                TokenKind::Identifier("filter".to_owned()),
            ]
        );
    }

    #[test]
    fn recognizes_quantifiers() {
        assert_eq!(
            kinds("1 of selection_*"),
            [
                TokenKind::Number(1),
                TokenKind::Of,
                TokenKind::Identifier("selection_*".to_owned()),
            ]
        );

        assert_eq!(
            kinds("all of them"),
            [TokenKind::All, TokenKind::Of, TokenKind::Them]
        );
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert_eq!(
            kinds("A AND B"),
            [
                TokenKind::Identifier("A".to_owned()),
                TokenKind::And,
                TokenKind::Identifier("B".to_owned()),
            ]
        );
    }

    #[test]
    fn a_word_containing_a_keyword_stays_an_identifier() {
        // `android` must not lex as `and` followed by `roid`.
        assert_eq!(
            kinds("android"),
            [TokenKind::Identifier("android".to_owned())]
        );
        assert_eq!(
            kinds("all_events"),
            [TokenKind::Identifier("all_events".to_owned())]
        );
    }

    #[test]
    fn spans_point_at_the_source() {
        let source = "selection and filter";
        let tokens = tokenize(source).expect("tokenize");

        assert_eq!(tokens[0].span.slice(source), Some("selection"));
        assert_eq!(tokens[1].span.slice(source), Some("and"));
        assert_eq!(tokens[2].span.slice(source), Some("filter"));
    }

    #[test]
    fn parentheses_need_no_surrounding_space() {
        assert_eq!(
            kinds("(a or b)"),
            [
                TokenKind::LParen,
                TokenKind::Identifier("a".to_owned()),
                TokenKind::Or,
                TokenKind::Identifier("b".to_owned()),
                TokenKind::RParen,
            ]
        );
    }

    #[test]
    fn rejects_characters_that_cannot_start_a_token() {
        let err = tokenize("selection & filter").expect_err("`&` is not Sigma syntax");

        match err {
            ConditionError::UnexpectedCharacter { character, span } => {
                assert_eq!(character, '&');
                assert_eq!(span, Span::new(10, 11));
            }
            other => panic!("expected an unexpected character error, got {other:?}"),
        }
    }

    #[test]
    fn stops_at_the_aggregation_pipe() {
        // The aggregation tail is refused by the parser, not lexed here: its
        // characters are valid in that grammar but not in ours.
        let kinds = kinds("selection | count() by User > 5");
        assert_eq!(
            kinds,
            [
                TokenKind::Identifier("selection".to_owned()),
                TokenKind::Pipe
            ]
        );
    }

    #[test]
    fn empty_source_yields_no_tokens() {
        assert!(kinds("   ").is_empty());
    }
}
