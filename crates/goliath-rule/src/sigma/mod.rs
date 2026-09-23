//! Resolving Sigma rules into the resolved form.
//!
//! Resolution is where every Sigma-specific meaning is decided, once:
//!
//! - field names become OCSF paths through a [`MappingSet`];
//! - `contains`, `startswith`, and `endswith` become wildcard patterns;
//! - transformations such as `base64offset` and `windash` become the variants
//!   they produce;
//! - unless the rule says `cased`, literals are folded, so an execution path
//!   only has to fold the event value;
//! - quantifiers such as `1 of selection_*` become plain disjunctions over the
//!   searches they cover.
//!
//! Anything that cannot be resolved exactly is an error. A rule that loads
//! with a guessed meaning is worse than a rule that refuses to load.

mod transform;

use std::collections::BTreeMap;

use goliath_sigma::{
    Condition, FieldKey, FieldPredicate, Modifier, Pattern, PatternPart, Quantifier, Rule, Search,
    Value,
};

use crate::error::ResolveError;
use crate::fold::fold;
use crate::mapping::{LogSourceSelector, MappingSet, SourceMapping};
use crate::path::FieldPath;
use crate::resolved::{
    Comparison, Expr, MappingVersion, Network, Number, Predicate, ResolvedRule, StringTest, Test,
};
use transform::TransformError;

/// Resolves a parsed Sigma rule through a mapping set.
///
/// # Errors
///
/// Returns [`ResolveError`] if no mapping applies to the rule's log source, a
/// field has no mapping, or a modifier cannot be resolved exactly.
///
/// # Examples
///
/// ```
/// use goliath_rule::{MappingSet, sigma};
///
/// let mappings = MappingSet::from_yaml(r"
/// name: example
/// version: 1
/// mappings:
///   - logsource: { category: process_creation, product: windows }
///     class: { class_uid: 1007 }
///     fields: { CommandLine: process.cmd_line }
/// ")?;
///
/// let rule = goliath_sigma::parse_rule(r"
/// title: Encoded PowerShell
/// logsource: { category: process_creation, product: windows }
/// detection:
///   selection:
///     CommandLine|contains: ' -EncodedCommand '
///   condition: selection
/// ")?;
///
/// let resolved = sigma::resolve(&rule, &mappings)?;
/// assert_eq!(resolved.mapping.name, "example");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn resolve(rule: &Rule, mappings: &MappingSet) -> Result<ResolvedRule, ResolveError> {
    let logsource = LogSourceSelector::from(&rule.logsource);
    let mapping = mappings.select(&logsource)?;
    let resolver = Resolver {
        mapping,
        logsource: &logsource,
    };

    let searches = rule
        .detection
        .searches
        .iter()
        .map(|(name, search)| Ok((name.as_str(), resolver.search(search)?)))
        .collect::<Result<BTreeMap<_, _>, ResolveError>>()?;

    let conditions = rule
        .detection
        .conditions
        .iter()
        .map(|condition| resolve_condition(&condition.parsed, &searches))
        .collect();

    Ok(ResolvedRule {
        title: rule.title.clone(),
        id: rule.id.clone(),
        mapping: MappingVersion {
            name: mappings.name.clone(),
            version: mappings.version,
        },
        class: mapping.class.clone(),
        condition: Expr::any(conditions),
    })
}

/// Replaces search identifiers with the searches they name.
///
/// `parse_rule` has already refused identifiers and patterns that name no
/// search, so every reference here resolves.
fn resolve_condition(condition: &Condition, searches: &BTreeMap<&str, Expr>) -> Expr {
    match condition {
        Condition::Identifier { name, .. } => searches
            .get(name.as_str())
            .cloned()
            .unwrap_or(Expr::Or(Vec::new())),
        Condition::Quantified {
            quantifier, target, ..
        } => {
            let covered = searches
                .iter()
                .filter(|(name, _)| target.matches(name))
                .map(|(_, search)| search.clone())
                .collect();
            match quantifier {
                Quantifier::Any => Expr::any(covered),
                Quantifier::All => Expr::all(covered),
            }
        }
        Condition::Not { operand, .. } => Expr::Not(Box::new(resolve_condition(operand, searches))),
        Condition::And { operands, .. } => Expr::all(
            operands
                .iter()
                .map(|operand| resolve_condition(operand, searches))
                .collect(),
        ),
        Condition::Or { operands, .. } => Expr::any(
            operands
                .iter()
                .map(|operand| resolve_condition(operand, searches))
                .collect(),
        ),
    }
}

struct Resolver<'a> {
    mapping: &'a SourceMapping,
    logsource: &'a LogSourceSelector,
}

impl Resolver<'_> {
    fn search(&self, search: &Search) -> Result<Expr, ResolveError> {
        match search {
            Search::AllOf(predicates) => self.predicates(predicates),
            Search::AnyOf(alternatives) => Ok(Expr::any(
                alternatives
                    .iter()
                    .map(|predicates| self.predicates(predicates))
                    .collect::<Result<_, _>>()?,
            )),
            Search::Keywords(values) => Ok(Expr::any(
                values.iter().map(keyword).collect::<Result<_, _>>()?,
            )),
        }
    }

    fn predicates(&self, predicates: &[FieldPredicate]) -> Result<Expr, ResolveError> {
        Ok(Expr::all(
            predicates
                .iter()
                .map(|predicate| self.predicate(predicate))
                .collect::<Result<_, _>>()?,
        ))
    }

    fn paths(&self, field: &str) -> Result<Vec<FieldPath>, ResolveError> {
        self.mapping
            .fields
            .get(field)
            .cloned()
            .ok_or_else(|| ResolveError::UnmappedField {
                field: field.to_owned(),
                logsource: self.logsource.clone(),
            })
    }

    fn predicate(&self, predicate: &FieldPredicate) -> Result<Expr, ResolveError> {
        let key = &predicate.key;
        let paths = self.paths(&key.field)?;

        let values = predicate
            .values
            .iter()
            .map(|value| {
                let tests = self.tests(key, value)?;
                Ok(Expr::any(
                    tests
                        .into_iter()
                        .map(|test| {
                            Expr::Field(Predicate {
                                paths: paths.clone(),
                                test,
                            })
                        })
                        .collect(),
                ))
            })
            .collect::<Result<Vec<_>, ResolveError>>()?;

        Ok(if key.requires_all() {
            Expr::all(values)
        } else {
            Expr::any(values)
        })
    }

    /// The tests one value stands for; the value matches if any holds.
    fn tests(&self, key: &FieldKey, value: &Value) -> Result<Vec<Test>, ResolveError> {
        let field = || key.field.clone();

        if key.modifiers.contains(&Modifier::Expand) {
            return Err(ResolveError::UnsupportedModifier {
                field: field(),
                modifier: Modifier::Expand.name(),
            });
        }
        let cased = key.modifiers.contains(&Modifier::Cased);

        if key.modifiers.contains(&Modifier::FieldRef) {
            let other = value.as_pattern().map(Pattern::source).unwrap_or_default();
            return Ok(vec![Test::FieldRef {
                paths: self.paths(other)?,
                cased,
            }]);
        }

        let single = |test: Test| Ok(vec![test]);
        match (key.match_modifier(), value) {
            (Some(Modifier::Exists), Value::Boolean(present)) => single(Test::Exists(*present)),
            (
                Some(comparison @ (Modifier::Lt | Modifier::Lte | Modifier::Gt | Modifier::Gte)),
                _,
            ) => {
                let op = match comparison {
                    Modifier::Lt => Comparison::Less,
                    Modifier::Lte => Comparison::LessOrEqual,
                    Modifier::Gt => Comparison::Greater,
                    _ => Comparison::GreaterOrEqual,
                };
                single(Test::Compare {
                    op,
                    value: number(value)
                        .ok_or_else(|| invalid(field(), "a comparison needs a number"))?,
                })
            }
            (Some(Modifier::Re(flags)), Value::String(pattern)) => single(Test::Regex {
                pattern: pattern.source().to_owned(),
                flags: *flags,
            }),
            (Some(Modifier::Cidr), Value::String(pattern)) => {
                let network = pattern
                    .as_literal()
                    .and_then(Network::parse)
                    .ok_or_else(|| invalid(field(), "cidr needs an address or network"))?;
                single(Test::Cidr(network))
            }
            (None, Value::Null) => single(Test::Null),
            (None, Value::Boolean(expected)) => single(Test::Boolean(*expected)),
            (None, Value::Integer(_) | Value::Float(_)) if key.transforms().next().is_none() => {
                single(Test::Equals(
                    number(value).ok_or_else(|| invalid(field(), "not a number"))?,
                ))
            }
            (None | Some(Modifier::Contains | Modifier::StartsWith | Modifier::EndsWith), _) => {
                string_tests(key, value, cased)
            }
            _ => Err(invalid(
                field(),
                "this value cannot be used with this modifier",
            )),
        }
    }
}

/// The string tests one value stands for, after transformations.
fn string_tests(key: &FieldKey, value: &Value, cased: bool) -> Result<Vec<Test>, ResolveError> {
    let field = || key.field.clone();
    let parts = match value {
        Value::String(pattern) => pattern.parts().to_vec(),
        // A number compared as text, as in `EventID|startswith: 46`.
        Value::Integer(integer) => vec![PatternPart::Literal(integer.to_string())],
        Value::Float(float) => vec![PatternPart::Literal(float.to_string())],
        Value::Boolean(_) | Value::Null => {
            return Err(invalid(field(), "a string match needs a string"));
        }
    };

    let transforms: Vec<&Modifier> = key.transforms().collect();
    let transformed = transform::apply(&parts, &transforms).map_err(|error| match error {
        TransformError::Invalid(reason) => invalid(field(), reason),
        TransformError::TooManyVariants(count) => ResolveError::TooManyVariants {
            field: field(),
            count,
        },
    })?;
    // Case carries information in encoded text.
    let cased = cased || transformed.encoded;

    Ok(transformed
        .variants
        .into_iter()
        .map(|variant| Test::String(string_test(variant, key.match_modifier(), cased)))
        .collect())
}

/// Builds the pattern for a match modifier, folding literals unless cased.
fn string_test(parts: Vec<PatternPart>, modifier: Option<&Modifier>, cased: bool) -> StringTest {
    let (leading, trailing) = match modifier {
        Some(Modifier::Contains) => (true, true),
        Some(Modifier::StartsWith) => (false, true),
        Some(Modifier::EndsWith) => (true, false),
        _ => (false, false),
    };

    let parts = parts.into_iter().map(|part| match part {
        PatternPart::Literal(text) if !cased => PatternPart::Literal(fold(&text).into_owned()),
        other => other,
    });
    let pattern = Pattern::from_parts(
        leading
            .then_some(PatternPart::AnySequence)
            .into_iter()
            .chain(parts)
            .chain(trailing.then_some(PatternPart::AnySequence)),
    );

    StringTest { pattern, cased }
}

/// A keyword searches every string in the event for its text.
fn keyword(value: &Value) -> Result<Expr, ResolveError> {
    let parts = match value {
        Value::String(pattern) => pattern.parts().to_vec(),
        Value::Integer(integer) => vec![PatternPart::Literal(integer.to_string())],
        other => {
            return Err(ResolveError::UnsupportedKeyword {
                found: match other {
                    Value::Null => "null",
                    Value::Boolean(_) => "a boolean",
                    _ => "a number",
                },
            });
        }
    };
    Ok(Expr::Keyword(string_test(
        parts,
        Some(&Modifier::Contains),
        false,
    )))
}

fn number(value: &Value) -> Option<Number> {
    match value {
        Value::Integer(integer) => Some(Number::Integer(*integer)),
        Value::Float(float) => Some(Number::Float(*float)),
        _ => None,
    }
}

fn invalid(field: String, reason: &'static str) -> ResolveError {
    ResolveError::InvalidValue { field, reason }
}
