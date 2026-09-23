//! The reference evaluator: one rule against one event, as plainly as
//! possible.
//!
//! This is the definition of what a resolved rule means. It is written for
//! obvious correctness and nothing else: no index, no shared work between
//! rules, no cleverness. The fast engine is correct exactly when it agrees with
//! this on every rule and every event, which is the M1 exit criterion in
//! `docs/roadmap.md`.
//!
//! # Value semantics
//!
//! A predicate pools the values all its paths reach. Then:
//!
//! - **String tests** read strings, and numbers as their decimal text, so
//!   `EventID|startswith: 46` works whether the event stores `4688` or
//!   `"4688"`. Booleans and nulls never match a string test.
//! - **Number tests** read numbers, and strings that parse as numbers.
//! - **Absence is not a match**, so `not selection` holds for an event that
//!   lacks the field: a filter on a field the event does not have filters
//!   nothing out.

use std::net::IpAddr;

use goliath_rule::{
    ClassValue, Comparison, Expr, FieldPath, Network, Number, Predicate, ResolvedRule, StringTest,
    Test, fold,
};
use goliath_sigma::RegexFlags;
use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::error::CompileError;

/// Upper bound on the compiled size of one regular expression, in bytes.
///
/// The `regex` crate runs in time linear in the input whatever the pattern,
/// so a rule cannot make matching slow; this bounds the memory a pattern can
/// make compilation take instead.
///
/// Classes such as `\w` are Unicode aware, which makes them large: `SigmaHQ`'s
/// `-k\s\w{1,64}` compiles to more than a megabyte. Ten megabytes, the `regex`
/// crate's own default, loads every rule in the repository.
///
/// Unicode classes are also a deliberate difference from PCRE, where `\w`,
/// `\d`, and `\s` are ASCII only. Positive classes match more here, so a
/// value spelled with non-ASCII letters or digits cannot slip past a rule by
/// that alone; negated classes such as `\W` match correspondingly less.
const REGEX_SIZE_LIMIT: usize = 10 << 20;

/// A resolved rule prepared for reference evaluation.
///
/// Preparation compiles regular expressions, so that a pattern the engine
/// cannot run is refused when the rule loads rather than when an event
/// arrives.
#[derive(Debug, Clone)]
pub struct ReferenceRule {
    rule: ResolvedRule,
    condition: Node,
}

/// [`Expr`] with regular expressions compiled.
#[derive(Debug, Clone)]
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Field(Vec<FieldPath>, Check),
    Keyword(StringTest),
}

/// [`Test`] with regular expressions compiled.
#[derive(Debug, Clone)]
enum Check {
    Plain(Test),
    Regex(Regex),
}

impl ReferenceRule {
    /// Prepares a resolved rule.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] if a regular expression does not compile,
    /// for instance because it uses a lookaround or a backreference, which
    /// the `regex` crate refuses in order to guarantee linear time.
    pub fn new(rule: ResolvedRule) -> Result<Self, CompileError> {
        let condition = compile(&rule.condition)?;
        Ok(Self { rule, condition })
    }

    /// Returns the rule this was prepared from.
    pub fn rule(&self) -> &ResolvedRule {
        &self.rule
    }

    /// Reports whether `event` matches the rule.
    ///
    /// The rule's class condition is checked first; an event of another class
    /// never matches, whatever the detection says.
    pub fn matches(&self, event: &Value) -> bool {
        self.rule
            .class
            .iter()
            .all(|(path, expected)| has_class_value(event, path, expected))
            && evaluate(&self.condition, event)
    }
}

fn compile(expr: &Expr) -> Result<Node, CompileError> {
    let all = |operands: &[Expr]| operands.iter().map(compile).collect::<Result<_, _>>();
    Ok(match expr {
        Expr::And(operands) => Node::And(all(operands)?),
        Expr::Or(operands) => Node::Or(all(operands)?),
        Expr::Not(operand) => Node::Not(Box::new(compile(operand)?)),
        Expr::Keyword(test) => Node::Keyword(test.clone()),
        Expr::Field(Predicate { paths, test }) => {
            let check = match test {
                Test::Regex { pattern, flags } => Check::Regex(regex(pattern, *flags)?),
                other => Check::Plain(other.clone()),
            };
            Node::Field(paths.clone(), check)
        }
    })
}

fn regex(pattern: &str, flags: RegexFlags) -> Result<Regex, CompileError> {
    RegexBuilder::new(pattern)
        .case_insensitive(flags.case_insensitive)
        .multi_line(flags.multiline)
        .dot_matches_new_line(flags.dot_all)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|source| CompileError::Regex {
            pattern: pattern.to_owned(),
            reason: source.to_string(),
        })
}

fn has_class_value(event: &Value, path: &FieldPath, expected: &ClassValue) -> bool {
    path.lookup(event).into_iter().any(|value| match expected {
        ClassValue::Integer(expected) => value.as_i64() == Some(*expected),
        ClassValue::String(expected) => value.as_str() == Some(expected.as_str()),
    })
}

fn evaluate(node: &Node, event: &Value) -> bool {
    match node {
        Node::And(operands) => operands.iter().all(|operand| evaluate(operand, event)),
        Node::Or(operands) => operands.iter().any(|operand| evaluate(operand, event)),
        Node::Not(operand) => !evaluate(operand, event),
        Node::Keyword(test) => any_string(event, &mut |text| string_matches(test, text)),
        Node::Field(paths, check) => {
            let values = pool(event, paths);
            match check {
                Check::Regex(regex) => values
                    .iter()
                    .filter_map(|value| text(value))
                    .any(|text| regex.is_match(&text)),
                Check::Plain(test) => test_values(test, &values, event),
            }
        }
    }
}

/// Every non-null value any of `paths` reaches.
fn pool<'a>(event: &'a Value, paths: &[FieldPath]) -> Vec<&'a Value> {
    paths
        .iter()
        .flat_map(|path| path.lookup(event))
        .filter(|value| !value.is_null())
        .collect()
}

fn test_values(test: &Test, values: &[&Value], event: &Value) -> bool {
    match test {
        Test::String(test) => values
            .iter()
            .filter_map(|value| text(value))
            .any(|text| string_matches(test, &text)),
        Test::Cidr(network) => values
            .iter()
            .filter_map(|value| value.as_str())
            .filter_map(|text| text.trim().parse::<IpAddr>().ok())
            .any(|address| Network::contains(network, address)),
        Test::Exists(expected) => values.is_empty() != *expected,
        Test::Null => values.is_empty(),
        Test::Equals(expected) => values.iter().any(|value| {
            number(value)
                .is_some_and(|actual| compare(actual, *expected) == Some(std::cmp::Ordering::Equal))
        }),
        Test::Boolean(expected) => values.iter().any(|value| match value {
            Value::Bool(actual) => actual == expected,
            Value::String(written) => {
                written.eq_ignore_ascii_case(if *expected { "true" } else { "false" })
            }
            _ => false,
        }),
        Test::Compare { op, value: bound } => values.iter().any(|value| {
            number(value)
                .and_then(|actual| compare(actual, *bound))
                .is_some_and(|ordering| match op {
                    Comparison::Less => ordering.is_lt(),
                    Comparison::LessOrEqual => ordering.is_le(),
                    Comparison::Greater => ordering.is_gt(),
                    Comparison::GreaterOrEqual => ordering.is_ge(),
                })
        }),
        Test::FieldRef { paths, cased } => {
            let others = pool(event, paths);
            values
                .iter()
                .any(|value| others.iter().any(|other| same_value(value, other, *cased)))
        }
        // Compiled into `Check::Regex`; never reaches here.
        Test::Regex { .. } => false,
    }
}

fn string_matches(test: &StringTest, candidate: &str) -> bool {
    if test.cased {
        test.pattern.matches(candidate)
    } else {
        test.pattern.matches(&fold(candidate))
    }
}

/// A value as text: strings as they are, numbers in decimal.
fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// A value as a number: numbers as they are, strings that parse as numbers.
fn number(value: &Value) -> Option<Number> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .map(Number::Integer)
            .or_else(|| number.as_f64().map(Number::Float)),
        Value::String(text) => {
            let text = text.trim();
            text.parse::<i64>()
                .map(Number::Integer)
                .ok()
                .or_else(|| text.parse::<f64>().ok().map(Number::Float))
        }
        _ => None,
    }
}

/// Compares two numbers exactly when both are integers.
#[allow(clippy::cast_precision_loss)] // Only reached when one side is a float already.
fn compare(left: Number, right: Number) -> Option<std::cmp::Ordering> {
    match (left, right) {
        (Number::Integer(left), Number::Integer(right)) => Some(left.cmp(&right)),
        (Number::Integer(left), Number::Float(right)) => (left as f64).partial_cmp(&right),
        (Number::Float(left), Number::Integer(right)) => left.partial_cmp(&(right as f64)),
        (Number::Float(left), Number::Float(right)) => left.partial_cmp(&right),
    }
}

fn same_value(left: &Value, right: &Value, cased: bool) -> bool {
    match (text(left), text(right)) {
        (Some(left), Some(right)) if cased => left == right,
        (Some(left), Some(right)) => fold(&left) == fold(&right),
        _ => left == right,
    }
}

/// Calls `visit` on every string anywhere in `value` until it returns true.
fn any_string(value: &Value, visit: &mut impl FnMut(&str) -> bool) -> bool {
    match value {
        Value::String(text) => visit(text),
        Value::Array(items) => items.iter().any(|item| any_string(item, visit)),
        Value::Object(map) => map.values().any(|item| any_string(item, visit)),
        _ => false,
    }
}
