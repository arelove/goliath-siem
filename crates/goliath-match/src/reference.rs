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

use goliath_rule::{Expr, FieldPath, Predicate, ResolvedRule, StringTest, Test};
use regex::Regex;
use serde_json::Value;

use crate::error::CompileError;
use crate::semantics::{
    any_string, has_class_value, pool, regex, string_matches, test_values, text,
};

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
