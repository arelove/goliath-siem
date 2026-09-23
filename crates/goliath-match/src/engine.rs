//! The engine: many rules against one event, sharing the work between them.
//!
//! The reference evaluator asks every rule about every event independently.
//! With thousands of rules that repeats the same work thousands of times: a
//! command line is scanned once per `contains` that mentions it. The engine
//! does each piece of work once per event:
//!
//! 1. **Rules are grouped by class condition.** An event is checked against a
//!    group's class once, and a group whose class does not match is skipped
//!    whole: a registry event never reaches a process creation rule.
//! 2. **Identical tests are evaluated once.** Within a group, a test that
//!    several rules share is one predicate, computed at most once per event.
//! 3. **Literals are found in one pass.** Every string test whose pattern is a
//!    literal, a prefix, a suffix, or a substring becomes a key in one
//!    Aho-Corasick automaton per field, so one scan of a field answers all of
//!    them together.
//! 4. **Rules wait for a trigger.** For each rule the engine derives a set of
//!    literals at least one of which must occur for the rule to hold. A rule
//!    is not evaluated at all until one of them is found.
//!
//! Everything else, from regular expressions to number comparisons, is asked
//! through the same functions the reference evaluator uses. The engine is
//! correct exactly when it returns what the reference evaluator returns for
//! every rule and every event; the tests check that on random rules and events.

use std::collections::{BTreeMap, HashMap};

use aho_corasick::{AhoCorasick, MatchKind};
use goliath_rule::{ClassValue, Expr, FieldPath, Predicate, ResolvedRule, Test, fold};
use goliath_sigma::{Pattern, PatternPart};
use regex::Regex;
use serde_json::Value;

use crate::error::CompileError;
use crate::semantics::{has_class_value, pool, regex, test_values, text};

/// A class condition: attribute values an event must have.
type Class = Vec<(FieldPath, ClassValue)>;

/// Rules compiled to be evaluated together.
#[derive(Debug, Clone)]
pub struct Engine {
    rules: Vec<ResolvedRule>,
    groups: Vec<Group>,
}

/// The rules sharing one class condition.
#[derive(Debug, Clone)]
struct Group {
    class: Class,
    sources: Vec<Source>,
    predicates: Vec<Pred>,
    /// Global rule index and compiled condition.
    rules: Vec<(usize, Node)>,
    /// For each literal, the rules it triggers, as positions in `rules`.
    triggers: Vec<Vec<usize>>,
    /// Rules without a trigger, evaluated for every event of the class.
    untriggered: Vec<usize>,
    /// Number of literals across all sources.
    literals: usize,
}

/// Where the texts a string test reads come from, and whether they are
/// folded.
#[derive(Debug, Clone)]
struct Source {
    origin: Origin,
    cased: bool,
    /// Finds every literal of this source; `None` when it has none.
    automaton: Option<AhoCorasick>,
    /// The index of this source's first literal in the group's literal space.
    first_literal: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Origin {
    Paths(Vec<FieldPath>),
    /// Every string anywhere in the event, as keywords search.
    AnyString,
}

#[derive(Debug, Clone)]
enum Pred {
    /// A pattern decided by where a literal occurs.
    Literal {
        source: usize,
        literal: usize,
        shape: Shape,
    },
    /// Any other pattern, evaluated directly, but only once the literal it
    /// cannot match without has been found.
    General {
        source: usize,
        required: Option<usize>,
        pattern: Pattern,
    },
    /// A non-string test, asked through the shared semantics.
    Other { paths: Vec<FieldPath>, check: Check },
}

#[derive(Debug, Clone, Copy)]
enum Shape {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone)]
enum Check {
    Plain(Test),
    Regex(Regex),
}

#[derive(Debug, Clone)]
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Pred(usize),
}

/// Where a literal was found among a source's texts.
mod hit {
    pub(super) const ANY: u8 = 1;
    pub(super) const START: u8 = 2;
    pub(super) const END: u8 = 4;
    pub(super) const WHOLE: u8 = 8;
}

impl Engine {
    /// Compiles rules for evaluation together.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] if a regular expression does not compile, as
    /// [`ReferenceRule::new`](crate::ReferenceRule::new) would.
    pub fn new(rules: Vec<ResolvedRule>) -> Result<Self, CompileError> {
        // Keyed by the class condition's serialized form: equal conditions
        // serialize equally, since the condition is an ordered map.
        let mut by_class: BTreeMap<String, (Class, Vec<usize>)> = BTreeMap::new();
        for (index, rule) in rules.iter().enumerate() {
            let key = serde_json::to_string(&rule.class).unwrap_or_default();
            by_class
                .entry(key)
                .or_insert_with(|| {
                    let class = rule
                        .class
                        .iter()
                        .map(|(path, value)| (path.clone(), value.clone()))
                        .collect();
                    (class, Vec::new())
                })
                .1
                .push(index);
        }

        let groups = by_class
            .into_values()
            .map(|(class, members)| GroupBuilder::default().build(class, &members, &rules))
            .collect::<Result<_, _>>()?;

        Ok(Self { rules, groups })
    }

    /// Returns the rules, in the order given to [`Engine::new`].
    pub fn rules(&self) -> &[ResolvedRule] {
        &self.rules
    }

    /// Returns the indices of every rule `event` matches, in ascending order.
    pub fn matches(&self, event: &Value) -> Vec<usize> {
        let mut matched = Vec::new();
        for group in &self.groups {
            if group
                .class
                .iter()
                .all(|(path, expected)| has_class_value(event, path, expected))
            {
                group.evaluate(event, &mut matched);
            }
        }
        matched.sort_unstable();
        matched
    }
}

impl Group {
    fn evaluate(&self, event: &Value, matched: &mut Vec<usize>) {
        // Gather each source's texts and find every literal in one pass each.
        let mut hits = vec![0_u8; self.literals];
        let texts: Vec<Vec<String>> = self
            .sources
            .iter()
            .map(|source| {
                let texts = source.texts(event);
                if let Some(automaton) = &source.automaton {
                    for candidate in &texts {
                        for found in automaton.find_overlapping_iter(candidate.as_str()) {
                            let mut flags = hit::ANY;
                            if found.start() == 0 {
                                flags |= hit::START;
                            }
                            if found.end() == candidate.len() {
                                flags |= hit::END;
                            }
                            if found.start() == 0 && found.end() == candidate.len() {
                                flags |= hit::WHOLE;
                            }
                            hits[source.first_literal + found.pattern().as_usize()] |= flags;
                        }
                    }
                }
                texts
            })
            .collect();

        // Only rules triggered by a literal found, and those without a
        // trigger, can hold.
        let mut candidate = vec![false; self.rules.len()];
        for &position in &self.untriggered {
            candidate[position] = true;
        }
        for (literal, flags) in hits.iter().enumerate() {
            if flags & hit::ANY != 0 {
                for &position in &self.triggers[literal] {
                    candidate[position] = true;
                }
            }
        }

        let mut memo = vec![None; self.predicates.len()];
        let context = Context {
            group: self,
            event,
            hits: &hits,
            texts: &texts,
        };
        for (position, (index, node)) in self.rules.iter().enumerate() {
            if candidate[position] && context.node(node, &mut memo) {
                matched.push(*index);
            }
        }
    }
}

impl Source {
    fn texts(&self, event: &Value) -> Vec<String> {
        let mut texts = Vec::new();
        match &self.origin {
            Origin::Paths(paths) => {
                texts.extend(pool(event, paths).into_iter().filter_map(text));
            }
            Origin::AnyString => strings(event, &mut texts),
        }
        if !self.cased {
            for candidate in &mut texts {
                if let std::borrow::Cow::Owned(folded) = fold(candidate) {
                    *candidate = folded;
                }
            }
        }
        texts
    }
}

/// Every string anywhere in `value`, as keywords search them.
fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| strings(item, out)),
        Value::Object(map) => map.values().for_each(|item| strings(item, out)),
        _ => {}
    }
}

/// What one event's evaluation of a group can read.
struct Context<'a> {
    group: &'a Group,
    event: &'a Value,
    hits: &'a [u8],
    texts: &'a [Vec<String>],
}

impl Context<'_> {
    /// A source's literal index in the group's literal space.
    fn global(&self, source: usize, literal: usize) -> usize {
        self.group.sources[source].first_literal + literal
    }

    fn node(&self, node: &Node, memo: &mut [Option<bool>]) -> bool {
        match node {
            Node::And(operands) => operands.iter().all(|operand| self.node(operand, memo)),
            Node::Or(operands) => operands.iter().any(|operand| self.node(operand, memo)),
            Node::Not(operand) => !self.node(operand, memo),
            Node::Pred(index) => {
                if let Some(known) = memo[*index] {
                    return known;
                }
                let value = self.predicate(&self.group.predicates[*index]);
                memo[*index] = Some(value);
                value
            }
        }
    }

    fn predicate(&self, predicate: &Pred) -> bool {
        match predicate {
            Pred::Literal {
                source,
                literal,
                shape,
            } => {
                let wanted = match shape {
                    Shape::Equals => hit::WHOLE,
                    Shape::Contains => hit::ANY,
                    Shape::StartsWith => hit::START,
                    Shape::EndsWith => hit::END,
                };
                self.hits[self.global(*source, *literal)] & wanted != 0
            }
            Pred::General {
                source,
                required,
                pattern,
            } => {
                required
                    .is_none_or(|literal| self.hits[self.global(*source, literal)] & hit::ANY != 0)
                    && self.texts[*source]
                        .iter()
                        .any(|candidate| pattern.matches(candidate))
            }
            Pred::Other { paths, check } => {
                let values = pool(self.event, paths);
                match check {
                    Check::Regex(regex) => values
                        .iter()
                        .filter_map(|value| text(value))
                        .any(|candidate| regex.is_match(&candidate)),
                    Check::Plain(test) => test_values(test, &values, self.event),
                }
            }
        }
    }
}

/// Collects one group's sources, literals, and predicates while compiling
/// its rules.
#[derive(Default)]
struct GroupBuilder {
    sources: Vec<(Origin, bool)>,
    /// Literals per source, in automaton order.
    literals: Vec<Vec<String>>,
    literal_ids: HashMap<(usize, String), usize>,
    predicates: Vec<Pred>,
    /// Predicate by the serialized form of the expression it came from.
    predicate_ids: HashMap<String, usize>,
    /// The literal each predicate cannot hold without, as `(source, index)`.
    atoms: Vec<Option<(usize, usize)>>,
}

impl GroupBuilder {
    fn build(
        mut self,
        class: Class,
        members: &[usize],
        rules: &[ResolvedRule],
    ) -> Result<Group, CompileError> {
        let mut compiled = Vec::with_capacity(members.len());
        for &index in members {
            let node = self.node(&rules[index].condition)?;
            compiled.push((index, node));
        }

        // Literal ids become global within the group once every source's
        // literals are known.
        let mut first_literal = Vec::with_capacity(self.literals.len());
        let mut total = 0;
        for literals in &self.literals {
            first_literal.push(total);
            total += literals.len();
        }
        let global = |(source, index): (usize, usize)| first_literal[source] + index;

        let mut triggers = vec![Vec::new(); total];
        let mut untriggered = Vec::new();
        for (position, (_, node)) in compiled.iter().enumerate() {
            match self.trigger(node) {
                Some(literals) => {
                    for literal in literals {
                        triggers[global(literal)].push(position);
                    }
                }
                None => untriggered.push(position),
            }
        }

        let sources = self
            .sources
            .iter()
            .zip(&self.literals)
            .zip(&first_literal)
            .map(|(((origin, cased), literals), &first)| {
                let automaton = if literals.is_empty() {
                    None
                } else {
                    Some(
                        AhoCorasick::builder()
                            .match_kind(MatchKind::Standard)
                            .build(literals)
                            .map_err(|source| CompileError::Automaton {
                                reason: source.to_string(),
                            })?,
                    )
                };
                Ok(Source {
                    origin: origin.clone(),
                    cased: *cased,
                    automaton,
                    first_literal: first,
                })
            })
            .collect::<Result<_, CompileError>>()?;

        Ok(Group {
            class,
            sources,
            predicates: self.predicates,
            rules: compiled,
            triggers,
            untriggered,
            literals: total,
        })
    }

    fn node(&mut self, expr: &Expr) -> Result<Node, CompileError> {
        Ok(match expr {
            Expr::And(operands) => Node::And(
                operands
                    .iter()
                    .map(|operand| self.node(operand))
                    .collect::<Result<_, _>>()?,
            ),
            Expr::Or(operands) => Node::Or(
                operands
                    .iter()
                    .map(|operand| self.node(operand))
                    .collect::<Result<_, _>>()?,
            ),
            Expr::Not(operand) => Node::Not(Box::new(self.node(operand)?)),
            leaf => Node::Pred(self.predicate(leaf)?),
        })
    }

    /// Returns the predicate for a leaf, creating it on first sight.
    fn predicate(&mut self, leaf: &Expr) -> Result<usize, CompileError> {
        let key = serde_json::to_string(leaf).unwrap_or_default();
        if let Some(&id) = self.predicate_ids.get(&key) {
            return Ok(id);
        }

        let (predicate, atom) = match leaf {
            Expr::Keyword(test) => {
                let source = self.source(Origin::AnyString, test.cased);
                self.string(source, &test.pattern)
            }
            Expr::Field(Predicate {
                paths,
                test: Test::String(test),
            }) => {
                let source = self.source(Origin::Paths(paths.clone()), test.cased);
                self.string(source, &test.pattern)
            }
            Expr::Field(Predicate { paths, test }) => {
                let check = match test {
                    Test::Regex { pattern, flags } => Check::Regex(regex(pattern, *flags)?),
                    other => Check::Plain(other.clone()),
                };
                (
                    Pred::Other {
                        paths: paths.clone(),
                        check,
                    },
                    None,
                )
            }
            // Operators never reach here; `node` handles them.
            Expr::And(_) | Expr::Or(_) | Expr::Not(_) => (
                Pred::Other {
                    paths: Vec::new(),
                    check: Check::Plain(Test::Exists(false)),
                },
                None,
            ),
        };

        let id = self.predicates.len();
        self.predicates.push(predicate);
        self.atoms.push(atom);
        self.predicate_ids.insert(key, id);
        Ok(id)
    }

    fn source(&mut self, origin: Origin, cased: bool) -> usize {
        if let Some(index) = self
            .sources
            .iter()
            .position(|(known, known_cased)| *known == origin && *known_cased == cased)
        {
            return index;
        }
        self.sources.push((origin, cased));
        self.literals.push(Vec::new());
        self.sources.len() - 1
    }

    fn literal(&mut self, source: usize, text: &str) -> usize {
        let key = (source, text.to_owned());
        if let Some(&index) = self.literal_ids.get(&key) {
            return index;
        }
        let index = self.literals[source].len();
        self.literals[source].push(text.to_owned());
        self.literal_ids.insert(key, index);
        index
    }

    /// A string predicate, classified by the shape of its pattern.
    fn string(&mut self, source: usize, pattern: &Pattern) -> (Pred, Option<(usize, usize)>) {
        use PatternPart::{AnySequence as Any, Literal};

        let shaped = match pattern.parts() {
            [Literal(text)] => Some((text, Shape::Equals)),
            [Any, Literal(text), Any] => Some((text, Shape::Contains)),
            [Literal(text), Any] => Some((text, Shape::StartsWith)),
            [Any, Literal(text)] => Some((text, Shape::EndsWith)),
            _ => None,
        };

        if let Some((text, shape)) = shaped.filter(|(text, _)| !text.is_empty()) {
            let literal = self.literal(source, text);
            return (
                Pred::Literal {
                    source,
                    literal,
                    shape,
                },
                Some((source, literal)),
            );
        }

        // The longest literal is the most selective one to wait for.
        let required = pattern
            .parts()
            .iter()
            .filter_map(|part| match part {
                Literal(text) if !text.is_empty() => Some(text),
                _ => None,
            })
            .max_by_key(|text| text.len())
            .map(|text| (source, self.literal(source, text)));

        (
            Pred::General {
                source,
                required: required.map(|(_, literal)| literal),
                pattern: pattern.clone(),
            },
            required,
        )
    }

    /// Literals at least one of which must be found for `node` to hold, or
    /// `None` if no such set is known.
    fn trigger(&self, node: &Node) -> Option<Vec<(usize, usize)>> {
        match node {
            Node::Pred(index) => self.atoms[*index].map(|atom| vec![atom]),
            // Any one operand's trigger will do; the smallest wakes the rule
            // least often.
            Node::And(operands) => operands
                .iter()
                .filter_map(|operand| self.trigger(operand))
                .min_by_key(Vec::len),
            // Every operand needs a trigger, and any of them may be the one.
            Node::Or(operands) => {
                let mut all = Vec::new();
                for operand in operands {
                    all.extend(self.trigger(operand)?);
                }
                all.sort_unstable();
                all.dedup();
                Some(all)
            }
            Node::Not(_) => None,
        }
    }
}
