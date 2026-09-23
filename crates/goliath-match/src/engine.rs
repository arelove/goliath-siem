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

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use aho_corasick::{AhoCorasick, MatchKind};
use goliath_rule::{ClassValue, Expr, FieldPath, Predicate, ResolvedRule, Test, fold_into};
use goliath_sigma::{Pattern, PatternPart};
use regex::Regex;
use serde_json::Value;

use crate::error::CompileError;
use crate::semantics::{
    has_class_value, pool_into, regex, regex_matches_any, test_values, write_number,
};

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
    ///
    /// Allocates working memory for this one call. To evaluate many events,
    /// use [`Engine::matches_into`] with one [`Scratch`] kept across them.
    pub fn matches(&self, event: &Value) -> Vec<usize> {
        let mut scratch = self.scratch();
        let mut matched = Vec::new();
        self.matches_into(event, &mut scratch, &mut matched);
        matched
    }

    /// Creates working memory sized for this engine.
    pub fn scratch(&self) -> Scratch {
        Scratch {
            groups: self
                .groups
                .iter()
                .map(|group| GroupScratch {
                    hits: vec![0; group.literals],
                    found: Vec::new(),
                    texts: (0..group.sources.len()).map(|_| Texts::default()).collect(),
                    candidate: vec![0; group.rules.len()],
                    candidates: Vec::new(),
                    memo: vec![0; group.predicates.len()],
                    memo_value: vec![false; group.predicates.len()],
                    generation: 0,
                    values: Vec::new(),
                    number: String::new(),
                })
                .collect(),
        }
    }

    /// Writes the indices of every rule `event` matches into `matched`, in
    /// ascending order, replacing its contents.
    ///
    /// Once `scratch` has seen a few events it has grown to fit them, and
    /// evaluation stops allocating. A scratch made by another engine is
    /// replaced by one that fits this engine.
    pub fn matches_into(&self, event: &Value, scratch: &mut Scratch, matched: &mut Vec<usize>) {
        if !scratch.fits(self) {
            *scratch = self.scratch();
        }
        matched.clear();
        for (group, work) in self.groups.iter().zip(&mut scratch.groups) {
            if group
                .class
                .iter()
                .all(|(path, expected)| has_class_value(event, path, expected))
            {
                group.evaluate(event, work, matched);
            }
        }
        matched.sort_unstable();
    }
}

/// Working memory for [`Engine::matches_into`], kept across events so that
/// evaluation does not allocate once warmed up.
#[derive(Debug, Default)]
pub struct Scratch {
    groups: Vec<GroupScratch>,
}

impl Scratch {
    /// Reports whether this scratch was sized for `engine`.
    fn fits(&self, engine: &Engine) -> bool {
        self.groups.len() == engine.groups.len()
            && self.groups.iter().zip(&engine.groups).all(|(work, group)| {
                work.hits.len() == group.literals
                    && work.texts.len() == group.sources.len()
                    && work.candidate.len() == group.rules.len()
                    && work.memo.len() == group.predicates.len()
            })
    }
}

#[derive(Debug)]
struct GroupScratch {
    /// Where each literal was found, for this event.
    hits: Vec<u8>,
    /// The literals with any hit, so resetting touches only them.
    found: Vec<usize>,
    /// Each source's texts, for this event.
    texts: Vec<Texts>,
    /// The generation in which each rule last became a candidate.
    candidate: Vec<u32>,
    /// This event's candidate rules, as positions.
    candidates: Vec<usize>,
    /// The generation in which each predicate was last computed, and its
    /// value then.
    memo: Vec<u32>,
    memo_value: Vec<bool>,
    /// Increments per evaluation, so stale marks need no clearing.
    generation: u32,
    /// The buffer for non-string tests' values, kept empty between events.
    values: Vec<&'static Value>,
    /// The buffer a number is written to for a regular expression.
    number: String,
}

impl GroupScratch {
    /// Starts a new evaluation, invalidating every mark from the last one.
    fn next_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            // Wrapped: old marks could now look current, so clear them.
            self.candidate.fill(0);
            self.memo.fill(0);
            self.generation = 1;
        }
    }
}

/// Text buffers reused across events; only the first `len` are current.
#[derive(Debug, Default)]
struct Texts {
    buffers: Vec<String>,
    len: usize,
}

impl Texts {
    fn clear(&mut self) {
        self.len = 0;
    }

    /// An empty buffer for the next text.
    fn next(&mut self) -> &mut String {
        if self.len == self.buffers.len() {
            self.buffers.push(String::new());
        }
        let buffer = &mut self.buffers[self.len];
        buffer.clear();
        self.len += 1;
        buffer
    }

    /// Adds `text`, folded unless `cased`.
    fn push(&mut self, text: &str, cased: bool) {
        let buffer = self.next();
        if cased {
            buffer.push_str(text);
        } else {
            fold_into(text, buffer);
        }
    }

    fn current(&self) -> &[String] {
        &self.buffers[..self.len]
    }
}

impl Group {
    fn evaluate(&self, event: &Value, work: &mut GroupScratch, matched: &mut Vec<usize>) {
        work.next_generation();

        // Gather each source's texts and find every literal in one pass each.
        for (source, texts) in self.sources.iter().zip(&mut work.texts) {
            source.gather(event, texts);
            let Some(automaton) = &source.automaton else {
                continue;
            };
            for candidate in texts.current() {
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
                    let literal = source.first_literal + found.pattern().as_usize();
                    if work.hits[literal] == 0 {
                        work.found.push(literal);
                    }
                    work.hits[literal] |= flags;
                }
            }
        }

        // Only rules triggered by a literal found, and those without a
        // trigger, can hold.
        work.candidates.clear();
        let generation = work.generation;
        let triggered = work
            .found
            .iter()
            .flat_map(|&literal| &self.triggers[literal]);
        for &position in self.untriggered.iter().chain(triggered) {
            if work.candidate[position] != generation {
                work.candidate[position] = generation;
                work.candidates.push(position);
            }
        }

        let GroupScratch {
            hits,
            found,
            texts,
            candidates,
            memo,
            memo_value,
            values,
            number,
            ..
        } = work;
        let context = Context {
            group: self,
            event,
            hits,
            texts,
            generation,
            values: RefCell::new(recycle(std::mem::take(values))),
            number: RefCell::new(std::mem::take(number)),
        };
        for &position in candidates.iter() {
            let (index, node) = &self.rules[position];
            if context.node(node, memo, memo_value) {
                matched.push(*index);
            }
        }
        *values = recycle(context.values.into_inner());
        *number = context.number.into_inner();

        for &literal in found.iter() {
            hits[literal] = 0;
        }
        found.clear();
    }
}

impl Source {
    /// Collects this source's texts from `event`, folded unless cased.
    ///
    /// Reads the same values, in the same order, as the reference evaluator:
    /// strings and numbers for paths, strings only for keywords.
    fn gather(&self, event: &Value, texts: &mut Texts) {
        texts.clear();
        let cased = self.cased;
        match &self.origin {
            Origin::Paths(paths) => {
                for path in paths {
                    path.visit(event, &mut |value| match value {
                        Value::String(text) => texts.push(text, cased),
                        // Written in place: a number's decimal text has
                        // nothing for folding to change.
                        Value::Number(number) => write_number(number, texts.next()),
                        _ => {}
                    });
                }
            }
            Origin::AnyString => strings(event, &mut |text| texts.push(text, cased)),
        }
    }
}

/// Calls `visit` on every string anywhere in `value`, as keywords search them.
fn strings(value: &Value, visit: &mut impl FnMut(&str)) {
    match value {
        Value::String(text) => visit(text),
        Value::Array(items) => items.iter().for_each(|item| strings(item, visit)),
        Value::Object(map) => map.values().for_each(|item| strings(item, visit)),
        _ => {}
    }
}

/// Empties `values` and returns its allocation typed for another lifetime.
///
/// The collect reuses the allocation, because the element type keeps its
/// size and alignment, so a buffer of references into one event can be kept
/// for the next without allocating.
fn recycle<'b>(mut values: Vec<&Value>) -> Vec<&'b Value> {
    values.clear();
    values
        .into_iter()
        .map(|_| unreachable!("emptied"))
        .collect()
}

/// What one event's evaluation of a group can read.
struct Context<'a> {
    group: &'a Group,
    event: &'a Value,
    hits: &'a [u8],
    texts: &'a [Texts],
    generation: u32,
    /// Values for non-string tests, reused across the predicates of one
    /// event instead of collected afresh for each.
    values: RefCell<Vec<&'a Value>>,
    number: RefCell<String>,
}

impl Context<'_> {
    /// A source's literal index in the group's literal space.
    fn global(&self, source: usize, literal: usize) -> usize {
        self.group.sources[source].first_literal + literal
    }

    fn node(&self, node: &Node, memo: &mut [u32], values: &mut [bool]) -> bool {
        match node {
            Node::And(operands) => operands
                .iter()
                .all(|operand| self.node(operand, memo, values)),
            Node::Or(operands) => operands
                .iter()
                .any(|operand| self.node(operand, memo, values)),
            Node::Not(operand) => !self.node(operand, memo, values),
            Node::Pred(index) => {
                if memo[*index] == self.generation {
                    return values[*index];
                }
                let value = self.predicate(&self.group.predicates[*index]);
                memo[*index] = self.generation;
                values[*index] = value;
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
                        .current()
                        .iter()
                        .any(|candidate| pattern.matches(candidate))
            }
            Pred::Other { paths, check } => {
                let mut values = self.values.borrow_mut();
                values.clear();
                pool_into(self.event, paths, &mut values);
                match check {
                    Check::Regex(regex) => {
                        regex_matches_any(regex, &values, &mut self.number.borrow_mut())
                    }
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

        // The longest literal is the most selective one to wait for, as it
        // occurs least often.
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

    /// Estimates how often a trigger set wakes its rule, for choosing among
    /// the triggers of a conjunction. Lower is rarer.
    ///
    /// A short literal such as `.exe` occurs in nearly every event, a long
    /// one such as `\sessionresume_` almost never, so each literal counts
    /// inversely to the square of its length, and a set costs the sum of its
    /// literals. On the `SigmaHQ` regression events this cuts the rules
    /// evaluated per event from 41 to 30 compared with choosing the set with
    /// the fewest literals.
    fn wake_cost(&self, trigger: &[(usize, usize)]) -> u64 {
        trigger
            .iter()
            .map(|&(source, index)| {
                let length = self.literals[source][index].len().max(1) as u64;
                1_000_000 / (length * length)
            })
            .sum()
    }

    /// Literals at least one of which must be found for `node` to hold, or
    /// `None` if no such set is known.
    fn trigger(&self, node: &Node) -> Option<Vec<(usize, usize)>> {
        match node {
            Node::Pred(index) => self.atoms[*index].map(|atom| vec![atom]),
            // Any one operand's trigger will do; the least likely to be found
            // wakes the rule least often.
            Node::And(operands) => operands
                .iter()
                .filter_map(|operand| self.trigger(operand))
                .min_by_key(|trigger| self.wake_cost(trigger)),
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
