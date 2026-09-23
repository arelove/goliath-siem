//! The engine must agree with the reference evaluator on every rule and every
//! event. These tests generate rules and events at random, from a fixed seed,
//! and compare the two.
//!
//! The alphabet is deliberately tiny, so that random patterns and random
//! values collide often: overlapping literals, a literal that is a prefix of
//! another, a pattern equal to the whole value, upper and lower case of the
//! same letter.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use goliath_match::{Engine, ReferenceRule};
use goliath_rule::{
    ClassValue, Comparison, Expr, FieldPath, MappingVersion, Number, Predicate, ResolvedRule,
    StringTest, Test, fold,
};
use goliath_sigma::{Pattern, PatternPart};
use serde_json::{Map, Value, json};

/// A small deterministic generator, so a failure reproduces from its seed.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        // xorshift64
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("fits")
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const FIELDS: [&str; 4] = ["a", "b", "c.d", "list"];
const LETTERS: [char; 4] = ['a', 'b', 'A', '\u{df}'];

fn path(text: &str) -> FieldPath {
    FieldPath::parse(text).expect("valid path")
}

fn text(random: &mut Random, max: usize) -> String {
    let length = random.below(max + 1);
    (0..length).map(|_| *random.pick(&LETTERS)).collect()
}

/// A pattern of every shape the engine distinguishes, and some it does not.
fn pattern(random: &mut Random, cased: bool) -> Pattern {
    let core = text(random, 3);
    let folded = if cased {
        core.clone()
    } else {
        fold(&core).into_owned()
    };
    let literal = || PatternPart::Literal(folded.clone());
    let parts = match random.below(6) {
        0 => vec![literal()],
        1 => vec![
            PatternPart::AnySequence,
            literal(),
            PatternPart::AnySequence,
        ],
        2 => vec![literal(), PatternPart::AnySequence],
        3 => vec![PatternPart::AnySequence, literal()],
        4 => {
            // Mixed wildcards, which take the general path.
            let second = text(random, 2);
            let second = if cased {
                second
            } else {
                fold(&second).into_owned()
            };
            vec![
                literal(),
                PatternPart::AnyChar,
                PatternPart::Literal(second),
                PatternPart::AnySequence,
            ]
        }
        _ => vec![PatternPart::AnySequence],
    };
    Pattern::from_parts(parts)
}

fn leaf(random: &mut Random) -> Expr {
    let paths = if random.chance(20) {
        vec![
            path(random.pick::<&str>(&FIELDS)),
            path(random.pick::<&str>(&FIELDS)),
        ]
    } else {
        vec![path(random.pick::<&str>(&FIELDS))]
    };
    let cased = random.chance(30);
    let test = match random.below(10) {
        0 => Test::Exists(random.chance(50)),
        1 => Test::Null,
        2 => Test::Equals(Number::Integer(
            i64::try_from(random.below(4)).expect("small"),
        )),
        3 => Test::Compare {
            op: *random.pick(&[
                Comparison::Less,
                Comparison::LessOrEqual,
                Comparison::Greater,
                Comparison::GreaterOrEqual,
            ]),
            value: Number::Integer(i64::try_from(random.below(4)).expect("small")),
        },
        4 if random.chance(50) => {
            return Expr::Keyword(StringTest {
                pattern: pattern(random, false),
                cased: false,
            });
        }
        _ => Test::String(StringTest {
            pattern: pattern(random, cased),
            cased,
        }),
    };
    Expr::Field(Predicate { paths, test })
}

fn expr(random: &mut Random, depth: usize) -> Expr {
    if depth == 0 || random.chance(35) {
        return leaf(random);
    }
    let operands = |random: &mut Random| {
        (0..random.below(4))
            .map(|_| expr(random, depth - 1))
            .collect::<Vec<_>>()
    };
    match random.below(3) {
        0 => Expr::And(operands(random)),
        1 => Expr::Or(operands(random)),
        _ => Expr::Not(Box::new(expr(random, depth - 1))),
    }
}

fn rule(random: &mut Random, index: usize) -> ResolvedRule {
    let mut class = BTreeMap::new();
    if random.chance(50) {
        class.insert(
            path("class_uid"),
            ClassValue::Integer(i64::try_from(random.below(2)).expect("small")),
        );
    }
    ResolvedRule {
        title: format!("rule {index}"),
        id: None,
        mapping: MappingVersion {
            name: "random".to_owned(),
            version: 1,
        },
        class,
        condition: expr(random, 3),
    }
}

fn value(random: &mut Random) -> Value {
    match random.below(6) {
        0 => json!(random.below(4)),
        1 => json!(format!("{}", random.below(4))),
        2 => Value::Null,
        _ => json!(text(random, 5)),
    }
}

fn event(random: &mut Random) -> Value {
    let mut event = Map::new();
    event.insert("class_uid".to_owned(), json!(random.below(2)));
    for name in ["a", "b"] {
        if random.chance(80) {
            event.insert(name.to_owned(), value(random));
        }
    }
    if random.chance(70) {
        event.insert("c".to_owned(), json!({ "d": value(random) }));
    }
    if random.chance(50) {
        let items: Vec<Value> = (0..random.below(3)).map(|_| value(random)).collect();
        event.insert("list".to_owned(), Value::Array(items));
    }
    Value::Object(event)
}

fn compare(seed: u64, rules: usize, events: usize) {
    let mut random = Random(seed);
    let generated: Vec<ResolvedRule> = (0..rules).map(|index| rule(&mut random, index)).collect();
    let engine = Engine::new(generated.clone()).expect("engine compiles");
    let references: Vec<ReferenceRule> = generated
        .into_iter()
        .map(|rule| ReferenceRule::new(rule).expect("rule compiles"))
        .collect();

    for _ in 0..events {
        let event = event(&mut random);
        let expected: Vec<usize> = references
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.matches(&event))
            .map(|(index, _)| index)
            .collect();
        let actual = engine.matches(&event);
        if actual != expected {
            let differing: Vec<_> = (0..references.len())
                .filter(|index| expected.contains(index) != actual.contains(index))
                .map(|index| (index, &references[index].rule().condition))
                .collect();
            panic!(
                "seed {seed}: engine and reference disagree on {event}\n\
                 expected {expected:?}, got {actual:?}\n{differing:#?}"
            );
        }
    }
}

#[test]
fn agrees_with_the_reference_on_random_rules_and_events() {
    for seed in 1..=300 {
        compare(seed, 12, 40);
    }
}

#[test]
fn agrees_when_many_rules_share_literals() {
    // Many rules over the same few fields: shared predicates, shared
    // literals, and triggers that wake many rules at once.
    for seed in 1_000..1_020 {
        compare(seed, 200, 50);
    }
}
