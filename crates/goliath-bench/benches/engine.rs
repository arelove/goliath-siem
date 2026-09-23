//! Instructions the engine spends, counted by Callgrind.
//!
//! ```text
//! cargo bench -p goliath-bench --features callgrind --bench engine
//! ```
//!
//! Needs Linux, Valgrind, and `gungraun-runner` of the same version as the
//! `gungraun` dev-dependency. See `docs/benchmarks.md`.

#![allow(missing_docs, clippy::expect_used)]

use std::hint::black_box;

use goliath_bench::{Workload, process_creation};
use goliath_match::{Engine, Scratch};
use goliath_rule::ResolvedRule;
use gungraun::{library_benchmark, library_benchmark_group, main};
use serde_json::Value;

/// About as many rules as `SigmaHQ` has for the five Windows sources Goliath
/// maps.
const RULES: usize = 2_000;
const EVENTS: usize = 1_000;
const SEED: u64 = 2026;

fn workload() -> Workload {
    process_creation(RULES, EVENTS, SEED)
}

fn rules() -> Vec<ResolvedRule> {
    workload().rules
}

/// A compiled engine whose scratch has already seen every event, so the
/// measurement is the steady state a long running detector is in.
fn warmed_up() -> (Engine, Vec<Value>, Scratch) {
    let Workload { rules, events } = workload();
    let engine = Engine::new(rules).expect("rules compile");
    let mut scratch = engine.scratch();
    let mut matched = Vec::new();
    for event in &events {
        engine.matches_into(event, &mut scratch, &mut matched);
    }
    (engine, events, scratch)
}

#[library_benchmark]
#[bench::process_creation(setup = rules)]
fn compile(rules: Vec<ResolvedRule>) -> Engine {
    black_box(Engine::new(black_box(rules)).expect("rules compile"))
}

#[library_benchmark]
#[bench::process_creation(setup = warmed_up)]
fn evaluate((engine, events, mut scratch): (Engine, Vec<Value>, Scratch)) -> usize {
    let mut matched = Vec::new();
    let mut total = 0;
    for event in &events {
        engine.matches_into(black_box(event), &mut scratch, &mut matched);
        total += matched.len();
    }
    black_box(total)
}

library_benchmark_group!(name = engine, benchmarks = [compile, evaluate]);

main!(library_benchmark_groups = engine);
