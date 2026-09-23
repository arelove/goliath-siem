# goliath-match

Evaluation of resolved detection rules against OCSF events, for the
[Goliath](https://github.com/arelove/goliath-siem) security platform.

Rules arrive resolved by `goliath-rule`, referring only to OCSF paths. This
crate decides whether an event matches.

## Scope

- A reference evaluator that checks one rule against one event, written for
  obvious correctness. It defines what a match means.
- Later, the fast engine: a predicate index shared across thousands of rules,
  required to agree with the reference evaluator on every rule and event.

## Regular expressions run in linear time

Sigma writes regular expressions in a dialect close to PCRE. This crate runs
them with the `regex` crate, which guarantees time linear in the input and
therefore refuses lookarounds and backreferences. A rule using them fails to
load with an error naming the pattern. Event data is attacker controlled, and a
backtracking engine would let one crafted log line stall detection.

## License

[Apache License 2.0](../../LICENSE).
