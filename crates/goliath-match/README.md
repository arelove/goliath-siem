# goliath-match

Evaluation of resolved detection rules against OCSF events, for the
[Goliath](https://github.com/arelove/goliath-siem) security platform.

Rules arrive resolved by `goliath-rule`, referring only to OCSF paths. This
crate decides whether an event matches.

## Scope

- A reference evaluator that checks one rule against one event, written for
  obvious correctness. It defines what a match means.
- An engine that evaluates many rules against one event while sharing the
  work: rules grouped by class, identical tests computed once, every literal
  of a field found in one Aho-Corasick pass, and rules skipped until a literal
  they need is found. It must agree with the reference evaluator on every rule
  and event, which random differential tests and the SigmaHQ regression events
  check.

## Regular expressions run in linear time

Sigma writes regular expressions in a dialect close to PCRE. This crate runs
them with the `regex` crate, which guarantees time linear in the input and
therefore refuses lookarounds and backreferences. A rule using them fails to
load with an error naming the pattern. Event data is attacker controlled, and a
backtracking engine would let one crafted log line stall detection.

## License

[Apache License 2.0](../../LICENSE).
