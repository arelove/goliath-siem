# Security policy

## Reporting a vulnerability

Report privately, through
[GitHub's private vulnerability reporting](https://github.com/arelove/goliath-siem/security/advisories/new).
Do not open a public issue for a vulnerability.

Include what you can of:

- the rule, event, or input that shows the problem, reduced as far as you can;
- what happens, and what should happen instead;
- the commit you tested.

This is a project maintained by one person. A report is acknowledged within
a week, and you are told what will be done and when. Once a fix is on `main`,
the advisory is published with credit to you, unless you prefer otherwise.

## Supported versions

Goliath is pre-alpha and has no releases. Fixes land on `main` only.

## What counts

A detection platform fails its users in ways a general library does not, so
the scope is wider than crashes:

- **A missed detection.** An event that a rule matches under the documented
  semantics, but the engine does not. The engine is tested against a
  deliberately simple reference evaluator; any disagreement between the two
  is treated as a vulnerability, because an attacker who finds one has a way
  past the rule.
- **Untrusted rules.** Rule files come from third parties and are parsed as
  untrusted input ([ADR-0011](docs/adr/0011-untrusted-yaml.md)). A rule that
  makes parsing or compilation crash, or take unbounded time or memory, is in
  scope.
- **Untrusted events.** Events are attacker-influenced by nature. An event
  that makes evaluation crash, hang, or take time that grows faster than its
  size is in scope.
- **Anything else** that lets a rule or an event read, write, or execute what
  it should not.

Out of scope, and welcome as ordinary issues: a Sigma rule that is weak in
itself, and a Sigma field that does not load because it has no OCSF mapping
yet.
