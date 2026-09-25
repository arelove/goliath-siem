# 0014. Rust for every platform service

- **Status:** Accepted
- **Date:** 2026-09-25
- **Supersedes:** the service rows of [ADR-0005](0005-languages-and-process-boundaries.md)

## Context

ADR-0005 put the hot path in Rust, the API, control plane, and case service in
Go, playbooks in Python, and the interface in TypeScript. Four days of building
the hot path changed three facts it relied on.

1. **The API needs the Rust crates.** Search compiles filters on OCSF paths to
   ClickHouse SQL, and must reject a path the schema does not have. The
   schema, path resolution, the Sigma parser, and the Sigma to ClickHouse
   compiler are Rust crates. In Go each would be reimplemented or generated,
   and kept in step by hand, which is exactly the drift ADR-0005's own
   consequences warn about.
2. **Single-binary mode needs one runtime.** The architecture promises one
   process with embedded substitutes, running in under a minute. ADR-0005
   forbids FFI between languages, so a Go API is always a second process, and
   a Python worker a third. The laptop deployment becomes a process manager.
3. **Go's SDK advantage did not hold.** The official ClickHouse client for
   Rust is in use and tested against real servers; librdkafka covers Kafka;
   PostgreSQL has mature async drivers. The one real gap is Temporal, whose
   Rust SDK is not first-class, and Temporal is itself a cluster that single
   binary mode cannot embed.

Development speed was Go's remaining argument. For request handling and
state machines the difference is small, and it is paid once, while a second
service language is paid on every change to shared types, in CI, and by every
contributor.

## Decision

**Every platform service is Rust. The interface is TypeScript. Python is used
only outside the platform process: detection content tooling, and analytics
or language-model components that run as optional sidecars.**

| Layer | Language |
| --- | --- |
| Hot path: normalization, matching, enrichment, storage | Rust |
| API, control plane, cases, scheduler, playbook runtime | Rust |
| Web interface | TypeScript + React |
| Detection content tooling, analytics and language-model sidecars | Python |

The process boundary rule of ADR-0005 stands: no FFI between languages, and
sidecars talk over the network.

### Playbooks

Playbooks become declarative, like source definitions and rules: a versioned
file of steps, approvals, and actions, executed by a Rust runtime with durable
state in PostgreSQL. Actions are built in, WASM modules
([ADR-0004](0004-configuration-and-extensibility.md)), or HTTP calls to a
sidecar, which is where Python integrations live. Temporal is no longer
assumed; the runtime is decided in its own ADR at M6, under the constraint
that single-binary mode can run it.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Rust services, TypeScript interface, Python sidecars | One binary possible; shared types without generation; one toolchain in CI | Slower to write request handlers; smaller pool of Rust web developers | **Accepted** |
| ADR-0005 as written: Go services | Fast CRUD development, first-class Temporal SDK | Reimplements the schema and compilers; no single binary; four languages | No |
| Rust services with Temporal via its Go or TypeScript SDK | Keeps Temporal | A cluster to run for every deployment, and a second service language after all | No |

## Consequences

- One `goliath` binary can host every role, including `api`, which makes
  single-binary mode a configuration rather than a separate product.
- The search API of M2.5 is the first Rust service, and reuses the OCSF
  schema and the storage crate directly.
- Types shared with the interface are generated from Rust into TypeScript, one
  direction only.
- A playbook author writes a file, not a program; integrations that need a
  general-purpose language run as sidecars.

## When to revisit

- The API's request handling becomes the measured bottleneck of feature
  delivery, such as three consecutive milestones slipping on API work while the
  engine is on time.
- A durable execution engine that embeds in a Rust process and is licensed
  under Apache 2.0 or MIT appears, which would change the M6 decision rather
  than this one.
