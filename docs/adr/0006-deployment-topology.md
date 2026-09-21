# 0006. Roles compose; topology is configuration

- **Status:** Accepted
- **Date:** 2026-09-21

## Context

Deployments of this class of system differ more than their code does. A small
team wants one process on one host. A bank wants collectors in each branch,
normalization in a regional DMZ, and detection in a central SOC. A managed
service provider wants one control plane over many isolated tenant pipelines.

If topology is baked into the binaries, we ship a different product for each
shape, and the shapes we did not anticipate are impossible.

## Decision

**Every component is a library crate plus a thin role wrapper. One binary can
host any subset of roles. Where roles run is configuration, not code.**

## Roles

| Role | Responsibility | Typical placement |
| --- | --- | --- |
| `collector` | Acquire raw records from sources, frame, compress, ship | Near the source |
| `normalizer` | Parse, map to OCSF, validate | Edge or central |
| `enricher` | Attach entity, asset, geo, and indicator context | With the detector |
| `detector` | Evaluate rules, emit alerts | Central |
| `scheduler` | Run windowed detections against the warehouse | Central |
| `api` | Control plane, query, RBAC, tenancy | Central |
| `worker` | Execute response playbooks | Central or isolated |
| `ui` | Web interface | Central |

Selection is a list:

```toml
roles = ["collector", "normalizer"]
```

## Transport is an abstraction

Roles never call each other directly. Every inter-role hop goes through one
pipe abstraction with interchangeable implementations:

| Implementation | Used when |
| --- | --- |
| In-process channel | Roles share a process |
| Unix socket or local disk queue | Roles share a host |
| Kafka or Redpanda | Roles are distributed |
| S3 buffer | Cloud deployment where inter-AZ traffic dominates cost |

The rule that makes this real: **no role may assume co-location, even when
co-located.** Sharing a struct pointer between two roles because they happen to
run in the same process is rejected at review. Without this, the distributed
path rots while nobody is looking and only breaks in production.

## Testing requirement

CI runs the same integration suite against two topologies: all roles in one
process, and every role in its own container. A change that passes one and
fails the other does not merge. This is what keeps the abstraction honest.

## Consequences

- Single-binary mode is a supported deployment, not a demo. It enables the
  sub-minute cold start in [architecture.md](../architecture.md).
- A serialization boundary exists between every pair of roles, costing some
  throughput in the co-located case. Measured and accepted: the alternative is
  a system that cannot be deployed the way its operators need.
- The pipe abstraction must be versioned, because a rolling upgrade will run
  mixed versions across roles.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Role composition in one binary | One artifact, any shape, trivial local development | Serialization overhead when co-located; discipline needed to keep the boundary real | **Accepted** |
| Separate binaries per component | Clear boundaries by construction | Cannot collapse into a single process; slow local development; more release artifacts | No |
| Monolith with feature flags at compile time | Best co-located performance | A different binary per shape; combinatorial build matrix | No |

Precedent for the accepted option: OpenTelemetry Collector, Grafana Alloy,
Vector, HashiCorp Nomad.

## When to revisit

Serialization at a co-located boundary is measured above 10% of total per-event
cost, in which case specific adjacent role pairs may share a zero-copy buffer
while keeping the pipe interface.
