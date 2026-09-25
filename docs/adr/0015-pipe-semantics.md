# 0015. Pipe semantics

- **Status:** Accepted
- **Date:** 2026-09-25
- **Amended:** 2026-09-25, how Kafka keeps the contract

## Context

[ADR-0006](0006-deployment-topology.md) makes every hop between roles go
through one pipe abstraction with interchangeable implementations: in-process,
local disk, Kafka, S3. It does not say what a pipe promises. The roles cannot
be written until it does, and the implementations cannot be interchangeable
unless they promise the same thing.

Two consumers read the normalized stream: the writer and the detector. The
architecture requires that a slow or crashed detector never stops storage, and
that a detector which recovers evaluates every event it missed.

## Decision

A pipe is a sequence of **topics**. Every implementation provides the same
contract:

1. **Bytes only.** A record is an opaque byte string. Roles serialize; the
   pipe never carries a pointer, even in one process, so the in-process pipe
   exercises the same path as Kafka.
2. **Order.** Records of a topic are delivered in the order they were sent,
   each with an **offset**, increasing by one.
3. **Consumer groups.** Each reading role subscribes under a group name and
   has its own position. Groups do not affect each other's position.
4. **At least once.** A group acknowledges an offset once everything up to it
   is durably handled. A group that restarts resumes after its last
   acknowledgement, so unacknowledged records are delivered again. Duplicates
   are expected and are removed where it matters: storage deduplicates by
   event identity ([ADR-0013](0013-event-storage.md)).
5. **Bounded.** A topic holds a bounded amount. When it is full, sending
   waits: backpressure travels to the source, which is buffered by the
   collector, instead of memory growing until the process dies.

A record is released only when every group has acknowledged it. A group that
stops acknowledging therefore stops its topic once the bound is reached. That
is deliberate: dropping records a group has not handled would break point 4
for it. A group that is gone for good is removed explicitly.

### Implementations

| Implementation | Durable across restarts | Used when |
| --- | --- | --- |
| Memory | No | Tests, and roles in one process that can replay their input |
| Local disk log | Yes | Single-binary mode; roles in one process on one host |
| Kafka or Redpanda | Yes | Roles on several hosts |

Every implementation runs the same contract test suite, one test per point
above; only what an implementation adds, such as crash recovery on disk, is
tested separately.

### Kafka

Kafka keeps order per partition, so a topic has **one partition**, written by
an idempotent producer with `acks=all`: offsets are Kafka's own and
consecutive. A group's position is its committed offset; a receiver assigns
the partition itself rather than joining the group, so there are no
rebalances, and a new group commits the end of the topic at once.

Kafka deletes records by age or size, whether or not a group has read them,
which would break points 4 and 5 for a slow group. So the bound is kept by the
sender: before each batch it measures how far the slowest reading group is
behind, and waits while that exceeds the capacity. The reading groups are
those subscribed in the same process and those the configuration names.
A named group with no position yet is given the end of the topic when a
sender opens it, so a reader in another process that starts after the sender
receives what was sent, instead of starting after it as a new group would.
Kafka's own retention is set well beyond the capacity, as a safety net only.

One partition bounds a topic's throughput to what one broker can append,
hundreds of megabytes per second. Partitioning a topic changes point 2 to
order per partition, and is a change to this record when it is needed.

The memory pipe loses what it holds when the process ends. It is correct only
where the input itself can be read again from the last acknowledged position,
such as a file the collector tails. Single-binary mode uses the disk log.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Consumer groups with acknowledged offsets, bounded topics | Kafka's model, so every implementation maps onto it; independent writer and detector | A stuck group stalls the topic at its bound | **Accepted** |
| Channels between roles, one per consumer | Simplest in process | No replay, no independent recovery, nothing like it across hosts | No |
| Unbounded topics | A stuck consumer never stalls anything | Memory or disk grows until failure; loss moves to the worst moment | No |
| Exactly-once delivery | No duplicates | Needs transactions across the pipe and ClickHouse; identity-based deduplication gives the same stored result | No |

## Consequences

- A role's loop is the same everywhere: receive, handle, write, acknowledge.
- The writer acknowledges only after a successful flush, and the detector only
  after its alerts are emitted, so neither loses records on a crash.
- A detector that falls behind by more than a topic's bound slows ingestion
  rather than losing events. Where that is unacceptable, the bound is raised
  or the detector reads from a separate topic.

## When to revisit

A deployment needs to keep ingesting while a consumer group is stalled beyond
the bound, and the operators accept that group losing records.
