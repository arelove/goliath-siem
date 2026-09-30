# 0018. Collection over the network

- **Status:** Accepted
- **Date:** 2026-09-28

## Context

The platform takes records from one place today: files renamed into a
collector's inbox. Companies send logs over the network, from agents and
services they already run: rsyslog and syslog-ng, Fluent Bit and Vector,
cloud services that push over HTTPS, and OpenTelemetry collectors. M3.5's
exit criterion is that each shipped source reaches search from a live sender
within five seconds, and that each receiver sustains the M3 rate, 100,000
records a second on one machine, without losing an acknowledged record.

Four facts shape the design:

- The raw topic of each source is the platform's entry point
  ([ADR-0015](0015-pipe-semantics.md)). A raw record is a batch of the
  source's records in the source's own framing, stamped with when the
  platform took it, and the normalizer splits it. The file collector already
  writes such records; a receiver can write the same.
- The topic is bounded. When it is full, sending waits. Whatever a receiver
  does while it waits decides whether a sender's records are lost.
- The protocols promise different things. HTTP answers each request, so a
  sender learns whether its batch was taken. Syslog over TCP has no
  application acknowledgement: a sender knows only that the kernel accepted
  its bytes. OTLP over HTTP answers each export request.
- Anything that listens on a network is reachable by whoever can reach that
  address. The API already refuses to listen beyond loopback without a token.

## Decision

**Add a `receiver` role whose listeners each belong to one source and write
what they receive to that source's raw topic, acknowledging a sender only
after the pipe has taken its records, and slowing senders down, never
dropping, when the topic is full.**

### Listeners

- A source lists the listeners that feed it beside its inbox:

  ```toml
  [[sources]]
  definition = "falco"
  http = { token_file = "/run/secrets/falco_token" }

  [[sources]]
  definition = "auditd"
  syslog = { listen = "0.0.0.0:6514", tls = { certificate = "...", key = "..." } }
  ```

- **HTTP ingest.** `POST /ingest/{source}` on the receiver's HTTP listener,
  one for all sources, with the source's own bearer token. The body is a
  batch of the source's records in its framing, such as JSON lines for Falco
  or audit lines for auditd, optionally gzip-encoded, at most 16 MiB. It
  becomes one raw record.
- **Syslog.** TCP, with TLS, framed by octet counting or by newline as RFC
  6587 describes, carrying RFC 5424 or RFC 3164 messages. Messages are
  gathered into raw records of at most 1,000 messages or 250 milliseconds.
  The syslog header is kept: the source definition reads it through a
  `syslog` decoding that gives the header's fields and decodes the message
  as the definition says, JSON or text. UDP is left out: it loses messages
  under exactly the load the platform is measured at.
- **OTLP logs.** `POST /v1/logs` over HTTP, protobuf or JSON, with the
  source's token, on the same HTTP listener. Each log record becomes one JSON
  line: its time, severity, body, attributes, and its resource's attributes,
  so that a definition reads it with `lines` framing and `json` decoding. gRPC
  can follow if senders need it.

### Acknowledgement and backpressure

- **HTTP and OTLP** answer `200` only once the raw record is in the pipe, so
  a sender that has its answer has lost nothing to a crash of the receiver.
  While the topic is full, the request waits; after 10 seconds it is answered
  `503` with `Retry-After`, and the sender retries, as agents do. A request
  over the size limit is answered `413`, a bad token `401`, an unknown source
  `404`.
- **Syslog** stops reading a connection while its batch cannot be sent, so
  TCP's own flow control slows the sender; nothing is dropped for being
  late. What syslog cannot promise is stated as such: messages the receiver
  has read but not yet sent are lost if it crashes, up to one batch per
  connection. RELP, which acknowledges messages, is the answer if that
  matters, and is left for when a user asks.

### Security

- Every HTTP request carries the bearer token of the source it names,
  compared in constant time, of at least 32 bytes, read from a file. A token
  names one source, so a leaked token lets its holder write to that source
  only.
- Listeners bind to loopback unless configured otherwise, and a listener
  beyond loopback needs TLS: HTTP with a certificate and key, syslog the
  same. Plain TCP beyond loopback is refused at start, as the API refuses a
  token-less address.
- Limits keep one sender from exhausting the receiver: the body size, a
  syslog message of at most 64 KiB, and a number of open connections.

### Observing

The receiver reports, by source and listener, records and bytes received,
requests refused and why, and time spent waiting on a full topic, beside the
metrics the other roles serve. Source health, M3.5's third deliverable,
reads the last of these and the stored events.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| One listener per source, each on its own port | No routing | Ports multiply with sources; firewalls and load balancers need each | HTTP and OTLP share one listener, routed by path and token; syslog, which has no path, has a port per source |
| A receiver that splits records and sends one raw record per message | The raw topic holds messages | Many small records; the pipe and the normalizer already handle batches | Batches, as the file collector sends |
| Accept and buffer in memory when the topic is full | Senders never wait | Memory grows until the process dies, or records are dropped | Refused: backpressure, as ADR-0015 decided |
| Acknowledge HTTP on receipt, before the pipe | Lower latency | An answered request can be lost | Refused |
| Syslog over UDP | Common in older devices | Loses messages silently under load | Left out; a relay such as rsyslog can forward UDP over TCP |
| gRPC for OTLP first | The OTLP default | A second server stack for one protocol | HTTP first; gRPC when a sender needs it |

## Consequences

- Senders the platform does not ship with, such as Fluent Bit, Vector, and
  the OpenTelemetry Collector, can send to it with their own configuration,
  and M3.5's sources can be tested from live senders.
- A new `syslog` decoding joins the definition language, and every
  definition of a source carried by syslog uses it.
- The receiver is a new process to operate, with TLS certificates to renew.
  One binary still holds every role ([ADR-0006](0006-deployment-topology.md)).
- A full topic becomes visible to senders as slower answers and `503`s,
  which is the point: a platform that falls behind says so, and loses
  nothing it said it took.

## When to revisit

If a user needs syslog delivery guarantees, add RELP. If a sender that
matters speaks only OTLP over gRPC, add it. If one receiver cannot hold the
M3 rate on one machine while the pipe can, measure where it waits before
adding receivers behind a load balancer.
