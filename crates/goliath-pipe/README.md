# goliath-pipe

Transport between the roles of the
[Goliath](https://github.com/arelove/goliath-siem) security platform.

Every implementation keeps one contract, set out in
[ADR-0015](https://github.com/arelove/goliath-siem/blob/main/docs/adr/0015-pipe-semantics.md):

- records are opaque bytes, delivered in order, with consecutive offsets;
- each reading role has a consumer group of its own, reading at its own pace;
- delivery is at least once: a group that restarts receives again everything
  it had not acknowledged;
- topics are bounded, and sending waits while one is full, so backpressure
  reaches the source instead of memory growing without limit.

| Implementation | Status |
| --- | --- |
| Memory | Available |
| Local disk log | Next |
| Kafka or Redpanda | Planned |

## License

Copyright 2026 arelove. Licensed under the
[Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE).
