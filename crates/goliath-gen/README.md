# goliath-gen

Deterministic synthetic security telemetry for Goliath's benchmark rig.
An organization links Sysmon accounts and hosts to Entra users and devices.
No attack recordings are included.

```rust
use goliath_gen::{Generator, Options, Organization, entities};

let org = Organization::generate(&Options::default());
let mut generator = Generator::new(&org, 42);
let record = generator.next(1_790_244_930_123);
assert!(matches!(record.source, "sysmon" | "entra"));
let truth: Vec<_> = entities(&org).collect();
```

Write each `Record.bytes` followed by a newline into its source's stream.
Write each value from `entities` followed by a newline to `entities.jsonl`.
Identifier values are arrays; administrator accounts belong to the same
person. DHCP addresses are time-dependent and are not static identifiers.

The stream is approximately 92.5% Sysmon and 7.5% Entra. Workstation and
sign-in selection follows user activity and the office's local hour:
09:00-18:00 on weekdays has weight 1, 18:00-23:00 weight 0.3, and other hours
and weekends weight 0.05. Servers keep weight 0.02 each. Office UTC offsets
are fixed; daylight saving is not simulated. Sysmon covers event IDs 1, 3,
7, 11, and 13, retaining process identity between launch and later activity.

The same organization, generator seed, and sequence of timestamps produce
identical bytes. Workload proportions are synthetic assumptions, not measured
enterprise distributions. Auditd, Falco, replay, and attack injection remain
future work. Data sources and licenses are in [data/README.md](data/README.md).
