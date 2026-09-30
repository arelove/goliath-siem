# goliath-attack

Adversary knowledge frameworks for the [Goliath](https://github.com/arelove/goliath-siem) security platform, with MITRE ATT&CK as the first: tactics, techniques, and the data components that detect them, read from the STIX 2.1 bundles MITRE publishes; coverage of a rule set against the data a deployment collects; and ATT&CK Navigator layers of it. See [ADR-0009](../../docs/adr/0009-attack-knowledge-model.md).

A technique a rule detects, whose data no configured source collects, is reported as blind: the rule exists and cannot fire.

ATT&CK is © The MITRE Corporation, used under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## License

Copyright 2026 arelove. Licensed under the [Apache License 2.0](https://github.com/arelove/goliath-siem/blob/main/LICENSE).
