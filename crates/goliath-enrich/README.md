# goliath-enrich

Context for the [Goliath](https://github.com/arelove/goliath-siem) security
platform: what a site knows of its own networks, machines, accounts, and
groups, found for the values of an event and written as OCSF enrichments.

A finding says that an event held an indicator. This crate adds what no feed
knows: whose machine it is, which network the address is in, whether the
account is privileged, whether it still exists.

- **The site's export, as it is.** A definition in YAML says which of a
  file's own columns are identifiers, typed fields, and labels. CSV and JSON
  lines are read. Nothing is renamed to suit the platform.
- **A few typed fields, and labels for the rest.** The typed fields have the
  names of OCSF's device and user objects: owner, organization, criticality,
  zone, type. Whatever else a site keeps, such as a payment card scope or a
  cloud project, is a label under the site's own name.
- **Found by any identifier.** A machine by host name, address, MAC, or a
  product's identifier; an account by any form of its name, an email address,
  or a SID. Names take the canonical form indicators have.
- **At the time of the event.** A record may say from when and until when it
  holds. An address that was another machine an hour ago is found as it was,
  and an account closed before the event is found as ended.
- **Within a scope.** Two customers, or two branches, that use one address
  range each get their own context.
- **Lists that describe.** A row of a context list is found by an address,
  a range that holds one, or a domain a host name is under.
- **Sources are not merged.** Two sources that describe one thing give two
  enrichments, each under its source's name and version.

## A definition

```yaml
name: cmdb-servers
description: Servers, exported nightly from the CMDB
kind: asset
format: csv
identifiers:
  host: [hostname, fqdn]
  address: [ip_address]
  uid: [asset_tag]
fields:
  owner: owner_email
  org: business_unit
  criticality: tier
criticality: { gold: 4, silver: 3, bronze: 2 }
labels:
  pci_scope: pci
  information_system: system
groups: { column: roles, separator: ";" }
```

| Kind | Found by | Typed fields |
| --- | --- | --- |
| `network` | `range`; the narrowest range of a source wins | `name`, `zone`, `region`, `site` |
| `asset` | `host`, `address`, `mac`, `uid` | `name`, `type`, `owner`, `org`, `criticality`, `is_managed`, `zone`, `region` |
| `identity` | `user`, `email`, `uid` | `name`, `type`, `org`, `department`, `manager`, `criticality`, `is_privileged`, `is_enabled` |
| `group` | `group`, `uid` | `name`, `type`, `is_privileged` |
| `list` | `range`, `address`, `host` | `label` |

Other members of a definition: `scope`, `set` for typed fields every row
has, `valid_from` and `valid_until` for the columns of a row's times,
`separator` for cells that hold several identifiers, and `csv` for the
delimiter, the comment mark, and the column names of a file without a row
of them. For JSON lines a column is a member of the line's object, or a
path such as `tags.project`.

An export that is not what its definition describes is refused whole: a
column that is gone, no record at all, or more than one row in ten that
gives none. The snapshot then keeps what it had.

## What a finding gets

```json
{
  "name": "ip",
  "value": "10.20.30.17",
  "type": "asset",
  "provider": "cmdb-servers",
  "data": {
    "source_version": "2026-10-09",
    "owner": "g.ivanova@bank.example",
    "criticality": 4,
    "labels": { "information_system": "core banking" }
  }
}
```

Networks come first, then assets, identities, groups, and rows of context
lists, and no more than 32 entries in all. The groups a found record names
are looked up too, so a group said once to be privileged is said so in every
finding of a member.

The snapshot is held in memory, and moves to disk when a measurement shows
a site's records do not fit. The detector
reads the exports named in its configuration and adds the entries to
findings. The design is
[ADR-0022](https://github.com/arelove/goliath-siem/blob/main/docs/adr/0022-context-snapshot.md).
