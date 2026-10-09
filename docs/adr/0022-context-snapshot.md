# 0022. What the context snapshot holds, and where it comes from

- **Status:** Proposed
- **Date:** 2026-10-10

## Context

A finding says that an event held an indicator, and which feeds assert it.
The analyst who opens it then asks what no feed knows: whose machine this
is, which network the address is in, whether the account has administrator
rights, whether the far address is a VPN exit. Without the answers each
finding starts with the same lookups made by hand, in other tools.

Three records already decide where those answers are kept and when they are
added:

- [ADR-0003](0003-data-boundary.md): the event path reads a snapshot local
  to the node, and accepts that it is stale by up to one refresh.
- [ADR-0020](0020-state-beyond-events.md): the snapshot is in RocksDB,
  embedded in the process that reads it, and is refreshed in bulk. M4 runs
  without PostgreSQL.
- [ADR-0021](0021-enrichment-placement.md): the detector adds context to
  findings, and in M5 to alerts, not to every event.

They leave three things open:

- What the snapshot holds. "Assets, users, networks, and the lists typed as
  context" names four kinds of record and no field of any.
- Where the records come from in M4. The system of record ADR-0020 names
  for entities is PostgreSQL, which arrives in M4.5.
- What a finding gets: for which values of the event, in what form, and how
  it says how old the context was.

Facts that bear on the answer:

- A company already keeps this knowledge somewhere: a CMDB, Active
  Directory, an IPAM, a spreadsheet. Each of them exports rows.
- The sizes are small beside indicators. A company of 100,000 people has
  some hundreds of thousands of machines and accounts and some thousands of
  networks; M4's indicator sets are 10^8.
- Reference lists that describe an address and do not accuse it are already
  fetched and pinned by feed definitions
  ([detector.md](../detector.md#reference-lists)): ranges of VPN providers,
  dynamic DNS domains, public resolvers. Matching them as indicators would
  raise findings about ordinary traffic.
- OCSF has an object for this, `enrichment`: the name of what was enriched,
  its value, a type, a provider, and free data. Detection Finding holds an
  array of them.

## Decision

**The snapshot holds networks, assets, users, and context lists, each read
from files a site exports and replaced whole when a file changes; the
detector looks up the addresses, host names, and user names of a matched
event in it, and writes what it finds as OCSF enrichments of the finding,
each with the version of the record's source.**

### What it holds

| Kind | Found by | Says |
| --- | --- | --- |
| Network | An address inside its range; the narrowest range wins | Its name, site, and zone, such as `internal`, `dmz`, `guest`, or `vpn` |
| Asset | A host name, or an address | Its owner, role, and criticality from 1 to 4; free tags |
| User | A user name, in the forms sources write it | Department, whether the account is privileged, whether it is a service account; free tags |
| Context list | A value of the list's kind, as an indicator is found | The list's name and the row's label |

- The fields are few on purpose: each is one an analyst sorts findings by,
  or one a later rule can test. A site's other columns go into the tags.
- A user is found under every form the file gives for them, such as
  `CORP\adam` and `adam@corp.example`. Deciding that two forms are one
  person is the entity graph's work in M4.5; here the file says so.
- An asset found by address is right only while the address is its own. A
  file that lists addresses handed out by DHCP is wrong within a day, and
  the documentation says to list host names for such machines.

### Where it comes from

- Networks, assets, and users are files in CSV or YAML that the site
  exports from where it keeps them, named in the detector's configuration.
  A file is read at start and when it changes, as a feed given as a file
  is, and replaces all records of its kind from that file at once.
- A context list is a feed definition marked as context. It is fetched,
  pinned, and versioned as any feed, and its values go to the snapshot and
  not to the indicator store, so it can never raise a finding.
- When PostgreSQL arrives in M4.5 it becomes the system of record for
  entities, and writes the same records into the snapshot. The files remain
  as a way in, since a site without the graph still has a CMDB export.
- Connectors that fetch from a CMDB or a directory are not part of this
  decision. They would write the same files.

### What a finding gets

- The detector looks up the addresses, host names, and user names among the
  matched event's observables, the matched one included.
- Each record found becomes one entry of the finding's `enrichments`: the
  attribute's kind as `name`, the value as `value`, the kind of record as
  `type`, the source file or list and its version as `provider`, and the
  record's fields as `data`.
- At most 32 entries are written for one finding, networks and assets
  first. An event that names more than that is a scan or a list, and its
  context is in the event.
- A value found in nothing gets no entry. The absence says the snapshot does
  not know it, which for an internal address is itself worth seeing: the
  network entry is there and the asset entry is not.
- The finding's identifier does not depend on its enrichments. A finding
  made twice, as the event arrived and later from the store, is stored once,
  with the context of whichever was written last.

### How old the context is

- Each entry names the version of its source: when the file was written, or
  the revision of a pinned list. A finding therefore says what was known
  when it was made, and is not rewritten when the snapshot changes.
- The detector reports the age of each source as a metric, as it does for
  feeds, so that an export that stopped is seen.

### What it is built on

- The snapshot is behind a trait with two stores, in memory and in RocksDB,
  as the indicator store is. The store in memory comes first and is what
  tests use; RocksDB follows before the milestone ends, as ADR-0020
  decides.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Files exported by the site, replaced whole | Every source of this knowledge can export rows; no new server; the same refresh as feeds | The site must schedule the export; stale by its period | **Chosen** |
| Wait for PostgreSQL in M4.5 | One system of record from the start | M4's findings have no context until then; the snapshot's readers are written against nothing | Rejected |
| Derive assets and users from the events | Nothing to export | That is the entity graph, with its own resolution and its own milestone; an owner and a criticality are in no event | Rejected for M4 |
| Query the CMDB or directory when a finding is made | Always current | A network call on the detector's path, forbidden by ADR-0003; the finding then depends on a server being up | Rejected |
| Match context lists as indicators with a low confidence | No new kind of record | A finding for every connection to a VPN range or a public resolver; confidence then means two things | Rejected |
| Add context to every event | Searches by context need no join | Rewrites or widens every stored event for the few that become findings; decided against in ADR-0021 | Rejected |

## Consequences

- A finding answers the first questions asked of it in one place, and they
  can be sorted and filtered by criticality, zone, and privilege.
- A site has files to export and keep current. An export that stops leaves
  context that is quietly wrong, which the age metric is there to show.
- The records' fields are a contract from the first release: rules in M5
  and the interface will read them. They are added to, not renamed.
- Context is as good as the file. An address that changed hands since the
  export is attributed to its old owner, and the entry's version is the only
  sign.
- Events are not enriched. A search for every event of critical assets
  needs the join ADR-0021 leaves until the interface asks for it.

## When to revisit

- If a snapshot of 10^6 assets and users takes more than 1 GiB in memory or
  more than 30 seconds to replace, move the bulk load to sorted files
  written beside the store, as for indicators.
- If more than one finding in ten reaches the limit of 32 entries on a real
  site's events, choose what to keep by the kind of event, not by order.
- If sites ask for context fields that are tested by rules and are not in
  the table above, add them as fields; if the asks do not converge, give
  the tags types.
- When the entity graph resolves identities, the forms of a user come from
  it, and the user file's list of forms is dropped.
