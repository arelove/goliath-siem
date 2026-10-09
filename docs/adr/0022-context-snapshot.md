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

They leave open what the snapshot holds, where its records come from before
PostgreSQL arrives in M4.5, and what a finding gets. The answer must hold
for a bank with branches, a company that runs wholly in a cloud, and a
provider that watches many customers, without a change of model for each.

### How the systems in use do it

| System | What holds context | Where it comes from | What its design shows |
| --- | --- | --- | --- |
| Splunk Enterprise Security | Two lookups, assets and identities, with columns the product fixes: for an asset `ip`, `mac`, `nt_host`, `dns`, `owner`, `priority`, `bunit`, `category`, `pci_domain`, `is_expected`, `requires_av`; for an identity `priority`, `bunit`, `category`, `watchlist`, and the dates the person started and ended | CSV files and searches the site maintains, merged on a schedule | A fixed header does not fit: a column the product does not know is dropped, so sites pack what they need into `category`. Priority is what the product acts on: it is combined with a rule's severity into urgency. A zone column was added later, for address ranges that overlap |
| Microsoft Sentinel | `IdentityInfo`, a table of accounts with department, manager, group membership, roles, risk level, and tags; and watchlists, which are CSV files of any columns found by one key column | The directory, synchronized; watchlists uploaded by the site, from templates such as high value assets, VIP users, and terminated employees | The directory gives identity for free, and everything else is a list the site names itself. A watchlist has no fixed columns at all |
| Google Security Operations | An entity graph: assets, users, resources, and groups, each a record with a time it holds for | Identity providers, a CMDB, and vulnerability scanners, as feeds of context; and context derived from the events, such as when a value was first seen | An asset is found by any of host name, address, MAC, asset identifier, or the product's own identifier; a user by SID, identifier, employee number, or email. Context is tied to time, so that an address means the machine that held it then. Cloud resources and groups are entities beside hosts and users |
| Elastic Security | An entity store of hosts, users, and services, with a criticality for each | The events, identity providers, and asset repositories; criticality set by hand or uploaded | Criticality is one field the product acts on, in a risk score. It is copied into an alert when the alert is made, and an alert does not change when the criticality later does |
| OCSF | The `device` and `user` objects: owner, organization, groups, zone, region, risk level, whether managed, whether compliant, a type | It is a schema, not a store | A vocabulary for these fields exists already, in the schema the findings are written in |

Six things follow, and each is a requirement:

- **A few fields are acted on, and the rest differ at every site.** Every
  system has a criticality or priority, an owner, and a unit of the
  organization. Beyond those, a bank needs the payment card scope of a
  machine, a cloud company its project and cluster, a provider its
  customer. A fixed header loses them; a list with no types gives rules
  nothing to test.
- **An entity has several identifiers.** A machine is its host name, its
  addresses, its MAC, the identifier its agent gives it; a person is a
  short name, a qualified name, an email address, a SID, an object
  identifier of a directory.
- **Not every entity is a workstation or a person.** In a cloud the things
  that act are instances that live for minutes, and service accounts and
  workload identities; they outnumber the people.
- **Context holds for a time.** An address is another machine tomorrow, a
  cloud address within minutes; a person leaves, and the account that then
  signs in is the finding.
- **One address range is used twice.** 10.0.0.0/8 is in every branch, every
  acquired company, and every customer of a provider.
- **More than one source describes the same thing**, the CMDB and the
  directory and the scanner, and they disagree.

### Cases the model must serve

- A bank: a teller's workstation connects to a Tor exit node. The finding
  must say that the machine is in the cardholder data environment and whose
  it is; the same connection from the guest wireless network is noise.
- A company in a cloud: an instance that existed for six minutes resolved a
  domain of a botnet. Its address now belongs to another instance. The
  finding must name the instance by its identifier, with its project,
  service, and the identity it ran as, as they were at that time.
- An account signs in a week after its owner left the company. Nothing in
  the event is wrong; the context is the finding.
- A service account that runs a nightly job opens an interactive session.
  The finding must say that it is a service account.
- A provider, or a group after a merger: 10.1.2.3 matches in two customers'
  events. Each finding must get the context of its own customer.
- The CMDB says a server belongs to one team and the cloud's tags say
  another. The analyst must see both, and which said what.

## Decision

**The snapshot holds records of five kinds: networks, assets, identities,
groups, and context lists. A record has a small set of typed fields, named
as OCSF names them, and any labels the site adds; it is found by any of
its identifiers, within a scope, at the time of the event. Records are read
from files a site exports, each described by a definition that maps the
site's own columns. The detector writes every record found for a matched
event into the finding as an OCSF enrichment, one for each source, with the
source's version.**

### What it holds

| Kind | Found by | Typed fields |
| --- | --- | --- |
| Network | An address inside its range; the narrowest range wins | `name`, `zone`, `region`, `site` |
| Asset: a machine, or a cloud resource | Host name, address, MAC, or an identifier such as an agent's, an instance's, or a resource name | `type`, `owner`, `org`, `criticality`, `is_managed`, `zone`, `region` |
| Identity: a person, or an account that is not one | Any form of its name, an email address, a SID, or an identifier of a directory | `type`, `org`, `department`, `manager`, `criticality`, `is_privileged`, `is_enabled` |
| Group | Its name or identifier | `name`, `type`, `is_privileged` |
| Context list | A value of the list's kind, as an indicator is found | The list's name and the row's label |

- `type` says what the entity is: for an asset a server, a workstation, a
  network device, a container, a cloud instance, and the other values of
  OCSF's device type; for an identity a person, an administrator, a service
  account, or a workload identity.
- `criticality` is 1 to 4, on assets and identities alike. It is the one
  field every system acts on, and M5 can raise a finding's severity by it.
- **Labels** are the rest: names and values the site chooses, such as
  `pci_scope: cde`, `project: payments-prod`, `information_system: core
  banking`. They are kept as given, written into the enrichment, and can be
  tested by name. A site's model is its typed fields and its labels, and
  no release of the platform is needed to add one.
- A record names its groups, and a group is a record of its own, so that
  `Domain Admins` is said to be privileged once.

### How a record is found

- **By any of its identifiers.** A record lists as many as its source
  knows. A value of an event is looked up as the kind of identifier it is:
  an address as an address, a host name as a host name. The forms of a
  user's name are canonical as indicators' are, so `CORP\adam` in the file
  matches `corp\Adam` in an event.
- **At the time of the event.** A record may say from when and until when
  it holds. A lookup is made for the event's time, so a look back over
  stored events gets the context of that day, and an account that ended
  before the event is found as ended. A record with no times holds always.
- **Within a scope.** A source of records may name a scope, such as a
  customer, a subsidiary, or a site, and an event has the scope of the
  source it was collected from. A record with a scope is found only for
  events of that scope; a record without one is found for all. A site with
  one address space sets none.
- An asset found by an address is right only while the address is its own.
  For machines whose address changes, the source lists host names or
  identifiers, or gives each address the time it was held.

### Where it comes from

- Networks, assets, identities, and groups are files in CSV or JSON lines
  that the site exports from where it keeps them: a CMDB, a directory, an
  IPAM, a cloud's inventory. Each file has a **definition**, as a feed
  has: which kind of record it holds, which of its columns are the
  identifiers and the typed fields, which become labels, and its scope.
  The site's export is read as it is, under its own column names.
- A file is read at start and when it changes, and replaces all the
  records of its source at once.
- A context list is a feed definition marked as context. It is fetched,
  pinned, and versioned as any feed, and its values go to the snapshot and
  not to the indicator store, so it can never raise a finding.
- Definitions ship for the exports most sites have, and are written as
  they are met: Active Directory and Entra ID users and groups, and the
  inventories of the large clouds.
- When PostgreSQL arrives in M4.5 it is one more source of the same
  records, and so are connectors that fetch from a CMDB or a directory.
  Neither changes the model.

### When sources disagree

- Records are not merged. Two sources that describe one machine give two
  records, and a finding gets both, each under its source's name.
- This is what the indicator store does with feeds, for the same reason:
  the analyst sees who said what, and a wrong source is found and fixed in
  place of being averaged away.
- Where one value is needed, as for `criticality` when M5 acts on it, the
  highest is taken.

### What a finding gets

- The detector looks up the addresses, host names, user names, and
  resource identifiers among the matched event's observables, the matched
  one included.
- Each record found becomes one entry of the finding's `enrichments`: the
  kind of the value as `name`, the value as `value`, the kind of record as
  `type`, the source and its version as `provider`, and the record's typed
  fields and labels as `data`. A reader that knows OCSF's device and user
  objects knows the names in `data`.
- At most 32 entries are written for one finding, networks and assets
  first. An event that names more than that is a scan or a list, and its
  context is in the event.
- A value found in nothing gets no entry. For an internal address that
  absence is worth seeing: the network's entry is there and no asset's is.
- The finding's identifier does not depend on its enrichments. A finding
  made twice, as the event arrived and later from the store, is stored
  once.

### How old the context is

- Each entry names the version of its source: when the file was written,
  or the revision of a pinned list. A finding says what was known when it
  was made, and is not rewritten when the snapshot changes.
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
| Typed fields in OCSF's names, labels for the rest, files mapped by a definition | Fits a site as it is; rules have fields to test; a finding is read by anything that reads OCSF | A definition to write for each export | **Chosen** |
| A fixed header the site must produce, as Splunk's lookups | Simple to document | What the product does not name is lost; every site reshapes its export | Rejected |
| Lists of any columns found by one key, as Sentinel's watchlists | Nothing to model | No field has a meaning, so no rule or interface can rely on one; one key only | Rejected as the model; labels take what is good in it |
| Merge the sources into one record for each entity | One answer | Hides which source said what; needs rules of precedence for every field; that is the entity graph's work in M4.5 | Rejected for M4 |
| Derive assets and identities from the events | Nothing to export | An owner and a criticality are in no event; resolution is M4.5 | Rejected for M4 |
| Query the CMDB or directory when a finding is made | Always current | A network call on the detector's path, forbidden by ADR-0003; no context of the event's own time | Rejected |
| Match context lists as indicators with a low confidence | No new kind of record | A finding for every connection to a VPN range; confidence then means two things | Rejected |
| Add context to every event | Searches by context need no join | Decided against in ADR-0021 | Rejected |

## Consequences

- A finding answers the first questions asked of it in one place, in
  names another OCSF tool reads, and can be sorted by criticality, zone,
  and privilege.
- A site keeps its own words. What it calls a thing is a label, and
  arrives in the finding as it was written.
- A site has exports to schedule and a definition for each. An export that
  stops leaves context that is quietly old, which the age metric is there
  to show.
- The typed fields are a contract from the first release: rules in M5 and
  the interface read them. They are added to, not renamed. Labels are the
  site's contract with itself.
- Time and scope make a lookup more than a map from a key: each is a
  filter over the records a key gives. Most keys give one record.
- Two sources give two entries, and a reader that wants one answer must
  choose. That cost is taken to keep the provenance.
- Events are not enriched. A search for every event of critical assets
  needs the join ADR-0021 leaves until the interface asks for it.

## When to revisit

- If a snapshot of 10^6 assets and identities takes more than 1 GiB in
  memory or more than 30 seconds to replace, move the bulk load to sorted
  files written beside the store, as for indicators.
- If more than one finding in ten reaches the limit of 32 entries on a real
  site's events, choose what to keep by the kind of event, not by order.
- If the same label is asked for by name at three sites, make it a typed
  field.
- If a site cannot say which address a machine held when, and its findings
  name the wrong machine more often than one time in a hundred, take
  address leases from the events, DHCP and the cloud's own, as Google
  Security Operations does.
- When the entity graph resolves identities in M4.5, the forms of a name
  come from it, and merging is decided there.

## Sources

- Splunk Enterprise Security, asset and identity lookups:
  <https://docs.splunk.com/Documentation/ES/6.3.0/Admin/Formatassetoridentitylist>,
  <https://docs.splunk.com/Documentation/ES/6.0.1/Admin/Assetandidentityfields>
- Microsoft Sentinel, the `IdentityInfo` table and UEBA:
  <https://learn.microsoft.com/azure/sentinel/ueba-reference>
- Google Security Operations, the entity context graph and enrichment:
  <https://docs.cloud.google.com/chronicle/docs/event-processing/entity-graph>,
  <https://docs.cloud.google.com/chronicle/docs/event-processing/data-enrichment>
- Elastic Security, the entity store and asset criticality:
  <https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/entity-store>
- OCSF, the device object: <https://schema.ocsf.io/1.3.0/objects/device>
