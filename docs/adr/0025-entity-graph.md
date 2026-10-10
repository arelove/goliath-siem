# 0025. The entity graph: what an entity is, how it is resolved, and where it is kept

- **Status:** Accepted
- **Date:** 2026-10-10

## Context

An event names things: an account, a machine, an address, a domain, a file.
A finding names the same things, and the analyst who opens it asks about
them and not about the row: what else did this account do, which machines
did this address belong to, how did the two meet. Today each such question
is a search written by hand, and the same account under another name is
not found by it.

The roadmap's M4.5 asks for four things: a model of entities and links, the
resolution of one entity under the identifiers each source gives it, a
store, and an API. Its review notes ask three questions this record must
answer before any of it is built:

- Where entities and links are kept.
  [ADR-0003](0003-data-boundary.md) and
  [ADR-0020](0020-state-beyond-events.md) put identity decisions in
  PostgreSQL; the roadmap puts entities and links in ClickHouse and asks
  that a merge can be undone.
- How an address is tied to a machine when the address changes hands, and
  what a false merge costs.
- What bounds a walk of the graph, since two links from a domain
  controller reach most of a company.

Earlier records already hold part of the answer.
[ADR-0022](0022-context-snapshot.md) says that an entity has several
identifiers, that context holds for a time and within a scope, and that
sources which disagree are not merged; it leaves merging to this record.
[ADR-0024](0024-interface.md) needs an entity to open from any value, and
findings grouped under the entity they share.

### How the systems in use do it

| System | What an entity is | How identifiers become one entity | What its design shows |
| --- | --- | --- | --- |
| Microsoft Sentinel | Typed entities, such as Account and Host, each with a list of identifiers | An identifier is strong if it names one entity without doubt, and weak if it does so only at times. For an account `Sid`, `AADUserId`, and `Name` with `UPNSuffix` or `NTDomain` are strong, and `Name` alone is weak; for a host a name with its domain is strong and a bare `HostName` is weak. Entities are merged when a strong identifier matches. A SID of a built-in account is strong only with its host | Strength is a property of the identifier, decided once, and a weak identifier alone never joins two things. The same name on two machines, such as a local administrator, is two accounts |
| Elastic Security | A record for each host, user, and service, under an identifier built from the first complete one of an ordered list: for a host `host.id`, then `host.name`; for a user `user.email`, then `user.id`, then the name with its domain, within the provider it came from | A resolution group links records that are the same real thing. Links are made by a task for accounts that share an email address, or by a person, and are undone through the API. The records stay as they were; a risk score is counted for each account and again for the group | An identifier that can be computed from the event needs no lookup to write. Resolution is a layer of links over records that do not change, so undoing one loses nothing. Its authors name the failure both ways: several people blended into one entity, or one person split across many. Shared names such as `root` and `admin` are excluded |
| Google Security Operations | Assets, users, resources, and groups in an entity context graph | Records that share a host name, a MAC, an asset identifier, a user identifier, a SID, an email address, or an employee number are merged. Aliases between host names, MACs, and addresses are built from DHCP events. Entities are timed or timeless, and a timed one is read for the time of the search or the rule | An address means a machine only for a time, and the leases are in the events. Merging on any shared key is simple and has no guard against a key that is shared by accident |
| Splunk Enterprise Security | Rows of the asset and identity lookups | Rows that share a value in a key field are merged into one, their other fields becoming lists of values. Merging can be turned off, the key field changed, or the rows placed in different zones | Its users report assets that carry every category and several addresses after a merge, and wrong alerts from them. A merge that rewrites the record cannot be told from the truth afterwards, and the only remedy offered is to turn merging off |
| Microsoft Defender XDR | Nodes and edges of an exposure graph, read as two tables in hunting queries | Built by the platform from its own products | A graph kept as a table of edges, with a label and the two ends on each row, is queried with what queries everything else |
| BloodHound | Nodes with kinds and directed edges with kinds, in a graph a site can extend | Not applicable: its identifiers are a directory's | Every edge has a direction and one kind, and the direction is the direction of access. Its full support moved to PostgreSQL, a relational store |

Seven things follow, and each is a requirement:

- **Strength belongs to the identifier.** A SID, an object identifier of a
  directory, and a name with its domain name one account. A bare name, a
  short host name, and an address do not.
- **A false merge is worse than a missed one.** A missed merge shows one
  person as two rows, which an analyst can see and join. A false merge
  shows two people as one, hides both, and blends what each did; no row
  says that it happened.
- **A merge must not rewrite what was seen.** Where the merged record
  replaces its parts, the merge cannot be explained or undone. Where it is
  a link over parts that stay, it can be both.
- **An identifier that can be computed needs no lookup.** What is written
  as events arrive must not wait for a decision about identity.
- **An address is a machine for a time.** The times are in the events, as
  leases and as records that name a machine and its address together.
- **Some identifiers are shared.** `root`, a kiosk's account, a shared
  mailbox, the address of a gateway. A rule that joins on them joins
  everything.
- **Some nodes touch everything.** A domain controller, a resolver, a
  proxy. A walk through one is the whole company.

### Cases the model must serve

- One person signs in to Windows as `CORP\adam`, to the cloud as
  `adam@corp.example`, and is in the directory under an object identifier.
  A finding about any of the three must show what the three did.
- The same person has an administrator account, `CORP\adm-adam`, with
  another SID. It is another account and the same person, and the analyst
  must see both facts.
- `Administrator` exists on every workstation with the same well known
  SID. A sign in as `Administrator` on two machines is two accounts.
- A laptop holds 10.20.4.17 in the morning and another holds it in the
  afternoon. A connection from that address at noon belongs to the first.
- 10.1.2.3 is used in two customers of a provider. It is two addresses.
- A shared mailbox is the email address of forty accounts in an export. It
  must not make them one person.
- An analyst sees that two accounts were joined wrongly. They must be able
  to see why they were joined, to part them, and to see everything each did
  apart, as if the merge had never been made.
- From a compromised account, an analyst asks what is within two links.
  One of its links is to a domain controller. The answer must say that the
  controller is there and how much is behind it, and not return it all.

## Decision

**What events show is kept as it was seen, under the identifiers the events
give: which identifiers were seen as one thing, and which things were seen
to act on which. It is derived in the stream and stored in ClickHouse
beside the events. Which identifiers are one entity is decided from that
evidence by rules, at rest, as a mapping with its reasons, and is applied
when the graph is read. Nothing seen is rewritten by a merge, so a merge
is explained by the rows that made it and undone by removing it. What a
person decides about identity is a file of the site's content until M6
gives the platform users, and PostgreSQL does not arrive with M4.5.**

### What an entity is

| Kind | What it is | Its identity |
| --- | --- | --- |
| User | An account: of a person, of a service, of a workload | Resolved from its identifiers |
| Host | A machine, or a resource of a cloud that acts as one | Resolved from its identifiers |
| Address | An IP address | The address, within a scope if it is private |
| Domain | A DNS name | The name |
| File | A file's content | Its hash |
| Process | One run of a program on a host | The host and the identifier the source gives the run, or its PID with its start |

- A user and a host have several identifiers, and resolution is about
  these two kinds. An address, a domain, and a file are their own value:
  nothing is resolved, as nothing is for an indicator.
- An entity has a `type` in the words of ADR-0022: a person, a service
  account, a workstation, a cloud instance. It comes from context and is
  not part of the identity.
- **A person is not a kind.** A person's accounts are joined by the rules
  below when the evidence says they are one person's, and the entity then
  holds several accounts. The accounts stay told apart inside it.
- **A process is not stored in the graph.** A run of a program is the most
  numerous thing there is and lives for seconds. What it did is linked to
  its host and its user, with the events as evidence, and the process is
  reached through those events. The kind exists so that an API and an
  interface can name one.

### Identifiers and their strength

| Kind | Strong | Weak |
| --- | --- | --- |
| User | A SID that is not well known; an object identifier of a directory; a name with its domain, as `CORP\adam` or `adam@corp.example`; an email address | A bare name; a well known SID |
| Host | An identifier an agent or a directory gives the machine; an instance identifier of a cloud; a host name with its domain | A short host name; a MAC; an address |

- Identifiers are of the kinds ADR-0022 already has, and are made
  canonical as it says: `corp\Adam` and `CORP\adam` are one.
- A weak identifier is made strong by what it is found beside: a bare
  name, with no strong identifier in its object, is a local account of the
  host it is on, and a short host name is strong within a scope whose
  definition says its short names are unique.
- A well known SID makes no account. Windows writes the system account
  under the machine's own account of the domain, as `CORP\DC-01$` with
  `S-1-5-18`, so an account made of the SID and the host would join that
  name to every machine it is seen on. `S-1-0-0`, which Windows writes
  where there is no account, is not an identifier at all. Both were found
  on the fixtures of the Windows Security log.
- **An entity is referred to by any of its identifiers**, written as kind,
  kind of identifier, and value, such as `user:sid:S-1-5-21-...`. No
  identifier is made up for it. The one shown first is its strongest, by a
  fixed order, so that it does not change when a weaker one is learnt.
- Every identifier is within the scope of the source that gave it, as in
  ADR-0022. Public addresses, domains, and hashes have no scope.

### What is derived from an event

Two kinds of rows, and both are counts over a span of time, not a row for
each event:

- **A claim**: two identifiers seen as one thing. They were in one object
  of one event, such as a sign in that names a SID and a name with its
  domain, or in one record of context, such as a row of a directory's
  export. A claim holds the two identifiers, the rule that read them, how
  often and from when until when they were seen together, and the first
  and the last event that showed it.
- **A link**: one thing seen to act on another. It has a kind and a
  direction, from the one that acted.

| Link | From | To | Read from |
| --- | --- | --- | --- |
| `logged_on_to` | User | Host | Authentication |
| `ran_on` | User | Host | Process activity, with the program's file as evidence |
| `ran` | Host | File | Process and module activity |
| `wrote` | Host | File | File activity |
| `connected_to` | Host | Address | Network activity |
| `resolved` | Host | Domain | DNS activity |
| `resolved_to` | Domain | Address | DNS answers |
| `held` | Host | Address | DHCP, and any object that names a machine and its address together |

- The ends of a link are identifiers, not entities. A link is written
  under the strongest identifier the event gives for each end.
- A link is counted by the hour: its ends, its kind, the hour, how many
  events, the first and the last time, and the first and the last event.
  The events behind a link are found by a search for its ends in its time,
  which the row is enough to write.
- Which attribute of an event is which kind of thing is read from the
  types of the OCSF schema, as indicators' observables are, and which
  class gives which link is a table versioned with the schema.
- `held` is a link and never a claim. An address is not an identifier of
  a machine: it is something the machine held for a time.

### Where it is derived

- A role of its own reads the normalized events beside the writer, as the
  detector does under [ADR-0015](0015-pipe-semantics.md), and never slows
  storage. It gathers the claims and links of a batch, adds up those that
  repeat, and sends the rows through the pipe to the writer.
- If it falls behind and is moved past events, it notes the range of
  receipt time they lie in and reads those events back from the store, as
  the detector does.
- What was stored before the role first ran is read the same way: at its
  first start it asks the store where what it holds begins, and notes
  everything from there up to where it began to read the stream. A site
  that turns the role on has its history in the graph, and a setting
  bounds how far back.
- Rows that repeat are added up again in ClickHouse. An event read twice
  is counted twice: the count of a link is a number to look at, as the
  counts of an overview are, and not one to audit. That a link exists,
  when it was first and last seen, and which events those were do not
  change by a second reading.

### How identifiers become an entity

Resolution runs at rest, on a schedule and when asked, over the claims:

1. **Two strong identifiers in one claim are one entity.** This is the
   only rule that joins.
2. **A weak identifier joins nothing.** It belongs to the entity of the
   strong identifier it was claimed with, within the scope and for the
   time it was seen, and one weak identifier may belong to many entities.
   Seen alone it is an entity of its own, marked as provisional.
3. **A shared identifier is no evidence.** An identifier claimed with more
   strong identifiers of one kind than a limit, three by default, is
   marked as shared, and its claims join nothing. This is the mailbox of
   forty accounts and the name `svc-backup` on every server. Names known
   to be shared, such as `root` and `Administrator`, and the well known
   SIDs, are shared from the start.
4. **A person's word is last.** A file of the site's content says that two
   identifiers are the same or are not. "Not the same" removes the
   evidence between them, and what each side did parts again.

- The result is a mapping from every identifier to its entity, with a
  version, and for every pair joined the claim that joined them. It is a
  table in ClickHouse, read as a dictionary.
- **The mapping is applied when the graph is read.** Links are stored
  under identifiers and stay there. A merge changes which rows are read
  together and no row itself, so undoing it restores exactly what was
  there before.
- An event that names only an address is given to the machine that held
  the address at the event's time, through `held`, when it is read. The
  answer says that it was found by the address, and by which lease.

### Where it is kept

| What | Where | Why |
| --- | --- | --- |
| Claims and links | ClickHouse, in tables that add up rows of one key | They are counts of events, as many as events make them, and are read with the events |
| The mapping from identifiers to entities | ClickHouse, a table replaced with each version | It is computed from the claims and can be computed again |
| What a person says is or is not the same | A file beside the rules and the allowlists, until M6 | It is reviewed and versioned as they are, and has an author by the history of the file |

- Links are kept as long as the events are, since a link without its
  events cannot be explained. Claims are kept for a year by default: an
  identity outlasts the events that showed it.
- The table of links is sorted by the end that acted, with a second order
  by the other end, so that both directions of a walk read neighbouring
  rows.
- **PostgreSQL does not arrive with this milestone.** ADR-0020 placed
  identity decisions there because a merge had to change several rows
  together and be undone. With a merge that changes no row, nothing has
  to change together. The decisions of people need users and roles to be
  more than a file, and those come with M6, where PostgreSQL arrives for
  cases. The decisions move there then, and the file is their import.

### What the API answers

Under the discipline of [ADR-0016](0016-event-search.md): every request is
checked before a query is written, every value is a parameter, and every
query is read-only and within limits.

- **An entity**, by any of its identifiers: all of them, with the claim
  behind each, its records of context, and when it was first and last
  seen.
- **Its neighbours** within a time range, optionally of some kinds of
  link: for each, the kinds of link, the counts, the first and last time.
- **What lies within two links** of an entity within a time range: the
  entities reached, each with its distance, and the links between them.
- **A path** between two entities within a time range, of four links at
  most. It is searched from both ends, a whole step at once, so that the
  path found is a shortest one within the bounds.

Three bounds hold for every answer:

- **Time.** No request is without a range, and the range has the limits a
  search has.
- **Size.** Neighbours are returned most recent first, 100 by default and
  1,000 at most, and the answer says how many there are in all.
- **Degree.** A node with more neighbours in the range than a limit is a
  hub. It is returned, with its degree, and is not walked through: its own
  neighbours are given only when it is asked for by name. A path does not
  pass through a hub unless the request allows it.

A walk is made by the API one step at a time, each step one bounded query,
and not as a recursive query in the store: the bounds apply between steps.
A step is made from a bounded number of entities and reads a bounded
number of rows, and an answer that a bound cut short says so: "no path"
and "no path found within the bounds" are different answers. The hubs a
path met and did not go through are named in its answer.

### How it is measured

The exit criterion of M4.5 is made testable:

- Resolution is measured on the generator's stream against its ground
  truth, over pairs of identifiers: precision is the share of joined pairs
  that are truly one entity, and recall the share of true pairs that were
  joined. They are reported apart and never as one number. The target is
  a precision of 0.999 and a recall of 0.95, and the first is the one that
  may not be missed.
- The generator gains the cases that make the measurement honest: address
  leases that change hands within the day, a machine used by several
  people, an account whose name is used again after its owner left, a
  shared mailbox, and local accounts of one name on every machine.
- The time of an answer is measured for the neighbours within two links of
  an alert's subject, on a named size of organization and day of events,
  with the bounds above. The target is one second.

### Order of building

1. The identifiers: kinds, strength, canonical forms, and reading them
   and the claims and links from an event, tested on every source's
   fixtures.
2. The tables, the role that derives the rows, and the writer storing
   them.
3. Resolution at rest: the mapping, its reasons, and the file of a
   person's word. The measurement against the generator's truth.
4. The API: an entity, its neighbours, a path.
5. The interface: the Entity view, findings grouped by entity, and "open
   its entity" in the menu of a value.
6. The generator's hard cases, and the exit measurement.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Observed rows under identifiers, a mapping decided at rest and applied at read | A merge rewrites nothing, so it is explained and undone; nothing waits for identity as events arrive; resolution can be improved and run again over what is stored | Every read of the graph joins through the mapping; two layers to explain | **Chosen** |
| Resolve in the stream and write events and links under an entity identifier | Reads need no join | A wrong merge is in every row written since, and undoing it is a rewrite of history; the stream waits for a lookup; a rule that improves cannot be applied to what is stored | Rejected |
| Merge records on any shared key, as Google Security Operations and Splunk do | Simple; high recall | No guard against a key shared by accident; Splunk's users turn it off | Rejected |
| Resolve by likeness of names, with a score | Finds what no identifier shows, such as `adam` and `adam.smith` | A score is not a reason an analyst can check, and a false merge is the costly error | Rejected for joining. It may propose pairs for a person to decide |
| Entities and identity decisions in PostgreSQL now, as ADR-0020 has it | One home for all mutable state | A second server in every installation, for decisions a file holds until there are users to make them | Deferred to M6 |
| A graph database for nodes and edges | Walks are its native query | A third engine to run, back up, and keep in step with the events; the walks asked for are two to four steps with bounds, which a sorted table answers | Rejected |
| Recursive queries in ClickHouse for walks | One query | The bounds on degree cannot be applied between steps; a dense graph makes the query's cost unknown before it runs | Rejected |
| A stored node for each process | The model of the roadmap as written | More rows than any other kind, each alive for seconds, each already an event | Rejected. Processes are reached through their events |
| An address as an identifier of a host | Events that name only an address find their machine with no further step | The address is another machine tomorrow, and a merge by it joins both | Rejected. `held` is a link with its times |

## Consequences

- An analyst can ask of any entity why it is one: every identifier it has
  is there by a claim, and every claim names a rule, a count, and the
  events that showed it.
- A wrong merge is corrected in a file and is gone at the next run of
  resolution. Nothing else needs repair.
- Resolution can change, by a new rule or a new limit, and be run over
  everything stored. Entities then change under the same findings, and a
  finding names its entities by identifiers for that reason.
- Recall is given up for precision. An account seen only under a bare name
  stays apart until a source names it fully, and the interface must show a
  provisional entity as what it is.
- A read of the graph is a join through the mapping. This is the cost of
  not rewriting, and it is measured in the exit criterion.
- One more role runs, and one more topic carries its rows. A site that
  wants no graph does not start the role.
- ADR-0020's table changes in one row: identity decisions are a file until
  M6. ADR-0003's picture, entities in PostgreSQL, is true of the decisions
  of people from M6 on and of nothing else.
- The roadmap's list for M4.5 changes: processes are not stored objects,
  and the exit criterion names its sizes and its bounds.
- ADR-0022's snapshot gains nothing and loses nothing. Its records are
  context, found by identifiers, and are one source of claims.

## When to revisit

- If precision on the generator's hard cases is under the target with
  these rules, tighten what is strong before adding any rule that joins.
- If recall is under the target because sources name accounts by bare
  names, let a definition of a source say which domain its names are in,
  before considering likeness of names.
- If the join through the mapping makes the two link answer slower than
  the target, write the entity beside the identifiers in the rows of
  links for the current version of the mapping, as a column that is
  rebuilt, and keep the identifiers as the truth.
- If the rows of links for a day are more than a tenth of the events of
  that day on a real stream, count by the day in place of the hour for
  links older than a week.
- If a site needs a walk longer than four links or a query over the whole
  graph, such as every path to a critical asset, that is the work of an
  attack path tool, and the answer is an export of the links in a form
  such a tool reads.
- When M6 brings users, a person's decision is made in the interface, is
  kept in PostgreSQL with its author, and the file becomes its import.

## Sources

- Microsoft Sentinel, entities and their strong and weak identifiers:
  <https://learn.microsoft.com/azure/sentinel/entities>,
  <https://learn.microsoft.com/azure/sentinel/entities-reference>
- Elastic Security, the entity store, its identifiers, and resolution:
  <https://www.elastic.co/security-labs/entity-resolution-identity-scoring-elastic-security>,
  <https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/entity-store>
- Google Security Operations, the entity context graph and aliasing:
  <https://docs.cloud.google.com/chronicle/docs/event-processing/entity-graph>,
  <https://docs.cloud.google.com/chronicle/docs/event-processing/overview-of-aliasing-and-enrichment>
- Splunk Enterprise Security, merging of assets and identities, and what
  its users report of it:
  <https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/asset-and-identity-validation/overwrite-asset-or-identity-data-with-entitymerge-in-splunk-enterprise-security>,
  <https://community.splunk.com/t5/Splunk-Enterprise-Security/How-to-avoid-mixng-values-of-assets-by-entitymerge-command-in-ES/m-p/476348>
- Microsoft Defender XDR, the exposure graph as a table of edges:
  <https://learn.microsoft.com/defender-xdr/advanced-hunting-exposuregraphedges-table>
- BloodHound, the model of nodes and directed edges:
  <https://bloodhound.specterops.io/opengraph/schema>,
  <https://specterops.io/blog/2025/08/01/attack-graph-model-design-requirements-and-examples/>
- GitLab, a graph queried in ClickHouse over tables of edges sorted both
  ways:
  <https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/gitlab_knowledge_graph/querying/graph_engine/>
- TigerGraph, on entities resolved too far:
  <https://tigergraph.com/blog/how-over-resolved-entities-suppress-alerts/>
- ClickHouse, recursive queries and their limits:
  <https://clickhouse.com/docs/reference/statements/select/with>
