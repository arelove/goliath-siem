# 0024. The interface

- **Status:** Proposed
- **Date:** 2026-10-10

## Context

The interface has three views today: an overview with charts of what was
stored, a search over events with a table and an event's full record, and
the health of sources. They were built as the base of M7, one at a time, as
the data for each came to exist. M4 added findings with context, and
[ADR-0023](0023-platform-health.md) adds the health of the platform. Before
more views are added one at a time, this record decides what views there
are, how a person moves between them, and how they look.

### How the systems in use do it

| System | What an analyst works in | What its design shows |
| --- | --- | --- |
| Splunk Enterprise Security 8 | An analyst queue: one table of findings and investigations. A side panel shows a finding, changes its status and owner, and starts an investigation, without leaving the queue. Findings added to an investigation are nested under it and leave the queue. Later releases added saved views and queues for a team | The queue is the place of work, and what is decided there is decided in a panel beside it. What is already part of an investigation must stop being a row of its own |
| Elastic Security | Any alert, event, host, or user opens in a flyout over the page. A value in it can be filtered in, filtered out, added as a column, or sent to Timeline, a workspace that stays at the bottom of every page | A person keeps their place. Every value offers the same few actions wherever it is shown. What is collected during an investigation needs a place that outlives the page |
| Microsoft Sentinel in the Defender portal | An incident page with the list of its entities; an entity opens a side panel with what is known of it, its timeline, and insights, each with the query behind it. Entity pages are reached from incidents, the graph, and search | An entity has one page, reached from everywhere. An insight that shows its query can be checked |
| Google Security Operations | An alert page with an overview, a graph of its entities with a card for each, and its history. Search returns events with the context of entities. A question in plain language becomes a search that is shown | The graph is one tab of an alert, not the first thing seen. What a model writes is shown as the search it wrote |
| Wazuh | An overview of counters, alerts over time by level, the agents and rule groups with most alerts, and ATT&CK tactics. Every part of every chart is a filter: selecting one narrows the whole page | A chart is a way in, not a picture. Its users ask for views fitted to a role, and for alerts that are joined into incidents, which it does not do |
| IBM QRadar | Tabs of offences, log activity, and network activity | Its reviews name the interface more than those of any other: basic, dated, in need of extensions to be usable. An interface is part of what a product is judged by |

What those who work in these systems say, in what was read for this record:

- Most of an analyst's time on an alert goes to collecting what is known of
  it. A survey paid for by a vendor gives 85 percent of analysts who spend
  significant time linking evidence; a study of analysts at work describes
  the same thing, done by hand across a SIEM, public sources, and internal
  tools.
- False positives are the first complaint of detection, in 73 percent of
  the organisations a SANS survey asked.
- A platform that is several products behind one name feels like several
  products. Analysts asked of Sentinel and Defender said so.
- A number that cannot be traced to its rows cannot be shown to a manager.
- Alerts that are merged with no way to see why lose what an analyst needs.

Seven requirements follow:

- **What needs a decision is first.** Not a picture of the data.
- **A person keeps their place.** Detail opens beside the list, not in
  place of it.
- **Every value is a way on.** An address, a host, a user, or a hash offers
  the same actions wherever it is shown.
- **Context is there already.** What the site knows of a value is in the
  finding ([ADR-0022](0022-context-snapshot.md)); the interface shows it
  and does not make the analyst look for it.
- **Every number opens its rows.** A counter, a bar, and a cell of a matrix
  each lead to the search that counted them.
- **A view is a link.** What is on the screen can be sent to another person
  as an address.
- **One product.** One shell, one time range, one way of showing a state,
  whether the view is about events or about the platform.

### Cases the answer must serve

| Who | What they do | What it asks of the interface |
| --- | --- | --- |
| An analyst on shift at a bank | Decides some hundreds of findings a day | A queue worked by keyboard, dense, with a decision in one key |
| An analyst at a company with one security engineer | Opens the interface twice a day | The first view says in ten seconds whether anything needs them |
| A detection engineer | Asks whether a rule fires and on what | From a rule to its findings, and to coverage of ATT&CK |
| Whoever runs the platform | Asks what is broken | Platform health in the same shell, not another product |
| A stranger with their own logs | Starts the platform for the first time | A first view that is useful with no findings yet, and says what is missing |
| A site with no route to the Internet | Runs it on an isolated network | No font, script, or map fetched from anywhere but the product |

## Decision

### The views

| View | What it answers | State |
| --- | --- | --- |
| Overview | What needs a decision, whether data arrives, whether the platform is well | Exists, about events alone; rebuilt around these three |
| Findings | The queue: what was found, most severe and newest first | New |
| Search | Events, by time, class, and any path | Exists |
| Entity | Everything about one user, host, address, domain, or file | New, with M4.5 |
| Cases | Findings that belong together, and what was decided | With M6 |
| Coverage | For each ATT&CK technique, whether a rule covers it and whether its data arrives | New; the data exists in `goliath-attack` |
| Platform | Sources and their health, roles, flows, feeds, and exports of context | Sources exist; the rest follows ADR-0023 |

- Overview is the first view. The roadmap named coverage as the landing
  view; coverage is what a detection engineer asks for, and the person who
  opens the interface most asks what needs them now. Coverage is a view of
  its own.
- Overview is made of charts, as Wazuh's is, and every part of every chart
  is a link: a bar of findings by severity opens the queue with that
  severity, a point in time opens that hour.
- With no findings, Overview says what would give some: which sources
  send, which feeds are loaded, how many rules can fire on the data.

### The shell

- A rail of views on the left, which can be reduced to icons.
- A bar on top with the time range and a field that finds a view, an
  entity, or a saved search, opened with `Ctrl+K`.
- One time range for every view. Changing view keeps it.
- Detail opens in a panel on the right, over the list it came from. A
  panel opened from a panel replaces it, and a line at its top leads back.
  The list keeps its place and its selection.
- The address holds the view, the time range, the filters, and the panel
  that is open. It can be copied and opened by another person, who sees
  the same thing if they are allowed to.

### From a finding to a decision

A finding's panel answers, in this order:

1. **What was found and why.** The rule or the indicator, the feed that
   asserts it with its confidence and its version, and the fields of the
   event that matched, marked.
2. **Who and what.** Each entity of the event, with what the site knows of
   it: owner, unit, criticality, the network it is in, the lists that name
   it. This is the finding's enrichments, read as written.
3. **What else.** Other findings about the same entities in the time
   range, and the events around this one on the same host.
4. **The event.** The full record, as the search view shows it.
5. **The decision.** Benign, expected, or malicious, with a note; or added
   to a case.

- The first four are built from what M4 stores. The decision needs a place
  to be kept, which is the case service of M6; until then the panel shows
  the first four and the queue has no status.
- Findings that share an entity within the time range are shown grouped,
  under the entity, and the group opens to its rows. Nothing is merged out
  of sight: the reason for a group is its heading.

### A value is a way on

Every value that names something, wherever it is shown, offers the same
menu:

- show findings and events that hold it;
- filter the current view to it, or to everything but it;
- open its entity;
- copy it.

The menu is one component. A view does not write its own.

### A number opens its rows

- Every counter, bar, slice, and cell is a link to the search that gives
  its rows.
- Every chart can show the search it was drawn from.
- A count of zero and data that is missing are shown differently: "0" and
  "no data, since 10:02" are not the same statement.

### States

Every view and every panel has five states, each drawn on purpose: loading,
loaded, empty with the reason, failed with what failed, and stale with the
time of what is shown. A view never shows an empty table with no words.

### Keyboard

- `j` and `k` move in a list, `Enter` opens the panel, `Esc` closes it.
- `/` goes to the filter, `Ctrl+K` to the field that finds anything.
- A decision in a finding's panel has one key each.
- Everything a pointer can do, keys can do.

### How it looks

The palette until now was warm graphite with bronze as the product's
colour. Bronze reads as orange, orange is what most systems use for high
severity, and a product's colour that looks like a severity is a fault.
It is replaced.

- **Dark first.** A security operations room is dark and the screen is
  read for hours. A light theme stays, with the same tokens.
- **Neutral, cool, and layered.** The ground is near black with a small
  share of blue. Surfaces above it are told apart by lightness, in three
  steps, not by lines and not by shadow.
- **One accent, blue.** It marks what can be acted on and what is
  selected, and nothing else. It is never a severity and never a state.
- **Colour that means something is kept for meaning.** Severity and state
  are the only other colours in the interface.

| Token | Dark | Light | Used for |
| --- | --- | --- | --- |
| `--bg` | `#0b0c0e` | `#f5f5f7` | The ground |
| `--panel` | `#141518` | `#ffffff` | A surface |
| `--raised` | `#1c1d21` | `#f0f0f3` | A surface above a surface |
| `--line` | `#26282d` | `#dedee3` | Where a line is needed |
| `--text` | `#f2f3f5` | `#1d1d1f` | Text |
| `--muted` | `#8b8d98` | `#6e6e73` | Text that is secondary |
| `--accent` | `#0a84ff` | `#0071e3` | What can be acted on, what is selected |
| `--critical` | `#ff453a` | `#d70015` | Severity: critical; state: failing |
| `--high` | `#ff9f0a` | `#c93400` | Severity: high |
| `--medium` | `#ffd60a` | `#a05a00` | Severity: medium; state: degraded |
| `--low` | `#7d8fa9` | `#5b6b82` | Severity: low |
| `--info` | `#5c5e69` | `#a1a1a6` | Severity: informational |
| `--good` | `#30d158` | `#248a3d` | State: ok |

- The values are a start and are checked before they are merged: text at
  4.5 to 1 against its surface, a mark of a chart at 3 to 1, and the
  severities told apart by a person who does not see red from green.
- Severity is never colour alone. It has its word or its letter beside
  it, and its place in the order.
- **Type.** The system's own face: San Francisco on Apple's systems, Segoe
  on Windows, whatever the system has elsewhere. A monospaced face for
  values that are copied. Numbers in columns have one width. No font is
  fetched or shipped.
- **Shape.** Corners of 10 pixels on a surface and 6 on a control. A
  panel and the field that finds anything are the only things that lie
  over others, and the only ones with a shadow and a blurred ground.
- **Movement.** A panel and a change of chart take at most 200
  milliseconds, and none when the system asks for reduced motion.
- **Dense.** A row of a table is 28 pixels. An analyst reads rows, and
  space between them is rows not seen.
- The mark keeps its shape; its one coloured bar becomes the accent.
- The project's site takes the same tokens.

### Charts

| Chart | Used for |
| --- | --- |
| Bars over time, stacked by severity | Findings and events over the time range. Dragging across it sets the time range |
| Counter with a line of its history and the change from the period before | How many, and whether that is usual |
| Horizontal bars, the first ten | Hosts, users, rules, and sources with most |
| Ring | Parts of a whole, when there are five or fewer |
| Matrix of ATT&CK tactics and techniques | Coverage, and where findings fall |
| Heat of the hour by the day | When something happens, over weeks |

- They are drawn by the product on a canvas, as the charts that exist
  are. A library is not added for six kinds of chart.
- A chart has a table behind it with the same numbers, which a screen
  reader reads and a person can copy.
- Categories that are not a severity take colours from one list of eight,
  in a fixed order, so that a source has the same colour everywhere.

### Views for a role

Users of Wazuh ask for an overview fitted to a role. The answer here is a
saved view, not a builder of dashboards: a view, its filters, its columns,
and its time range, kept under a name, for one person or for all. A
builder of dashboards is a product of its own, and those who need one have
Grafana, which reads the same store.

### What it is built on

- TypeScript and React, as [ADR-0005](0005-languages-and-process-boundaries.md)
  decides, with the query and virtual list libraries already in use.
- Colours, sizes, and movement are tokens in one stylesheet. No library
  of components: the shell, the panel, the table, the menu of a value,
  and the charts are the product's own, and few.
- Every call goes to the API of the platform. The interface holds no
  state of its own but what a person prefers: the theme, the width of a
  panel, the columns.

### Order of building

1. The tokens, the shell with its rail and bar, and the palette, with the
   three views that exist moved into it.
2. Platform, as ADR-0023 is built.
3. Findings: the queue, the panel, the menu of a value.
4. Overview rebuilt on findings, sources, and platform.
5. Coverage.
6. Entity, with M4.5. Cases and the decision, with M6.

## Options considered

- **A builder of dashboards as the base**, as Kibana and what is built on
  it. Flexible, and the reason their users land on pictures and not on
  work. It also makes every view somebody's task to build. Refused; saved
  views answer the need named.
- **The store's own interface, or Grafana, in place of ours.** It costs
  nothing to build. A finding's panel, the menu of a value, and a
  decision are not things a dashboard has. Refused as the interface, kept
  as what a site may add.
- **A library of components**, such as MUI or Ant Design. Faster at
  first. It brings its own look, which is what its users are recognised
  by, and a weight of code for the few components used. Refused.
- **The graph as the first view of a finding.** It is what a demonstration
  shows. In the systems read it is a tab, and the list of entities with
  their context is what is read first. The graph comes with M4.5 as a
  part of the entity view.
- **Coverage as the landing view**, as the roadmap had it. It is the view
  that tells this product from others, and it is not what a person on
  shift opens the interface for. It keeps a place in Overview as one
  counter that leads to it.
- **Bronze kept, with other severities.** A severity scale with no orange
  is one its readers must learn again. Refused.

## Consequences

- The roadmap's list for M7 changes: Overview is the landing view, the
  queue of findings is named, Platform is a view, and coverage is not
  first.
- The first step touches every stylesheet rule that names a colour, the
  mark, the favicon, and the site, with no change to what any view does.
- The queue of findings needs findings from the API, which serves events
  alone today.
- A decision cannot be kept until M6. The queue is useful before that and
  is not complete.
- The product's own components are work a library would have saved, and
  five states for every view are more work than one.
- No dashboards made by a user. Those who ask are told of saved views and
  of Grafana.

## When to revisit

- If the six kinds of chart become ten, or one of them needs zoom and
  pan, weigh a library against the canvas code.
- If saved views do not answer what users ask for, weigh panels that a
  user arranges on Overview, and nothing wider.
- If a measurement shows the queue slow at 10^5 findings in the time
  range, group on the server.
- If people who use the interface say they cannot tell the severities
  apart, change the values; the tokens are the place for it.

## Sources

Read for this record on 2026-10-10. Where a page could be read only as a
summary, what is said of it is what the summary said.

- Splunk, release notes of Enterprise Security 8.0 and workflow updates of
  8.3 and 8.4: <https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.0/splunk-enterprise-security-release-notes/release-notes-for-splunk-enterprise-security>,
  <https://lantern.splunk.com/Security_Use_Cases/Advanced_Threat_Detection/Workflow_updates_in_Splunk_Enterprise_Security_8.3_Premier>
- Elastic Security, the interface and the details of an alert:
  <https://www.elastic.co/docs/solutions/security/get-started/elastic-security-ui>
- Microsoft, entity pages in Sentinel and investigating incidents:
  <https://learn.microsoft.com/en-us/azure/sentinel/entity-pages>,
  <https://learn.microsoft.com/en-us/defender-xdr/investigate-incidents>
- Tech Field Day, a round table on Microsoft Sentinel, October 2025:
  <https://techfieldday.com/?p=91969>
- Google Security Operations, investigating an alert:
  <https://docs.cloud.google.com/chronicle/docs/investigation/investigate-alert>
- Wazuh, the application shown on an attack, and what a user asks of it:
  <https://wazuh.com/blog/wazuh-app-overview-brute-force-attack/>,
  <https://groups.google.com/g/wazuh/c/ZBp3kkJicAQ>
- Reviews of IBM QRadar:
  <https://www.peerspot.com/products/ibm-security-qradar-pros-and-cons>
- A survey of analysts, paid for by Devo:
  <https://itbrief.news/story/soc-analysts-face-alert-overload-duplicate-effort-survey-finds>
- A study of analysts at work, NDSS:
  <https://dev.ndss-symposium.org/ndss-paper/auto-draft-735>
- The SANS survey of detection and response of 2025, as Rapid7 cites it:
  <https://www.rapid7.com/cdn/assets/blta100cd2d89588b66/6992f62d124cd30008fe7010/siem-e-book.pdf>
- Severity colours in a dark theme, an issue of GitLab:
  <https://gitlab.com/gitlab-org/gitlab/-/issues/581121>
- W3C, Web Content Accessibility Guidelines 2.1, contrast:
  <https://www.w3.org/TR/WCAG21/#contrast-minimum>
