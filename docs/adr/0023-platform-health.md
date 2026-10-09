# 0023. Platform health

- **Status:** Accepted
- **Date:** 2026-10-10

## Context

[ADR-0019](0019-source-health.md) decides how a source that stops sending
is noticed. It does not say what is wrong when the platform itself is the
cause: a collector that lost its link, a writer that the store refuses, a
normalizer that restarts every minute, a feed that was last fetched three
days ago. Each of these leaves searches that still answer and a platform
that looks alive.

What exists today:

- Every process serves its measures as Prometheus metrics: what it took,
  normalized, and stored, the backlog of each reader, the age of each feed
  and each export of context.
- `GET /api/v1/health` says that the API answers.
- Roles run in one process or in many ([ADR-0006](0006-deployment-topology.md)).
  A collector and a normalizer reach the pipe and nothing else; the writer
  reaches the pipe and the store; the API reaches the store alone. No
  process sees all the others.

That is enough for a site that runs Prometheus and writes its own alerts,
and it is not what the first person to start the platform has. M8's exit
criterion is a stranger who runs it against their own logs within ten
minutes; that person has no Prometheus, and needs to be told what is wrong
in the product.

### How the systems in use do it

| System | How health is told | What its design shows |
| --- | --- | --- |
| Splunk | A health report: a tree of features, each with indicators that have two thresholds, yellow and red. A feature is as bad as its worst indicator, and the top as bad as the worst feature. A forwarder that is missing is found by a table of the forwarders that were seen, built on a schedule | A tree with reasons at its leaves is read at a glance and can be opened to the cause. What is expected is learned from what was seen, not declared by hand |
| Elastic Fleet | Each agent has a status: healthy, unhealthy, updating, offline after five minutes without a check-in, inactive after a longer time. An agent's units report their own state and the agent's is taken from them | An instance that stops reporting is a state of its own, apart from one that reports a fault, and one that has been gone long enough leaves the view |
| Microsoft Sentinel | A table of health events, written when a connector changes from success to failure or back, with the reason. It is off until turned on, and covers some connectors | Health as events gives a history: since when, how often. Health that must be turned on and covers part of the platform is the complaint its users write of |
| Google Security Operations | Metrics of ingestion, with a heartbeat for each forwarder, and alerts on a metric's absence in the cloud's monitoring service | Absence is the signal for what is silent. Setting it up in another product is the cost its documentation names |
| Cribl Stream | Each source and destination is green, yellow, or red, with its errors behind it. Backpressure is told when a destination was blocked for a share of a window, not at an instant, and a queue on disk when it passes a share of its room | Health belongs to each end of a flow. A share of a window does not flap. How full a buffer is says more than that it is in use |
| Kubernetes | Conditions: a type, a status, a reason for machines, a message for people, and when it last changed; each answers one question, and they are not one state. Three probes, of which liveness restarts a container and readiness stops work going to it | A condition with its reason and its time is the smallest thing that explains itself. A liveness probe that fails when a dependency is down restarts a healthy process and loses what it held |

What those who run these systems say, in what was read for this record:
the failure that costs most is the silent one, a total that looks healthy
hides one part that stopped, and a tool that watches others is itself the
last thing watched.

Seven requirements follow:

- **The product says it, with no other product.** A site with Prometheus
  keeps it; nobody needs it to learn that the writer is refused.
- **Every state has a reason and a time.** "Degraded" with no cause is a
  second problem.
- **Silence is a state.** A process that died reports nothing, so someone
  else must notice that it stopped.
- **What is expected is learned.** Nobody keeps a list of pods.
- **A restart is normal, a loop of them is not.** In a cluster a process
  gets a new name each time it starts.
- **A trend is told before a limit.** A backlog that grows by one percent a
  minute crosses no threshold for an hour.
- **Records are accounted for.** What was taken is stored, or refused with
  a reason, or still waiting; anything else is lost and must be said.

### Cases the answer must serve

- One machine: the store's disk fills. The writer is refused, the topic
  fills, and searches answer as before. The person who opens the interface
  must read that the writer cannot store, since when, why, and how long
  the topic can hold what arrives.
- A collector in a branch loses its link to the centre. It can report
  nothing, by the same link. The centre must say that this collector is
  gone and since when, and its sources go silent a little later.
- A cluster: the normalizer is killed for memory and started again, each
  minute. Each start has a new name. The view must say that the normalizer
  restarts, how often, and not show seven normalizers.
- The backlog of the writer grows slowly through a morning. The view must
  say when the topic's bound will be reached at this rate.
- A feed was last fetched three days ago, and the detector matches against
  what it had.
- The receiver's certificate expires in five days.
- The store is down, so the interface has nothing to read health from. It
  must still say that.
- Everything is down. Nothing in the product can say so.

## Decision

**Every process reports what it is and the state of each thing it does, as
conditions with a reason and a time, through the pipe it already uses. The
writer stores the reports, and the API judges from them: each role by its
instances, each flow by its backlog and its trend, and the records by an
account of where each went. The same conditions drive three probes on every
process. A process that stops reporting is found by its silence.**

### What a process reports

- Each process sends a report every 15 seconds to a `health` topic, as it
  sends events: its roles, its version, a name for the instance, when it
  started, its counters, and its conditions.
- The pipe carries it because the pipe is the one thing every role
  reaches. A collector in a branch has no way to the store, and must not be
  given one for this.
- The instance's name is the host's or the pod's, or what the
  configuration gives. It need not be lasting: a role is judged by how many
  of its instances report, not by which.

### Conditions

A condition answers one question about one thing a role does:

| Member | What it is |
| --- | --- |
| `type` | The question, such as `storing` |
| `status` | `ok`, `degraded`, or `failing` |
| `reason` | A word for machines, such as `store_refused` |
| `message` | A sentence for people, with the numbers and what to look at |
| `since` | When the status last changed |

The first set, each from a measure the role already keeps:

| Role | Condition | Degraded when | Failing when |
| --- | --- | --- | --- |
| collector | `accepting` | The receiver's certificate expires within 14 days | A listener is not bound, or the certificate expired |
| collector | `delivering` | Senders waited for the pipe more than 5% of the last five minutes | Nothing was delivered in five minutes while records waited |
| normalizer | `normalizing` | More than 1% of records became dead letters in the last hour | More than half did |
| writer | `storing` | The store took longer than 10 seconds for a batch | The store refused the last batch |
| writer, detector, normalizer | `keeping_up` | The backlog grew through the last ten minutes | At this rate the topic's bound is reached within an hour |
| detector | `feeds_current` | A feed is older than twice its refresh | A feed was never loaded |
| detector | `context_current` | An export is older than twice its usual age | An export was refused and none was ever loaded |
| detector | `matching` | It was moved past events it did not match | Ranges wait to be matched from the store and none is being read |
| api | `store_reachable` | A query took longer than 5 seconds | The store does not answer |

- A threshold is judged over a window, never at an instant, so that a
  status does not change with every sample.
- `since` moves only when the status does. The message may change while
  the status holds, as the numbers do.
- A role adds a condition when it gains something that can fail. The
  thresholds are in the configuration with these defaults.

### Judging

The API answers from the stored reports:

- **An instance** is `reporting` while its last report is younger than a
  minute, then `gone`. An instance gone for an hour leaves the view, unless
  its role is then short of instances.
- **A role** is as bad as the worst condition of its reporting instances.
  It is `failing` when none reports, and `degraded` when fewer report than
  were seen at once in the last day, or than the configuration expects.
  More than three starts of a role in ten minutes is `restarting`, whatever
  the names of the instances.
- **A flow**, from each topic to its reader, has its backlog, its change
  over ten minutes, and the time until the topic's bound at that rate.
- **The account**: over the last hour, records taken, stored, refused as
  dead letters, and waiting in a topic. What is left over is `unaccounted`.
  It is zero while every record is somewhere; more than a tenth of a
  percent is `failing`, with the stage where the counts stop agreeing.
- **The platform** is as bad as its worst role, flow, or the account.

Two things the API says from itself, not from reports, since reports reach
it through the store: whether the store answers, and how old the newest
report of any instance is. With the store down it says so. With every
report old and the store up, it says that reports are not arriving, which
is the writer or the pipe.

### History

- A change of a condition's status is kept as a row: what changed, from
  what to what, the reason, and when. The reports themselves are kept a
  day; the changes five weeks, as source health keeps its counts.
- The view therefore shows since when a thing is wrong and how often it
  was wrong before, and not only that it is wrong now.

### Probes

Every process answers three questions on the listener it serves metrics on:

| Path | Says yes when | What must not make it say no |
| --- | --- | --- |
| `/health/live` | Each of its loops ran within the last minute | The store, the pipe, or any other process being down: a restart mends none of them and loses what the process holds |
| `/health/ready` | It can take work now: listeners bound, and what it sends to accepts | |
| `/health/startup` | It finished starting: migrations applied, feeds looked at once | |

They are Kubernetes' three probes, and a load balancer's check. On one
machine nothing calls them, and nothing needs to.

### What the product cannot say

- That all of it is down. For that, something outside must ask
  `/health/live` or watch the metrics; alert rules for Prometheus are
  shipped beside the dashboards, with the same thresholds.
- Which collector a silent source came through. A source's events do not
  yet say which instance took them; until they do, the view puts a silent
  source and a collector that went at the same time side by side, and the
  reader makes the link.

### Serving

- `GET /api/v1/platform` gives the platform's status, each role with its
  instances and conditions, each flow, the account, and the recent changes.
- The interface shows it as the path a record takes, from sources through
  collectors, the raw topic, the normalizer, the normalized topic, and the
  writer to the store, with the detector beside the writer, each stage
  with its status, rate, and backlog, and the reason one click away. Source
  health is in the same view, at the path's start. Its design is the
  interface's record.

## Options considered

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| Reports through the pipe, stored by the writer, judged by the API | No new component and no new credentials; every role can report; history for free | Health arrives by the path it describes, so the API must also judge from the store's own answer and the reports' age | **Chosen** |
| Prometheus and dashboards alone | Standard; already served | A second product to install before the first problem is explained; numbers, with the reasons left to whoever reads them | Kept beside, not as the answer |
| Each process writes its reports to the store | One hop | A collector in a branch gets a way to the store and its password | Rejected |
| A control plane that every process registers with, as Fleet Server or Cribl's leader | One place that knows what should run; can also configure | A new service that must itself be watched, and a single point every role depends on; configuration from a centre is another decision | Rejected for now |
| Kubernetes resources and an operator | Native to a cluster | Nothing for one machine or for hosts, which is where most first installs are | Rejected as the model; the probes serve clusters |
| A list of expected instances in the configuration | Exact | Nobody keeps it current, and a pod's name is new at each start | Rejected; an expected number for each role is optional |

## Consequences

- Whoever starts the platform sees what is wrong with it in the product,
  with a reason and a time, on one machine and on many.
- Each role gains conditions to keep, and a new thing that can fail gains
  one. That is a rule for every change after this.
- A report every 15 seconds from each instance is a few rows a minute;
  the store's cost is not worth measuring. The topic is one more to keep.
- Health reaches the view through the writer. When the writer is the
  fault, the view says that reports stopped, and not which condition
  failed; the writer's own log and probes say the rest.
- Thresholds are defaults that will be wrong for some site. They are
  configuration from the first release so that nobody changes code to
  quiet a status.
- The account compares counters of processes that restart. A restart
  loses the part of an hour's counts not yet reported, so the account is
  judged over complete reports and says when it cannot be.

## When to revisit

- If a site runs more than 1,000 instances, a report from each every 15
  seconds is 4,000 rows a minute and the view cannot list them: report
  less often and show instances by role and condition.
- If statuses change more than once an hour on a platform nobody touched,
  the windows are too short or the thresholds too tight: measure which,
  and change the defaults.
- If operators ask to stop and start roles, or to change configuration,
  from the view, that is a control plane, and is decided on its own.
- When events say which instance took them, a silent source is tied to
  its collector by the product and not by the reader.

## Sources

- Splunk, the splunkd health report:
  <https://docs.splunk.com/Documentation/Splunk/7.1.0/DMC/Aboutfeaturemonitoring>
- Elastic, monitoring Elastic Agents:
  <https://www.elastic.co/docs/reference/fleet/monitor-elastic-agent>
- Microsoft Sentinel, the health of data connectors:
  <https://learn.microsoft.com/azure/sentinel/monitor-data-connector-health>
- Google Security Operations, ingestion health and silent hosts:
  <https://docs.cloud.google.com/chronicle/docs/ingestion/ingestion-notifications-for-health-metrics>,
  <https://docs.cloud.google.com/chronicle/docs/ingestion/silent-host-monitoring>
- Cribl, internal metrics and notifications:
  <https://docs.cribl.io/edge/4.0/internal-metrics/>,
  <https://docs.cribl.io/edge/4.0/notifications/>
- Kubernetes, probes, and KEP-1623 on conditions:
  <https://kubernetes.io/docs/concepts/workloads/pods/probes/>,
  <https://www.kubernetes.dev/resources/keps/1623/>
- Expel, on SIEM health and data quality:
  <https://expel.com/cyberspeak/how-to-ensure-siem-health-and-data-quality>
