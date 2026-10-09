//! What the processes of the platform report of themselves, as it is kept.
//!
//! A [`Report`] is what one process says at one moment: who it is and the
//! [`Condition`] of each thing it does. The store keeps the newest reports
//! a day, to tell which processes run, and each time a condition's status
//! held for five weeks, to tell since when a thing is wrong and how often
//! it was before. See `docs/adr/0023-platform-health.md`.

use std::collections::{BTreeMap, BTreeSet};

use clickhouse::Row;
use serde::{Deserialize, Serialize};

use crate::error::StoreError;
use crate::search::{SearchLimits, with_limits};
use crate::store::Store;

/// How well one thing a role does is going.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// As it should.
    Ok,
    /// It works, and not as it should.
    Degraded,
    /// It does not work.
    Failing,
}

impl Standing {
    /// The name it is reported and stored under.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Failing => "failing",
        }
    }

    /// The standing stored as `name`; one this build does not know is
    /// taken as degraded, so that it is shown and not hidden.
    pub fn from_name(name: &str) -> Self {
        match name {
            "ok" => Self::Ok,
            "failing" => Self::Failing,
            _ => Self::Degraded,
        }
    }
}

/// The answer to one question about one thing a role does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    /// The role it is about, such as `writer`.
    pub role: String,
    /// The question, such as `storing`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The answer.
    pub status: Standing,
    /// A word for machines, such as `store_refused`.
    pub reason: String,
    /// A sentence for people, with the numbers and what to look at.
    pub message: String,
    /// When the status last changed, in milliseconds since the epoch.
    pub since: i64,
}

/// What one process says of itself at one moment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// A name for the process: its host's or its pod's. It need not last.
    pub instance: String,
    /// The roles it runs.
    pub roles: Vec<String>,
    /// The version of the platform it is.
    pub version: String,
    /// When it started, in milliseconds since the epoch.
    pub started: i64,
    /// When it said this, by its own clock.
    pub sent: i64,
    /// What it counted since it started, by name.
    #[serde(default)]
    pub counters: BTreeMap<String, u64>,
    /// The state of each thing it does.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// The newest report of one run of a process, as it was kept.
#[derive(Debug, Clone, PartialEq, Eq, Row, Deserialize)]
pub struct Reported {
    /// The process's name.
    pub instance: String,
    /// The roles it runs.
    pub roles: Vec<String>,
    /// Its version.
    pub version: String,
    /// When it started, in milliseconds since the epoch.
    pub started: i64,
    /// When it sent the report, by its own clock.
    pub sent: i64,
    /// When the report was taken, by the writer's clock.
    pub received: i64,
    /// What it counted, by name.
    pub counters: Vec<(String, u64)>,
}

/// A time through which a condition's status held.
#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub struct Held {
    /// The process's name.
    pub instance: String,
    /// The role the condition is about.
    pub role: String,
    /// The question, such as `storing`.
    pub kind: String,
    /// The status, as [`Standing::as_str`] names it.
    pub status: String,
    /// The reason last given.
    pub reason: String,
    /// The message last given.
    pub message: String,
    /// When the status began, in milliseconds since the epoch.
    pub since: i64,
    /// When it was last reported.
    pub seen: i64,
}

#[derive(Debug, Row, Serialize)]
struct ReportRow<'a> {
    received: i64,
    instance: &'a str,
    roles: &'a [String],
    version: &'a str,
    started: i64,
    sent: i64,
    counters: Vec<(&'a str, u64)>,
}

#[derive(Debug, Row, Serialize)]
struct ConditionRow<'a> {
    instance: &'a str,
    role: &'a str,
    r#type: &'a str,
    since: i64,
    status: &'a str,
    reason: &'a str,
    message: &'a str,
    seen: i64,
}

impl Store {
    /// Keeps `reports`, taken at `received`, in milliseconds since the
    /// epoch.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if an insert fails.
    pub async fn write_reports(&self, reports: &[Report], received: i64) -> Result<(), StoreError> {
        if reports.is_empty() {
            return Ok(());
        }
        let mut insert = self
            .client()
            .insert::<ReportRow<'_>>("platform_reports")
            .await?;
        for report in reports {
            insert
                .write(&ReportRow {
                    received,
                    instance: &report.instance,
                    roles: &report.roles,
                    version: &report.version,
                    started: report.started,
                    sent: report.sent,
                    counters: report
                        .counters
                        .iter()
                        .map(|(name, count)| (name.as_str(), *count))
                        .collect(),
                })
                .await?;
        }
        insert.end().await?;
        if reports.iter().all(|report| report.conditions.is_empty()) {
            return Ok(());
        }
        let mut insert = self
            .client()
            .insert::<ConditionRow<'_>>("platform_conditions")
            .await?;
        for report in reports {
            for condition in &report.conditions {
                insert
                    .write(&ConditionRow {
                        instance: &report.instance,
                        role: &condition.role,
                        r#type: &condition.kind,
                        since: condition.since,
                        status: condition.status.as_str(),
                        reason: &condition.reason,
                        message: &condition.message,
                        seen: received,
                    })
                    .await?;
            }
        }
        insert.end().await?;
        Ok(())
    }

    /// The newest report of each run of each process taken since `since`,
    /// in milliseconds since the epoch, the newest first. A process that
    /// started twice in that time is there twice.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails or exceeds
    /// `limits`.
    pub async fn platform_reports(
        &self,
        since: i64,
        limits: SearchLimits,
    ) -> Result<Vec<Reported>, StoreError> {
        let query = self
            .client()
            .query(
                "SELECT instance, roles, version, toUnixTimestamp64Milli(started) AS started, \
                 toUnixTimestamp64Milli(sent) AS sent, \
                 toUnixTimestamp64Milli(received) AS received, counters \
                 FROM platform_reports WHERE received >= fromUnixTimestamp64Milli(?) \
                 ORDER BY received DESC, instance LIMIT 1 BY instance, started",
            )
            .bind(since);
        Ok(by_column(with_limits(query, limits))
            .fetch_all::<Reported>()
            .await?)
    }

    /// Each time a condition's status held that was last reported since
    /// `since`, in milliseconds since the epoch, in the order of instance,
    /// role, type, and beginning.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails or exceeds
    /// `limits`.
    pub async fn platform_conditions(
        &self,
        since: i64,
        limits: SearchLimits,
    ) -> Result<Vec<Held>, StoreError> {
        let query = self
            .client()
            .query(
                "SELECT instance, role, type AS kind, status, reason, message, \
                 toUnixTimestamp64Milli(since) AS since, toUnixTimestamp64Milli(seen) AS seen \
                 FROM platform_conditions FINAL WHERE seen >= fromUnixTimestamp64Milli(?) \
                 ORDER BY instance, role, type, since",
            )
            .bind(since);
        Ok(by_column(with_limits(query, limits))
            .fetch_all::<Held>()
            .await?)
    }
}

/// A process is reporting while its newest report is younger than this.
const REPORTING: i64 = 60_000;
/// A process gone this long leaves the view.
const LEAVES: i64 = 3_600_000;
/// More starts of a role than [`STARTS`] within this is a role that
/// restarts.
const STARTS_WITHIN: i64 = 600_000;
const STARTS: usize = 3;
/// The changes of conditions that are answered, the newest first.
const CHANGES: usize = 50;

/// One process, as its newest report and the conditions it last gave say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Instance {
    /// Its name.
    pub instance: String,
    /// Whether its newest report is younger than a minute.
    pub reporting: bool,
    /// Its version.
    pub version: String,
    /// When it started, in milliseconds since the epoch.
    pub started: i64,
    /// When its newest report was taken.
    pub last_report: i64,
    /// The conditions of the role, as it last gave them.
    pub conditions: Vec<Condition>,
}

/// What one reader of one topic has still to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flow {
    /// The topic.
    pub topic: String,
    /// The role that reads it.
    pub reader: String,
    /// Records sent and not yet handled by the reader, as the process that
    /// reports most says.
    pub backlog: u64,
}

/// One role, judged from the processes that run it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleHealth {
    /// The role, such as `writer`.
    pub role: String,
    /// How it stands.
    pub status: Standing,
    /// Why, in a word: `no_instance`, `restarting`, `fewer_instances`, the
    /// reason of its worst condition, or `ok`.
    pub reason: String,
    /// Why, in a sentence.
    pub message: String,
    /// Processes that run it and report.
    pub reporting: usize,
    /// Processes that ran it at once within the last day.
    pub expected: usize,
    /// Times a process that runs it started in the last ten minutes.
    pub starts: usize,
    /// Its processes: those that report, those gone within the hour, and
    /// those gone longer while the role is short of them.
    pub instances: Vec<Instance>,
}

/// The platform, judged from what its processes reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Platform {
    /// As bad as its worst role; failing with no report at all.
    pub status: Standing,
    /// Why, in a word: `no_reports`, or the role and its reason, such as
    /// `writer:store_refused`; `ok` otherwise.
    pub reason: String,
    /// Why, in a sentence.
    pub message: String,
    /// When the newest report of any process was taken.
    pub newest_report: Option<i64>,
    /// The roles, the worst first.
    pub roles: Vec<RoleHealth>,
    /// Each topic and its reader, the longest backlog first.
    pub flows: Vec<Flow>,
    /// The times a condition's status held, the newest first: what changed
    /// and when.
    pub changes: Vec<Held>,
}

/// Judges the platform at `now`, in milliseconds since the epoch, from the
/// `reports` of the last day, as [`Store::platform_reports`] gives them,
/// and the conditions `held`, as [`Store::platform_conditions`] does.
///
/// A role is judged by how many of its processes report and not by which:
/// a process that starts again under another name is the same role. See
/// `docs/adr/0023-platform-health.md`.
pub fn judge_platform(now: i64, reports: &[Reported], held: &[Held]) -> Platform {
    let newest_report = reports.iter().map(|report| report.received).max();
    // The newest run under each name is what that process is now.
    let mut current: BTreeMap<&str, &Reported> = BTreeMap::new();
    for report in reports {
        let known = current.entry(&report.instance).or_insert(report);
        if report.received > known.received {
            *known = report;
        }
    }
    let names: BTreeSet<&str> = reports
        .iter()
        .flat_map(|report| report.roles.iter().map(String::as_str))
        .collect();
    let mut roles: Vec<RoleHealth> = names
        .into_iter()
        .filter_map(|role| judge_role(now, role, reports, &current, held))
        .collect();
    roles.sort_by(|a, b| b.status.cmp(&a.status).then_with(|| a.role.cmp(&b.role)));

    let flows = flows(now, current.values().copied());

    let mut changes: Vec<Held> = held.to_vec();
    changes.sort_by_key(|change| std::cmp::Reverse(change.since));
    changes.truncate(CHANGES);

    let (status, reason, message) = match roles.first() {
        None => (
            Standing::Failing,
            "no_reports".to_owned(),
            "No process has reported in the last day. With the store answering, that is the \
             writer or the pipe."
                .to_owned(),
        ),
        Some(worst) if worst.status == Standing::Ok => (
            Standing::Ok,
            "ok".to_owned(),
            "Every role reports and none says anything is wrong.".to_owned(),
        ),
        Some(worst) => (
            worst.status,
            format!("{}:{}", worst.role, worst.reason),
            worst.message.clone(),
        ),
    };
    Platform {
        status,
        reason,
        message,
        newest_report,
        roles,
        flows,
        changes,
    }
}

/// The backlog of each topic and reader, from the counters named
/// `backlog:<topic>:<reader>` of the processes that report. Processes of
/// one group in Kafka each report the group's backlog, so the most is
/// taken and they are not added.
fn flows<'a>(now: i64, current: impl Iterator<Item = &'a Reported>) -> Vec<Flow> {
    let mut backlogs: BTreeMap<(&str, &str), u64> = BTreeMap::new();
    for report in current.filter(|report| now - report.received < REPORTING) {
        for (name, count) in &report.counters {
            let Some((topic, reader)) = name
                .strip_prefix("backlog:")
                .and_then(|rest| rest.rsplit_once(':'))
            else {
                continue;
            };
            let known = backlogs.entry((topic, reader)).or_default();
            *known = (*known).max(*count);
        }
    }
    let mut flows: Vec<Flow> = backlogs
        .into_iter()
        .map(|((topic, reader), backlog)| Flow {
            topic: topic.to_owned(),
            reader: reader.to_owned(),
            backlog,
        })
        .collect();
    flows.sort_by_key(|flow| std::cmp::Reverse(flow.backlog));
    flows
}

/// The role `role`, or `None` if every process that ran it left the view
/// and none runs it now.
fn judge_role(
    now: i64,
    role: &str,
    reports: &[Reported],
    current: &BTreeMap<&str, &Reported>,
    held: &[Held],
) -> Option<RoleHealth> {
    let runs: Vec<&Reported> = reports
        .iter()
        .filter(|report| report.roles.iter().any(|ran| ran == role))
        .collect();
    let expected = at_once(&runs);
    let starts = runs
        .iter()
        .filter(|run| run.started >= now - STARTS_WITHIN)
        .count();
    // A process whose newest run no longer has the role does not run it.
    let mut instances: Vec<Instance> = current
        .values()
        .filter(|report| report.roles.iter().any(|ran| ran == role))
        .map(|report| Instance {
            instance: report.instance.clone(),
            reporting: now - report.received < REPORTING,
            version: report.version.clone(),
            started: report.started,
            last_report: report.received,
            conditions: conditions_of(report, role, held),
        })
        .collect();
    let reporting = instances
        .iter()
        .filter(|instance| instance.reporting)
        .count();
    // Those gone longer than an hour leave, unless the role is short.
    instances.sort_by_key(|instance| std::cmp::Reverse(instance.last_report));
    let mut kept = 0;
    instances.retain(|instance| {
        let stays = instance.reporting
            || now - instance.last_report < LEAVES
            || (reporting < expected && kept < expected);
        kept += usize::from(stays);
        stays
    });
    if instances.is_empty() {
        return None;
    }
    instances.sort_by(|a, b| a.instance.cmp(&b.instance));

    let worst = instances
        .iter()
        .filter(|instance| instance.reporting)
        .flat_map(|instance| &instance.conditions)
        .max_by_key(|condition| condition.status);
    let (status, reason, message) = if reporting == 0 {
        let last = instances
            .iter()
            .map(|instance| instance.last_report)
            .max()
            .unwrap_or(now);
        (
            Standing::Failing,
            "no_instance".to_owned(),
            format!(
                "No process that runs `{role}` reports; the last did {} ago.",
                ago(now - last)
            ),
        )
    } else if let Some(worst) = worst.filter(|worst| worst.status == Standing::Failing) {
        (worst.status, worst.reason.clone(), worst.message.clone())
    } else if starts > STARTS {
        (
            Standing::Degraded,
            "restarting".to_owned(),
            format!(
                "A process that runs `{role}` started {starts} times in the last ten minutes. \
                 Look at why it stops."
            ),
        )
    } else if let Some(worst) = worst.filter(|worst| worst.status == Standing::Degraded) {
        (worst.status, worst.reason.clone(), worst.message.clone())
    } else if reporting < expected {
        (
            Standing::Degraded,
            "fewer_instances".to_owned(),
            format!(
                "{reporting} of the {expected} processes that ran `{role}` at once within the \
                 last day report."
            ),
        )
    } else {
        (
            Standing::Ok,
            "ok".to_owned(),
            format!("{reporting} of {expected} report, and none says anything is wrong."),
        )
    };
    Some(RoleHealth {
        role: role.to_owned(),
        status,
        reason,
        message,
        reporting,
        expected,
        starts,
        instances,
    })
}

/// The most of `runs` that ran at one time, each from when it started to
/// its newest report.
fn at_once(runs: &[&Reported]) -> usize {
    let mut edges: Vec<(i64, i32)> = runs
        .iter()
        .flat_map(|run| [(run.started, 1), (run.received.max(run.started) + 1, -1)])
        .collect();
    // At one moment an end comes before a beginning.
    edges.sort_unstable();
    let (mut running, mut most) = (0_i32, 0_i32);
    for (_, change) in edges {
        running += change;
        most = most.max(running);
    }
    usize::try_from(most).unwrap_or(0)
}

/// The conditions of `role` that the process of `report` gave with its
/// newest reports: of each question the status that began last, if it was
/// still given within a minute of the newest report.
fn conditions_of(report: &Reported, role: &str, held: &[Held]) -> Vec<Condition> {
    let mut newest: BTreeMap<&str, &Held> = BTreeMap::new();
    for held in held {
        if held.instance != report.instance
            || held.role != role
            || held.since < report.started
            || held.seen < report.received - REPORTING
        {
            continue;
        }
        let known = newest.entry(&held.kind).or_insert(held);
        if held.since > known.since {
            *known = held;
        }
    }
    newest
        .into_values()
        .map(|held| Condition {
            role: held.role.clone(),
            kind: held.kind.clone(),
            status: Standing::from_name(&held.status),
            reason: held.reason.clone(),
            message: held.message.clone(),
            since: held.since,
        })
        .collect()
}

/// A length of time in words, such as `5 minutes`.
fn ago(milliseconds: i64) -> String {
    let seconds = milliseconds.max(0) / 1000;
    match seconds {
        0..=119 => format!("{seconds} seconds"),
        120..=7199 => format!("{} minutes", seconds / 60),
        _ => format!("{} hours", seconds / 3600),
    }
}

/// A column is answered under its own name as a number, and asked about
/// as the time it is: without this the name would mean the number.
fn by_column(query: clickhouse::query::Query) -> clickhouse::query::Query {
    query.with_setting("prefer_column_name_to_alias", "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_is_written_and_read_as_json_with_type_for_the_question() {
        let text = r#"{"instance":"writer-0","roles":["writer"],"version":"0.1.0",
            "started":1000,"sent":16000,"counters":{"stored":42},
            "conditions":[{"role":"writer","type":"storing","status":"failing",
            "reason":"store_refused","message":"The store refused the last batch.","since":9000}]}"#;
        let report: Report = serde_json::from_str(text).unwrap();
        assert_eq!(report.conditions[0].kind, "storing");
        assert_eq!(report.conditions[0].status, Standing::Failing);
        assert_eq!(report.counters["stored"], 42);
        let again: Report = serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(again, report);
        // A report of a process with nothing to say of itself yet.
        let bare: Report = serde_json::from_str(
            r#"{"instance":"a","roles":[],"version":"0.1.0","started":1,"sent":2}"#,
        )
        .unwrap();
        assert_eq!((bare.counters.len(), bare.conditions.len()), (0, 0));
    }

    const NOW: i64 = 100_000_000;

    fn reported(instance: &str, roles: &[&str], started: i64, received: i64) -> Reported {
        Reported {
            instance: instance.to_owned(),
            roles: roles.iter().map(|&role| role.to_owned()).collect(),
            version: "0.1.0".to_owned(),
            started,
            sent: received,
            received,
            counters: Vec::new(),
        }
    }

    fn held(instance: &str, kind: &str, status: &str, since: i64, seen: i64) -> Held {
        Held {
            instance: instance.to_owned(),
            role: "writer".to_owned(),
            kind: kind.to_owned(),
            status: status.to_owned(),
            reason: format!("{kind}_{status}"),
            message: format!("{kind} is {status}."),
            since,
            seen,
        }
    }

    fn role<'a>(platform: &'a Platform, name: &str) -> &'a RoleHealth {
        platform
            .roles
            .iter()
            .find(|role| role.role == name)
            .unwrap_or_else(|| panic!("no role {name} in {platform:?}"))
    }

    #[test]
    fn a_platform_that_reports_and_says_nothing_is_wrong_is_ok() {
        let started = NOW - 3_600_000;
        let reports = [
            reported("one", &["collector", "normalizer"], started, NOW - 5_000),
            reported("two", &["writer", "api"], started, NOW - 9_000),
        ];
        let conditions = [held("two", "storing", "ok", started, NOW - 9_000)];
        let platform = judge_platform(NOW, &reports, &conditions);
        assert_eq!(
            (platform.status, platform.reason.as_str()),
            (Standing::Ok, "ok")
        );
        assert_eq!(platform.newest_report, Some(NOW - 5_000));
        assert_eq!(platform.roles.len(), 4);
        let writer = role(&platform, "writer");
        assert_eq!(
            (writer.reporting, writer.expected, writer.starts),
            (1, 1, 0)
        );
        assert_eq!(writer.instances[0].conditions[0].kind, "storing");
        // The condition is the writer's, not the api's, of the same process.
        assert_eq!(role(&platform, "api").instances[0].conditions, []);
    }

    #[test]
    fn flows_are_the_backlogs_the_reporting_processes_count() {
        let started = NOW - 3_600_000;
        let mut one = reported("writer-0", &["writer"], started, NOW - 5_000);
        one.counters = vec![
            ("backlog:normalized:writer".to_owned(), 40),
            ("backlog:findings:writer".to_owned(), 0),
            ("stored".to_owned(), 9),
        ];
        // Another of the same group says the same backlog, a little later.
        let mut two = reported("writer-1", &["writer"], started, NOW - 2_000);
        two.counters = vec![("backlog:normalized:writer".to_owned(), 55)];
        // A source's name may hold what divides the parts.
        let mut three = reported("n-0", &["normalizer"], started, NOW - 2_000);
        three.counters = vec![("backlog:raw-a:b:normalizer".to_owned(), 7)];
        // One that is gone says nothing of now.
        let mut gone = reported("writer-2", &["writer"], started, NOW - 900_000);
        gone.counters = vec![("backlog:normalized:writer".to_owned(), 99_999)];
        let platform = judge_platform(NOW, &[one, two, three, gone], &[]);
        let flows: Vec<(&str, &str, u64)> = platform
            .flows
            .iter()
            .map(|flow| (flow.topic.as_str(), flow.reader.as_str(), flow.backlog))
            .collect();
        assert_eq!(
            flows,
            [
                ("normalized", "writer", 55),
                ("raw-a:b", "normalizer", 7),
                ("findings", "writer", 0),
            ]
        );
    }

    #[test]
    fn a_role_is_as_bad_as_the_worst_condition_of_those_that_report() {
        let started = NOW - 3_600_000;
        let reports = [
            reported("a", &["writer"], started, NOW - 5_000),
            reported("b", &["writer"], started, NOW - 5_000),
        ];
        let conditions = [
            held("a", "storing", "ok", started, NOW - 5_000),
            // It stored, and then was refused: the status that began last.
            held("b", "storing", "ok", started, NOW - 50_000),
            held("b", "storing", "failing", NOW - 40_000, NOW - 5_000),
            held("b", "keeping_up", "degraded", NOW - 90_000, NOW - 5_000),
        ];
        let platform = judge_platform(NOW, &reports, &conditions);
        let writer = role(&platform, "writer");
        assert_eq!(
            (
                writer.status,
                writer.reason.as_str(),
                writer.message.as_str()
            ),
            (Standing::Failing, "storing_failing", "storing is failing.")
        );
        assert_eq!(
            (platform.status, platform.reason.as_str()),
            (Standing::Failing, "writer:storing_failing")
        );
        // What changed, the newest first.
        let changes: Vec<(&str, &str)> = platform
            .changes
            .iter()
            .map(|change| (change.kind.as_str(), change.status.as_str()))
            .collect();
        assert_eq!(
            changes[..2],
            [("storing", "failing"), ("keeping_up", "degraded")]
        );
    }

    #[test]
    fn a_role_none_of_whose_processes_reports_is_failing() {
        let reports = [
            reported("a", &["collector"], NOW - 3_600_000, NOW - 5_000),
            reported("w", &["writer"], NOW - 3_600_000, NOW - 300_000),
        ];
        // What it last said does not count: it does not say it now.
        let conditions = [held("w", "storing", "ok", NOW - 3_600_000, NOW - 300_000)];
        let platform = judge_platform(NOW, &reports, &conditions);
        let writer = role(&platform, "writer");
        assert_eq!(
            (writer.status, writer.reason.as_str(), writer.reporting),
            (Standing::Failing, "no_instance", 0)
        );
        assert_eq!(
            writer.message,
            "No process that runs `writer` reports; the last did 5 minutes ago."
        );
        assert!(!writer.instances[0].reporting);
        assert_eq!(platform.roles[0].role, "writer");
        assert_eq!(role(&platform, "collector").status, Standing::Ok);
    }

    #[test]
    fn a_process_under_a_new_name_is_the_same_role_and_fewer_of_them_is_told() {
        let day = NOW - 80_000_000;
        // A pod was replaced by another: one after the other, never two.
        let replaced = [
            reported("writer-abc", &["writer"], day, NOW - 7_200_000),
            reported("writer-xyz", &["writer"], NOW - 7_190_000, NOW - 5_000),
        ];
        let platform = judge_platform(NOW, &replaced, &[]);
        let writer = role(&platform, "writer");
        assert_eq!((writer.status, writer.expected), (Standing::Ok, 1));
        // The one gone two hours ago has left the view.
        assert_eq!(writer.instances.len(), 1);

        // Two ran at once, and one stopped ten minutes ago.
        let fewer = [
            reported("writer-0", &["writer"], day, NOW - 5_000),
            reported("writer-1", &["writer"], day, NOW - 600_000),
        ];
        let platform = judge_platform(NOW, &fewer, &[]);
        let writer = role(&platform, "writer");
        assert_eq!(
            (
                writer.status,
                writer.reason.as_str(),
                writer.reporting,
                writer.expected
            ),
            (Standing::Degraded, "fewer_instances", 1, 2)
        );
        assert_eq!(writer.instances.len(), 2);

        // Gone longer than an hour, it stays while the role is short.
        let long = [
            reported("writer-0", &["writer"], day, NOW - 5_000),
            reported("writer-1", &["writer"], day, NOW - 7_200_000),
        ];
        let writer_long = judge_platform(NOW, &long, &[]);
        assert_eq!(role(&writer_long, "writer").instances.len(), 2);
    }

    #[test]
    fn a_role_that_starts_again_and_again_is_restarting() {
        let reports: Vec<Reported> = (0..5)
            .map(|run| {
                let started = NOW - 500_000 + run * 100_000;
                reported(
                    &format!("writer-{run}"),
                    &["writer"],
                    started,
                    started + 60_000,
                )
            })
            .collect();
        let platform = judge_platform(NOW, &reports, &[]);
        let writer = role(&platform, "writer");
        assert_eq!(
            (writer.status, writer.reason.as_str(), writer.starts),
            (Standing::Degraded, "restarting", 5)
        );
        // One run after another: one was expected, and one reports.
        assert_eq!((writer.expected, writer.reporting), (1, 1));
    }

    #[test]
    fn with_no_report_the_platform_says_that_reports_do_not_arrive() {
        let platform = judge_platform(NOW, &[], &[]);
        assert_eq!(
            (
                platform.status,
                platform.reason.as_str(),
                platform.newest_report
            ),
            (Standing::Failing, "no_reports", None)
        );
        assert_eq!((platform.roles.len(), platform.changes.len()), (0, 0));
    }

    #[test]
    fn standings_are_ordered_by_how_bad_and_an_unknown_one_is_shown() {
        assert!(Standing::Ok < Standing::Degraded && Standing::Degraded < Standing::Failing);
        for standing in [Standing::Ok, Standing::Degraded, Standing::Failing] {
            assert_eq!(Standing::from_name(standing.as_str()), standing);
        }
        assert_eq!(Standing::from_name("restarting"), Standing::Degraded);
    }
}
