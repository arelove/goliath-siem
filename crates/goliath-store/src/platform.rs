//! What the processes of the platform report of themselves, as it is kept.
//!
//! A [`Report`] is what one process says at one moment: who it is and the
//! [`Condition`] of each thing it does. The store keeps the newest reports
//! a day, to tell which processes run, and each time a condition's status
//! held for five weeks, to tell since when a thing is wrong and how often
//! it was before. See `docs/adr/0023-platform-health.md`.

use std::collections::BTreeMap;

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
#[derive(Debug, Clone, PartialEq, Eq, Row, Deserialize)]
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

    #[test]
    fn standings_are_ordered_by_how_bad_and_an_unknown_one_is_shown() {
        assert!(Standing::Ok < Standing::Degraded && Standing::Degraded < Standing::Failing);
        for standing in [Standing::Ok, Standing::Degraded, Standing::Failing] {
            assert_eq!(Standing::from_name(standing.as_str()), standing);
        }
        assert_eq!(Standing::from_name("restarting"), Standing::Degraded);
    }
}
