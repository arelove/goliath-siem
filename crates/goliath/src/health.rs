//! What a process says of itself to whatever started it: the three probes
//! of `docs/adr/0023-platform-health.md`, served beside the metrics.
//!
//! - `/health/live`: the process answers. Nothing outside it can make this
//!   say no: a restart mends neither the store nor the pipe, and loses what
//!   the process holds.
//! - `/health/startup`: it finished starting, and what startup waits for,
//!   such as the feeds looked at once, is done.
//! - `/health/ready`: it started and is not shutting down.
//!
//! And what it says to the rest of the platform: every 15 seconds a report
//! of who it is and the condition of each thing it does, sent through the
//! pipe to the `health` topic, which the writer keeps.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use goliath_pipe::Sender;
use goliath_store::{Condition, Report, Standing};
use serde_json::json;
use tokio::sync::watch;
use tracing::warn;

use crate::RunError;
use crate::config::Config;

/// How often a process reports.
const EVERY: Duration = Duration::from_secs(15);

/// A backlog is remembered this often, for this long.
const SAMPLE: i64 = 15_000;
const WINDOW: i64 = 600_000;
/// A backlog shorter than this is not said to grow, whatever it does.
const WORTH_TELLING: u64 = 1_000;

/// What one reader of one topic had still to read, over the last ten
/// minutes.
#[derive(Default)]
struct Backlog {
    /// When, in milliseconds since the epoch, and how many records.
    samples: VecDeque<(i64, u64)>,
    now: u64,
}

impl Backlog {
    fn sample(&mut self, at: i64, records: u64) {
        self.now = records;
        if self
            .samples
            .back()
            .is_none_or(|(last, _)| at - last >= SAMPLE)
        {
            self.samples.push_back((at, records));
        }
        while self
            .samples
            .front()
            .is_some_and(|(first, _)| at - first > WINDOW)
        {
            self.samples.pop_front();
        }
    }

    /// From how many records to how many it grew through the last ten
    /// minutes: longer at their middle than at their start, and longer now
    /// than at their middle. `None` while ten minutes were not yet seen, or
    /// it did not grow, or it is short.
    fn grew(&self, at: i64) -> Option<(u64, u64)> {
        let (first_at, first) = *self.samples.front()?;
        if at - first_at < WINDOW - SAMPLE || self.now < WORTH_TELLING {
            return None;
        }
        let middle = self
            .samples
            .iter()
            .find(|(sampled, _)| *sampled >= first_at + (at - first_at) / 2)
            .map(|(_, records)| *records)?;
        (first < middle && middle < self.now).then_some((first, self.now))
    }
}

/// What the process knows of its own state, shared by its roles.
#[derive(Clone, Default)]
pub(crate) struct Health(Arc<Inner>);

#[derive(Default)]
struct Inner {
    /// Whether every role was started.
    started: AtomicBool,
    /// Whether the process is shutting down.
    stopping: AtomicBool,
    /// What startup still waits for.
    holds: Mutex<BTreeSet<&'static str>>,
    /// The state of each thing a role does, by role and question.
    conditions: Mutex<BTreeMap<(&'static str, String), Condition>>,
    /// What each reader has still to read, by topic and reader.
    backlogs: Mutex<BTreeMap<(String, &'static str), Backlog>>,
}

/// Who a process is, as its reports say.
#[derive(Debug, Clone)]
pub(crate) struct Identity {
    instance: String,
    roles: Vec<String>,
    started: i64,
}

impl Identity {
    /// The process `config` describes, started now.
    pub(crate) fn of(config: &Config) -> Self {
        let instance = config
            .instance
            .clone()
            // A pod's name, a Linux host's, and a Windows machine's.
            .or_else(|| std::env::var("HOSTNAME").ok())
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "goliath".to_owned());
        Self {
            instance,
            roles: config
                .roles
                .iter()
                .map(|role| role.as_str().to_owned())
                .collect(),
            started: crate::raw::now(),
        }
    }
}

/// Something startup waits for, until this is dropped.
pub(crate) struct Hold {
    health: Health,
    what: &'static str,
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.health.holds().remove(self.what);
    }
}

impl Health {
    fn holds(&self) -> std::sync::MutexGuard<'_, BTreeSet<&'static str>> {
        self.0.holds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes startup wait for `what`, until what is returned is dropped.
    pub(crate) fn hold(&self, what: &'static str) -> Hold {
        self.holds().insert(what);
        Hold {
            health: self.clone(),
            what,
        }
    }

    /// Says how `kind`, one thing `role` does, is going. When the status
    /// began is kept while the status holds, whatever the reason and the
    /// message become.
    pub(crate) fn set(
        &self,
        role: &'static str,
        kind: &str,
        status: Standing,
        reason: &'static str,
        message: String,
    ) {
        self.set_at(crate::raw::now(), role, kind, status, reason, message);
    }

    fn set_at(
        &self,
        now: i64,
        role: &'static str,
        kind: &str,
        status: Standing,
        reason: &'static str,
        message: String,
    ) {
        let mut conditions = self
            .0
            .conditions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let key = (role, kind.to_owned());
        let since = conditions
            .get(&key)
            .filter(|held| held.status == status)
            .map_or(now, |held| held.since);
        conditions.insert(
            key,
            Condition {
                role: role.to_owned(),
                kind: kind.to_owned(),
                status,
                reason: reason.to_owned(),
                message,
                since,
            },
        );
    }

    /// Notes that `reader` has `records` of `topic` still to read, and says
    /// whether it keeps up: the condition `keeping_up:<topic>` of the
    /// reader's role is degraded while the backlog grew through the last
    /// ten minutes.
    pub(crate) fn backlog(&self, topic: &str, reader: &'static str, records: u64) {
        self.backlog_at(crate::raw::now(), topic, reader, records);
    }

    fn backlog_at(&self, now: i64, topic: &str, reader: &'static str, records: u64) {
        let grew = {
            let mut backlogs = self
                .0
                .backlogs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let backlog = backlogs.entry((topic.to_owned(), reader)).or_default();
            backlog.sample(now, records);
            backlog.grew(now)
        };
        let kind = format!("keeping_up:{topic}");
        match grew {
            Some((from, to)) => self.set_at(
                now,
                reader,
                &kind,
                Standing::Degraded,
                "backlog_grows",
                format!(
                    "The backlog of `{topic}` grew from {from} to {to} records in the last ten \
                     minutes: the {reader} is slower than what is sent to it."
                ),
            ),
            None => self.set_at(
                now,
                reader,
                &kind,
                Standing::Ok,
                "current",
                format!("The backlog of `{topic}` is {records} records."),
            ),
        }
    }

    /// What the process `identity` names says of itself at `now`.
    fn report(&self, identity: &Identity, now: i64) -> Report {
        Report {
            instance: identity.instance.clone(),
            roles: identity.roles.clone(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started: identity.started,
            sent: now,
            counters: self
                .0
                .backlogs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|((topic, reader), backlog)| {
                    (format!("backlog:{topic}:{reader}"), backlog.now)
                })
                .collect(),
            conditions: self
                .0
                .conditions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values()
                .cloned()
                .collect(),
        }
    }

    /// Every role was started.
    pub(crate) fn started(&self) {
        self.0.started.store(true, Ordering::Relaxed);
    }

    /// The process is shutting down, and takes no new work.
    pub(crate) fn stopping(&self) {
        self.0.stopping.store(true, Ordering::Relaxed);
    }

    /// What startup still waits for; empty once it finished.
    fn waiting(&self) -> Vec<&'static str> {
        let mut waiting = Vec::new();
        if !self.0.started.load(Ordering::Relaxed) {
            waiting.push("roles");
        }
        waiting.extend(self.holds().iter().copied());
        waiting
    }

    fn startup(&self) -> Response {
        answer(&self.waiting(), "starting")
    }

    fn ready(&self) -> Response {
        if self.0.stopping.load(Ordering::Relaxed) {
            return answer(&["shutdown"], "stopping");
        }
        self.startup()
    }

    /// The probes, to be served beside the metrics.
    pub(crate) fn probes(&self) -> Router {
        let (startup, ready) = (self.clone(), self.clone());
        Router::new()
            .route("/health/live", get(|| async { answer(&[], "") }))
            .route(
                "/health/startup",
                get(move || async move { startup.startup() }),
            )
            .route("/health/ready", get(move || async move { ready.ready() }))
    }
}

/// Sends what the process says of itself to `reports` every 15 seconds,
/// until `stop` turns true.
///
/// A report that cannot be sent in that time is given up: the next one says
/// more, and a process must not stop over its own health. So no error of
/// the pipe ends this.
pub(crate) async fn report(
    health: Health,
    identity: Identity,
    reports: impl Sender + Sync,
    mut stop: watch::Receiver<bool>,
) -> Result<(), RunError> {
    let mut every = tokio::time::interval(EVERY);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = every.tick() => {}
            _ = stop.wait_for(|stopping| *stopping) => return Ok(()),
        }
        let report = health.report(&identity, crate::raw::now());
        let Ok(payload) = serde_json::to_vec(&report) else {
            continue;
        };
        match tokio::time::timeout(EVERY, reports.send(vec![payload])).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "the report of this process was not sent"),
            Err(_) => warn!("the health topic is full; the report of this process was given up"),
        }
    }
}

/// Yes with nothing waited for; otherwise no, with `status` and what for.
fn answer(waiting: &[&str], status: &str) -> Response {
    if waiting.is_empty() {
        (StatusCode::OK, axum::Json(json!({ "status": "ok" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "status": status, "waiting_for": waiting })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    async fn ask(health: &Health, path: &str) -> (StatusCode, serde_json::Value) {
        let response = health
            .probes()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn startup_waits_for_the_roles_and_for_what_holds_it() {
        let health = Health::default();
        let feeds = health.hold("feeds");
        let (status, body) = ask(&health, "/health/startup").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            json!({ "status": "starting", "waiting_for": ["roles", "feeds"] })
        );

        health.started();
        let (status, body) = ask(&health, "/health/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["waiting_for"], json!(["feeds"]));

        drop(feeds);
        for path in ["/health/startup", "/health/ready"] {
            let (status, body) = ask(&health, path).await;
            assert_eq!((status, body), (StatusCode::OK, json!({ "status": "ok" })));
        }
    }

    #[tokio::test]
    async fn a_process_that_shuts_down_is_not_ready_and_is_still_live() {
        let health = Health::default();
        health.started();
        health.stopping();
        let (status, body) = ask(&health, "/health/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            json!({ "status": "stopping", "waiting_for": ["shutdown"] })
        );
        assert_eq!(ask(&health, "/health/startup").await.0, StatusCode::OK);
        assert_eq!(ask(&health, "/health/live").await.0, StatusCode::OK);
    }

    fn identity() -> Identity {
        Identity {
            instance: "writer-0".to_owned(),
            roles: vec!["writer".to_owned()],
            started: 1_000,
        }
    }

    #[test]
    fn a_condition_keeps_when_it_began_while_its_status_holds() {
        let health = Health::default();
        health.set_at(
            2_000,
            "writer",
            "storing",
            Standing::Ok,
            "stored",
            "a".to_owned(),
        );
        health.set_at(
            3_000,
            "writer",
            "storing",
            Standing::Ok,
            "stored",
            "b".to_owned(),
        );
        let report = health.report(&identity(), 3_500);
        assert_eq!(report.conditions.len(), 1);
        assert_eq!(
            (
                report.conditions[0].since,
                report.conditions[0].message.as_str()
            ),
            (2_000, "b")
        );

        health.set_at(
            4_000,
            "writer",
            "storing",
            Standing::Failing,
            "store_refused",
            "c".to_owned(),
        );
        // Another question of the same role is a condition of its own.
        health.set_at(
            4_500,
            "writer",
            "keeping_up",
            Standing::Ok,
            "current",
            "d".to_owned(),
        );
        let report = health.report(&identity(), 5_000);
        let said: Vec<(&str, Standing, &str, i64)> = report
            .conditions
            .iter()
            .map(|held| {
                (
                    held.kind.as_str(),
                    held.status,
                    held.reason.as_str(),
                    held.since,
                )
            })
            .collect();
        assert_eq!(
            said,
            [
                ("keeping_up", Standing::Ok, "current", 4_500),
                ("storing", Standing::Failing, "store_refused", 4_000),
            ]
        );
        assert_eq!(
            (report.instance.as_str(), report.started, report.sent),
            ("writer-0", 1_000, 5_000)
        );
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn a_backlog_that_grew_through_ten_minutes_is_told_and_a_short_one_is_not() {
        let condition = |health: &Health| {
            let report = health.report(&identity(), 0);
            let held = &report.conditions[0];
            (
                held.kind.clone(),
                held.status,
                held.reason.clone(),
                held.since,
            )
        };
        let health = Health::default();
        // It grows from the start, and ten minutes were not yet seen.
        for step in 0..39_u32 {
            health.backlog_at(
                i64::from(step) * 15_000,
                "normalized",
                "writer",
                2_000 + 100 * u64::from(step),
            );
        }
        assert_eq!(
            condition(&health),
            (
                "keeping_up:normalized".to_owned(),
                Standing::Ok,
                "current".to_owned(),
                0
            )
        );
        // Ten minutes of it.
        health.backlog_at(39 * 15_000, "normalized", "writer", 5_900);
        let report = health.report(&identity(), 600_000);
        assert_eq!(
            condition(&health),
            (
                "keeping_up:normalized".to_owned(),
                Standing::Degraded,
                "backlog_grows".to_owned(),
                585_000
            )
        );
        assert_eq!(
            report.conditions[0].message,
            "The backlog of `normalized` grew from 2000 to 5900 records in the last ten \
             minutes: the writer is slower than what is sent to it."
        );
        assert_eq!(report.counters["backlog:normalized:writer"], 5_900);
        // The reader catches up.
        health.backlog_at(40 * 15_000, "normalized", "writer", 100);
        assert_eq!(condition(&health).1, Standing::Ok);

        // One that grows and stays short is not worth telling.
        let short = Health::default();
        for step in 0..60_u32 {
            short.backlog_at(
                i64::from(step) * 15_000,
                "findings",
                "writer",
                u64::from(step),
            );
        }
        assert_eq!(condition(&short).1, Standing::Ok);
        // One that is long and does not grow is the store's own pace.
        let level = Health::default();
        for step in 0..60_u32 {
            level.backlog_at(i64::from(step) * 15_000, "normalized", "writer", 50_000);
        }
        assert_eq!(condition(&level).1, Standing::Ok);
    }

    #[tokio::test]
    async fn a_report_is_sent_at_once_and_none_after_the_process_stops() {
        use goliath_pipe::{DiskOptions, DiskTopic, Receiver};

        let directory = tempfile::tempdir().unwrap();
        let topic =
            DiskTopic::open(directory.path().join("health"), DiskOptions::default()).unwrap();
        let mut reader = topic.subscribe("writer").unwrap();
        let health = Health::default();
        health.set(
            "writer",
            "storing",
            Standing::Ok,
            "stored",
            "Stored.".to_owned(),
        );
        let (stop, stopped) = watch::channel(false);
        let reporting = tokio::spawn(report(health, identity(), topic.sender(), stopped));

        let sent = reader.receive(10, Duration::from_secs(5)).await.unwrap();
        assert_eq!(sent.len(), 1);
        let said: Report = serde_json::from_slice(&sent[0].payload).unwrap();
        assert_eq!(said.instance, "writer-0");
        assert_eq!(said.roles, ["writer"]);
        assert_eq!(said.conditions[0].kind, "storing");

        stop.send(true).unwrap();
        assert!(reporting.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn live_says_yes_before_anything_started() {
        let health = Health::default();
        let _feeds = health.hold("feeds");
        let (status, body) = ask(&health, "/health/live").await;
        assert_eq!((status, body), (StatusCode::OK, json!({ "status": "ok" })));
    }
}
