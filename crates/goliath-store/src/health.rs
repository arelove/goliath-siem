//! Source health: for each source, the last event stored, its events in the
//! last complete hour against the same hour of the seven days before, and
//! its dead letters, from the hourly counts ClickHouse keeps as rows are
//! inserted. See docs/adr/0019-source-health.md.

use std::collections::{BTreeMap, BTreeSet};

use clickhouse::Row;
use serde::Deserialize;

use crate::error::StoreError;
use crate::search::{SearchLimits, with_limits};
use crate::store::Store;

/// How long a source may send nothing before it is `silent`, unless its
/// configuration says otherwise.
pub const DEFAULT_SILENT_AFTER_MINUTES: u32 = 60;

/// Dead letters in an hour, at the least, for a source to be `rejecting`.
const REJECTING_AT_LEAST: u64 = 10;

/// Events an hour a baseline must reach for a rate to be compared with it.
const COMPARED_FROM: u64 = 20;

/// Days before the last hour whose same hour makes the baseline.
const BASELINE_DAYS: i64 = 7;

/// Of those days, how many must have been counted for there to be a
/// baseline.
const BASELINE_AT_LEAST: usize = 3;

const HOUR: i64 = 3600;
const DAY: i64 = 24 * HOUR;

/// Events of one source stored in one hour.
#[derive(Debug, Clone, PartialEq, Eq, Row, Deserialize)]
pub struct SourceHour {
    /// The source.
    pub source: String,
    /// The hour's start, in seconds since the epoch.
    pub hour: u32,
    /// Events stored.
    pub events: u64,
    /// When the last of them was received, in milliseconds since the epoch.
    pub last_received: i64,
}

/// Dead letters of one source and stage in one hour.
#[derive(Debug, Clone, PartialEq, Eq, Row, Deserialize)]
pub struct DeadLetterHour {
    /// The source.
    pub source: String,
    /// Where the record failed, such as `decoding`.
    pub stage: String,
    /// The hour's start, in seconds since the epoch.
    pub hour: u32,
    /// Dead letters stored.
    pub dead_letters: u64,
    /// When the last of them was received, in milliseconds since the epoch.
    pub last_received: i64,
}

/// A source the platform is configured to take, and how long it may be
/// quiet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watched {
    /// The source.
    pub source: String,
    /// Minutes without an event before it is `silent`.
    pub silent_after_minutes: u32,
}

/// What a source's numbers say, the first that holds in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    /// Many of its records in the last hour could not be read.
    Rejecting,
    /// No event of it is stored in the counted weeks.
    Waiting,
    /// No event for longer than it may be quiet.
    Silent,
    /// Far fewer events in the last hour than in the same hour before.
    Low,
    /// Far more events in the last hour than in the same hour before.
    High,
    /// Too few days counted for a baseline.
    Learning,
    /// None of the above.
    Ok,
}

impl Status {
    /// The status as the API names it, such as `silent`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rejecting => "rejecting",
            Self::Waiting => "waiting",
            Self::Silent => "silent",
            Self::Low => "low",
            Self::High => "high",
            Self::Learning => "learning",
            Self::Ok => "ok",
        }
    }
}

/// The health of one source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    /// The source.
    pub source: String,
    /// What its numbers say.
    pub status: Status,
    /// When its last event was received, in milliseconds since the epoch.
    pub last_event: Option<i64>,
    /// The start of the last complete hour, in seconds since the epoch.
    pub hour: i64,
    /// Its events in that hour.
    pub last_hour: u64,
    /// The median of its events in the same hour of the seven days before,
    /// if at least three of them were counted.
    pub baseline: Option<u64>,
    /// Its dead letters in the last complete hour.
    pub dead_letters_last_hour: u64,
    /// Its dead letters in the 24 complete hours before now, by stage.
    pub dead_letters_last_day: BTreeMap<String, u64>,
    /// When its last dead letter was received, in milliseconds since the
    /// epoch.
    pub last_dead_letter: Option<i64>,
    /// Minutes without an event before it is `silent`.
    pub silent_after_minutes: u32,
}

/// Judges every source that is watched or has counts, at `now`, in
/// milliseconds since the epoch: the ones needing attention first, then by
/// name.
pub fn judge(
    now: i64,
    watched: &[Watched],
    hours: &[SourceHour],
    dead_letters: &[DeadLetterHour],
) -> Vec<Health> {
    let last = now.div_euclid(1000).div_euclid(HOUR) * HOUR - HOUR;
    let sources: BTreeSet<&str> = watched
        .iter()
        .map(|watched| watched.source.as_str())
        .chain(hours.iter().map(|hour| hour.source.as_str()))
        .chain(dead_letters.iter().map(|hour| hour.source.as_str()))
        .collect();
    let mut judged: Vec<Health> = sources
        .into_iter()
        .map(|source| {
            let silent_after_minutes = watched
                .iter()
                .find(|watched| watched.source == source)
                .map_or(DEFAULT_SILENT_AFTER_MINUTES, |watched| {
                    watched.silent_after_minutes
                });
            one(now, last, source, silent_after_minutes, hours, dead_letters)
        })
        .collect();
    judged.sort_by(|a, b| (a.status, &a.source).cmp(&(b.status, &b.source)));
    judged
}

fn one(
    now: i64,
    last: i64,
    source: &str,
    silent_after_minutes: u32,
    hours: &[SourceHour],
    dead_letters: &[DeadLetterHour],
) -> Health {
    let mut counts: BTreeMap<i64, u64> = BTreeMap::new();
    let mut last_event = None;
    for hour in hours.iter().filter(|hour| hour.source == source) {
        *counts.entry(i64::from(hour.hour)).or_default() += hour.events;
        last_event = last_event.max(Some(hour.last_received));
    }
    let last_hour = counts.get(&last).copied().unwrap_or_default();
    let baseline = counts
        .keys()
        .next()
        .and_then(|&first| baseline(&counts, first, last));

    let mut dead_letters_last_hour = 0;
    let mut dead_letters_last_day = BTreeMap::new();
    let mut last_dead_letter = None;
    for hour in dead_letters.iter().filter(|hour| hour.source == source) {
        let at = i64::from(hour.hour);
        if at == last {
            dead_letters_last_hour += hour.dead_letters;
        }
        if at > last - DAY && at <= last {
            *dead_letters_last_day.entry(hour.stage.clone()).or_default() += hour.dead_letters;
        }
        last_dead_letter = last_dead_letter.max(Some(hour.last_received));
    }

    let quiet = last_event.map(|at| now - at);
    let status = if dead_letters_last_hour >= REJECTING_AT_LEAST
        && dead_letters_last_hour * 100 >= last_hour + dead_letters_last_hour
    {
        Status::Rejecting
    } else if quiet.is_none() {
        Status::Waiting
    } else if quiet > Some(i64::from(silent_after_minutes) * 60_000) {
        Status::Silent
    } else {
        match baseline {
            Some(baseline) if baseline >= COMPARED_FROM && last_hour * 4 < baseline => Status::Low,
            Some(baseline) if baseline >= COMPARED_FROM && last_hour > baseline * 4 => Status::High,
            Some(_) => Status::Ok,
            None => Status::Learning,
        }
    };
    Health {
        source: source.to_owned(),
        status,
        last_event,
        hour: last,
        last_hour,
        baseline,
        dead_letters_last_hour,
        dead_letters_last_day,
        last_dead_letter,
        silent_after_minutes,
    }
}

/// The median of the counts in the same hour as `last` on each of the seven
/// days before it, counting an hour with none as zero, if at least three of
/// those hours are at or after `first`, when counting began.
fn baseline(counts: &BTreeMap<i64, u64>, first: i64, last: i64) -> Option<u64> {
    let mut same_hours: Vec<u64> = (1..=BASELINE_DAYS)
        .map(|days| last - days * DAY)
        .filter(|&hour| hour >= first)
        .map(|hour| counts.get(&hour).copied().unwrap_or_default())
        .collect();
    if same_hours.len() < BASELINE_AT_LEAST {
        return None;
    }
    same_hours.sort_unstable();
    let middle = same_hours.len() / 2;
    Some(if same_hours.len() % 2 == 1 {
        same_hours[middle]
    } else {
        u64::midpoint(same_hours[middle - 1], same_hours[middle])
    })
}

impl Store {
    /// Events stored by source and hour, over the five weeks kept.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails or exceeds
    /// `limits`.
    pub async fn source_hours(&self, limits: SearchLimits) -> Result<Vec<SourceHour>, StoreError> {
        let query = self.client().query(
            "SELECT source, toUnixTimestamp(hour) AS hour, sum(events) AS events, \
             toUnixTimestamp64Milli(max(last_received)) AS last_received \
             FROM source_hours GROUP BY source, hour ORDER BY source, hour",
        );
        Ok(with_limits(query, limits).fetch_all::<SourceHour>().await?)
    }

    /// Dead letters stored by source, stage, and hour, over the five weeks
    /// kept.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if the query fails or exceeds
    /// `limits`.
    pub async fn dead_letter_hours(
        &self,
        limits: SearchLimits,
    ) -> Result<Vec<DeadLetterHour>, StoreError> {
        let query = self.client().query(
            "SELECT source, stage, toUnixTimestamp(hour) AS hour, \
             sum(dead_letters) AS dead_letters, \
             toUnixTimestamp64Milli(max(last_received)) AS last_received \
             FROM dead_letter_hours GROUP BY source, stage, hour \
             ORDER BY source, stage, hour",
        );
        Ok(with_limits(query, limits)
            .fetch_all::<DeadLetterHour>()
            .await?)
    }

    /// The health of every source that is `watched` or has counts, at `now`,
    /// in milliseconds since the epoch.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a query fails or exceeds
    /// `limits`.
    pub async fn source_health(
        &self,
        now: i64,
        watched: &[Watched],
        limits: SearchLimits,
    ) -> Result<Vec<Health>, StoreError> {
        let hours = self.source_hours(limits).await?;
        let dead_letters = self.dead_letter_hours(limits).await?;
        Ok(judge(now, watched, &hours, &dead_letters))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-28 12:30 UTC, in milliseconds; the last complete hour is 11:00.
    const NOW: i64 = 1_790_598_600_000;
    const LAST: i64 = 1_790_593_200;

    fn hour(source: &str, at: i64, events: u64) -> SourceHour {
        SourceHour {
            source: source.to_owned(),
            hour: u32::try_from(at).unwrap_or_default(),
            events,
            last_received: at * 1000 + 3_599_000,
        }
    }

    fn dead(source: &str, stage: &str, at: i64, dead_letters: u64) -> DeadLetterHour {
        DeadLetterHour {
            source: source.to_owned(),
            stage: stage.to_owned(),
            hour: u32::try_from(at).unwrap_or_default(),
            dead_letters,
            last_received: at * 1000 + 60_000,
        }
    }

    /// `per_hour` events in every hour of the eight days before now, and
    /// `now_last` in the last complete hour.
    fn steady(source: &str, per_hour: u64, now_last: u64) -> Vec<SourceHour> {
        (0..8 * 24)
            .map(|back| {
                let at = LAST - back * HOUR;
                hour(source, at, if back == 0 { now_last } else { per_hour })
            })
            .collect()
    }

    fn status(hours: &[SourceHour], dead_letters: &[DeadLetterHour]) -> Status {
        let judged = judge(NOW, &[], hours, dead_letters);
        assert_eq!(judged.len(), 1, "{judged:?}");
        judged[0].status
    }

    #[test]
    fn a_source_like_its_week_is_ok() {
        let judged = judge(NOW, &[], &steady("okta", 100, 90), &[]);
        assert_eq!(judged[0].status, Status::Ok);
        assert_eq!(judged[0].last_hour, 90);
        assert_eq!(judged[0].baseline, Some(100));
        assert_eq!(judged[0].hour, LAST);
    }

    #[test]
    fn far_fewer_or_far_more_than_the_same_hour_before_is_low_or_high() {
        assert_eq!(status(&steady("okta", 100, 24), &[]), Status::Low);
        assert_eq!(status(&steady("okta", 100, 25), &[]), Status::Ok);
        assert_eq!(status(&steady("okta", 100, 401), &[]), Status::High);
    }

    #[test]
    fn a_small_rate_is_not_compared() {
        assert_eq!(status(&steady("okta", 19, 0), &[]), Status::Ok);
    }

    #[test]
    fn the_baseline_is_the_median_of_the_same_hour() {
        // One day ten times busier does not move the median.
        let mut hours = steady("okta", 100, 100);
        for entry in &mut hours {
            if i64::from(entry.hour) == LAST - 3 * DAY {
                entry.events = 1000;
            }
        }
        assert_eq!(judge(NOW, &[], &hours, &[])[0].baseline, Some(100));
        // Only the same hour counts: busy days, quiet nights.
        let hours: Vec<SourceHour> = (0..8 * 24)
            .map(|back| {
                let at = LAST - back * HOUR;
                hour("dc", at, if back % 24 == 0 { 1000 } else { 1 })
            })
            .collect();
        assert_eq!(judge(NOW, &[], &hours, &[])[0].baseline, Some(1000));
    }

    #[test]
    fn a_source_counted_for_less_than_three_days_is_learning() {
        let hours: Vec<SourceHour> = (0..=2 * 24)
            .map(|back| hour("new", LAST - back * HOUR, 50))
            .collect();
        let judged = judge(NOW, &[], &hours, &[]);
        assert_eq!(judged[0].status, Status::Learning);
        assert_eq!(judged[0].baseline, None);
    }

    #[test]
    fn a_quiet_source_is_silent_after_its_own_limit() {
        // The last event at 09:59:59, 2.5 hours before now.
        let hours = [hour("m365", LAST - 2 * HOUR, 5)];
        assert_eq!(status(&hours, &[]), Status::Silent);
        let watched = [Watched {
            source: "m365".to_owned(),
            silent_after_minutes: 240,
        }];
        let judged = judge(NOW, &watched, &hours, &[]);
        assert_eq!(judged[0].status, Status::Learning);
        assert_eq!(judged[0].silent_after_minutes, 240);
    }

    #[test]
    fn a_watched_source_with_no_events_is_waiting() {
        let watched = [Watched {
            source: "zeek".to_owned(),
            silent_after_minutes: DEFAULT_SILENT_AFTER_MINUTES,
        }];
        let judged = judge(NOW, &watched, &[], &[]);
        assert_eq!(judged[0].status, Status::Waiting);
        assert_eq!(judged[0].last_event, None);
    }

    #[test]
    fn many_dead_letters_are_rejecting_before_anything_else() {
        let dead_letters = [
            dead("okta", "decoding", LAST, 6),
            dead("okta", "normalizing", LAST, 4),
            dead("okta", "decoding", LAST - 5 * HOUR, 2),
            dead("okta", "decoding", LAST - DAY, 7),
        ];
        let judged = judge(NOW, &[], &steady("okta", 100, 100), &dead_letters);
        assert_eq!(judged[0].status, Status::Rejecting);
        assert_eq!(judged[0].dead_letters_last_hour, 10);
        assert_eq!(
            judged[0].dead_letters_last_day,
            BTreeMap::from([("decoding".to_owned(), 8), ("normalizing".to_owned(), 4)])
        );
        // Fewer than ten, or under 1% of the records, is not.
        assert_eq!(
            status(&steady("okta", 100, 100), &dead_letters[..1]),
            Status::Ok
        );
        assert_eq!(
            status(&steady("okta", 2000, 2000), &dead_letters),
            Status::Ok
        );
        // A source whose every record fails has no events at all.
        assert_eq!(status(&[], &dead_letters), Status::Rejecting);
    }

    #[test]
    fn sources_needing_attention_come_first() {
        let mut hours = steady("b", 100, 100);
        hours.extend(steady("a", 100, 100));
        hours.extend(steady("c", 100, 0));
        let order: Vec<String> = judge(NOW, &[], &hours, &[])
            .into_iter()
            .map(|health| health.source)
            .collect();
        assert_eq!(order, ["c", "a", "b"]);
    }
}
