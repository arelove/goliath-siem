//! The queue of findings: what was found, the most severe first and, within
//! a severity, the newest first.
//!
//! See `docs/adr/0024-interface.md`. A finding is an OCSF Detection Finding
//! stored among the events, so the queue is a search of that one class in
//! another order, with what a search cannot say: how many findings of each
//! severity its filters leave.

use std::fmt;
use std::str::FromStr;

use clickhouse::Row;
use goliath_search::{Checked, Cursor};
use serde::Deserialize;

use crate::error::StoreError;
use crate::search::{
    COLUMNS, Compiled, Found, FoundRow, Param, SearchLimits, conditions, hex, with_limits,
};
use crate::store::Store;

/// The class of a finding: OCSF Detection Finding.
pub const FINDING: u32 = 2004;

/// Where a page of the queue ended: a finding's severity, and where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    /// The finding's `severity_id`.
    pub severity_id: u8,
    /// Its time and identity.
    pub at: Cursor,
}

/// Text that is not a place in the queue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not where a previous page of findings ended")]
pub struct PlaceError(String);

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.severity_id, self.at)
    }
}

impl FromStr for Place {
    type Err = PlaceError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || PlaceError(text.chars().take(64).collect());
        let (severity_id, at) = text.split_once(':').ok_or_else(invalid)?;
        Ok(Self {
            severity_id: severity_id.parse().map_err(|_| invalid())?,
            at: at.parse().map_err(|_| invalid())?,
        })
    }
}

/// Findings of one severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Row, Deserialize)]
pub struct SeverityCount {
    /// The OCSF `severity_id`.
    pub severity_id: u8,
    /// Findings.
    pub count: u64,
}

/// One page of the queue.
#[derive(Debug, Clone, PartialEq)]
pub struct Queue {
    /// The findings, the most severe first and then the newest.
    pub findings: Vec<Found>,
    /// Where to continue, if the page is full and more may follow.
    pub next: Option<Place>,
    /// Findings the range and the filters leave, by severity, whichever
    /// severities the page was asked for: what choosing another would show.
    pub severities: Vec<SeverityCount>,
}

#[derive(Debug, Row, Deserialize)]
struct QueueRow {
    time_ms: i64,
    id: [u8; 16],
    class_uid: u32,
    source: String,
    kind: String,
    event_json: String,
    severity_id: u8,
}

impl Store {
    /// One page of the findings `search` leaves, of the `severities` named
    /// or of every severity if none is, after `after`.
    ///
    /// The classes of `search` and where it would begin are not read: the
    /// queue holds findings only, and has its own place.
    ///
    /// Runs read-only, within `limits`, and with `FINAL`, so that a finding
    /// stored twice is shown and counted once.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ClickHouse`] if a query fails or exceeds its
    /// limits, and [`StoreError::Stored`] if a stored finding is not JSON.
    pub async fn findings(
        &self,
        search: &Checked,
        severities: &[u8],
        after: Option<Place>,
        limits: SearchLimits,
    ) -> Result<Queue, StoreError> {
        let search = Checked {
            classes: vec![FINDING],
            after: None,
            ..search.clone()
        };
        let (page, counts) = compile(&search, severities, after);
        let mut query = self.client().query(&page.sql);
        for (name, param) in &page.params {
            query = query.param(name, param);
        }
        let rows = with_limits(query, limits).fetch_all::<QueueRow>().await?;
        let full = u32::try_from(rows.len()).is_ok_and(|count| count == search.limit);
        let next = full
            .then(|| {
                rows.last().map(|row| Place {
                    severity_id: row.severity_id,
                    at: Cursor {
                        time: row.time_ms,
                        id: row.id,
                    },
                })
            })
            .flatten();
        let findings = rows
            .into_iter()
            .map(|row| {
                FoundRow {
                    time_ms: row.time_ms,
                    id: row.id,
                    class_uid: row.class_uid,
                    source: row.source,
                    kind: row.kind,
                    event_json: row.event_json,
                }
                .into_found()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut query = self.client().query(&counts.sql);
        for (name, param) in &counts.params {
            query = query.param(name, param);
        }
        let severities = with_limits(query, limits)
            .fetch_all::<SeverityCount>()
            .await?;
        Ok(Queue {
            findings,
            next,
            severities,
        })
    }
}

/// The query for a page, and the query that counts by severity.
fn compile(search: &Checked, severities: &[u8], after: Option<Place>) -> (Compiled, Compiled) {
    let mut counts = Compiled::new();
    let within = conditions(&mut counts, search);
    counts.sql = format!(
        "SELECT severity_id, count() AS count FROM events FINAL WHERE {} \
         GROUP BY severity_id ORDER BY severity_id DESC",
        within.join(" AND ")
    );

    let mut page = Compiled::new();
    let mut within = conditions(&mut page, search);
    if !severities.is_empty() {
        let list = page.bind(Param::Integers(
            severities
                .iter()
                .map(|&severity| i64::from(severity))
                .collect(),
        ));
        within.push(format!("has({list}, toInt64(severity_id))"));
    }
    if let Some(after) = after {
        let severity = page.bind(Param::Integer(i64::from(after.severity_id)));
        let time = page.bind(Param::Integer(after.at.time));
        let id = page.bind(Param::Text(hex(&after.at.id)));
        within.push(format!(
            "(toInt64(severity_id), time, id) < \
             ({severity}, fromUnixTimestamp64Milli({time}, 'UTC'), toFixedString(unhex({id}), 16))"
        ));
    }
    let limit = page.bind(Param::Integer(i64::from(search.limit)));
    page.sql = format!(
        "SELECT {COLUMNS}, severity_id FROM events FINAL WHERE {} \
         ORDER BY severity_id DESC, time DESC, id DESC LIMIT {limit}",
        within.join(" AND ")
    );
    (page, counts)
}

#[cfg(test)]
mod tests {
    use goliath_search::{Limits, Search};
    use serde_json::json;

    use super::*;

    fn checked() -> Checked {
        let search: Search = serde_json::from_value(json!({
            "from": "2026-09-25T00:00:00Z",
            "to": "2026-09-26T00:00:00Z",
            "classes": [1007],
            "limit": 50,
        }))
        .unwrap();
        Checked {
            classes: vec![FINDING],
            ..search.check(&Limits::default()).unwrap()
        }
    }

    #[test]
    fn a_place_reads_back_from_its_text() {
        let place = Place {
            severity_id: 4,
            at: Cursor {
                time: 1_790_330_000_000,
                id: [7; 16],
            },
        };
        assert_eq!(place.to_string().parse(), Ok(place));
        for text in [
            "",
            "4",
            "4:",
            "high:1-00",
            "300:1790330000000-07070707070707070707070707070707",
        ] {
            assert!(text.parse::<Place>().is_err(), "{text}");
        }
    }

    #[test]
    fn the_queue_reads_the_most_severe_first_and_then_the_newest() {
        let (page, counts) = compile(&checked(), &[], None);
        assert_eq!(
            page.sql,
            "SELECT toUnixTimestamp64Milli(time) AS time_ms, id, class_uid, source, kind, \
             toJSONString(event) AS event_json, severity_id FROM events FINAL \
             WHERE time >= fromUnixTimestamp64Milli({p0:Int64}, 'UTC') \
             AND time < fromUnixTimestamp64Milli({p1:Int64}, 'UTC') \
             AND class_uid IN ({p2:Int64}) \
             ORDER BY severity_id DESC, time DESC, id DESC LIMIT {p3:Int64}"
        );
        assert!(
            page.params
                .contains(&("p2".to_owned(), Param::Integer(2004)))
        );
        assert!(
            counts
                .sql
                .ends_with("GROUP BY severity_id ORDER BY severity_id DESC")
        );
    }

    #[test]
    fn the_severities_asked_for_bound_the_page_and_not_the_counts() {
        let after = Place {
            severity_id: 3,
            at: Cursor {
                time: 5,
                id: [1; 16],
            },
        };
        let (page, counts) = compile(&checked(), &[4, 5], Some(after));
        assert!(
            page.sql
                .contains("has({p3:Array(Int64)}, toInt64(severity_id))"),
            "{}",
            page.sql
        );
        assert!(
            page.sql
                .contains("(toInt64(severity_id), time, id) < ({p4:Int64}, "),
            "{}",
            page.sql
        );
        assert!(!counts.sql.contains("has("), "{}", counts.sql);
        assert_eq!(counts.params.len(), 3);
    }
}
