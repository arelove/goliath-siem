//! Replaying a recording of real telemetry as if it were happening now.
//!
//! A recording is read in its source's own format, the records ordered by
//! the time they claim, and each record's times moved so that the first one
//! is the moment the replay starts. Gaps between records are kept, divided by
//! a speed multiplier, and a record is released when its new time comes, so
//! the platform receives the recording at the pace it was made, or faster.
//! See `docs/adr/0017-benchmark-rig.md`, Replay.

use std::fmt;

use serde_json::Value;

/// Where a source's records say when they happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clock {
    /// JSON values, with times at these JSON pointers: RFC 3339, or
    /// `YYYY-MM-DD hh:mm:ss.fff` in UTC as Sysmon's `UtcTime` writes it.
    /// The first pointer present orders the records; every one present is
    /// moved.
    Json(&'static [&'static str]),
    /// Linux audit lines, each stamped `msg=audit(seconds.millis:serial)`;
    /// the lines of one event share the stamp.
    Audit,
}

impl Clock {
    /// The clock of a shipped source definition, by its name.
    pub fn of(source: &str) -> Option<Self> {
        match source {
            "sysmon" => Some(Self::Json(&[
                "/Event/System/TimeCreated/#attributes/SystemTime",
                "/Event/EventData/UtcTime",
            ])),
            "sysmon-flat" => Some(Self::Json(&["/@timestamp", "/TimeCreated", "/UtcTime"])),
            "entra" => Some(Self::Json(&["/time", "/properties/createdDateTime"])),
            "falco" => Some(Self::Json(&["/time"])),
            "auditd" => Some(Self::Audit),
            _ => None,
        }
    }
}

/// Why a recording cannot be replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// A record is not valid JSON, at this byte offset.
    Json(usize, String),
    /// A record has no time the clock can read; the number is its position.
    Untimed(usize),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(offset, reason) => write!(f, "not JSON at byte {offset}: {reason}"),
            Self::Untimed(index) => {
                write!(f, "record {index} has no time the source's clock reads")
            }
        }
    }
}

impl std::error::Error for ReplayError {}

/// One record, with the time it claims in milliseconds since the epoch.
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    time: i64,
    body: Body,
}

#[derive(Debug, Clone, PartialEq)]
enum Body {
    Json(Value),
    Audit(Vec<String>),
}

/// A recording, ordered by the time its records claim.
#[derive(Debug, Clone, PartialEq)]
pub struct Recording {
    clock: Clock,
    entries: Vec<Entry>,
}

impl Recording {
    /// Reads a recording: JSON values one after another, separated by any
    /// whitespace, or audit lines.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError`] if a record is not JSON or has no time.
    pub fn read(clock: Clock, bytes: &[u8]) -> Result<Self, ReplayError> {
        let mut entries = match clock {
            Clock::Json(pointers) => {
                let mut entries = Vec::new();
                let mut values = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
                while let Some(value) = values.next() {
                    let value = value.map_err(|error| {
                        ReplayError::Json(values.byte_offset(), error.to_string())
                    })?;
                    let time = pointers
                        .iter()
                        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
                        .and_then(parse_time)
                        .ok_or(ReplayError::Untimed(entries.len()))?;
                    entries.push(Entry {
                        time,
                        body: Body::Json(value),
                    });
                }
                entries
            }
            Clock::Audit => audit_events(&String::from_utf8_lossy(bytes))?,
        };
        // Stable, so records of one instant keep their recorded order.
        entries.sort_by_key(|entry| entry.time);
        Ok(Self { clock, entries })
    }

    /// Records in the recording.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it holds no records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Milliseconds from its first record to its last, as recorded.
    pub fn span(&self) -> i64 {
        match (self.entries.first(), self.entries.last()) {
            (Some(first), Some(last)) => last.time - first.time,
            _ => 0,
        }
    }

    /// The records as a replay starting at `start` releases them, with
    /// their times moved: each with the millisecond it is due, in order.
    ///
    /// A record `gap` milliseconds after the first is due `gap / speed`
    /// after `start`, and claims that time too, so that what the platform
    /// stores looks as if it happened as it arrived.
    pub fn schedule(&self, start: i64, speed: f64) -> impl Iterator<Item = (i64, Vec<u8>)> + '_ {
        let first = self.entries.first().map_or(0, |entry| entry.time);
        let speed = if speed.is_finite() && speed > 0.0 {
            speed
        } else {
            1.0
        };
        self.entries.iter().map(move |entry| {
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let due = start + ((entry.time - first) as f64 / speed).round() as i64;
            (due, self.render(entry, due - entry.time))
        })
    }

    /// A record as its source writes it, every time in it moved by `shift`
    /// milliseconds, ending with a newline.
    fn render(&self, entry: &Entry, shift: i64) -> Vec<u8> {
        match (&entry.body, self.clock) {
            (Body::Json(value), Clock::Json(pointers)) => {
                let mut value = value.clone();
                for pointer in pointers {
                    if let Some(field) = value.pointer_mut(pointer)
                        && let Some(moved) = field.as_str().and_then(|text| moved(text, shift))
                    {
                        *field = Value::String(moved);
                    }
                }
                let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
                bytes.push(b'\n');
                bytes
            }
            (Body::Audit(lines), _) => {
                let mut bytes = Vec::new();
                for line in lines {
                    bytes.extend_from_slice(restamp(line, shift).as_bytes());
                    bytes.push(b'\n');
                }
                bytes
            }
            (Body::Json(_), Clock::Audit) => Vec::new(),
        }
    }
}

/// The lines of an audit log grouped into events by their stamp, each with
/// its time.
fn audit_events(text: &str) -> Result<Vec<Entry>, ReplayError> {
    let mut events: Vec<(String, Entry)> = Vec::new();
    for (index, line) in text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let (stamp, time) = audit_stamp(line).ok_or(ReplayError::Untimed(index))?;
        if let Some((_, entry)) = events.iter_mut().rev().find(|(seen, _)| *seen == stamp) {
            if let Body::Audit(lines) = &mut entry.body {
                lines.push(line.to_owned());
            }
        } else {
            events.push((
                stamp,
                Entry {
                    time,
                    body: Body::Audit(vec![line.to_owned()]),
                },
            ));
        }
    }
    Ok(events.into_iter().map(|(_, entry)| entry).collect())
}

/// A line's `seconds.millis:serial` stamp and its time in milliseconds.
fn audit_stamp(line: &str) -> Option<(String, i64)> {
    let start = line.find("msg=audit(")? + "msg=audit(".len();
    let end = start + line[start..].find(')')?;
    let stamp = &line[start..end];
    let (time, _) = stamp.split_once(':')?;
    let (seconds, millis) = time.split_once('.').unwrap_or((time, "0"));
    let millis = format!("{millis:0<3}");
    let time = seconds.parse::<i64>().ok()? * 1000 + millis.get(..3)?.parse::<i64>().ok()?;
    Some((stamp.to_owned(), time))
}

/// A line with its audit stamp's time moved by `shift` milliseconds.
fn restamp(line: &str, shift: i64) -> String {
    let Some(start) = line.find("msg=audit(").map(|at| at + "msg=audit(".len()) else {
        return line.to_owned();
    };
    let Some(colon) = line[start..].find(':').map(|at| start + at) else {
        return line.to_owned();
    };
    let Some((_, time)) = audit_stamp(line) else {
        return line.to_owned();
    };
    let moved = time + shift;
    format!(
        "{}{}.{:03}{}",
        &line[..start],
        moved.div_euclid(1000),
        moved.rem_euclid(1000),
        &line[colon..]
    )
}

/// A time as RFC 3339, or as `YYYY-MM-DD hh:mm:ss.fff` in UTC, in
/// milliseconds since the epoch.
fn parse_time(text: &str) -> Option<i64> {
    if let Ok(timestamp) = text.parse::<jiff::Timestamp>() {
        return Some(timestamp.as_millisecond());
    }
    let civil: jiff::civil::DateTime = text.parse().ok()?;
    civil
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()
        .map(|zoned| zoned.timestamp().as_millisecond())
}

/// `text`, a time, moved by `shift` milliseconds and written as it was:
/// RFC 3339 with a `Z`, or a space-separated UTC time.
fn moved(text: &str, shift: i64) -> Option<String> {
    let time = parse_time(text)? + shift;
    let timestamp = jiff::Timestamp::from_millisecond(time).ok()?;
    let written = timestamp.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    Some(if text.contains('T') {
        written
    } else {
        written.replace('T', " ").trim_end_matches('Z').to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSMON: Clock = Clock::Json(&[
        "/Event/System/TimeCreated/#attributes/SystemTime",
        "/Event/EventData/UtcTime",
    ]);

    fn sysmon(system: &str, utc: &str, id: u32) -> String {
        format!(
            r##"{{"Event":{{"System":{{"EventRecordID":{id},"TimeCreated":{{"#attributes":{{"SystemTime":"{system}"}}}}}},"EventData":{{"UtcTime":"{utc}"}}}}}}"##
        )
    }

    #[test]
    fn records_are_released_in_time_order_with_their_gaps_divided_by_the_speed() {
        // Written out of order, and pretty-printed as evtx_dump does.
        let recording = format!(
            "{}\n{}\n  {}",
            sysmon("2026-09-24T10:00:02.000Z", "2026-09-24 10:00:02.000", 3),
            sysmon("2026-09-24T10:00:00.0000000Z", "2026-09-24 10:00:00.000", 1),
            sysmon("2026-09-24T10:00:01.5Z", "2026-09-24 10:00:01.500", 2),
        );
        let recording = Recording::read(SYSMON, recording.as_bytes()).unwrap();
        assert_eq!(recording.len(), 3);
        assert_eq!(recording.span(), 2000);

        let start = 1_800_000_000_000; // 2027-01-15T08:00:00Z
        let released: Vec<(i64, Value)> = recording
            .schedule(start, 2.0)
            .map(|(due, bytes)| (due, serde_json::from_slice(&bytes).unwrap()))
            .collect();
        let dues: Vec<i64> = released.iter().map(|(due, _)| *due - start).collect();
        assert_eq!(dues, [0, 750, 1000]);
        let ids: Vec<u64> = released
            .iter()
            .map(|(_, value)| value["Event"]["System"]["EventRecordID"].as_u64().unwrap())
            .collect();
        assert_eq!(ids, [1, 2, 3]);

        // Both times claim the moment the record is released, each written
        // as it was.
        let (due, last) = &released[2];
        let system = last
            .pointer("/Event/System/TimeCreated/#attributes/SystemTime")
            .unwrap();
        let utc = last.pointer("/Event/EventData/UtcTime").unwrap();
        assert_eq!(parse_time(system.as_str().unwrap()), Some(*due));
        assert_eq!(parse_time(utc.as_str().unwrap()), Some(*due));
        assert_eq!(system.as_str().unwrap(), "2027-01-15T08:00:01.000Z");
        assert_eq!(utc.as_str().unwrap(), "2027-01-15 08:00:01.000");
    }

    #[test]
    fn audit_lines_are_grouped_into_events_and_restamped_together() {
        let recording = "\
type=SYSCALL msg=audit(1727251200.123:4521): arch=c000003e syscall=59 success=yes
type=SYSCALL msg=audit(1727251201.5:4522): arch=c000003e syscall=59 success=yes
type=EXECVE msg=audit(1727251200.123:4521): argc=1 a0=\"ls\"
";
        let recording = Recording::read(Clock::Audit, recording.as_bytes()).unwrap();
        assert_eq!(recording.len(), 2);
        assert_eq!(recording.span(), 1377);
        let released: Vec<(i64, String)> = recording
            .schedule(1_800_000_000_000, 1.0)
            .map(|(due, bytes)| (due, String::from_utf8(bytes).unwrap()))
            .collect();
        assert_eq!(
            released[0].1,
            "type=SYSCALL msg=audit(1800000000.000:4521): arch=c000003e syscall=59 success=yes\n\
             type=EXECVE msg=audit(1800000000.000:4521): argc=1 a0=\"ls\"\n"
        );
        assert_eq!(released[1].0, 1_800_000_001_377);
        assert!(released[1].1.contains("msg=audit(1800000001.377:4522)"));
    }

    #[test]
    fn a_record_without_a_time_or_that_is_not_json_is_refused() {
        let untimed = r#"{"time":"2026-09-24T10:00:00Z"} {"other":1}"#;
        assert_eq!(
            Recording::read(Clock::Json(&["/time"]), untimed.as_bytes()),
            Err(ReplayError::Untimed(1))
        );
        assert!(matches!(
            Recording::read(Clock::Json(&["/time"]), b"{\"time\": nope}"),
            Err(ReplayError::Json(..))
        ));
        assert_eq!(
            Recording::read(Clock::Audit, b"type=SYSCALL no stamp here\n"),
            Err(ReplayError::Untimed(0))
        );
    }

    #[test]
    fn every_shipped_source_has_a_clock() {
        for source in ["sysmon", "sysmon-flat", "entra", "falco", "auditd"] {
            assert!(Clock::of(source).is_some(), "{source}");
        }
        assert_eq!(Clock::of("syslog"), None);
    }
}
