//! Feeds: where indicators come from, declared as files, and how what a feed
//! publishes becomes indicators.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::key::{Key, Kind};
use crate::store::Store;
use crate::{Assertion, IntelError, stix};

/// Rows whose value cannot be of its kind, in a hundred, above which a feed
/// is refused: more than this is a changed format, not a bad row.
const REJECTED_PERCENT: usize = 10;
/// Reasons kept of the rows rejected.
const REASONS: usize = 5;
const DAY: i64 = 86_400;

/// A feed as a file: versioned, reviewed content beside rules.
///
/// ```yaml
/// name: feodo-tracker
/// url: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
/// confidence: 90
/// refresh_minutes: 60
/// valid_days: 30
/// format: csv
/// csv:
///   value: dst_ip
///   kind: ip
///   first_seen: first_seen_utc
///   last_seen: last_online
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    /// The feed's name, which a hit is reported with.
    pub name: String,
    /// What the feed is, for those who read the file.
    pub description: Option<String>,
    /// Where it is published.
    pub url: Option<String>,
    /// The terms it is published under.
    pub licence: Option<String>,
    /// The confidence of its indicators, 0 to 100, unless a row says.
    pub confidence: u8,
    /// How often it is fetched; every hour if left out.
    #[serde(default = "hourly")]
    pub refresh_minutes: u32,
    /// How long an indicator holds after the feed last saw it, or first saw
    /// it, or was fetched, whichever the feed gives; without end if left
    /// out. An indicator that says until when it holds keeps its own end.
    pub valid_days: Option<u32>,
    /// How what it publishes is read.
    pub format: Format,
    /// How its rows are read; needed by, and only by, the `csv` format.
    pub csv: Option<Csv>,
}

fn hourly() -> u32 {
    60
}

/// How what a feed publishes is read.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// Rows of separated values, one indicator a row. A list of values, one
    /// a line, is the same with one column.
    Csv,
    /// A STIX 2.1 bundle: its `indicator` objects whose pattern compares
    /// for equality.
    Stix,
}

/// How the rows of a feed are read.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Csv {
    /// The names of the columns, if the feed has no header row or has it
    /// in a comment; otherwise the first row names them.
    pub columns: Option<Vec<String>>,
    /// What a line that is not a row begins with; `#` if left out.
    #[serde(default = "hash")]
    pub comment: String,
    /// What separates values; a comma if left out.
    #[serde(default = "comma")]
    pub delimiter: char,
    /// The column of the indicator's value.
    pub value: String,
    /// What every value is; or `kind_column` and `kinds`.
    pub kind: Option<Kind>,
    /// The column that says what the value is.
    pub kind_column: Option<String>,
    /// What each value of `kind_column` means. A row with a value not
    /// listed is ignored: the feed holds kinds the platform does not match.
    #[serde(default)]
    pub kinds: BTreeMap<String, Kind>,
    /// The column of when the feed first saw the indicator.
    pub first_seen: Option<String>,
    /// The column of when the feed last saw the indicator.
    pub last_seen: Option<String>,
    /// The column of the row's own confidence, 0 to 100.
    pub confidence: Option<String>,
}

fn hash() -> String {
    "#".to_owned()
}

fn comma() -> char {
    ','
}

/// What a feed's publication became.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// The indicators, each with what the feed asserts of it.
    pub indicators: Vec<(Key, Assertion)>,
    /// Rows or objects ignored: of a kind the platform does not match, or
    /// revoked.
    pub ignored: usize,
    /// Rows or objects whose value cannot be of its kind.
    pub rejected: usize,
    /// Why the first of them were rejected.
    pub reasons: Vec<String>,
}

/// What replacing a feed with its publication did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    /// The indicators the feed now asserts.
    pub indicators: usize,
    /// Rows or objects ignored.
    pub ignored: usize,
    /// Rows or objects whose value cannot be of its kind.
    pub rejected: usize,
    /// Why the first of them were rejected.
    pub reasons: Vec<String>,
}

impl Parsed {
    pub(crate) fn reject(&mut self, reason: impl FnOnce() -> String) {
        self.rejected += 1;
        if self.reasons.len() < REASONS {
            self.reasons.push(reason());
        }
    }
}

impl Feed {
    /// Reads a feed's definition from YAML, as untrusted input.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Yaml`] if the YAML is malformed or is not a
    /// feed, and [`IntelError::Feed`] if the definition contradicts itself:
    /// a confidence above 100, a `csv` format without `csv`, both `kind` and
    /// `kind_column` or neither.
    pub fn from_yaml(source: &str) -> Result<Self, IntelError> {
        let feed: Self = goliath_sigma::yaml::from_str(source)?;
        let refuse = |why: &str| {
            Err(IntelError::Feed {
                feed: feed.name.clone(),
                why: why.to_owned(),
            })
        };
        if feed.name.is_empty() || feed.name.contains('\0') {
            return refuse("a feed needs a name");
        }
        if feed.confidence > 100 {
            return refuse("confidence is 0 to 100");
        }
        if feed.refresh_minutes == 0 {
            return refuse("refresh_minutes is at least 1");
        }
        match (feed.format, &feed.csv) {
            (Format::Csv, None) => return refuse("the csv format needs `csv`"),
            (Format::Stix, Some(_)) => return refuse("`csv` is for the csv format"),
            (Format::Csv, Some(csv)) => {
                if csv.kind.is_some() == csv.kind_column.is_some() {
                    return refuse("`csv` needs `kind`, or `kind_column` with `kinds`");
                }
                if csv.kind_column.is_some() == csv.kinds.is_empty() {
                    return refuse("`kinds` goes with `kind_column`");
                }
                if csv.comment.is_empty() {
                    return refuse("`comment` cannot be empty");
                }
            }
            (Format::Stix, None) => {}
        }
        Ok(feed)
    }

    /// Reads what the feed published, fetched at `fetched_at` in seconds
    /// since the epoch.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Feed`] if the bytes are not the feed's format,
    /// hold no indicator, or have more than one row in ten whose value
    /// cannot be of its kind. A feed that changed its format is refused
    /// whole, so that it does not replace what the store holds with less.
    pub fn parse(&self, bytes: &[u8], fetched_at: i64) -> Result<Parsed, IntelError> {
        let refuse = |why: String| IntelError::Feed {
            feed: self.name.clone(),
            why,
        };
        let text = std::str::from_utf8(bytes).map_err(|_| refuse("it is not UTF-8".to_owned()))?;
        let mut parsed = Parsed::default();
        match (self.format, &self.csv) {
            (Format::Csv, Some(csv)) => self.rows(csv, text, fetched_at, &mut parsed),
            (Format::Stix, _) => stix::indicators(self, text, fetched_at, &mut parsed),
            (Format::Csv, None) => Err("the csv format needs `csv`".to_owned()),
        }
        .map_err(refuse)?;

        if parsed.indicators.is_empty() {
            return Err(refuse(match parsed.reasons.first() {
                Some(reason) => format!("it holds no indicator; {reason}"),
                None => "it holds no indicator".to_owned(),
            }));
        }
        let rows = parsed.indicators.len() + parsed.rejected;
        if parsed.rejected * 100 > rows * REJECTED_PERCENT {
            return Err(refuse(format!(
                "{} of {rows} values cannot be of their kind; {}",
                parsed.rejected,
                parsed.reasons.join("; ")
            )));
        }
        Ok(parsed)
    }

    /// Reads what the feed published and replaces the feed in `store` with
    /// it, as `version`. The store is not touched if the publication is
    /// refused.
    ///
    /// # Errors
    ///
    /// As [`parse`](Self::parse), and [`IntelError::Store`] if the store
    /// cannot be written.
    pub fn load(
        &self,
        store: &impl Store,
        bytes: &[u8],
        version: &str,
        fetched_at: i64,
    ) -> Result<Loaded, IntelError> {
        let parsed = self.parse(bytes, fetched_at)?;
        Ok(Loaded {
            indicators: store.replace_feed(&self.name, version, parsed.indicators)?,
            ignored: parsed.ignored,
            rejected: parsed.rejected,
            reasons: parsed.reasons,
        })
    }

    /// An assertion of this feed, holding as `valid_days` says.
    pub(crate) fn assertion(
        &self,
        confidence: Option<u8>,
        first_seen: Option<i64>,
        last_seen: Option<i64>,
        fetched_at: i64,
    ) -> Assertion {
        let until = self.valid_days.map(|days| {
            last_seen
                .or(first_seen)
                .unwrap_or(fetched_at)
                .saturating_add(i64::from(days) * DAY)
        });
        Assertion::new(confidence.unwrap_or(self.confidence))
            .valid(None, until)
            .seen(first_seen, last_seen)
    }

    fn rows(
        &self,
        csv: &Csv,
        text: &str,
        fetched_at: i64,
        parsed: &mut Parsed,
    ) -> Result<(), String> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with(&csv.comment));
        let header = match &csv.columns {
            Some(columns) => columns.clone(),
            None => fields(lines.next().unwrap_or_default(), csv.delimiter),
        };
        let column = |name: &str| {
            header
                .iter()
                .position(|column| column == name)
                .ok_or_else(|| format!("it has no column `{name}`"))
        };
        let value = column(&csv.value)?;
        let kind = csv.kind_column.as_deref().map(column).transpose()?;
        let first = csv.first_seen.as_deref().map(column).transpose()?;
        let last = csv.last_seen.as_deref().map(column).transpose()?;
        let confidence = csv.confidence.as_deref().map(column).transpose()?;

        for line in lines {
            let row = fields(line, csv.delimiter);
            let field = |index: Option<usize>| index.and_then(|index| row.get(index));
            let Some(text) = row.get(value) else {
                parsed.reject(|| format!("a row has {} values: {line}", row.len()));
                continue;
            };
            let kind = match (csv.kind, field(kind)) {
                (Some(kind), _) => kind,
                (None, Some(name)) => {
                    let Some(kind) = csv.kinds.get(name.as_str()) else {
                        parsed.ignored += 1;
                        continue;
                    };
                    *kind
                }
                (None, None) => {
                    parsed.reject(|| format!("a row has {} values: {line}", row.len()));
                    continue;
                }
            };
            match key(kind, text) {
                Ok(key) => parsed.indicators.push((
                    key,
                    self.assertion(
                        field(confidence).and_then(|text| text.parse::<u8>().ok()),
                        field(first).and_then(|text| time(text)),
                        field(last).and_then(|text| time(text)),
                        fetched_at,
                    ),
                )),
                Err(error) => parsed.reject(|| error.to_string()),
            }
        }
        Ok(())
    }
}

/// The key of `value`, with the port feeds write after an address removed.
pub(crate) fn key(kind: Kind, value: &str) -> Result<Key, IntelError> {
    Key::new(kind, value).or_else(|error| {
        if kind != Kind::Ip {
            return Err(error);
        }
        let Some((address, port)) = value.trim().rsplit_once(':') else {
            return Err(error);
        };
        if port.parse::<u16>().is_err() {
            return Err(error);
        }
        let address = address
            .strip_prefix('[')
            .and_then(|address| address.strip_suffix(']'))
            .unwrap_or(address);
        Key::new(kind, address).map_err(|_| error)
    })
}

/// A time as feeds write it, in seconds since the epoch: RFC 3339, or a date
/// and time, or a date, without an offset meaning UTC.
pub(crate) fn time(text: &str) -> Option<i64> {
    let text = text.trim();
    if let Ok(time) = text.parse::<jiff::Timestamp>() {
        return Some(time.as_second());
    }
    let civil = text
        .parse::<jiff::civil::DateTime>()
        .or_else(|_| {
            text.parse::<jiff::civil::Date>()
                .map(|date| date.at(0, 0, 0, 0))
        })
        .ok()?;
    Some(
        civil
            .to_zoned(jiff::tz::TimeZone::UTC)
            .ok()?
            .timestamp()
            .as_second(),
    )
}

/// The values of a row: separated by `delimiter`, each as written or in
/// double quotes, where a quote is written twice. Space around a value is
/// dropped. A value does not span lines.
fn fields(line: &str, delimiter: char) -> Vec<String> {
    let mut fields = Vec::new();
    let mut rest = line;
    loop {
        rest = rest.trim_start();
        let mut field = String::new();
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut characters = quoted.char_indices().peekable();
            let mut end = quoted.len();
            while let Some((index, character)) = characters.next() {
                if character != '"' {
                    field.push(character);
                } else if characters.peek().is_some_and(|(_, next)| *next == '"') {
                    field.push('"');
                    characters.next();
                } else {
                    end = index + 1;
                    break;
                }
            }
            rest = quoted.get(end..).unwrap_or_default();
            // Whatever follows the closing quote, up to the delimiter.
            match rest.find(delimiter) {
                Some(next) => rest = rest.get(next..).unwrap_or_default(),
                None => rest = "",
            }
        } else {
            let end = rest.find(delimiter).unwrap_or(rest.len());
            field.push_str(rest.get(..end).unwrap_or_default().trim_end());
            rest = rest.get(end..).unwrap_or_default();
        }
        fields.push(field);
        match rest.strip_prefix(delimiter) {
            Some(after) => rest = after,
            None => return fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fields, time};

    #[test]
    fn rows_split_into_values_quoted_or_not() {
        for (line, expected) in [
            ("a,b,c", vec!["a", "b", "c"]),
            (r#""a","b,c","d""e""#, vec!["a", "b,c", "d\"e"]),
            (r#""a", "b" , c ,"#, vec!["a", "b", "c", ""]),
            ("", vec![""]),
            (r#""unclosed, b"#, vec!["unclosed, b"]),
        ] {
            assert_eq!(fields(line, ','), expected, "{line}");
        }
        assert_eq!(fields("a;b", ';'), ["a", "b"]);
    }

    #[test]
    fn times_are_read_as_feeds_write_them() {
        assert_eq!(time("2026-10-03T09:45:06Z"), Some(1_791_020_706));
        assert_eq!(time("2026-10-03T11:45:06+02:00"), Some(1_791_020_706));
        assert_eq!(time("2026-10-03 09:45:06"), Some(1_791_020_706));
        assert_eq!(time("2026-10-03"), Some(1_790_985_600));
        assert_eq!(time(""), None);
        assert_eq!(time("None"), None);
    }
}
