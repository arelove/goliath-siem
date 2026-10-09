//! How a site's export is read into records.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::EnrichError;
use crate::record::{Id, IdKind, Kind, Range, Record};

/// How a file a site exports is read: what kind of record a row is, and
/// which of the file's own columns hold what.
///
/// ```yaml
/// name: cmdb-servers
/// description: Servers, exported nightly from the CMDB
/// kind: asset
/// format: csv
/// identifiers:
///   host: [hostname, fqdn]
///   address: [ip_address]
///   uid: [asset_tag]
/// fields:
///   owner: owner_email
///   org: business_unit
///   criticality: tier
/// criticality: { gold: 4, silver: 3, bronze: 2 }
/// labels:
///   pci_scope: pci
///   information_system: system
/// groups: { column: roles, separator: ";" }
/// ```
///
/// The export is read under its own column names; nothing in it is renamed
/// to suit the platform. A JSON lines export is read the same way, a column
/// being a member of each line's object, or a path such as `tags.project`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    /// The source's name, which an enrichment is reported with.
    pub name: String,
    /// What the source is, for those who read the file.
    pub description: Option<String>,
    /// What a row describes.
    pub kind: Kind,
    /// The scope its records are found within; every scope if left out.
    pub scope: Option<String>,
    /// How the file is read.
    pub format: Format,
    /// How rows of separated values are split; commas, and a first row of
    /// column names, if left out.
    #[serde(default)]
    pub csv: Csv,
    /// The columns that hold each kind of identifier. A cell may hold
    /// several, separated by `separator`.
    #[serde(default)]
    pub identifiers: BTreeMap<IdKind, Vec<String>>,
    /// The column of the range of addresses: a network's own, or that of a
    /// context list's row.
    pub range: Option<String>,
    /// The column of each typed field of the kind.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    /// Typed fields every row has, such as `zone: dmz` for a file of one
    /// zone. A column's value wins over these.
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    /// What each of the site's words for criticality means, 1 to 4. A cell
    /// that is itself 1 to 4 needs no entry.
    #[serde(default)]
    pub criticality: BTreeMap<String, u8>,
    /// The site's own labels: each label's name, and its column.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// The column of the groups a row is a member of.
    pub groups: Option<Many>,
    /// The column of when a row begins to hold.
    pub valid_from: Option<String>,
    /// The column of when a row stops holding.
    pub valid_until: Option<String>,
    /// What separates several identifiers in one cell; `;` if left out.
    #[serde(default = "semicolon")]
    pub separator: String,
}

/// How a file is read.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// Rows of separated values under a row of column names.
    Csv,
    /// One JSON object a line.
    Jsonl,
}

/// How rows of separated values are split.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Csv {
    /// What separates values; a comma if left out.
    #[serde(default = "comma")]
    pub delimiter: char,
    /// What a line that is not a row begins with; `#` if left out.
    #[serde(default = "hash")]
    pub comment: String,
    /// The names of the columns, if the file has no row of them.
    pub columns: Option<Vec<String>>,
}

impl Default for Csv {
    fn default() -> Self {
        Self {
            delimiter: comma(),
            comment: hash(),
            columns: None,
        }
    }
}

/// A column whose cell holds several values.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Many {
    /// The column.
    pub column: String,
    /// What separates the values; `;` if left out.
    #[serde(default = "semicolon")]
    pub separator: String,
}

fn comma() -> char {
    ','
}

fn hash() -> String {
    "#".to_owned()
}

fn semicolon() -> String {
    ";".to_owned()
}

/// What an export became.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parsed {
    /// The records.
    pub records: Vec<Record>,
    /// Rows that gave none: with no identifier, or a value that cannot be
    /// of its kind.
    pub rejected: usize,
    /// Why the first rejected rows were.
    pub reasons: Vec<String>,
}

impl Parsed {
    fn reject(&mut self, reason: String) {
        self.rejected += 1;
        if self.reasons.len() < 5 {
            self.reasons.push(reason);
        }
    }
}

/// The cells of one row, by column.
type Row = BTreeMap<String, Vec<String>>;

impl Definition {
    /// Reads a definition from YAML, as untrusted input.
    ///
    /// # Errors
    ///
    /// Returns [`EnrichError::Yaml`] if the YAML is malformed or is not a
    /// definition, and [`EnrichError::Definition`] if it names a field its
    /// kind does not have, a criticality outside 1 to 4, or nothing to
    /// find a row by.
    pub fn from_yaml(source: &str) -> Result<Self, EnrichError> {
        let definition: Self = goliath_sigma::yaml::from_str(source)?;
        let refuse = |why: String| {
            Err(EnrichError::Definition {
                source_name: definition.name.clone(),
                why,
            })
        };
        if definition.name.trim().is_empty() {
            return refuse("a source needs a name".to_owned());
        }
        let known = definition.kind.fields();
        for field in definition.fields.keys().chain(definition.set.keys()) {
            if !known.contains(&field.as_str()) {
                return refuse(format!(
                    "a record of kind {} has no field `{field}`; it has {}. What the site adds is a label",
                    definition.kind.as_str(),
                    known.join(", ")
                ));
            }
        }
        if definition
            .criticality
            .values()
            .any(|level| !(1..=4).contains(level))
        {
            return refuse("criticality is 1 to 4".to_owned());
        }
        let found_by_range = matches!(definition.kind, Kind::Network | Kind::List);
        if definition.range.is_some() && !found_by_range {
            return refuse("`range` is for networks and context lists".to_owned());
        }
        if definition.identifiers.values().all(Vec::is_empty) && definition.range.is_none() {
            return refuse("nothing to find a row by: name `identifiers`, or a `range`".to_owned());
        }
        if definition.kind == Kind::Network && definition.range.is_none() {
            return refuse("a network is found by its `range`".to_owned());
        }
        if definition.separator.is_empty()
            || definition
                .groups
                .as_ref()
                .is_some_and(|groups| groups.separator.is_empty())
        {
            return refuse("a separator cannot be empty".to_owned());
        }
        Ok(definition)
    }

    /// Reads what the site exported.
    ///
    /// # Errors
    ///
    /// Returns [`EnrichError::Source`] if the bytes are not the format, name
    /// no column the definition asks for, give no record, or have more than
    /// one row in ten that gives none. An export that changed its shape is
    /// refused whole, so that the snapshot keeps what it had.
    pub fn parse(&self, bytes: &[u8]) -> Result<Parsed, EnrichError> {
        let refuse = |why: String| EnrichError::Source {
            source_name: self.name.clone(),
            why,
        };
        let text = std::str::from_utf8(bytes).map_err(|_| refuse("it is not UTF-8".to_owned()))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut parsed = Parsed::default();
        let mut each = |row: &Row, parsed: &mut Parsed| match self.record(row) {
            Ok(record) => parsed.records.push(record),
            Err(reason) => parsed.reject(reason),
        };
        match self.format {
            Format::Csv => self
                .csv_rows(text, &mut parsed, &mut each)
                .map_err(refuse)?,
            Format::Jsonl => {
                for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
                    match serde_json::from_str::<Value>(line) {
                        Ok(Value::Object(object)) => {
                            let row = self.json_row(&Value::Object(object));
                            each(&row, &mut parsed);
                        }
                        _ => parsed.reject(format!("a line is not a JSON object: {line}")),
                    }
                }
            }
        }
        let rows = parsed.records.len() + parsed.rejected;
        if parsed.records.is_empty() {
            return Err(refuse(format!(
                "it gave no record{}",
                parsed
                    .reasons
                    .first()
                    .map(|reason| format!("; the first row: {reason}"))
                    .unwrap_or_default()
            )));
        }
        if parsed.rejected * 10 > rows {
            return Err(refuse(format!(
                "{} of its {rows} rows give no record; the first: {}",
                parsed.rejected,
                parsed.reasons.first().map_or("", String::as_str)
            )));
        }
        Ok(parsed)
    }

    /// Every column the definition reads.
    fn columns(&self) -> Vec<&str> {
        self.identifiers
            .values()
            .flatten()
            .chain(self.range.iter())
            .chain(self.fields.values())
            .chain(self.labels.values())
            .chain(self.groups.iter().map(|groups| &groups.column))
            .chain(self.valid_from.iter())
            .chain(self.valid_until.iter())
            .map(String::as_str)
            .collect()
    }

    fn csv_rows(
        &self,
        text: &str,
        parsed: &mut Parsed,
        each: &mut impl FnMut(&Row, &mut Parsed),
    ) -> Result<(), String> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with(&self.csv.comment));
        let header = match &self.csv.columns {
            Some(columns) => columns.clone(),
            None => split(lines.next().unwrap_or_default(), self.csv.delimiter),
        };
        for column in self.columns() {
            if !header.iter().any(|name| name == column) {
                return Err(format!(
                    "it has no column `{column}`; it has {}",
                    header.join(", ")
                ));
            }
        }
        for line in lines {
            let cells = split(line, self.csv.delimiter);
            let row: Row = header
                .iter()
                .zip(cells)
                .filter(|(_, cell)| !cell.is_empty())
                .map(|(name, cell)| (name.clone(), vec![cell]))
                .collect();
            each(&row, parsed);
        }
        Ok(())
    }

    /// The members the definition reads of one line's object. An array
    /// gives several values; a path of names reaches into objects.
    fn json_row(&self, object: &Value) -> Row {
        let mut row = Row::new();
        for column in self.columns() {
            let mut value = Some(object);
            // The whole name first: a member may itself hold a dot.
            if object.get(column).is_none() {
                for name in column.split('.') {
                    value = value.and_then(|value| value.get(name));
                }
            } else {
                value = object.get(column);
            }
            let cells: Vec<String> = match value {
                Some(Value::Array(values)) => values.iter().filter_map(cell).collect(),
                Some(value) => cell(value).into_iter().collect(),
                None => Vec::new(),
            };
            if !cells.is_empty() {
                row.insert(column.to_owned(), cells);
            }
        }
        row
    }

    /// The record of one row, or why it gives none.
    fn record(&self, row: &Row) -> Result<Record, String> {
        let cells = |column: &str| row.get(column).map(Vec::as_slice).unwrap_or_default();
        let first = |column: &str| cells(column).first().map(String::as_str);
        let mut record = Record::new(self.kind);
        record.scope.clone_from(&self.scope);
        for (kind, columns) in &self.identifiers {
            for column in columns {
                for cell in cells(column) {
                    for text in cell.split(&self.separator).map(str::trim) {
                        if text.is_empty() {
                            continue;
                        }
                        let id = Id::new(*kind, text).map_err(|error| error.to_string())?;
                        if !record.ids.contains(&id) {
                            record.ids.push(id);
                        }
                    }
                }
            }
        }
        if let Some(column) = &self.range {
            for cell in cells(column) {
                for text in cell.split(&self.separator).map(str::trim) {
                    if !text.is_empty() {
                        record
                            .ranges
                            .push(Range::new(text).map_err(|error| error.to_string())?);
                    }
                }
            }
        }
        if record.ids.is_empty() && record.ranges.is_empty() {
            return Err("a row has nothing to be found by".to_owned());
        }
        for (field, text) in &self.set {
            if let Some(value) = self.typed(field, text)? {
                record.fields.insert(field.clone(), value);
            }
        }
        for (field, column) in &self.fields {
            if let Some(text) = first(column)
                && let Some(value) = self.typed(field, text)?
            {
                record.fields.insert(field.clone(), value);
            }
        }
        for (label, column) in &self.labels {
            if let Some(text) = first(column) {
                record.labels.insert(label.clone(), text.to_owned());
            }
        }
        if let Some(groups) = &self.groups {
            for cell in cells(&groups.column) {
                for name in cell.split(&groups.separator).map(str::trim) {
                    if !name.is_empty() && !record.groups.iter().any(|held| held == name) {
                        record.groups.push(name.to_owned());
                    }
                }
            }
        }
        let time = |column: &Option<String>| -> Result<Option<i64>, String> {
            match column.as_deref().and_then(first) {
                Some(text) => seconds(text)
                    .map(Some)
                    .ok_or_else(|| format!("`{text}` is not a time")),
                None => Ok(None),
            }
        };
        record.valid_from = time(&self.valid_from)?;
        record.valid_until = time(&self.valid_until)?;
        Ok(record)
    }

    /// The value of a typed field as `text` writes it; `None` for a cell
    /// that says nothing.
    fn typed(&self, field: &str, text: &str) -> Result<Option<Value>, String> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        if field == "criticality" {
            let level = self
                .criticality
                .iter()
                .find(|(word, _)| word.eq_ignore_ascii_case(text))
                .map(|(_, level)| *level)
                .or_else(|| {
                    text.parse::<u8>()
                        .ok()
                        .filter(|level| (1..=4).contains(level))
                })
                .ok_or_else(|| {
                    format!("criticality `{text}` is not 1 to 4 and has no meaning given")
                })?;
            return Ok(Some(json!(level)));
        }
        if field.starts_with("is_") {
            return match text.to_ascii_lowercase().as_str() {
                "true" | "yes" | "y" | "1" => Ok(Some(json!(true))),
                "false" | "no" | "n" | "0" => Ok(Some(json!(false))),
                _ => Err(format!("`{field}` is yes or no, not `{text}`")),
            };
        }
        Ok(Some(json!(text)))
    }
}

/// A JSON value as the text of a cell; nothing for null, an object, or an
/// empty string.
fn cell(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_owned()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// A time as exports write it, in seconds since the epoch: seconds, RFC
/// 3339, or a date with or without a time, meaning UTC.
fn seconds(text: &str) -> Option<i64> {
    let text = text.trim();
    if let Ok(seconds) = text.parse::<i64>() {
        return Some(seconds);
    }
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

/// The values of one line, quoted or not, trimmed.
fn split(line: &str, delimiter: char) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = line;
    loop {
        rest = rest.trim_start();
        let mut value = String::new();
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut characters = quoted.char_indices().peekable();
            let mut end = quoted.len();
            while let Some((index, character)) = characters.next() {
                if character != '"' {
                    value.push(character);
                } else if characters.peek().is_some_and(|(_, next)| *next == '"') {
                    value.push('"');
                    characters.next();
                } else {
                    end = index + 1;
                    break;
                }
            }
            rest = quoted.get(end..).unwrap_or_default();
            match rest.find(delimiter) {
                Some(next) => rest = rest.get(next..).unwrap_or_default(),
                None => rest = "",
            }
        } else {
            let end = rest.find(delimiter).unwrap_or(rest.len());
            value.push_str(rest.get(..end).unwrap_or_default().trim_end());
            rest = rest.get(end..).unwrap_or_default();
        }
        values.push(value);
        match rest.strip_prefix(delimiter) {
            Some(after) => rest = after,
            None => return values,
        }
    }
}
