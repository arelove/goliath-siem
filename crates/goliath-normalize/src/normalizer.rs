//! Source definitions compiled for use, and records through them.

use goliath_ocsf::schema::{self, Base};
use goliath_rule::FieldPath;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::definition::{Coercion, Decoding, FieldSpec, Framing, SourceDefinition};
use crate::error::DefinitionError;

/// A source definition, checked and compiled.
///
/// Built once, then used for every record of the source. Normalizing is
/// deterministic: the same bytes under the same definition version always give
/// the same outcome.
#[derive(Debug, Clone)]
pub struct Normalizer {
    name: String,
    version: u32,
    framing: Framing,
    kinds: Vec<Kind>,
}

#[derive(Debug, Clone)]
struct Kind {
    name: String,
    when: Vec<(SourcePath, Value)>,
    /// `class_uid`, `category_uid`, `type_uid`, and `activity_id`.
    class: Vec<(&'static str, Value)>,
    /// The common fields, then the kind's own.
    fields: Vec<Field>,
    unmapped: Vec<SourcePath>,
}

#[derive(Debug, Clone)]
struct Field {
    target: FieldPath,
    source: Source,
}

#[derive(Debug, Clone)]
enum Source {
    Constant(Value),
    Path {
        path: SourcePath,
        coercion: Option<Coercion>,
    },
}

/// A dotted path into a decoded record. Unlike an OCSF path, it names exactly
/// one value: records are read, not searched.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourcePath {
    text: String,
    segments: Vec<String>,
}

impl SourcePath {
    fn parse(text: &str) -> Option<Self> {
        let segments: Vec<String> = text.split('.').map(str::to_owned).collect();
        segments
            .iter()
            .all(|segment| !segment.is_empty())
            .then(|| Self {
                text: text.to_owned(),
                segments,
            })
    }

    fn lookup<'a>(&self, record: &'a Value) -> Option<&'a Value> {
        self.segments
            .iter()
            .try_fold(record, |value, segment| value.get(segment.as_str()))
    }

    /// Whether this path names the member `key` of the object at `object`.
    fn is_member(&self, object: &Self, key: &str) -> bool {
        self.segments.len() == object.segments.len() + 1
            && self.segments.starts_with(&object.segments)
            && self.segments.last().is_some_and(|last| last == key)
    }

    fn last(&self) -> &str {
        self.segments.last().map_or("", String::as_str)
    }
}

/// What became of one record.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The record became an OCSF event.
    Event(Normalized),
    /// The record could not become an event, and is kept whole.
    DeadLetter(DeadLetter),
}

/// An OCSF event, and anything that did not convert on the way.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Normalized {
    /// Identifies the record the event came from, so that storage can drop
    /// a record delivered twice.
    pub id: EventId,
    /// The event.
    pub event: Value,
    /// The kind of record it was.
    pub kind: String,
    /// Values that did not convert. Each is kept as written under
    /// `unmapped`, and the event is still produced, so that a malformed field
    /// cannot keep an event away from detection.
    pub issues: Vec<Issue>,
}

/// The identity of a record: 128 bits of the BLAKE3 hash of the source's
/// name and the record's raw bytes.
///
/// It depends on nothing else, so a record delivered again, or collected
/// again, gets the same identity and can be dropped as a duplicate. Two
/// records with identical bytes from one source are the same record.
///
/// The hash is cryptographic on purpose. Whoever writes the logs chooses the
/// bytes, and with a hash built only for speed they could craft a record
/// whose identity equals that of another, and have storage drop one of the
/// two as a duplicate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId([u8; 16]);

impl EventId {
    /// Keys the hash, so that identities cannot be confused with any other
    /// use of BLAKE3. Changing it changes every identity.
    const CONTEXT: &str = "goliath 2026-09-25 event id";

    /// The identity of the record `raw` from the source `source`.
    pub fn of(source: &str, raw: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(Self::CONTEXT);
        // The name's length first, so that no name and record pair can end
        // where another pair's name does.
        hasher.update(&(source.len() as u64).to_le_bytes());
        hasher.update(source.as_bytes());
        hasher.update(raw);
        let mut id = [0; 16];
        hasher.finalize_xof().fill(&mut id);
        Self(id)
    }

    /// The identity's bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Display for EventId {
    /// Lowercase hexadecimal.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl std::str::FromStr for EventId {
    type Err = String;

    /// Parses the lowercase or uppercase hexadecimal [`Display`] writes.
    ///
    /// [`Display`]: std::fmt::Display
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || format!("`{text}` is not 32 hexadecimal digits");
        if text.len() != 32 {
            return Err(invalid());
        }
        let mut id = [0; 16];
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (byte, pair) in id.iter_mut().zip(pairs) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self(id))
    }
}

/// As its hexadecimal text, so that it reads the same in JSON as in logs.
impl Serialize for EventId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EventId({self})")
    }
}

/// A value that did not convert.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    /// The OCSF attribute it was meant for.
    pub target: String,
    /// Where it was read from.
    pub source: String,
    /// Why it did not convert.
    pub reason: String,
}

/// A record that could not become an event.
///
/// The raw bytes are kept exactly, so the record can be processed again once
/// the source definition is fixed. Nothing a source sends is dropped.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadLetter {
    /// The stage that failed.
    pub stage: Stage,
    /// Why.
    pub error: String,
    /// The record as received; for a stream that could not be framed, the
    /// rest of the stream.
    pub raw: Vec<u8>,
}

/// A stage of normalization, in order.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Splitting the stream into records.
    Framing,
    /// Turning a record into a field map.
    Decoding,
    /// Choosing a kind and writing the OCSF event.
    Mapping,
}

impl Stage {
    /// The stage's name, as reports and metrics use it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Framing => "framing",
            Self::Decoding => "decoding",
            Self::Mapping => "mapping",
        }
    }
}

impl Normalizer {
    /// Loads a source definition from YAML, as untrusted input.
    ///
    /// # Errors
    ///
    /// Returns [`DefinitionError`] if the YAML is not a valid definition.
    pub fn from_yaml(text: &str) -> Result<Self, DefinitionError> {
        let definition: SourceDefinition = goliath_sigma::yaml::from_str(text)?;
        Self::new(&definition)
    }

    /// Checks and compiles a source definition.
    ///
    /// # Errors
    ///
    /// Returns [`DefinitionError`] if a path does not parse, two fields
    /// would write over each other, a field writes an attribute that is set
    /// otherwise, or a kind would accept every record; and if a class,
    /// activity, or target is not in the OCSF schema, or a field writes a
    /// value its attribute cannot hold.
    pub fn new(definition: &SourceDefinition) -> Result<Self, DefinitionError> {
        if definition.kinds.is_empty() {
            return Err(DefinitionError::NoKinds);
        }
        let common = compile_fields("common", &definition.common)?;
        let mut kinds = Vec::with_capacity(definition.kinds.len());
        for kind in &definition.kinds {
            if kind.when.is_empty() {
                return Err(DefinitionError::Unconditional {
                    kind: kind.name.clone(),
                });
            }
            let when = kind
                .when
                .iter()
                .map(|(path, value)| Ok((source_path(&kind.name, path)?, Value::from(value))))
                .collect::<Result<_, DefinitionError>>()?;
            let mut fields = common.clone();
            fields.extend(compile_fields(&kind.name, &kind.fields)?);
            check_overlaps(&kind.name, &fields)?;
            check_schema(
                &kind.name,
                kind.class.class_uid,
                kind.class.activity_id,
                &fields,
            )?;
            let unmapped = kind
                .unmapped
                .iter()
                .map(|path| source_path(&kind.name, path))
                .collect::<Result<_, _>>()?;

            let class_uid = kind.class.class_uid;
            let activity_id = kind.class.activity_id;
            let category_uid = goliath_ocsf::Event::derive_category_uid(class_uid);
            let type_uid = goliath_ocsf::Event::derive_type_uid(class_uid, activity_id);
            kinds.push(Kind {
                name: kind.name.clone(),
                when,
                class: vec![
                    ("class_uid", Value::from(class_uid)),
                    ("category_uid", Value::from(category_uid)),
                    ("type_uid", Value::from(type_uid)),
                    ("activity_id", Value::from(activity_id)),
                ],
                fields,
                unmapped,
            });
        }
        // Only JSON exists so far; the match makes a new decoding a compile
        // error here rather than a silent fallback.
        match definition.decoding {
            Decoding::Json => {}
        }
        Ok(Self {
            name: definition.name.clone(),
            version: definition.version,
            framing: definition.framing,
            kinds,
        })
    }

    /// The source's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The definition's version, to be stored with every event it produces.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Splits `bytes` into records and normalizes each, calling `out` with
    /// every outcome in order.
    pub fn normalize(&self, bytes: &[u8], mut out: impl FnMut(Outcome)) {
        match self.framing {
            Framing::Lines => {
                for line in bytes.split(|&byte| byte == b'\n') {
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    if line.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    out(match serde_json::from_slice::<Value>(line) {
                        Ok(record) => self.record(&record, line),
                        Err(error) => dead(Stage::Decoding, error.to_string(), line),
                    });
                }
            }
            Framing::JsonValues => {
                let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
                let mut start = 0;
                while let Some(next) = stream.next() {
                    match next {
                        Ok(record) => {
                            let end = stream.byte_offset();
                            out(self.record(&record, trim(&bytes[start..end])));
                            start = end;
                        }
                        Err(error) => {
                            // Where one value ends cannot be known once the
                            // stream is broken, so the rest is kept together.
                            out(dead(
                                Stage::Framing,
                                error.to_string(),
                                trim(&bytes[start..]),
                            ));
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Normalizes one decoded record, whose raw bytes are `raw`.
    fn record(&self, record: &Value, raw: &[u8]) -> Outcome {
        if !record.is_object() {
            return dead(
                Stage::Decoding,
                "the record is not a JSON object".to_owned(),
                raw,
            );
        }
        let Some(kind) = self.kinds.iter().find(|kind| {
            kind.when
                .iter()
                .all(|(path, expected)| path.lookup(record) == Some(expected))
        }) else {
            return dead(
                Stage::Mapping,
                format!("no kind of source `{}` accepts the record", self.name),
                raw,
            );
        };

        let mut event = Map::new();
        let mut unmapped = Map::new();
        let mut issues = Vec::new();
        let mut consumed: Vec<&SourcePath> = Vec::new();
        for (name, value) in &kind.class {
            event.insert((*name).to_owned(), value.clone());
        }
        for field in &kind.fields {
            match &field.source {
                Source::Constant(value) => set(&mut event, field.target.segments(), value.clone()),
                Source::Path { path, coercion } => {
                    let Some(found) = path.lookup(record).filter(|value| !value.is_null()) else {
                        continue;
                    };
                    consumed.push(path);
                    match coerce(found, *coercion) {
                        Ok(value) => set(&mut event, field.target.segments(), value),
                        Err(reason) => {
                            issues.push(Issue {
                                target: field.target.as_str().to_owned(),
                                source: path.text.clone(),
                                reason,
                            });
                            // Kept by the name the `unmapped` lists would give
                            // it, or by its whole path where they give none,
                            // so that it cannot take another member's name.
                            let listed = kind
                                .unmapped
                                .iter()
                                .any(|object| path.is_member(object, path.last()));
                            let name = if listed { path.last() } else { &path.text };
                            unmapped.insert(name.to_owned(), found.clone());
                        }
                    }
                }
            }
        }
        for object in &kind.unmapped {
            let Some(Value::Object(members)) = object.lookup(record) else {
                continue;
            };
            for (key, member) in members {
                if member.is_null() || consumed.iter().any(|path| path.is_member(object, key)) {
                    continue;
                }
                unmapped
                    .entry(key.clone())
                    .or_insert_with(|| member.clone());
            }
        }
        if !unmapped.is_empty() {
            event.insert("unmapped".to_owned(), Value::Object(unmapped));
        }
        Outcome::Event(Normalized {
            id: EventId::of(&self.name, raw),
            event: Value::Object(event),
            kind: kind.name.clone(),
            issues,
        })
    }
}

fn dead(stage: Stage, error: String, raw: &[u8]) -> Outcome {
    Outcome::DeadLetter(DeadLetter {
        stage,
        error,
        raw: raw.to_vec(),
    })
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &bytes[start..end]
}

fn source_path(kind: &str, text: &str) -> Result<SourcePath, DefinitionError> {
    SourcePath::parse(text).ok_or_else(|| DefinitionError::SourcePath {
        kind: kind.to_owned(),
        path: text.to_owned(),
    })
}

fn compile_fields(
    kind: &str,
    specs: &std::collections::BTreeMap<String, FieldSpec>,
) -> Result<Vec<Field>, DefinitionError> {
    specs
        .iter()
        .map(|(target, spec)| {
            let path = FieldPath::parse(target).map_err(|source| DefinitionError::Target {
                kind: kind.to_owned(),
                target: target.clone(),
                source,
            })?;
            let reserved = match path.segments()[0].as_str() {
                "class_uid" | "category_uid" | "type_uid" | "activity_id" => {
                    Some("the kind's `class`")
                }
                "unmapped" => Some("the kind's `unmapped` list"),
                _ => None,
            };
            if let Some(reason) = reserved {
                return Err(DefinitionError::Reserved {
                    kind: kind.to_owned(),
                    target: target.clone(),
                    reason,
                });
            }
            let source = match spec {
                FieldSpec::Path(from) => Source::Path {
                    path: source_path(kind, from)?,
                    coercion: None,
                },
                FieldSpec::Converted { from, coercion } => Source::Path {
                    path: source_path(kind, from)?,
                    coercion: Some(*coercion),
                },
                FieldSpec::Value { value } => Source::Constant(Value::from(value)),
            };
            Ok(Field {
                target: path,
                source,
            })
        })
        .collect()
}

/// Rejects two fields writing the same attribute, or one inside another:
/// the second write would replace or be lost under the first.
fn check_overlaps(kind: &str, fields: &[Field]) -> Result<(), DefinitionError> {
    for (index, first) in fields.iter().enumerate() {
        for second in &fields[index + 1..] {
            let (a, b) = (first.target.segments(), second.target.segments());
            if a.starts_with(b) || b.starts_with(a) {
                return Err(DefinitionError::Overlap {
                    kind: kind.to_owned(),
                    first: first.target.as_str().to_owned(),
                    second: second.target.as_str().to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Checks the class, the activity, and every field against the OCSF schema,
/// so that a misspelled attribute fails here rather than produce events no
/// rule reads.
fn check_schema(
    kind: &str,
    class_uid: u32,
    activity_id: u32,
    fields: &[Field],
) -> Result<(), DefinitionError> {
    let class = schema::class(class_uid).ok_or_else(|| DefinitionError::UnknownClass {
        kind: kind.to_owned(),
        class_uid,
        version: goliath_ocsf::SCHEMA_VERSION,
    })?;
    let activities = class
        .attribute("activity_id")
        .map(schema::Attribute::enum_values)
        .unwrap_or_default();
    if !activities.contains(&i64::from(activity_id)) {
        return Err(DefinitionError::UnknownActivity {
            kind: kind.to_owned(),
            class: class.name(),
            activity_id,
        });
    }
    for field in fields {
        let target = field.target.as_str();
        let found = class
            .resolve(target)
            .map_err(|source| DefinitionError::Attribute {
                kind: kind.to_owned(),
                source,
            })?;
        if found.within_array {
            return Err(DefinitionError::WithinArray {
                kind: kind.to_owned(),
                target: target.to_owned(),
            });
        }
        // A copy keeps whatever the source holds, and a free-form attribute
        // takes anything, so neither has a type to check.
        let Some(writes) = field.source.writes() else {
            continue;
        };
        if found.free_form {
            continue;
        }
        let attribute = found.attribute;
        let fits = !attribute.is_array()
            && match writes {
                Writes::Boolean => attribute.base() == Base::Boolean,
                Writes::Integer => matches!(attribute.base(), Base::Integer | Base::Long),
                Writes::Text => attribute.base() == Base::String,
                Writes::Timestamp => attribute.type_name() == "timestamp_t",
            };
        if !fits {
            let holds = match (attribute.is_array(), attribute.base()) {
                (true, _) => format!("an array of `{}`", attribute.type_name()),
                (false, Base::Object) => format!("an object `{}`", attribute.type_name()),
                (false, _) => format!("`{}`", attribute.type_name()),
            };
            return Err(DefinitionError::Type {
                kind: kind.to_owned(),
                target: target.to_owned(),
                holds,
                writes: writes.describe(),
            });
        }
        let values = attribute.enum_values();
        if let Source::Constant(Value::Number(number)) = &field.source
            && let Some(value) = number.as_i64()
            && !values.is_empty()
            && !values.contains(&value)
        {
            return Err(DefinitionError::UnknownValue {
                kind: kind.to_owned(),
                target: target.to_owned(),
                value,
            });
        }
    }
    Ok(())
}

/// What a field writes, where that is known before any record is read.
#[derive(Debug, Clone, Copy)]
enum Writes {
    Boolean,
    Integer,
    Text,
    Timestamp,
}

impl Writes {
    fn describe(self) -> &'static str {
        match self {
            Self::Boolean => "a boolean",
            Self::Integer => "an integer",
            Self::Text => "text",
            Self::Timestamp => "a timestamp",
        }
    }
}

impl Source {
    fn writes(&self) -> Option<Writes> {
        match self {
            Self::Constant(Value::Bool(_)) => Some(Writes::Boolean),
            Self::Constant(Value::Number(_)) => Some(Writes::Integer),
            Self::Constant(Value::String(_)) => Some(Writes::Text),
            Self::Constant(_) | Self::Path { coercion: None, .. } => None,
            Self::Path {
                coercion: Some(coercion),
                ..
            } => Some(match coercion {
                Coercion::String => Writes::Text,
                Coercion::Integer => Writes::Integer,
                Coercion::Timestamp => Writes::Timestamp,
            }),
        }
    }
}

/// Writes `value` at `segments`, creating objects on the way. Overlapping
/// targets are rejected when the definition is compiled, so the way is
/// always clear.
fn set(object: &mut Map<String, Value>, segments: &[String], value: Value) {
    let Some((last, parents)) = segments.split_last() else {
        return;
    };
    let mut object = object;
    for segment in parents {
        let child = object
            .entry(segment.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(child) = child else {
            return;
        };
        object = child;
    }
    object.insert(last.clone(), value);
}

fn coerce(value: &Value, coercion: Option<Coercion>) -> Result<Value, String> {
    let Some(coercion) = coercion else {
        return Ok(value.clone());
    };
    match (coercion, value) {
        (Coercion::String, Value::String(_)) => Ok(value.clone()),
        (Coercion::String, Value::Number(number)) => Ok(Value::String(number.to_string())),
        (Coercion::Integer, Value::Number(number)) => number
            .as_i64()
            .map(Value::from)
            .ok_or_else(|| format!("{number} is not a whole number")),
        (Coercion::Integer, Value::String(text)) => text
            .trim()
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_| format!("`{text}` is not a whole number")),
        (Coercion::Timestamp, Value::String(text)) => text
            .parse::<jiff::Timestamp>()
            .map(|time| Value::from(time.as_millisecond()))
            .map_err(|error| format!("`{text}` is not an RFC 3339 time: {error}")),
        (coercion, other) => Err(format!(
            "cannot convert {} to {coercion:?}",
            describe(other)
        )),
    }
}

fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "text",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}
