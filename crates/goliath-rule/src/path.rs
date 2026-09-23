//! Dotted paths into an OCSF event.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::PathError;

/// A dotted path to an attribute of an OCSF event, such as
/// `process.parent_process.file.path`.
///
/// Arrays are traversed transparently: `observables.value` reaches the `value`
/// of every element of `observables`. OCSF nests arrays of objects throughout,
/// and a rule asking about a field means any occurrence of it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FieldPath {
    text: String,
    segments: Vec<String>,
}

impl FieldPath {
    /// Parses a dotted path.
    ///
    /// Segments are otherwise unrestricted, because `unmapped.<name>` carries
    /// field names exactly as the source spelled them.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] if the path or any of its segments is empty.
    pub fn parse(text: &str) -> Result<Self, PathError> {
        if text.is_empty() {
            return Err(PathError::Empty);
        }
        let segments: Vec<String> = text.split('.').map(str::to_owned).collect();
        if let Some(position) = segments.iter().position(String::is_empty) {
            return Err(PathError::EmptySegment {
                path: text.to_owned(),
                position,
            });
        }
        Ok(Self {
            text: text.to_owned(),
            segments,
        })
    }

    /// Returns the path as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the segments in order.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Returns every value this path reaches in `root`.
    ///
    /// Empty when the path reaches nothing. An array met along the way or at
    /// the end contributes each of its elements, so the result never contains
    /// an array. A JSON `null` is returned as found; deciding what it means is
    /// the caller's business.
    pub fn lookup<'a>(&self, root: &'a Value) -> Vec<&'a Value> {
        let mut found = Vec::new();
        collect(root, &self.segments, &mut found);
        found
    }
}

fn collect<'a>(value: &'a Value, segments: &[String], found: &mut Vec<&'a Value>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect(item, segments, found);
            }
        }
        _ => match segments.split_first() {
            None => found.push(value),
            Some((head, rest)) => {
                if let Some(child) = value.get(head.as_str()) {
                    collect(child, rest, found);
                }
            }
        },
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl TryFrom<String> for FieldPath {
    type Error = PathError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<FieldPath> for String {
    fn from(path: FieldPath) -> Self {
        path.text
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn path(text: &str) -> FieldPath {
        FieldPath::parse(text).expect("valid path")
    }

    #[test]
    fn rejects_empty_paths_and_segments() {
        assert_eq!(FieldPath::parse(""), Err(PathError::Empty));
        assert!(matches!(
            FieldPath::parse("process..path"),
            Err(PathError::EmptySegment { position: 1, .. })
        ));
        assert!(FieldPath::parse(".process").is_err());
        assert!(FieldPath::parse("process.").is_err());
    }

    #[test]
    fn reaches_a_nested_attribute() {
        let event = json!({ "process": { "file": { "path": r"C:\a.exe" } } });
        assert_eq!(
            path("process.file.path").lookup(&event),
            [&json!(r"C:\a.exe")]
        );
    }

    #[test]
    fn a_missing_attribute_reaches_nothing() {
        let event = json!({ "process": { "name": "a.exe" } });
        assert!(path("process.file.path").lookup(&event).is_empty());
        assert!(path("process.name.more").lookup(&event).is_empty());
    }

    #[test]
    fn arrays_are_traversed_along_the_way() {
        let event = json!({
            "observables": [
                { "name": "ip", "value": "10.0.0.1" },
                { "name": "host" },
                { "name": "user", "value": "adam" },
            ]
        });
        assert_eq!(
            path("observables.value").lookup(&event),
            [&json!("10.0.0.1"), &json!("adam")]
        );
    }

    #[test]
    fn an_array_at_the_end_contributes_its_elements() {
        let event = json!({ "tags": ["a", ["b", "c"]] });
        assert_eq!(
            path("tags").lookup(&event),
            [&json!("a"), &json!("b"), &json!("c")]
        );
    }

    #[test]
    fn null_is_returned_as_found() {
        let event = json!({ "user": null });
        assert_eq!(path("user").lookup(&event), [&Value::Null]);
    }

    #[test]
    fn unmapped_source_field_names_keep_their_spelling() {
        let event = json!({ "unmapped": { "EventID": 4688 } });
        assert_eq!(path("unmapped.EventID").lookup(&event), [&json!(4688)]);
    }

    #[test]
    fn serializes_as_the_dotted_text() {
        let original = path("process.cmd_line");
        let text = serde_json::to_string(&original).expect("serialize");
        assert_eq!(text, r#""process.cmd_line""#);
        let parsed: FieldPath = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(parsed, original);
        assert!(serde_json::from_str::<FieldPath>(r#""a..b""#).is_err());
    }
}
