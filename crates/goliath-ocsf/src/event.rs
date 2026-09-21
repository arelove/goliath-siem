//! The OCSF base event.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::ValidationError;
use crate::observable::Observable;
use crate::severity::Severity;

/// Milliseconds since the Unix epoch, as OCSF represents time.
pub type Timestamp = i64;

/// Provenance attached to every event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Metadata {
    /// The OCSF schema version this event conforms to, such as `1.5.0`.
    pub version: String,

    /// The product that produced the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<Product>,

    /// OCSF profiles applied to this event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,

    /// When the event was recorded by the collector, as opposed to when it
    /// occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logged_time: Option<Timestamp>,

    /// The identifier and version of the source definition that produced this
    /// event.
    ///
    /// Required by ADR-0007: parsing is deterministic, so knowing which
    /// definition version ran makes a parsing bug identifiable and the affected
    /// range reprocessable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_definition: Option<SourceDefinition>,
}

/// The product that produced an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Product {
    /// The product name.
    pub name: String,
    /// The vendor name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    /// The product version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// The source definition that parsed an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDefinition {
    /// The definition identifier, such as `windows.sysmon`.
    pub id: String,
    /// The definition version that produced this event.
    pub version: String,
}

/// An OCSF base event.
///
/// Class-specific attributes are not modeled here. They live in
/// [`attributes`](Event::attributes) until a class is given a typed
/// representation, which keeps ingestion lossless while the typed surface grows
/// one class at a time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// The event class, such as `1007` for Process Activity.
    pub class_uid: u32,

    /// The category the class belongs to.
    pub category_uid: u32,

    /// The activity within the class.
    pub activity_id: u32,

    /// The class and activity combined, per the OCSF derivation rule.
    pub type_uid: u64,

    /// When the activity occurred.
    pub time: Timestamp,

    /// How severe the activity is.
    #[serde(rename = "severity_id")]
    pub severity: Severity,

    /// Provenance.
    pub metadata: Metadata,

    /// Values an analyst can pivot on and indicator feeds can match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observables: Vec<Observable>,

    /// A human-readable description of the activity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// When a spanned activity began.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<Timestamp>,

    /// When a spanned activity ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time: Option<Timestamp>,

    /// Class-specific attributes, kept as received.
    #[serde(flatten)]
    pub attributes: Map<String, Value>,

    /// Source fields that no mapping claimed.
    ///
    /// Populated rather than dropped: a field nobody mapped is exactly the
    /// field an attacker uses an unusual code path to reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmapped: Option<Map<String, Value>>,
}

impl Event {
    /// Derives `type_uid` from a class and activity, per the OCSF rule.
    pub const fn derive_type_uid(class_uid: u32, activity_id: u32) -> u64 {
        class_uid as u64 * 100 + activity_id as u64
    }

    /// Derives `category_uid` from a class, per the OCSF rule.
    pub const fn derive_category_uid(class_uid: u32) -> u32 {
        class_uid / 1000
    }

    /// Checks the invariants the schema states but JSON cannot express.
    ///
    /// These are cheap arithmetic checks, so normalization runs them on every
    /// event rather than trusting producers.
    ///
    /// # Errors
    ///
    /// Returns the first invariant violated.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.metadata.version.is_empty() {
            return Err(ValidationError::MissingSchemaVersion);
        }

        if self.time <= 0 {
            return Err(ValidationError::InvalidTime { time: self.time });
        }

        let expected_type = Self::derive_type_uid(self.class_uid, self.activity_id);
        if self.type_uid != expected_type {
            return Err(ValidationError::TypeUidMismatch {
                found: self.type_uid,
                expected: expected_type,
            });
        }

        let expected_category = Self::derive_category_uid(self.class_uid);
        if self.category_uid != expected_category {
            return Err(ValidationError::CategoryMismatch {
                found: self.category_uid,
                expected: expected_category,
            });
        }

        if let (Some(start), Some(end)) = (self.start_time, self.end_time)
            && start > end
        {
            return Err(ValidationError::InvertedSpan { start, end });
        }

        Ok(())
    }

    /// Returns the observables worth looking up against indicator feeds.
    ///
    /// Filtering here rather than in the match engine keeps object-typed and
    /// empty observables from reaching the bloom filters at all. See ADR-0008.
    pub fn matchable_observables(&self) -> impl Iterator<Item = &Observable> {
        self.observables.iter().filter(|o| o.is_matchable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observable::ObservableType;

    /// A Process Activity / Launch event, which is class 1007 in category 1.
    fn sample() -> Event {
        Event {
            class_uid: 1007,
            category_uid: 1,
            activity_id: 1,
            type_uid: 100_701,
            time: 1_758_412_800_000,
            severity: Severity::Medium,
            metadata: Metadata {
                version: "1.5.0".to_owned(),
                source_definition: Some(SourceDefinition {
                    id: "windows.sysmon".to_owned(),
                    version: "1.0.0".to_owned(),
                }),
                ..Metadata::default()
            },
            observables: vec![
                Observable::new(
                    "actor.process.name",
                    ObservableType::ProcessName,
                    "powershell.exe",
                ),
                Observable::new("device.hostname", ObservableType::Hostname, "WS-001"),
            ],
            message: None,
            start_time: None,
            end_time: None,
            attributes: Map::new(),
            unmapped: None,
        }
    }

    #[test]
    fn sample_event_is_valid() {
        sample()
            .validate()
            .expect("sample must satisfy its own invariants");
    }

    #[test]
    fn type_uid_is_derived_from_class_and_activity() {
        assert_eq!(Event::derive_type_uid(1007, 1), 100_701);
        assert_eq!(Event::derive_category_uid(1007), 1);
        assert_eq!(Event::derive_category_uid(4001), 4);
    }

    #[test]
    fn rejects_inconsistent_type_uid() {
        let mut event = sample();
        event.type_uid = 100_702;

        let err = event
            .validate()
            .expect_err("mismatched type_uid must be rejected");
        assert!(matches!(
            err,
            ValidationError::TypeUidMismatch {
                found: 100_702,
                expected: 100_701
            }
        ));
    }

    #[test]
    fn rejects_inconsistent_category() {
        let mut event = sample();
        event.category_uid = 3;

        assert!(matches!(
            event.validate(),
            Err(ValidationError::CategoryMismatch {
                found: 3,
                expected: 1
            })
        ));
    }

    #[test]
    fn rejects_inverted_span() {
        let mut event = sample();
        event.start_time = Some(2_000);
        event.end_time = Some(1_000);

        assert!(matches!(
            event.validate(),
            Err(ValidationError::InvertedSpan { .. })
        ));
    }

    #[test]
    fn rejects_missing_schema_version() {
        let mut event = sample();
        event.metadata.version.clear();

        assert!(matches!(
            event.validate(),
            Err(ValidationError::MissingSchemaVersion)
        ));
    }

    #[test]
    fn round_trips_through_json() {
        let event = sample();
        let json = serde_json::to_string(&event).expect("serialize");
        let parsed: Event = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed, event);
        parsed
            .validate()
            .expect("a round-tripped event stays valid");
    }

    #[test]
    fn preserves_unknown_class_attributes() {
        // Attributes of a class we do not model yet must survive ingestion.
        let json = r#"{
            "class_uid": 1007, "category_uid": 1, "activity_id": 1,
            "type_uid": 100701, "time": 1758412800000, "severity_id": 3,
            "metadata": { "version": "1.5.0" },
            "process": { "cmd_line": "powershell -enc SQBFAFgA" }
        }"#;

        let event: Event = serde_json::from_str(json).expect("deserialize");
        event.validate().expect("valid");

        assert!(
            event.attributes.contains_key("process"),
            "class attributes must be kept"
        );

        let round_tripped = serde_json::to_value(&event).expect("serialize");
        assert_eq!(
            round_tripped["process"]["cmd_line"],
            Value::from("powershell -enc SQBFAFgA")
        );
    }

    #[test]
    fn matchable_observables_skip_object_types() {
        let mut event = sample();
        event
            .observables
            .push(Observable::new("device", ObservableType::Endpoint, "{...}"));
        event.observables.push(Observable::new(
            "src_endpoint.ip",
            ObservableType::IpAddress,
            "",
        ));

        let matchable: Vec<_> = event
            .matchable_observables()
            .map(|o| o.name.as_str())
            .collect();
        assert_eq!(matchable, ["actor.process.name", "device.hostname"]);
    }
}
