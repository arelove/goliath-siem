//! Field mappings: from a rule language's field names to OCSF paths.
//!
//! A mapping set is a versioned YAML file. Each entry selects rules by log
//! source, adds a class condition that restricts them to the right events, and
//! maps field names to one or more OCSF paths:
//!
//! ```yaml
//! name: sigma-windows
//! version: 1
//! mappings:
//!   - logsource: { category: process_creation, product: windows }
//!     class: { class_uid: 1007, activity_id: 1, device.os.type_id: 100 }
//!     fields:
//!       Image: [process.file.path, process.path]
//!       CommandLine: process.cmd_line
//! ```
//!
//! The format is ours, so unknown keys are errors rather than ignored: a typo
//! in a mapping file would otherwise drop a field silently, and every rule
//! using it would fail to load for a reason nobody could see.
//!
//! For the same reason, an entry with a `class_uid` is checked against the
//! OCSF schema: every path must be an attribute of that class, and every
//! class condition a value the attribute can hold. A misspelled path would
//! otherwise load, and every rule reading it would never fire.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use goliath_ocsf::schema::{self, Attribute, Base, Class};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::MappingError;
use crate::path::FieldPath;

/// A versioned collection of mappings, loaded from one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingSet {
    /// Identifies the set, such as `sigma-windows`.
    pub name: String,
    /// Incremented on every change. Alerts record it, so a mapping fix can be
    /// traced to the detections it affected.
    pub version: u32,
    /// The entries, each selecting rules by log source.
    pub mappings: Vec<SourceMapping>,
}

/// How rules for one log source resolve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMapping {
    /// Which rules this entry applies to.
    pub logsource: LogSourceSelector,
    /// Attribute values an event must have for these rules to apply to it.
    #[serde(default)]
    pub class: BTreeMap<FieldPath, ClassValue>,
    /// Field names and the OCSF paths they resolve to. A field with several
    /// paths matches when any of them does.
    #[serde(deserialize_with = "one_or_more_paths")]
    pub fields: BTreeMap<String, Vec<FieldPath>>,
}

/// Selects rules by the log source they declare.
///
/// Every key given must equal the rule's; keys left out match anything.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSourceSelector {
    /// A class of events, such as `process_creation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// A platform, such as `windows`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// A specific log, such as `sysmon`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

impl LogSourceSelector {
    /// Reports whether this selector applies to a rule declaring `logsource`.
    pub fn selects(&self, logsource: &LogSourceSelector) -> bool {
        let agrees = |wanted: &Option<String>, declared: &Option<String>| {
            wanted.is_none() || wanted == declared
        };
        agrees(&self.category, &logsource.category)
            && agrees(&self.product, &logsource.product)
            && agrees(&self.service, &logsource.service)
    }

    /// How many keys the selector constrains. More is more specific.
    fn specificity(&self) -> usize {
        [&self.category, &self.product, &self.service]
            .into_iter()
            .filter(|key| key.is_some())
            .count()
    }
}

impl From<&goliath_sigma::LogSource> for LogSourceSelector {
    fn from(logsource: &goliath_sigma::LogSource) -> Self {
        Self {
            category: logsource.category.clone(),
            product: logsource.product.clone(),
            service: logsource.service.clone(),
        }
    }
}

impl fmt::Display for LogSourceSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys = [
            ("category", &self.category),
            ("product", &self.product),
            ("service", &self.service),
        ];
        let mut first = true;
        for (name, value) in keys {
            if let Some(value) = value {
                if !first {
                    f.write_str(", ")?;
                }
                write!(f, "{name}: {value}")?;
                first = false;
            }
        }
        if first {
            f.write_str("no log source")?;
        }
        Ok(())
    }
}

impl SourceMapping {
    /// Checks the entry against its class in the OCSF schema. An entry
    /// without a `class_uid` has no class to check against.
    fn check_schema(&self, index: usize) -> Result<(), MappingError> {
        let class_uid = self.class.iter().find_map(|(path, value)| match value {
            ClassValue::Integer(uid) if path.as_str() == "class_uid" => Some(*uid),
            _ => None,
        });
        let Some(class_uid) = class_uid else {
            return Ok(());
        };
        let class = u32::try_from(class_uid)
            .ok()
            .and_then(schema::class)
            .ok_or(MappingError::UnknownClass {
                index,
                class_uid,
                version: goliath_ocsf::SCHEMA_VERSION,
            })?;
        for (path, value) in &self.class {
            let Some(attribute) = attribute(index, class, path)? else {
                continue;
            };
            let fits = match value {
                ClassValue::Integer(_) => matches!(attribute.base(), Base::Integer | Base::Long),
                ClassValue::String(_) => attribute.base() == Base::String,
            };
            if !fits || attribute.is_array() {
                return Err(MappingError::Type {
                    index,
                    path: path.as_str().to_owned(),
                    holds: holds(attribute),
                    value: match value {
                        ClassValue::Integer(value) => value.to_string(),
                        ClassValue::String(value) => format!("{value:?}"),
                    },
                });
            }
            if let ClassValue::Integer(value) = value
                && !attribute.enum_values().is_empty()
                && !attribute.enum_values().contains(value)
            {
                return Err(MappingError::UnknownValue {
                    index,
                    path: path.as_str().to_owned(),
                    value: *value,
                });
            }
        }
        for path in self.fields.values().flatten() {
            if let Some(attribute) = attribute(index, class, path)?
                && attribute.base() == Base::Object
            {
                return Err(MappingError::Type {
                    index,
                    path: path.as_str().to_owned(),
                    holds: holds(attribute),
                    value: "a rule's value".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// The attribute `path` names in `class`, or `None` where it continues into
/// a free-form attribute such as `unmapped`, whose members are not typed.
fn attribute(
    index: usize,
    class: &Class,
    path: &FieldPath,
) -> Result<Option<&'static Attribute>, MappingError> {
    let found = class
        .resolve(path.as_str())
        .map_err(|source| MappingError::Attribute { index, source })?;
    Ok((!found.free_form).then_some(found.attribute))
}

fn holds(attribute: &Attribute) -> String {
    match (attribute.is_array(), attribute.base()) {
        (true, _) => format!("an array of `{}`", attribute.type_name()),
        (false, Base::Object) => format!("an object `{}`", attribute.type_name()),
        (false, _) => format!("`{}`", attribute.type_name()),
    }
}

/// A value an event attribute must have for a mapping to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClassValue {
    /// An integer, as OCSF uses for identifiers and enums.
    Integer(i64),
    /// A string.
    String(String),
}

impl MappingSet {
    /// Parses and checks a mapping set.
    ///
    /// # Errors
    ///
    /// Returns [`MappingError`] if the YAML is malformed or unsafe, if an entry
    /// selects nothing or maps a field to no path, if two entries have the
    /// same selector, or if an entry with a `class_uid` names a class, path,
    /// or value the OCSF schema does not have.
    pub fn from_yaml(source: &str) -> Result<Self, MappingError> {
        let set: Self = goliath_sigma::yaml::from_str(source)?;
        set.check()?;
        Ok(set)
    }

    fn check(&self) -> Result<(), MappingError> {
        for (index, entry) in self.mappings.iter().enumerate() {
            if entry.logsource.specificity() == 0 {
                return Err(MappingError::EmptySelector { index });
            }
            if let Some(field) = entry.fields.iter().find(|(_, paths)| paths.is_empty()) {
                return Err(MappingError::NoPaths {
                    index,
                    field: field.0.clone(),
                });
            }
            if let Some(earlier) = self.mappings[..index]
                .iter()
                .position(|other| other.logsource == entry.logsource)
            {
                return Err(MappingError::DuplicateSelector { earlier, index });
            }
            entry.check_schema(index)?;
        }
        Ok(())
    }

    /// Chooses the entry for a rule declaring `logsource`.
    ///
    /// The most specific selecting entry wins, so a `service: sysmon` entry can
    /// refine a general `product: windows` one.
    ///
    /// # Errors
    ///
    /// Returns [`MappingError::NoMapping`] if nothing selects the log source,
    /// and [`MappingError::Ambiguous`] if two equally specific entries do.
    pub fn select(&self, logsource: &LogSourceSelector) -> Result<&SourceMapping, MappingError> {
        let mut best: Option<&SourceMapping> = None;
        let mut tied = false;

        for entry in &self.mappings {
            if !entry.logsource.selects(logsource) {
                continue;
            }
            let specificity = entry.logsource.specificity();
            match best.map(|current| current.logsource.specificity().cmp(&specificity)) {
                None | Some(Ordering::Less) => {
                    best = Some(entry);
                    tied = false;
                }
                Some(Ordering::Equal) => tied = true,
                Some(Ordering::Greater) => {}
            }
        }

        match best {
            None => Err(MappingError::NoMapping {
                logsource: logsource.clone(),
            }),
            Some(_) if tied => Err(MappingError::Ambiguous {
                logsource: logsource.clone(),
            }),
            Some(entry) => Ok(entry),
        }
    }
}

/// Accepts a single path or a list of paths for each field.
fn one_or_more_paths<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<FieldPath>>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMore {
        One(FieldPath),
        More(Vec<FieldPath>),
    }

    let raw = BTreeMap::<String, OneOrMore>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(field, paths)| {
            let paths = match paths {
                OneOrMore::One(path) => vec![path],
                OneOrMore::More(paths) => paths,
            };
            (field, paths)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SET: &str = r"
name: test
version: 3
mappings:
  - logsource: { product: windows }
    fields:
      User: actor.user.name
  - logsource: { category: process_creation, product: windows }
    class: { class_uid: 1007, activity_id: 1, device.os.type_id: 100 }
    fields:
      Image: [process.file.path, process.path]
      CommandLine: process.cmd_line
";

    fn selector(category: Option<&str>, product: Option<&str>) -> LogSourceSelector {
        LogSourceSelector {
            category: category.map(str::to_owned),
            product: product.map(str::to_owned),
            service: None,
        }
    }

    fn path(text: &str) -> FieldPath {
        FieldPath::parse(text).expect("valid path")
    }

    #[test]
    fn loads_single_and_multiple_paths() {
        let set = MappingSet::from_yaml(SET).expect("valid set");
        assert_eq!(set.version, 3);
        let process = &set.mappings[1];
        assert_eq!(
            process.fields["Image"],
            [path("process.file.path"), path("process.path")]
        );
        assert_eq!(process.fields["CommandLine"], [path("process.cmd_line")]);
        assert_eq!(process.class[&path("class_uid")], ClassValue::Integer(1007));
    }

    #[test]
    fn the_most_specific_entry_wins() {
        let set = MappingSet::from_yaml(SET).expect("valid set");
        let entry = set
            .select(&selector(Some("process_creation"), Some("windows")))
            .expect("selected");
        assert!(entry.fields.contains_key("Image"));

        let general = set
            .select(&selector(Some("registry_set"), Some("windows")))
            .expect("falls back to the product entry");
        assert!(general.fields.contains_key("User"));
    }

    #[test]
    fn keys_a_rule_declares_beyond_the_selector_do_not_prevent_selection() {
        let set = MappingSet::from_yaml(SET).expect("valid set");
        let mut logsource = selector(Some("process_creation"), Some("windows"));
        logsource.service = Some("sysmon".to_owned());
        assert!(set.select(&logsource).is_ok());
    }

    #[test]
    fn an_unselected_log_source_is_an_error() {
        let set = MappingSet::from_yaml(SET).expect("valid set");
        assert!(matches!(
            set.select(&selector(Some("process_creation"), Some("linux"))),
            Err(MappingError::NoMapping { .. })
        ));
    }

    #[test]
    fn equally_specific_matches_are_ambiguous() {
        let set = MappingSet::from_yaml(
            r"
name: test
version: 1
mappings:
  - logsource: { product: windows }
    fields: { A: a }
  - logsource: { category: process_creation }
    fields: { B: b }
",
        )
        .expect("valid set");
        assert!(matches!(
            set.select(&selector(Some("process_creation"), Some("windows"))),
            Err(MappingError::Ambiguous { .. })
        ));
    }

    #[test]
    fn rejects_unknown_keys() {
        let typo = SET.replace("fields:\n      User", "feilds:\n      User");
        assert!(matches!(
            MappingSet::from_yaml(&typo),
            Err(MappingError::Yaml(_))
        ));
    }

    #[test]
    fn rejects_an_entry_that_selects_everything() {
        let source = "name: t\nversion: 1\nmappings:\n  - logsource: {}\n    fields: { A: a }\n";
        assert_eq!(
            MappingSet::from_yaml(source),
            Err(MappingError::EmptySelector { index: 0 })
        );
    }

    #[test]
    fn rejects_a_field_with_no_paths() {
        let source = "name: t\nversion: 1\nmappings:\n  - logsource: { product: x }\n    fields: { A: [] }\n";
        assert!(matches!(
            MappingSet::from_yaml(source),
            Err(MappingError::NoPaths { index: 0, .. })
        ));
    }

    #[test]
    fn rejects_duplicate_selectors() {
        let source = "name: t\nversion: 1\nmappings:\n  - logsource: { product: x }\n    fields: { A: a }\n  - logsource: { product: x }\n    fields: { B: b }\n";
        assert_eq!(
            MappingSet::from_yaml(source),
            Err(MappingError::DuplicateSelector {
                earlier: 0,
                index: 1
            })
        );
    }

    #[test]
    fn rejects_malformed_paths() {
        let source = "name: t\nversion: 1\nmappings:\n  - logsource: { product: x }\n    fields: { A: a..b }\n";
        assert!(matches!(
            MappingSet::from_yaml(source),
            Err(MappingError::Yaml(_))
        ));
    }

    fn schema_error(replace: &str, with: &str) -> String {
        assert_eq!(SET.matches(replace).count(), 1, "{replace}");
        MappingSet::from_yaml(&SET.replace(replace, with))
            .expect_err("the schema rejects it")
            .to_string()
    }

    #[test]
    fn checks_entries_against_the_ocsf_schema() {
        assert_eq!(
            schema_error(
                "CommandLine: process.cmd_line",
                "CommandLine: process.cmdline"
            ),
            "mapping 1: `process.cmdline`: object `process` has no attribute `cmdline`"
        );
        assert_eq!(
            schema_error("class_uid: 1007", "class_uid: 1999"),
            "mapping 1: OCSF 1.5.0 has no class 1999"
        );
        assert_eq!(
            schema_error("activity_id: 1,", "activity_id: 42,"),
            "mapping 1: 42 is not a defined value of `activity_id`"
        );
        assert_eq!(
            schema_error("device.os.type_id: 100", "device.os.type_id: windows"),
            "mapping 1: `device.os.type_id` holds `integer_t`, which cannot equal \"windows\""
        );
        assert_eq!(
            schema_error("CommandLine: process.cmd_line", "CommandLine: process.file"),
            "mapping 1: `process.file` holds an object `file`, which cannot equal a rule's value"
        );
    }

    #[test]
    fn schema_checks_allow_arrays_free_form_paths_and_classless_entries() {
        // Rules search arrays, and `unmapped` members are not typed.
        let set = SET.replace(
            "CommandLine: process.cmd_line",
            "CommandLine: process.cmd_line
      Technique: attacks.technique.uid
      Hashes: unmapped.Hashes",
        );
        MappingSet::from_yaml(&set).expect("arrays and unmapped are fine");
        // The first entry has no class, so its paths are not checked.
        let set = SET.replace("User: actor.user.name", "User: anything.at.all");
        MappingSet::from_yaml(&set).expect("no class to check against");
    }
}
