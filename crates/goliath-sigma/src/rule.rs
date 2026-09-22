//! Sigma rules.
//!
//! A rule is metadata, a log source, and a detection block. The detection
//! block maps search identifiers to searches and names the condition that
//! combines them:
//!
//! ```yaml
//! detection:
//!   selection:              # a mapping: every field must match
//!     Image|endswith: '\powershell.exe'
//!     CommandLine|contains:  # a list of values: any may match
//!       - ' -enc '
//!       - ' -EncodedCommand '
//!   filter:
//!     - User: SYSTEM        # a list of mappings: any mapping may match
//!     - ParentImage|endswith: '\ccmexec.exe'
//!   keywords:               # a list of scalars: search any field
//!     - 'invoke-mimikatz'
//!   condition: selection and not filter
//! ```
//!
//! Top-level fields this crate does not model, such as `license` or
//! `related`, are ignored rather than rejected: real rule repositories carry
//! them, and they do not affect what a rule detects.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::condition::Condition;
use crate::error::RuleError;
use crate::modifier::{FieldKey, parse_field_key};
use crate::parser::parse_condition;
use crate::value::Value;
use crate::yaml::{self, RawValue};

/// The maturity a rule's author claims for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Tested in production for a long time; few false positives.
    Stable,
    /// Believed to work; tested in a limited set of environments.
    Test,
    /// New, and likely to produce false positives.
    Experimental,
    /// Replaced or no longer relevant.
    Deprecated,
    /// Cannot be used in its current state.
    Unsupported,
}

/// How severe a match is, as judged by the rule's author.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// No action expected; context for other detections.
    Informational,
    /// Notable, but rarely an incident alone.
    Low,
    /// Relevant; worth reviewing.
    Medium,
    /// Likely an incident; review soon.
    High,
    /// Almost certainly an incident; act immediately.
    Critical,
}

/// Which log data a rule applies to.
///
/// All fields are optional individually, and backends map the combination to
/// concrete sources.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LogSource {
    /// A class of events, such as `process_creation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// A platform, such as `windows`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// A specific log, such as `sysmon` or `security`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Free text describing prerequisites, such as required audit policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<String>,
}

/// One field condition inside a search: a field, its modifiers, and the
/// values it is compared against.
///
/// Several values match if any one does, or only if every one does when the
/// key carries the `all` modifier.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FieldPredicate {
    /// The field and its modifiers.
    pub key: FieldKey,
    /// The values to compare against.
    pub values: Vec<Value>,
}

/// What a search identifier stands for.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Search {
    /// A mapping: every predicate must match.
    AllOf(Vec<FieldPredicate>),
    /// A list of mappings: at least one mapping must match in full.
    AnyOf(Vec<Vec<FieldPredicate>>),
    /// A list of values searched for in any field: at least one must match.
    Keywords(Vec<Value>),
}

/// A condition together with the text it was parsed from.
///
/// The text is kept because every span in the parsed condition is an offset
/// into it, and an error pointing at a span is useless without the text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConditionSource {
    /// The condition as written.
    pub text: String,
    /// The parsed condition.
    pub parsed: Condition,
}

/// The detection block of a rule.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Detection {
    /// Searches by identifier.
    pub searches: BTreeMap<String, Search>,
    /// The conditions. A rule matches if any of them matches; almost every
    /// rule has exactly one.
    pub conditions: Vec<ConditionSource>,
    /// The legacy `timeframe` value, kept verbatim.
    ///
    /// It only has meaning alongside an aggregation, which the condition
    /// parser refuses, so it never affects matching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeframe: Option<String>,
}

/// A parsed Sigma rule.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rule {
    /// A short description of what the rule detects.
    pub title: String,
    /// A globally unique identifier, conventionally a UUID.
    pub id: Option<String>,
    /// The claimed maturity.
    pub status: Option<Status>,
    /// A longer description.
    pub description: Option<String>,
    /// Sources the rule is based on.
    pub references: Vec<String>,
    /// Who wrote it.
    pub author: Option<String>,
    /// When it was created, as written.
    pub date: Option<String>,
    /// When it was last changed, as written.
    pub modified: Option<String>,
    /// Tags, including ATT&CK references such as `attack.t1059.001`.
    pub tags: Vec<String>,
    /// Which log data it applies to.
    pub logsource: LogSource,
    /// What it detects.
    pub detection: Detection,
    /// Known benign causes of a match.
    pub falsepositives: Vec<String>,
    /// How severe a match is.
    pub level: Option<Level>,
    /// Fields worth showing an analyst alongside a match.
    pub fields: Vec<String>,
}

/// Parses a Sigma rule from YAML.
///
/// # Errors
///
/// Returns [`RuleError`] if the YAML is malformed or unsafe, if a required
/// field is missing, or if the detection block cannot be interpreted.
///
/// # Examples
///
/// ```
/// use goliath_sigma::{Search, parse_rule};
///
/// let rule = parse_rule(r"
/// title: Encoded PowerShell
/// logsource:
///   category: process_creation
///   product: windows
/// detection:
///   selection:
///     CommandLine|contains: ' -enc '
///   condition: selection
/// ")?;
///
/// assert!(matches!(rule.detection.searches["selection"], Search::AllOf(_)));
/// # Ok::<(), goliath_sigma::RuleError>(())
/// ```
pub fn parse_rule(source: &str) -> Result<Rule, RuleError> {
    let raw: RawRule = yaml::from_str(source)?;

    Ok(Rule {
        title: raw.title,
        id: raw.id,
        status: raw.status,
        description: raw.description,
        references: raw.references,
        author: raw.author,
        date: raw.date,
        modified: raw.modified,
        tags: raw.tags,
        logsource: raw.logsource,
        detection: build_detection(raw.detection)?,
        falsepositives: raw.falsepositives,
        level: raw.level,
        fields: raw.fields,
    })
}

/// The rule as it appears in YAML, before the detection block is interpreted.
#[derive(Deserialize)]
struct RawRule {
    title: String,
    id: Option<String>,
    status: Option<Status>,
    description: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    references: Vec<String>,
    author: Option<String>,
    date: Option<String>,
    modified: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    tags: Vec<String>,
    logsource: LogSource,
    detection: BTreeMap<String, RawValue>,
    #[serde(default, deserialize_with = "one_or_many")]
    falsepositives: Vec<String>,
    level: Option<Level>,
    #[serde(default, deserialize_with = "one_or_many")]
    fields: Vec<String>,
}

/// Accepts either a single string or a list of strings.
///
/// The specification says list, but a single `falsepositives: Unknown` is
/// common in the wild. Accepting it changes nothing a rule detects.
fn one_or_many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(item) => vec![item],
        OneOrMany::Many(items) => items,
    })
}

const CONDITION_KEY: &str = "condition";
const TIMEFRAME_KEY: &str = "timeframe";

fn build_detection(mut raw: BTreeMap<String, RawValue>) -> Result<Detection, RuleError> {
    let conditions = match raw.remove(CONDITION_KEY) {
        None => return Err(RuleError::MissingCondition),
        Some(RawValue::String(text)) => vec![build_condition(text)?],
        Some(RawValue::List(items)) if !items.is_empty() => items
            .into_iter()
            .map(|item| match item {
                RawValue::String(text) => build_condition(text),
                other => Err(RuleError::InvalidConditionType {
                    found: other.describe(),
                }),
            })
            .collect::<Result<_, _>>()?,
        Some(other) => {
            return Err(RuleError::InvalidConditionType {
                found: other.describe(),
            });
        }
    };

    let timeframe = match raw.remove(TIMEFRAME_KEY) {
        None => None,
        Some(RawValue::String(text)) => Some(text),
        Some(other) => {
            return Err(RuleError::InvalidTimeframe {
                found: other.describe(),
            });
        }
    };

    let searches = raw
        .into_iter()
        .map(|(identifier, value)| {
            let search = build_search(&identifier, value)?;
            Ok((identifier, search))
        })
        .collect::<Result<_, RuleError>>()?;

    Ok(Detection {
        searches,
        conditions,
        timeframe,
    })
}

fn build_condition(text: String) -> Result<ConditionSource, RuleError> {
    match parse_condition(&text) {
        Ok(parsed) => Ok(ConditionSource { text, parsed }),
        Err(source) => Err(RuleError::InvalidCondition { text, source }),
    }
}

fn build_search(identifier: &str, value: RawValue) -> Result<Search, RuleError> {
    match value {
        RawValue::Map(map) => Ok(Search::AllOf(build_predicates(identifier, map)?)),

        RawValue::List(items) if items.is_empty() => Err(RuleError::EmptySearch {
            identifier: identifier.to_owned(),
        }),

        RawValue::List(items) if items.iter().all(|item| matches!(item, RawValue::Map(_))) => {
            let alternatives = items
                .into_iter()
                .map(|item| match item {
                    RawValue::Map(map) => build_predicates(identifier, map),
                    // Excluded by the guard above.
                    _ => Err(RuleError::EmptySearch {
                        identifier: identifier.to_owned(),
                    }),
                })
                .collect::<Result<_, _>>()?;
            Ok(Search::AnyOf(alternatives))
        }

        RawValue::List(items) => {
            let keywords = items
                .into_iter()
                .map(|item| {
                    scalar(item).ok_or_else(|| RuleError::MixedSearchList {
                        identifier: identifier.to_owned(),
                    })
                })
                .collect::<Result<_, _>>()?;
            Ok(Search::Keywords(keywords))
        }

        RawValue::Null(()) => Err(RuleError::EmptySearch {
            identifier: identifier.to_owned(),
        }),

        scalar_value => {
            let keyword = scalar(scalar_value).ok_or_else(|| RuleError::EmptySearch {
                identifier: identifier.to_owned(),
            })?;
            Ok(Search::Keywords(vec![keyword]))
        }
    }
}

fn build_predicates(
    identifier: &str,
    map: BTreeMap<String, RawValue>,
) -> Result<Vec<FieldPredicate>, RuleError> {
    if map.is_empty() {
        return Err(RuleError::EmptySearch {
            identifier: identifier.to_owned(),
        });
    }

    map.into_iter()
        .map(|(key_text, raw_values)| {
            let key = parse_field_key(&key_text).map_err(|source| RuleError::InvalidFieldKey {
                identifier: identifier.to_owned(),
                source,
            })?;

            let invalid_value = |found: &'static str| RuleError::InvalidFieldValue {
                identifier: identifier.to_owned(),
                field: key_text.clone(),
                found,
            };

            let values = match raw_values {
                RawValue::List(items) if items.is_empty() => {
                    return Err(RuleError::EmptyValueList {
                        identifier: identifier.to_owned(),
                        field: key_text.clone(),
                    });
                }
                RawValue::List(items) => items
                    .into_iter()
                    .map(|item| {
                        let found = item.describe();
                        scalar(item).ok_or_else(|| invalid_value(found))
                    })
                    .collect::<Result<_, _>>()?,
                single => {
                    let found = single.describe();
                    vec![scalar(single).ok_or_else(|| invalid_value(found))?]
                }
            };

            Ok(FieldPredicate { key, values })
        })
        .collect()
}

/// Converts a scalar YAML value into a detection value, or `None` for a list
/// or mapping.
fn scalar(value: RawValue) -> Option<Value> {
    Some(match value {
        RawValue::Null(()) => Value::Null,
        RawValue::Boolean(b) => Value::Boolean(b),
        RawValue::Integer(i) => Value::Integer(i),
        RawValue::Float(f) => Value::Float(f),
        RawValue::String(s) => Value::string(&s),
        RawValue::List(_) | RawValue::Map(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modifier::Modifier;

    const ENCODED_POWERSHELL: &str = r"
title: Encoded PowerShell Command Line
id: 5b1f5e4e-2c8f-4a4e-9a51-6f3b0c1d2e7a
status: experimental
description: Detects PowerShell started with a base64 encoded command.
references:
  - https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_pwsh
author: Goliath contributors
date: 2026-09-22
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flag:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  filter_management:
    - ParentImage|endswith: '\ccmexec.exe'
    - User: SYSTEM
  condition: all of selection_* and not filter_management
falsepositives:
  - Management software that encodes its own commands
level: medium
license: DRL-1.1
";

    fn parse(source: &str) -> Rule {
        parse_rule(source).expect("rule should parse")
    }

    #[test]
    fn parses_metadata() {
        let rule = parse(ENCODED_POWERSHELL);
        assert_eq!(rule.title, "Encoded PowerShell Command Line");
        assert_eq!(rule.status, Some(Status::Experimental));
        assert_eq!(rule.level, Some(Level::Medium));
        assert_eq!(rule.tags, ["attack.execution", "attack.t1059.001"]);
        assert_eq!(rule.date.as_deref(), Some("2026-09-22"));
        assert_eq!(rule.logsource.category.as_deref(), Some("process_creation"));
        assert_eq!(rule.logsource.product.as_deref(), Some("windows"));
    }

    #[test]
    fn a_mapping_is_an_all_of_search() {
        let rule = parse(ENCODED_POWERSHELL);
        let Search::AllOf(predicates) = &rule.detection.searches["selection_image"] else {
            panic!("expected an all-of search");
        };

        assert_eq!(predicates.len(), 1);
        assert_eq!(predicates[0].key.field, "Image");
        assert_eq!(predicates[0].key.modifiers, [Modifier::EndsWith]);
        assert_eq!(
            predicates[0].values,
            [
                Value::string(r"\powershell.exe"),
                Value::string(r"\pwsh.exe")
            ]
        );
    }

    #[test]
    fn a_list_of_mappings_is_an_any_of_search() {
        let rule = parse(ENCODED_POWERSHELL);
        let Search::AnyOf(alternatives) = &rule.detection.searches["filter_management"] else {
            panic!("expected an any-of search");
        };
        assert_eq!(alternatives.len(), 2);
        assert_eq!(alternatives[1][0].key.field, "User");
    }

    #[test]
    fn a_list_of_scalars_is_a_keyword_search() {
        let rule = parse(
            "title: t\nlogsource: {}\ndetection:\n  keywords:\n    - mimikatz\n    - 4688\n  condition: keywords\n",
        );
        assert_eq!(
            rule.detection.searches["keywords"],
            Search::Keywords(vec![Value::string("mimikatz"), Value::Integer(4688)])
        );
    }

    #[test]
    fn a_single_scalar_is_a_keyword_search() {
        let rule = parse("title: t\nlogsource: {}\ndetection:\n  kw: mimikatz\n  condition: kw\n");
        assert_eq!(
            rule.detection.searches["kw"],
            Search::Keywords(vec![Value::string("mimikatz")])
        );
    }

    #[test]
    fn condition_and_timeframe_are_not_searches() {
        let rule = parse(
            "title: t\nlogsource: {}\ndetection:\n  s: {a: 1}\n  timeframe: 5m\n  condition: s\n",
        );
        assert_eq!(rule.detection.searches.keys().collect::<Vec<_>>(), ["s"]);
        assert_eq!(rule.detection.timeframe.as_deref(), Some("5m"));
        assert_eq!(rule.detection.conditions[0].text, "s");
    }

    #[test]
    fn a_list_of_conditions_is_kept_in_order() {
        let rule = parse(
            "title: t\nlogsource: {}\ndetection:\n  a: {x: 1}\n  b: {y: 2}\n  condition:\n    - a\n    - b\n",
        );
        let texts: Vec<_> = rule
            .detection
            .conditions
            .iter()
            .map(|c| c.text.as_str())
            .collect();
        assert_eq!(texts, ["a", "b"]);
    }

    #[test]
    fn a_single_string_is_accepted_where_a_list_is_expected() {
        let rule = parse(
            "title: t\nlogsource: {}\ndetection:\n  s: {a: 1}\n  condition: s\nfalsepositives: Unknown\n",
        );
        assert_eq!(rule.falsepositives, ["Unknown"]);
    }

    #[test]
    fn unmodelled_top_level_fields_are_ignored() {
        // `license` in the sample is not modelled, and must not break parsing.
        parse(ENCODED_POWERSHELL);
    }

    #[test]
    fn rejects_a_missing_condition() {
        let err = parse_rule("title: t\nlogsource: {}\ndetection:\n  s: {a: 1}\n")
            .expect_err("condition is required");
        assert_eq!(err, RuleError::MissingCondition);
    }

    #[test]
    fn rejects_an_invalid_condition_and_keeps_its_text() {
        let err =
            parse_rule("title: t\nlogsource: {}\ndetection:\n  s: {a: 1}\n  condition: s and\n")
                .expect_err("dangling operator");
        let RuleError::InvalidCondition { text, .. } = err else {
            panic!("expected an invalid condition error, got {err:?}");
        };
        assert_eq!(text, "s and");
    }

    #[test]
    fn an_unknown_modifier_names_its_search() {
        let err = parse_rule(
            "title: t\nlogsource: {}\ndetection:\n  selection:\n    Image|endswidth: x\n  condition: selection\n",
        )
        .expect_err("typo in modifier");
        let RuleError::InvalidFieldKey { identifier, .. } = err else {
            panic!("expected an invalid field key error, got {err:?}");
        };
        assert_eq!(identifier, "selection");
    }

    #[test]
    fn rejects_a_list_mixing_mappings_and_scalars() {
        let err = parse_rule(
            "title: t\nlogsource: {}\ndetection:\n  s:\n    - {a: 1}\n    - loose\n  condition: s\n",
        )
        .expect_err("mixed list");
        assert!(matches!(err, RuleError::MixedSearchList { .. }));
    }

    #[test]
    fn rejects_an_empty_value_list() {
        // An empty list matches nothing, so the search can never be true.
        let err =
            parse_rule("title: t\nlogsource: {}\ndetection:\n  s:\n    a: []\n  condition: s\n")
                .expect_err("empty value list");
        assert!(matches!(err, RuleError::EmptyValueList { .. }));
    }

    #[test]
    fn rejects_a_nested_mapping_as_a_value() {
        let err = parse_rule(
            "title: t\nlogsource: {}\ndetection:\n  s:\n    a: {nested: 1}\n  condition: s\n",
        )
        .expect_err("nested mapping value");
        let RuleError::InvalidFieldValue { field, found, .. } = err else {
            panic!("expected an invalid field value error, got {err:?}");
        };
        assert_eq!(field, "a");
        assert_eq!(found, "a mapping");
    }

    #[test]
    fn rejects_an_unknown_status_with_its_location() {
        let err =
            parse_rule("title: t\nstatus: production\nlogsource: {}\ndetection:\n  condition: x\n")
                .expect_err("unknown status");
        let RuleError::Yaml(yaml) = err else {
            panic!("expected a YAML error, got {err:?}");
        };
        assert_eq!(yaml.line, Some(2));
    }

    #[test]
    fn rejects_a_duplicate_field_inside_a_selection() {
        let err = parse_rule(
            "title: t\nlogsource: {}\ndetection:\n  s:\n    Image: a.exe\n    Image: b.exe\n  condition: s\n",
        )
        .expect_err("duplicate field");
        assert!(matches!(err, RuleError::Yaml(_)));
    }
}
