//! A framework's content, read from its STIX 2.1 bundle.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::Value;

use crate::AttackError;

/// A tactic: why an adversary uses a technique, such as Execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tactic {
    /// The identifier, such as `TA0002`.
    pub id: String,
    /// The name, such as `Execution`.
    pub name: String,
    /// The short name techniques name it by, such as `execution`.
    pub shortname: String,
}

/// Whether a technique is still in the framework.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Current.
    Active,
    /// Withdrawn without a replacement.
    Deprecated,
    /// Replaced, by the technique named if the framework says which.
    Revoked {
        /// The technique that replaced it, such as `T1059.001`.
        by: Option<String>,
    },
}

/// A technique or sub-technique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Technique {
    /// The identifier, such as `T1059.001`.
    pub id: String,
    /// The name, such as `PowerShell`.
    pub name: String,
    /// The short names of its tactics, in the framework's order.
    pub tactics: Vec<String>,
    /// The platforms it applies to, such as `Windows`.
    pub platforms: Vec<String>,
    /// The technique a sub-technique belongs to, such as `T1059`.
    pub parent: Option<String>,
    /// Whether it is still in the framework.
    pub state: State,
    /// The identifiers of the data components its detection strategies
    /// read, such as `DC0032`.
    pub data_components: BTreeSet<String>,
}

/// What a sensor records, such as Process Creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataComponent {
    /// The identifier, such as `DC0032`.
    pub id: String,
    /// The name, such as `Process Creation`.
    pub name: String,
}

/// One version of a framework, such as Enterprise ATT&CK 19.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framework {
    name: String,
    domain: String,
    version: String,
    tactics: Vec<Tactic>,
    techniques: BTreeMap<String, Technique>,
    data_components: BTreeMap<String, DataComponent>,
}

impl Framework {
    /// Reads an ATT&CK STIX 2.1 bundle, as
    /// [attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
    /// publishes each version. Objects of other types are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`AttackError::Json`] if the text is not JSON, and
    /// [`AttackError::Bundle`] if it is not a bundle, or names no collection
    /// with a version, or no matrix.
    pub fn from_stix(text: &str) -> Result<Self, AttackError> {
        let bundle: Value = serde_json::from_str(text)?;
        let objects = bundle
            .get("objects")
            .and_then(Value::as_array)
            .filter(|_| bundle.get("type").and_then(Value::as_str) == Some("bundle"))
            .ok_or_else(|| AttackError::Bundle("not a STIX bundle".to_owned()))?;
        let of = |kind: &'static str| {
            objects
                .iter()
                .filter(move |object| object.get("type").and_then(Value::as_str) == Some(kind))
        };
        let by_id: HashMap<&str, &Value> = objects
            .iter()
            .filter_map(|object| Some((text_of(object, "id")?, object)))
            .collect();

        let collection = of("x-mitre-collection")
            .next()
            .ok_or_else(|| AttackError::Bundle("no collection names the version".to_owned()))?;
        let version = text_of(collection, "x_mitre_version")
            .ok_or_else(|| AttackError::Bundle("the collection has no version".to_owned()))?;
        let matrix = of("x-mitre-matrix")
            .next()
            .ok_or_else(|| AttackError::Bundle("no matrix orders the tactics".to_owned()))?;

        let tactics: Vec<Tactic> = strings(matrix, "tactic_refs")
            .filter_map(|reference| by_id.get(reference))
            .filter_map(|tactic| {
                Some(Tactic {
                    id: external_id(tactic)?,
                    name: text_of(tactic, "name")?.to_owned(),
                    shortname: text_of(tactic, "x_mitre_shortname")?.to_owned(),
                })
            })
            .collect();
        let order: HashMap<&str, usize> = tactics
            .iter()
            .enumerate()
            .map(|(index, tactic)| (tactic.shortname.as_str(), index))
            .collect();

        let data_components: BTreeMap<String, DataComponent> = of("x-mitre-data-component")
            .filter(|component| {
                !flag(component, "revoked") && !flag(component, "x_mitre_deprecated")
            })
            .filter_map(|component| {
                let id = external_id(component)?;
                let name = text_of(component, "name")?.to_owned();
                Some((id.clone(), DataComponent { id, name }))
            })
            .collect();

        let mut techniques = BTreeMap::new();
        let mut ids: HashMap<&str, String> = HashMap::new();
        for pattern in of("attack-pattern") {
            if let Some((stix, technique)) = technique(pattern, &order) {
                ids.insert(stix, technique.id.clone());
                techniques.insert(technique.id.clone(), technique);
            }
        }
        for relationship in of("relationship") {
            relate(
                relationship,
                &ids,
                &by_id,
                &data_components,
                &mut techniques,
            );
        }

        Ok(Self {
            name: text_of(collection, "name").unwrap_or("ATT&CK").to_owned(),
            domain: external_id(matrix).unwrap_or_default(),
            version: version.to_owned(),
            tactics,
            techniques,
            data_components,
        })
    }

    /// The framework's name, such as `Enterprise ATT&CK`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The domain, such as `enterprise-attack`.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The version, such as `19.2`.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The tactics, in the order of the framework's matrix.
    pub fn tactics(&self) -> &[Tactic] {
        &self.tactics
    }

    /// Every technique, current or not, by identifier.
    pub fn techniques(&self) -> impl Iterator<Item = &Technique> {
        self.techniques.values()
    }

    /// The technique with this identifier, such as `T1059.001`, in any
    /// case.
    pub fn technique(&self, id: &str) -> Option<&Technique> {
        self.techniques.get(&id.to_ascii_uppercase())
    }

    /// Every current data component, by identifier.
    pub fn data_components(&self) -> impl Iterator<Item = &DataComponent> {
        self.data_components.values()
    }

    /// The data component with this identifier, such as `DC0032`.
    pub fn data_component(&self, id: &str) -> Option<&DataComponent> {
        self.data_components.get(id)
    }

    /// The data component with this name, such as `Process Creation`, in
    /// any case.
    pub fn data_component_named(&self, name: &str) -> Option<&DataComponent> {
        self.data_components
            .values()
            .find(|component| component.name.eq_ignore_ascii_case(name))
    }
}

/// A technique from its `attack-pattern`, with its STIX identifier, its
/// tactics in the matrix's `order`. Its parent, replacement, and data
/// components come from relationships.
fn technique<'a>(pattern: &'a Value, order: &HashMap<&str, usize>) -> Option<(&'a str, Technique)> {
    let stix = text_of(pattern, "id")?;
    let id = external_id(pattern)?;
    let name = text_of(pattern, "name")?;
    let mut tactics: Vec<String> = pattern
        .get("kill_chain_phases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|phase| text_of(phase, "kill_chain_name") == Some("mitre-attack"))
        .filter_map(|phase| text_of(phase, "phase_name").map(str::to_owned))
        .collect();
    tactics.sort_by_key(|shortname| order.get(shortname.as_str()).copied());
    let state = if flag(pattern, "revoked") {
        State::Revoked { by: None }
    } else if flag(pattern, "x_mitre_deprecated") {
        State::Deprecated
    } else {
        State::Active
    };
    Some((
        stix,
        Technique {
            id,
            name: name.to_owned(),
            tactics,
            platforms: strings(pattern, "x_mitre_platforms")
                .map(str::to_owned)
                .collect(),
            parent: None,
            state,
            data_components: BTreeSet::new(),
        },
    ))
}

/// Applies one relationship between techniques, or from a detection
/// strategy to a technique, which it detects through its analytics, each
/// reading log sources of data components.
fn relate(
    relationship: &Value,
    ids: &HashMap<&str, String>,
    by_id: &HashMap<&str, &Value>,
    data_components: &BTreeMap<String, DataComponent>,
    techniques: &mut BTreeMap<String, Technique>,
) {
    let (Some(kind), Some(source), Some(target)) = (
        text_of(relationship, "relationship_type"),
        text_of(relationship, "source_ref"),
        text_of(relationship, "target_ref"),
    ) else {
        return;
    };
    match kind {
        "subtechnique-of" => {
            if let (Some(child), Some(parent)) = (ids.get(source), ids.get(target))
                && let Some(technique) = techniques.get_mut(child)
            {
                technique.parent = Some(parent.clone());
            }
        }
        "revoked-by" => {
            if let (Some(old), Some(new)) = (ids.get(source), ids.get(target))
                && let Some(technique) = techniques.get_mut(old)
            {
                technique.state = State::Revoked {
                    by: Some(new.clone()),
                };
            }
        }
        "detects" => {
            let (Some(technique), Some(strategy)) = (
                ids.get(target).and_then(|id| techniques.get_mut(id)),
                by_id.get(source),
            ) else {
                return;
            };
            let components = strings(strategy, "x_mitre_analytic_refs")
                .filter_map(|analytic| by_id.get(analytic))
                .flat_map(|analytic| {
                    analytic
                        .get("x_mitre_log_source_references")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .filter_map(|source| text_of(source, "x_mitre_data_component_ref"))
                .filter_map(|component| by_id.get(component))
                .filter_map(|component| external_id(component))
                .filter(|id| data_components.contains_key(id));
            technique.data_components.extend(components);
        }
        _ => {}
    }
}

fn text_of<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn flag(object: &Value, key: &str) -> bool {
    object.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn strings<'a>(object: &'a Value, key: &str) -> impl Iterator<Item = &'a str> {
    object
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// The object's ATT&CK identifier, such as `T1059.001`, from its reference
/// to ATT&CK itself.
fn external_id(object: &Value) -> Option<String> {
    object
        .get("external_references")?
        .as_array()?
        .iter()
        .find(|reference| {
            text_of(reference, "source_name").is_some_and(|name| name.starts_with("mitre-"))
        })
        .and_then(|reference| text_of(reference, "external_id"))
        .map(str::to_owned)
}
