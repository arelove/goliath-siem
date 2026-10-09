//! Context for the Goliath security platform: what a site knows of its own
//! networks, machines, accounts, and groups, found for the values of an
//! event and written as OCSF enrichments.
//!
//! - A [`Definition`] reads a file the site exports, under the file's own
//!   column names, into [`Record`]s.
//! - A [`Snapshot`] holds the records of every source, and finds those of an
//!   identifier within a scope at a time.
//! - [`enrichments`] gives what a finding gets: one entry for each record
//!   found, each under its source's name and version.
//!
//! The design is `docs/adr/0022-context-snapshot.md`.
//!
//! ```
//! use goliath_enrich::{Definition, Id, IdKind, Snapshot, enrichments};
//!
//! let definition = Definition::from_yaml(
//!     "name: cmdb\nkind: asset\nformat: csv\n\
//!      identifiers: { host: [hostname] }\n\
//!      fields: { owner: owner, criticality: tier }\n\
//!      labels: { pci_scope: pci }\n",
//! )?;
//! let parsed = definition.parse(b"hostname,owner,tier,pci\nPAY-DB-01,dba@corp.example,4,cde\n")?;
//! let mut snapshot = Snapshot::new();
//! snapshot.replace(&definition.name, "2026-10-10", parsed.records);
//!
//! let host = Id::new(IdKind::Host, "pay-db-01")?;
//! let found = enrichments(&snapshot, &[host], None, 1_791_600_000);
//! assert_eq!(found[0]["data"]["criticality"], 4);
//! assert_eq!(found[0]["data"]["labels"]["pci_scope"], "cde");
//! # Ok::<(), goliath_enrich::EnrichError>(())
//! ```

mod definition;
mod record;
mod snapshot;

use serde_json::{Map, Value, json};

pub use definition::{Csv, Definition, Format, Many, Parsed};
pub use record::{Id, IdKind, Kind, Range, Record};
pub use snapshot::{Found, Snapshot};

/// The most entries [`enrichments`] gives for one finding. An event that
/// names more is a scan or a list, and its context is in the event.
pub const LIMIT: usize = 32;

/// What can go wrong with a definition, an export, or a value.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum EnrichError {
    /// A value cannot be of its kind.
    #[error("{kind} `{value}`: {why}")]
    Value {
        /// What it was to be.
        kind: &'static str,
        /// The value as written.
        value: String,
        /// Why not.
        why: String,
    },
    /// The YAML of a definition is malformed, or is not a definition.
    #[error(transparent)]
    Yaml(#[from] goliath_sigma::YamlError),
    /// A definition contradicts itself.
    #[error("the definition of `{source_name}`: {why}")]
    Definition {
        /// The source's name.
        source_name: String,
        /// What is wrong.
        why: String,
    },
    /// An export is not what its definition describes.
    #[error("the export of `{source_name}` is refused: {why}")]
    Source {
        /// The source's name.
        source_name: String,
        /// What is wrong.
        why: String,
    },
}

/// What a finding gets for the values of its event: an OCSF `enrichment`
/// for each record `snapshot` holds of each of `ids`, for an event of
/// `scope` at `at`, in seconds since the epoch.
///
/// - The groups a found record names are looked up too, so that a group
///   said once to be privileged is said so in the finding.
/// - Two sources that describe one thing give two entries. Nothing is
///   merged: each entry names its source as `provider` and the source's
///   version in `data`.
/// - Networks come first, then assets, identities, groups, and rows of
///   context lists, and no more than [`LIMIT`] in all.
pub fn enrichments(snapshot: &Snapshot, ids: &[Id], scope: Option<&str>, at: i64) -> Vec<Value> {
    /// Adds what the snapshot holds of `id`, each record once, and says
    /// where in `found` the additions are.
    fn add<'a>(
        snapshot: &'a Snapshot,
        id: &Id,
        scope: Option<&str>,
        at: i64,
        found: &mut Vec<(Id, Found<'a>)>,
    ) -> std::ops::Range<usize> {
        let before = found.len();
        for entry in snapshot.lookup(id, scope, at) {
            let seen = found
                .iter()
                .any(|(_, held)| std::ptr::eq(held.record, entry.record));
            if !seen {
                found.push((id.clone(), entry));
            }
        }
        before..found.len()
    }

    let mut found: Vec<(Id, Found<'_>)> = Vec::new();
    for id in ids {
        let added = add(snapshot, id, scope, at, &mut found);
        let groups: Vec<Id> = found
            .get(added)
            .unwrap_or_default()
            .iter()
            .flat_map(|(_, entry)| &entry.record.groups)
            .filter_map(|name| Id::new(IdKind::Group, name).ok())
            .collect();
        for group in &groups {
            add(snapshot, group, scope, at, &mut found);
        }
    }
    found.sort_by_key(|(_, entry)| entry.record.kind);
    found.truncate(LIMIT);
    found
        .iter()
        .map(|(id, entry)| enrichment(id, entry))
        .collect()
}

/// One record found, as an OCSF `enrichment` object.
fn enrichment(id: &Id, found: &Found<'_>) -> Value {
    let record = found.record;
    let mut data = Map::new();
    data.insert("source_version".to_owned(), json!(found.version));
    for (field, value) in &record.fields {
        data.insert(field.clone(), value.clone());
    }
    if !record.labels.is_empty() {
        data.insert("labels".to_owned(), json!(record.labels));
    }
    if !record.groups.is_empty() {
        data.insert("groups".to_owned(), json!(record.groups));
    }
    if let Some(range) = found.range {
        data.insert("range".to_owned(), json!(range.to_string()));
    }
    if let Some(scope) = &record.scope {
        data.insert("scope".to_owned(), json!(scope));
    }
    if let Some(from) = record.valid_from {
        data.insert("valid_from".to_owned(), json!(from));
    }
    if let Some(until) = record.valid_until {
        data.insert("valid_until".to_owned(), json!(until));
    }
    if found.ended {
        // The record stopped holding before the event: an account that was
        // closed, a machine that was retired.
        data.insert("ended".to_owned(), json!(true));
    }
    json!({
        "name": id.kind().as_str(),
        "value": id.value(),
        "type": record.kind.as_str(),
        "provider": found.source,
        "data": data,
    })
}
