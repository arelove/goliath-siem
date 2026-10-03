//! A hit as an OCSF Detection Finding: what is stored and searched in place
//! of a rewritten event. See `docs/adr/0021-enrichment-placement.md`.

use std::fmt::Write as _;

use goliath_ocsf::ObservableType;
use serde_json::{Map, Value, json};

use crate::key::{Key, Kind};
use crate::matcher::Hit;
use crate::observe::Observed;

/// The class of a Detection Finding, and its category.
const CLASS: u32 = 2004;
const CATEGORY: u32 = 2;
/// The activity `Create`.
const CREATE: u32 = 1;
/// The status `New`, and `Suppressed`.
const NEW: u32 = 1;
const SUPPRESSED: u32 = 3;
/// Keys the hash of a finding's identifier. Changing it changes every
/// identifier.
const CONTEXT: &str = "goliath 2026-10-03 indicator finding uid";

/// The identifier of the finding that `indicator` matched in the event
/// `event_id`: the same for the same two, so that an event read twice gives
/// one finding.
pub fn finding_uid(event_id: &str, indicator: &Key) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(CONTEXT);
    hasher.update(&(event_id.len() as u64).to_le_bytes());
    hasher.update(event_id.as_bytes());
    hasher.update(&indicator.to_bytes());
    let mut uid = [0u8; 16];
    hasher.finalize_xof().fill(&mut uid);
    let mut text = String::with_capacity(32);
    for byte in uid {
        // Writing to a string cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The Detection Finding for `hit`, which `observed` of the event `event`
/// with the identifier `event_id` gave, made at `created` in milliseconds
/// since the epoch.
///
/// - `osint` holds one entry for each feed that asserts the indicator, and
///   `unmapped.assertions` the same without loss: the exact confidence and
///   the feed's version.
/// - `evidences` names the event, its class and time, and the attribute
///   that held the value.
/// - A hit an allowlist suppressed has the status Suppressed, the entry that
///   suppressed it in `status_detail` and `unmapped.allowed`, and is not an
///   alert.
///
/// The finding's time is the event's, so that it is stored and searched
/// beside it, whenever the indicator arrived.
pub fn finding(
    event_id: &str,
    event: &Value,
    observed: &Observed<'_>,
    hit: &Hit,
    created: i64,
) -> Value {
    let uid = finding_uid(event_id, &hit.indicator);
    let kind = hit.indicator.kind();
    let confidence = hit.confidence();
    let band = match confidence {
        90.. => 3,
        50.. => 2,
        _ => 1,
    };
    let (status_id, severity_id) = match (&hit.suppressed, band) {
        (Some(_), _) => (SUPPRESSED, 1),
        (None, band) => (NEW, band + 1),
    };

    let (osint, assertions) = provenance(hit);

    let mut unmapped = Map::new();
    unmapped.insert("indicator_kind".to_owned(), json!(kind.as_str()));
    unmapped.insert("assertions".to_owned(), Value::Array(assertions));

    let mut finding = json!({
        "class_uid": CLASS,
        "category_uid": CATEGORY,
        "activity_id": CREATE,
        "type_uid": u64::from(CLASS) * 100 + u64::from(CREATE),
        "time": event.get("time").cloned().unwrap_or(json!(created)),
        "severity_id": severity_id,
        "status_id": status_id,
        "confidence_id": band,
        "confidence_score": confidence,
        "is_alert": hit.suppressed.is_none(),
        "message": format!("An indicator names the {kind} {}", hit.indicator.value()),
        "metadata": {
            "version": goliath_ocsf::SCHEMA_VERSION,
            "uid": uid,
            "product": { "name": "Goliath", "vendor_name": "Goliath" },
        },
        "finding_info": {
            "uid": uid,
            "title": format!("Indicator match: {kind} {}", hit.indicator.value()),
            "created_time": created,
            "analytic": { "name": "Indicator match", "uid": "goliath-intel", "type_id": 99, "type": "Indicator match" },
            "data_sources": hit.assertions.iter().map(|assertion| assertion.feed.as_str()).collect::<Vec<_>>(),
        },
        "evidences": [{
            "uid": event_id,
            "name": observed.path,
            "data": {
                "class_uid": event.get("class_uid"),
                "time": event.get("time"),
                "value": observed.value,
            },
        }],
        "observables": [{
            "name": observed.path,
            "type_id": observable_type(observed.kind).to_id(),
            "value": observed.value,
        }],
        "osint": osint,
    });
    if let (Some(allowed), Some(members)) = (&hit.suppressed, finding.as_object_mut()) {
        members.insert(
            "status_detail".to_owned(),
            json!(format!(
                "Allowlist {} version {}, entry {}: {}",
                allowed.list, allowed.version, allowed.entry, allowed.reason
            )),
        );
        unmapped.insert(
            "allowed".to_owned(),
            json!({
                "list": allowed.list,
                "version": allowed.version,
                "entry": allowed.entry,
                "reason": allowed.reason,
            }),
        );
    }
    if let Some(members) = finding.as_object_mut() {
        members.insert("unmapped".to_owned(), Value::Object(unmapped));
    }
    finding
}

/// What each feed asserts of the hit's indicator, as OCSF `osint` entries
/// and, without loss, as plain members.
fn provenance(hit: &Hit) -> (Vec<Value>, Vec<Value>) {
    let kind = hit.indicator.kind();
    let osint: Vec<Value> = hit
        .assertions
        .iter()
        .map(|assertion| {
            let mut entry = Map::new();
            entry.insert("value".to_owned(), json!(hit.indicator.value()));
            entry.insert("type_id".to_owned(), json!(osint_type(kind)));
            entry.insert("vendor_name".to_owned(), json!(assertion.feed));
            entry.insert("uid".to_owned(), json!(assertion.version));
            entry.insert(
                "confidence_id".to_owned(),
                json!(match assertion.confidence {
                    90.. => 3,
                    50.. => 2,
                    _ => 1,
                }),
            );
            for (name, time) in [
                ("created_time", assertion.first_seen),
                ("modified_time", assertion.last_seen),
                ("expiration_time", assertion.valid_until),
            ] {
                if let Some(time) = time {
                    entry.insert(name.to_owned(), json!(time.saturating_mul(1000)));
                }
            }
            Value::Object(entry)
        })
        .collect();
    let assertions: Vec<Value> = hit
        .assertions
        .iter()
        .map(|assertion| {
            json!({
                "feed": assertion.feed,
                "version": assertion.version,
                "confidence": assertion.confidence,
                "valid_from": assertion.valid_from,
                "valid_until": assertion.valid_until,
                "first_seen": assertion.first_seen,
                "last_seen": assertion.last_seen,
            })
        })
        .collect();
    (osint, assertions)
}

/// The OCSF type of an OSINT indicator of `kind`.
fn osint_type(kind: Kind) -> u32 {
    match kind {
        Kind::Ip | Kind::Cidr => 1,
        Kind::Domain => 2,
        Kind::Md5 | Kind::Sha1 | Kind::Sha256 | Kind::Imphash => 4,
        Kind::Url => 5,
        Kind::CertificateHash | Kind::CertificateSubject => 7,
        Kind::Email => 9,
        Kind::FilePath | Kind::FileName => 11,
        Kind::RegistryKey => 12,
        _ => 99,
    }
}

/// The OCSF type of an observable of `kind`.
fn observable_type(kind: Kind) -> ObservableType {
    match kind {
        Kind::Ip => ObservableType::IpAddress,
        Kind::Cidr => ObservableType::Subnet,
        Kind::Domain => ObservableType::Hostname,
        Kind::Url => ObservableType::UrlString,
        Kind::Email => ObservableType::EmailAddress,
        Kind::User => ObservableType::UserName,
        Kind::FileName => ObservableType::FileName,
        Kind::FilePath => ObservableType::FilePath,
        Kind::RegistryKey => ObservableType::RegistryKeyPath,
        Kind::Md5
        | Kind::Sha1
        | Kind::Sha256
        | Kind::Imphash
        | Kind::CertificateHash
        | Kind::Ja3
        | Kind::Ja3s
        | Kind::Jarm => ObservableType::Hash,
        _ => ObservableType::Other,
    }
}
