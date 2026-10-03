//! The observables of an event: the values of its attributes that an
//! indicator could name, found by the type the OCSF schema gives each
//! attribute, not by a list of paths that could drift from the events.

use std::borrow::Cow;
use std::collections::HashSet;

use goliath_ocsf::schema::{self, Attribute, Base};
use serde_json::Value;

use crate::key::Kind;

/// A value of an event that an indicator could name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed<'a> {
    /// Where it is in the event, such as `dst_endpoint.ip` or
    /// `answers.0.rdata`.
    pub path: String,
    /// What it could be an indicator of.
    pub kind: Kind,
    /// The value, as the event holds it.
    pub value: Cow<'a, str>,
}

/// The observables of `event`, an OCSF event as JSON, each value once for
/// each kind, at the first place it is found. An event of a class the
/// schema does not have gives none.
///
/// What a source left under `unmapped` is not looked at: its members have
/// no type.
pub fn observables(event: &Value) -> Vec<Observed<'_>> {
    let Some(class) = event
        .get("class_uid")
        .and_then(Value::as_u64)
        .and_then(|uid| u32::try_from(uid).ok())
        .and_then(schema::class)
    else {
        return Vec::new();
    };
    let Some(members) = event.as_object() else {
        return Vec::new();
    };
    let mut walk = Walk {
        port: event.pointer("/dst_endpoint/port").and_then(Value::as_u64),
        ..Walk::default()
    };
    for (name, value) in members {
        if let Some(attribute) = class.attribute(name) {
            walk.attribute(attribute, value, None);
        }
    }
    walk.found
}

#[derive(Default)]
struct Walk<'a> {
    /// The names and indexes from the event to the value being visited.
    path: Vec<Cow<'static, str>>,
    seen: HashSet<(Kind, &'a str)>,
    found: Vec<Observed<'a>>,
    /// The port the event's connection goes to, for a URL written without
    /// one.
    port: Option<u64>,
}

impl<'a> Walk<'a> {
    /// Visits `value`, the `attribute` of `within`, the object that holds
    /// it.
    fn attribute(
        &mut self,
        attribute: &'static Attribute,
        value: &'a Value,
        within: Option<&'a Value>,
    ) {
        self.path.push(Cow::Borrowed(attribute.name()));
        match value {
            Value::Array(items) if attribute.is_array() => {
                for (index, item) in items.iter().enumerate() {
                    self.path.push(Cow::Owned(index.to_string()));
                    self.value(attribute, item, within);
                    self.path.pop();
                }
            }
            _ => self.value(attribute, value, within),
        }
        self.path.pop();
    }

    fn value(
        &mut self,
        attribute: &'static Attribute,
        value: &'a Value,
        within: Option<&'a Value>,
    ) {
        match (attribute.base(), value) {
            (Base::Object, Value::Object(members)) => {
                let Some(object) = attribute.object().filter(|object| !object.is_free_form())
                else {
                    return;
                };
                for (name, member) in members {
                    if let Some(attribute) = object.attribute(name) {
                        self.attribute(attribute, member, Some(value));
                    }
                }
                if object.name() == "url"
                    && !members.contains_key("url_string")
                    && let Some(url) = self.url(members)
                {
                    self.find(Kind::Url, Cow::Owned(url), None);
                }
            }
            (Base::String, Value::String(text)) => {
                if let Some(kind) = self.kind(attribute, text, within) {
                    self.find(kind, Cow::Borrowed(text.as_str()), Some(text.as_str()));
                }
            }
            (Base::Integer, Value::Number(number))
                if attribute.name() == "number" && self.under("autonomous_system") =>
            {
                self.find(Kind::Asn, Cow::Owned(number.to_string()), None);
            }
            _ => {}
        }
    }

    fn find(&mut self, kind: Kind, value: Cow<'a, str>, borrowed: Option<&'a str>) {
        if value.is_empty() || borrowed.is_some_and(|text| !self.seen.insert((kind, text))) {
            return;
        }
        self.found.push(Observed {
            path: self.path.join("."),
            kind,
            value,
        });
    }

    /// The URL of a `url` object that holds its parts and not the whole, as
    /// sources that log the host and the path of a request apart write it.
    /// The scheme is `http` unless the object says; the port is the
    /// object's, or else the one the event's connection goes to.
    fn url(&self, parts: &serde_json::Map<String, Value>) -> Option<String> {
        let text = |name: &str| parts.get(name).and_then(Value::as_str);
        let path = text("path").unwrap_or_default();
        // A request through a proxy names the whole URL as its path.
        if path.contains("://") {
            return Some(path.to_owned());
        }
        let host = text("hostname").filter(|host| !host.is_empty())?;
        let scheme = text("scheme").unwrap_or("http");
        let mut url = format!("{scheme}://");
        // An IPv6 address is bracketed in a URL.
        if host.contains(':') && !host.starts_with('[') {
            url.push('[');
            url.push_str(host);
            url.push(']');
        } else {
            url.push_str(host);
        }
        let port = parts.get("port").and_then(Value::as_u64).or(self.port);
        if let Some(port) = port {
            url.push(':');
            url.push_str(&port.to_string());
        }
        if !path.is_empty() && !path.starts_with('/') {
            url.push('/');
        }
        url.push_str(path);
        if let Some(query) = text("query_string").filter(|query| !query.is_empty()) {
            url.push('?');
            url.push_str(query);
        }
        Some(url)
    }

    /// Whether the value being visited is under an attribute named `name`.
    fn under(&self, name: &str) -> bool {
        self.path.iter().any(|segment| segment == name)
    }

    /// What the string `text` of `attribute` could be an indicator of.
    fn kind(&self, attribute: &Attribute, text: &str, within: Option<&Value>) -> Option<Kind> {
        Some(match attribute.type_name() {
            "ip_t" => Kind::Ip,
            "hostname_t" => Kind::Domain,
            "url_t" => Kind::Url,
            "email_t" => Kind::Email,
            "file_name_t" => Kind::FileName,
            "file_path_t" => Kind::FilePath,
            "reg_key_path_t" => Kind::RegistryKey,
            "username_t" => Kind::User,
            "file_hash_t" => {
                if self.under("ja3s_hash") {
                    Kind::Ja3s
                } else if self.under("ja3_hash") {
                    Kind::Ja3
                } else if self.under("certificate") || self.under("certificate_chain") {
                    Kind::CertificateHash
                } else {
                    hash(text, within)?
                }
            }
            // Two attributes the schema leaves as plain strings: the name a
            // TLS client asked for, and the data of a DNS answer, which is
            // an address for the record types that resolve a name.
            "string_t" if attribute.name() == "sni" && self.under("tls") => Kind::Domain,
            "string_t"
                if attribute.name() == "rdata" && text.parse::<std::net::IpAddr>().is_ok() =>
            {
                Kind::Ip
            }
            _ => return None,
        })
    }
}

/// Which hash a fingerprint holds: as its `algorithm_id` says, or else by
/// its length.
fn hash(text: &str, fingerprint: Option<&Value>) -> Option<Kind> {
    let named = fingerprint
        .and_then(|fingerprint| fingerprint.get("algorithm"))
        .and_then(Value::as_str);
    if named.is_some_and(|name| name.eq_ignore_ascii_case("imphash")) {
        return Some(Kind::Imphash);
    }
    let algorithm = fingerprint
        .and_then(|fingerprint| fingerprint.get("algorithm_id"))
        .and_then(Value::as_u64);
    match (algorithm, text.len()) {
        (Some(1), _) | (None | Some(0 | 99), 32) => Some(Kind::Md5),
        (Some(2), _) | (None | Some(0 | 99), 40) => Some(Kind::Sha1),
        (Some(3), _) | (None | Some(0 | 99), 64) => Some(Kind::Sha256),
        _ => None,
    }
}
