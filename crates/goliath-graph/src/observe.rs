//! What an event shows of the things it names: which identifiers it gives
//! as one thing, and which thing it shows acting on which.
//!
//! The things are found by the objects of the OCSF schema, a `user`, a
//! `device`, an endpoint, wherever a class holds one, and not by a list of
//! paths. Which class shows which link is the table in [`links`].

use std::collections::BTreeMap;

use goliath_ocsf::schema::{self, Attribute, Base};
use serde_json::{Map, Value};

use crate::identifier::{Form, Identifier, Kind, Strength};

/// Two identifiers an event gave as one thing: they were in one object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Claim {
    /// The strongest identifier of the object.
    pub one: Identifier,
    /// Another identifier of the same object.
    pub other: Identifier,
    /// What read them as one, such as `user` for a user object.
    pub rule: &'static str,
}

/// What one thing was seen to do to another.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LinkKind {
    /// An account signed in to a machine.
    LoggedOnTo,
    /// An account ran a program on a machine.
    RanOn,
    /// A machine ran or loaded a file.
    Ran,
    /// A machine wrote a file.
    Wrote,
    /// A machine, or an address, opened a connection to an address.
    ConnectedTo,
    /// A machine, or an address, asked for a domain.
    Resolved,
    /// A domain was answered with an address.
    ResolvedTo,
    /// A machine held an address.
    Held,
}

impl LinkKind {
    /// Every kind of link.
    pub const ALL: [Self; 8] = [
        Self::LoggedOnTo,
        Self::RanOn,
        Self::Ran,
        Self::Wrote,
        Self::ConnectedTo,
        Self::Resolved,
        Self::ResolvedTo,
        Self::Held,
    ];

    /// The kind as it is stored and asked for.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LoggedOnTo => "logged_on_to",
            Self::RanOn => "ran_on",
            Self::Ran => "ran",
            Self::Wrote => "wrote",
            Self::ConnectedTo => "connected_to",
            Self::Resolved => "resolved",
            Self::ResolvedTo => "resolved_to",
            Self::Held => "held",
        }
    }
}

/// One thing seen to act on another, each under the strongest identifier
/// the event gives it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Link {
    /// The one that acted.
    pub from: Identifier,
    /// What it did.
    pub kind: LinkKind,
    /// The one it was done to.
    pub to: Identifier,
}

/// What one event shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    /// Identifiers given as one thing, each pair once.
    pub claims: Vec<Claim>,
    /// Things seen to act on things, each link once.
    pub links: Vec<Link>,
}

/// A user, a machine, or an endpoint as one object of an event names it.
#[derive(Debug, Default)]
struct Thing {
    /// Its identifiers, the strongest first.
    ids: Vec<Identifier>,
    /// The address the object gives beside them.
    address: Option<Identifier>,
}

impl Thing {
    /// What a link is written under: the strongest identifier, or with
    /// none the address.
    fn end(&self) -> Option<&Identifier> {
        self.ids.first().or(self.address.as_ref())
    }

    /// The same, if the object names a thing of `kind`.
    fn of(&self, kind: Kind) -> Option<&Identifier> {
        self.ids.first().filter(|id| id.kind() == kind)
    }
}

/// What `event`, an OCSF event as JSON, shows. An event of a class the
/// schema does not have shows nothing.
///
/// - Every user, device, and endpoint object gives its identifiers, and a
///   claim from the strongest to each of the others.
/// - A name that is bare, or under a domain every machine has, and has no
///   strong identifier beside it, is an account of the event's device, and
///   another account on another.
/// - A machine and an address in one object are a link, `held`, and never
///   a claim: the address is another machine's tomorrow.
/// - What a source left under `unmapped` is not looked at.
pub fn observe(event: &Value) -> Seen {
    let Some(class) = event
        .get("class_uid")
        .and_then(Value::as_u64)
        .and_then(|uid| u32::try_from(uid).ok())
        .and_then(schema::class)
    else {
        return Seen::default();
    };
    let Some(members) = event.as_object() else {
        return Seen::default();
    };
    // The machine the event is of, for the accounts that are its own.
    let device = members
        .get("device")
        .and_then(Value::as_object)
        .and_then(|device| host(device).ids.into_iter().next());
    let mut walk = Walk {
        device,
        path: Vec::new(),
        things: BTreeMap::new(),
        seen: Seen::default(),
    };
    for (name, value) in members {
        if let Some(attribute) = class.attribute(name) {
            walk.attribute(attribute, value);
        }
    }
    let Walk {
        things, mut seen, ..
    } = walk;
    links(class.uid(), event, &things, &mut seen);
    seen
}

struct Walk {
    device: Option<Identifier>,
    path: Vec<&'static str>,
    /// The things found, by where they are, such as `actor.user`. A thing
    /// in a list is not kept: no link is read from one.
    things: BTreeMap<String, Thing>,
    seen: Seen,
}

impl Walk {
    fn attribute(&mut self, attribute: &'static Attribute, value: &Value) {
        self.path.push(attribute.name());
        match value {
            Value::Array(items) if attribute.is_array() => {
                for item in items {
                    self.value(attribute, item, true);
                }
            }
            _ => self.value(attribute, value, false),
        }
        self.path.pop();
    }

    fn value(&mut self, attribute: &'static Attribute, value: &Value, listed: bool) {
        let (Base::Object, Value::Object(members)) = (attribute.base(), value) else {
            return;
        };
        let Some(object) = attribute.object().filter(|object| !object.is_free_form()) else {
            return;
        };
        let thing = match object.name() {
            "user" => Some(("user", user(members, self.device.as_ref()))),
            "device" | "network_endpoint" | "endpoint" => Some(("host", host(members))),
            _ => None,
        };
        if let Some((rule, thing)) = thing {
            self.claim(rule, &thing);
            if !listed {
                self.things.insert(self.path.join("."), thing);
            }
        }
        for (name, member) in members {
            if let Some(attribute) = object.attribute(name) {
                self.attribute(attribute, member);
            }
        }
    }

    fn claim(&mut self, rule: &'static str, thing: &Thing) {
        if let Some((one, others)) = thing.ids.split_first() {
            for other in others {
                push(
                    &mut self.seen.claims,
                    Claim {
                        one: one.clone(),
                        other: other.clone(),
                        rule,
                    },
                );
            }
            if let Some(address) = &thing.address {
                push(
                    &mut self.seen.links,
                    Link {
                        from: one.clone(),
                        kind: LinkKind::Held,
                        to: address.clone(),
                    },
                );
            }
        }
    }
}

fn push<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

/// What sources write where they know no value.
const NOTHING: [&str; 9] = [
    "-",
    "?",
    "null",
    "(null)",
    "none",
    "(none)",
    "n/a",
    "unknown",
    "(unknown)",
];

/// The text of the member `name`, unless it is empty or says that the
/// source knew no value: `?` names no machine.
fn text<'a>(members: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    members
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .filter(|text| {
            !NOTHING
                .iter()
                .any(|nothing| text.eq_ignore_ascii_case(nothing))
        })
}

/// The SID of no account.
const NOBODY: &str = "s-1-0-0";

/// The identifiers of a user object, for an event of the machine `device`.
///
/// A well known SID, such as `S-1-5-18`, is kept as the weak identifier it
/// is and makes no account of the machine: Windows writes the system
/// account under the machine's own account of the domain, and an account
/// made of the SID would join that one to every machine it is seen on.
fn user(members: &Map<String, Value>, device: Option<&Identifier>) -> Thing {
    let mut ids = Vec::new();
    for name in ["uid", "uid_alt"] {
        let Some(uid) = text(members, name) else {
            continue;
        };
        if uid
            .get(..4)
            .is_some_and(|start| start.eq_ignore_ascii_case("s-1-"))
        {
            // `S-1-0-0` is nobody: Windows writes it where there is no
            // account, as for a sign in that failed.
            if let Ok(sid) = Identifier::new(Kind::User, Form::Sid, uid)
                && sid.value() != NOBODY
            {
                push(&mut ids, sid);
            }
        } else if !uid.bytes().all(|byte| byte.is_ascii_digit()) {
            // A number alone is a POSIX user identifier, which every
            // machine counts from the same start.
            if let Ok(uid) = Identifier::new(Kind::User, Form::Uid, uid) {
                push(&mut ids, uid);
            }
        }
    }
    if let Some(email) = text(members, "email_addr")
        && let Ok(email) = Identifier::new(Kind::User, Form::Email, email)
    {
        push(&mut ids, email);
    }
    if let Some(name) = text(members, "name") {
        let written = match text(members, "domain") {
            Some(domain) if !name.contains(['\\', '@']) => format!("{domain}\\{name}"),
            _ => name.to_owned(),
        };
        if let Ok(named) = Identifier::new(Kind::User, Form::Name, &written) {
            // `ws-7\adam` on ws-7 is an account of that machine, as a
            // bare name is.
            let of_device = device.is_some_and(|host| {
                named.value().split_once('\\').is_some_and(|(domain, _)| {
                    host.form() == Form::Name && host.value().split('.').next() == Some(domain)
                })
            });
            // A weak name beside a strong identifier is that account's
            // name, and names no account of the machine.
            let alone = !ids.iter().any(|id| id.strength() == Strength::Strong);
            if (of_device || (alone && named.strength() == Strength::Weak))
                && let Some(local) = device.and_then(|host| Identifier::local(host, &written).ok())
            {
                push(&mut ids, local);
            }
            if !of_device {
                push(&mut ids, named);
            }
        }
    }
    ids.sort_by_key(Identifier::rank);
    Thing { ids, address: None }
}

/// The identifiers of a device or an endpoint object, and its address.
fn host(members: &Map<String, Value>) -> Thing {
    let mut ids = Vec::new();
    let mut address =
        text(members, "ip").and_then(|ip| Identifier::new(Kind::Address, Form::Ip, ip).ok());
    if let Some(uid) = text(members, "uid")
        && let Ok(uid) = Identifier::new(Kind::Host, Form::Uid, uid)
    {
        push(&mut ids, uid);
    }
    if let Some(name) = text(members, "hostname").or_else(|| text(members, "name")) {
        if let Ok(written) = Identifier::new(Kind::Address, Form::Ip, name) {
            // Some sources write the address where the name goes.
            address.get_or_insert(written);
        } else {
            let qualified = match text(members, "domain") {
                Some(domain)
                    if !name.contains('.') && !domain.eq_ignore_ascii_case("workgroup") =>
                {
                    format!("{name}.{domain}")
                }
                _ => name.to_owned(),
            };
            if let Ok(named) = Identifier::new(Kind::Host, Form::Name, &qualified) {
                push(&mut ids, named);
            }
        }
    }
    if let Some(mac) = text(members, "mac")
        && let Ok(mac) = Identifier::new(Kind::Host, Form::Mac, mac)
    {
        push(&mut ids, mac);
    }
    ids.sort_by_key(Identifier::rank);
    Thing { ids, address }
}

/// The file an object at `pointer` is, by the longest hash it gives.
fn file(event: &Value, pointer: &str) -> Option<Identifier> {
    event
        .pointer(pointer)?
        .as_array()?
        .iter()
        .filter_map(|hash| hash.get("value").and_then(Value::as_str))
        .filter_map(|value| Identifier::new(Kind::File, Form::Hash, value).ok())
        .max_by_key(|hash| hash.value().len())
}

const AUTHENTICATION: u32 = 3002;
const PROCESS_ACTIVITY: u32 = 1007;
const MODULE_ACTIVITY: u32 = 1005;
const FILE_ACTIVITY: u32 = 1001;
const DNS_ACTIVITY: u32 = 4003;
/// The category of the classes that describe traffic.
const NETWORK: u64 = 4;
/// The activities of file system activity that write: Create and Update.
const WRITES: [u64; 2] = [1, 3];

/// The links an event of class `class` shows between the things found in
/// it. This is the table of which class shows which link; it is versioned
/// with the schema the classes are of.
fn links(class: u32, event: &Value, things: &BTreeMap<String, Thing>, seen: &mut Seen) {
    let thing = |path: &str| things.get(path);
    let machine = thing("device").and_then(|device| device.of(Kind::Host));
    let mut link = |from: Option<&Identifier>, kind: LinkKind, to: Option<&Identifier>| {
        if let (Some(from), Some(to)) = (from, to)
            && from != to
        {
            push(
                &mut seen.links,
                Link {
                    from: from.clone(),
                    kind,
                    to: to.clone(),
                },
            );
        }
    };
    match class {
        AUTHENTICATION => {
            let to = thing("dst_endpoint")
                .and_then(|end| end.of(Kind::Host))
                .or(machine);
            let who = thing("user").and_then(|user| user.of(Kind::User));
            link(who, LinkKind::LoggedOnTo, to);
        }
        PROCESS_ACTIVITY => {
            let who = ["actor.user", "process.user"]
                .into_iter()
                .find_map(|path| thing(path).and_then(|user| user.of(Kind::User)));
            link(who, LinkKind::RanOn, machine);
            let program = file(event, "/process/file/hashes");
            link(machine, LinkKind::Ran, program.as_ref());
        }
        MODULE_ACTIVITY => {
            let module = file(event, "/module/file/hashes");
            link(machine, LinkKind::Ran, module.as_ref());
        }
        FILE_ACTIVITY => {
            let writes = event
                .get("activity_id")
                .and_then(Value::as_u64)
                .is_some_and(|activity| WRITES.contains(&activity));
            if writes {
                let written = file(event, "/file/hashes");
                link(machine, LinkKind::Wrote, written.as_ref());
            }
        }
        _ => {}
    }
    if event.get("category_uid").and_then(Value::as_u64) != Some(NETWORK) {
        return;
    }
    // The one that opened the connection: the source if the event names
    // one, and the machine that reports otherwise.
    let from = thing("src_endpoint").and_then(Thing::end).or(machine);
    let to = thing("dst_endpoint").and_then(|end| end.address.as_ref());
    link(from, LinkKind::ConnectedTo, to);
    if class == DNS_ACTIVITY {
        let asked = event
            .pointer("/query/hostname")
            .and_then(Value::as_str)
            .and_then(|name| Identifier::new(Kind::Domain, Form::Name, name).ok());
        link(from, LinkKind::Resolved, asked.as_ref());
        let answers = event
            .get("answers")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for answer in answers {
            let address = answer
                .get("rdata")
                .and_then(Value::as_str)
                .and_then(|rdata| Identifier::new(Kind::Address, Form::Ip, rdata).ok());
            link(asked.as_ref(), LinkKind::ResolvedTo, address.as_ref());
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims(seen: &Seen) -> Vec<String> {
        seen.claims
            .iter()
            .map(|claim| format!("{} = {} ({})", claim.one, claim.other, claim.rule))
            .collect()
    }

    fn links(seen: &Seen) -> Vec<String> {
        seen.links
            .iter()
            .map(|link| format!("{} {} {}", link.from, link.kind.as_str(), link.to))
            .collect()
    }

    #[test]
    fn a_sign_in_claims_the_names_of_an_account_and_links_it_to_the_machine() {
        let seen = observe(&json!({
            "class_uid": 3002, "category_uid": 3, "activity_id": 1,
            "user": { "name": "adam", "domain": "CORP", "uid": "S-1-5-21-1-2-3-1104" },
            "device": { "hostname": "dc-1.corp.example", "ip": "10.0.0.5" },
            "src_endpoint": { "ip": "10.20.4.17" },
        }));
        assert_eq!(
            claims(&seen),
            ["user:sid:s-1-5-21-1-2-3-1104 = user:name:corp\\adam (user)"]
        );
        assert_eq!(
            links(&seen),
            [
                "host:name:dc-1.corp.example held address:ip:10.0.0.5",
                "user:sid:s-1-5-21-1-2-3-1104 logged_on_to host:name:dc-1.corp.example",
            ]
        );
    }

    #[test]
    fn a_name_every_machine_has_is_an_account_of_the_machine() {
        let event = |host: &str| {
            observe(&json!({
                "class_uid": 1007, "category_uid": 1, "activity_id": 1,
                "device": { "hostname": host },
                "actor": { "user": { "name": "NT AUTHORITY\\SYSTEM", "uid": "S-1-5-18" } },
                "process": { "file": { "hashes": [
                    { "algorithm_id": 1, "value": "0".repeat(32) },
                    { "algorithm_id": 3, "value": "ab".repeat(32) },
                ] } },
            }))
        };
        let seen = event("ws-7.corp.example");
        // The account is the machine's, and its weak names join nothing.
        assert_eq!(
            claims(&seen),
            [
                "user:local:ws-7.corp.example\\system = user:sid:s-1-5-18 (user)",
                "user:local:ws-7.corp.example\\system = user:name:nt authority\\system (user)",
            ]
        );
        assert_eq!(
            links(&seen),
            [
                "user:local:ws-7.corp.example\\system ran_on host:name:ws-7.corp.example",
                format!(
                    "host:name:ws-7.corp.example ran file:hash:{}",
                    "ab".repeat(32)
                )
                .as_str(),
            ]
        );
        // On another machine it is another account.
        let other = event("ws-8.corp.example");
        assert_ne!(other.links[0].from, seen.links[0].from);
    }

    #[test]
    fn a_well_known_sid_and_a_weak_name_join_no_two_accounts() {
        // Windows writes the system account under the machine's account of
        // the domain, on every machine.
        let system = |host: &str| {
            observe(&json!({
                "class_uid": 3002, "category_uid": 3, "activity_id": 1,
                "device": { "hostname": host },
                "user": { "name": "DC-01$", "domain": "CORP", "uid": "S-1-5-18" },
            }))
        };
        for host in ["dc-01.corp.example", "ws-7.corp.example"] {
            assert_eq!(
                claims(&system(host)),
                ["user:name:corp\\dc-01$ = user:sid:s-1-5-18 (user)"]
            );
        }
        // Nobody: a sign in that failed names the account and no SID.
        let failed = observe(&json!({
            "class_uid": 3002, "category_uid": 3, "activity_id": 1,
            "device": { "hostname": "dc-01.corp.example" },
            "user": { "name": "adam", "domain": "CORP", "uid": "S-1-0-0" },
        }));
        assert!(failed.claims.is_empty(), "{:?}", claims(&failed));
        // A bare name beside a SID of the domain is that account's name.
        let named = observe(&json!({
            "class_uid": 3002, "category_uid": 3, "activity_id": 1,
            "device": { "hostname": "dc-01.corp.example" },
            "user": { "name": "adam", "uid": "S-1-5-21-1-2-3-1107" },
        }));
        assert_eq!(
            claims(&named),
            ["user:sid:s-1-5-21-1-2-3-1107 = user:name:adam (user)"]
        );
    }

    #[test]
    fn an_account_named_under_its_machine_is_local_to_it() {
        let seen = observe(&json!({
            "class_uid": 3002, "category_uid": 3, "activity_id": 1,
            "user": { "name": "WS-7\\adam" },
            "device": { "hostname": "WS-7.corp.example" },
        }));
        assert!(seen.claims.is_empty());
        assert_eq!(
            links(&seen),
            ["user:local:ws-7.corp.example\\adam logged_on_to host:name:ws-7.corp.example"]
        );
    }

    #[test]
    fn a_number_alone_is_not_an_identifier_of_an_account() {
        let seen = observe(&json!({
            "class_uid": 1007, "category_uid": 1, "activity_id": 1,
            "device": { "hostname": "web-1" },
            "actor": { "user": { "name": "root", "uid": "0" } },
        }));
        assert_eq!(
            claims(&seen),
            ["user:local:web-1\\root = user:name:root (user)"]
        );
        assert_eq!(
            links(&seen),
            ["user:local:web-1\\root ran_on host:name:web-1"]
        );
    }

    #[test]
    fn a_connection_is_from_the_source_and_an_address_alone_is_an_end() {
        let seen = observe(&json!({
            "class_uid": 4001, "category_uid": 4, "activity_id": 1,
            "device": { "hostname": "WS-7" },
            "src_endpoint": { "hostname": "ws-7.corp.example", "ip": "10.20.4.17", "port": 51544 },
            "dst_endpoint": { "ip": "192.0.2.10", "port": 443 },
        }));
        assert_eq!(
            links(&seen),
            [
                "host:name:ws-7.corp.example held address:ip:10.20.4.17",
                "host:name:ws-7.corp.example connected_to address:ip:192.0.2.10",
            ]
        );
        // A sensor that sees addresses alone.
        let seen = observe(&json!({
            "class_uid": 4001, "category_uid": 4, "activity_id": 1,
            "src_endpoint": { "ip": "10.20.4.17" },
            "dst_endpoint": { "ip": "192.0.2.10" },
        }));
        assert_eq!(
            links(&seen),
            ["address:ip:10.20.4.17 connected_to address:ip:192.0.2.10"]
        );
    }

    #[test]
    fn a_query_links_the_asker_to_the_domain_and_the_domain_to_its_answers() {
        let seen = observe(&json!({
            "class_uid": 4003, "category_uid": 4, "activity_id": 2,
            "device": { "hostname": "ws-7.corp.example" },
            "query": { "hostname": "Example.COM." },
            "answers": [{ "rdata": "192.0.2.10" }, { "rdata": "alias.example.net" }],
        }));
        assert_eq!(
            links(&seen),
            [
                "host:name:ws-7.corp.example resolved domain:name:example.com",
                "domain:name:example.com resolved_to address:ip:192.0.2.10",
            ]
        );
    }

    #[test]
    fn a_machine_and_its_address_are_a_link_and_never_a_claim() {
        let seen = observe(&json!({
            "class_uid": 4001, "category_uid": 4, "activity_id": 1,
            "src_endpoint": {
                "hostname": "ws-7", "domain": "corp.example",
                "mac": "00:1A:2B:3C:4D:5E", "ip": "10.20.4.17", "uid": "agent-77",
            },
        }));
        assert_eq!(
            claims(&seen),
            [
                "host:uid:agent-77 = host:name:ws-7.corp.example (host)",
                "host:uid:agent-77 = host:mac:001a2b3c4d5e (host)",
            ]
        );
        assert_eq!(
            links(&seen),
            ["host:uid:agent-77 held address:ip:10.20.4.17"]
        );
        assert!(
            seen.claims
                .iter()
                .all(|claim| claim.other.kind() != Kind::Address)
        );
    }

    #[test]
    fn what_a_source_writes_for_no_value_names_nothing() {
        let seen = observe(&json!({
            "class_uid": 4001, "category_uid": 4, "activity_id": 1,
            "src_endpoint": { "hostname": "?", "ip": "198.51.100.7" },
            "dst_endpoint": { "hostname": "(null)", "ip": "192.0.2.10" },
            "actor": { "user": { "name": "-", "uid": "Unknown" } },
        }));
        assert!(seen.claims.is_empty(), "{:?}", claims(&seen));
        assert_eq!(
            links(&seen),
            ["address:ip:198.51.100.7 connected_to address:ip:192.0.2.10"]
        );
    }

    #[test]
    fn what_is_not_an_event_of_the_schema_shows_nothing() {
        assert_eq!(observe(&json!({ "class_uid": 999_999 })), Seen::default());
        assert_eq!(observe(&json!("text")), Seen::default());
        assert_eq!(
            observe(&json!({ "class_uid": 4001, "unmapped": { "user": { "name": "x\\y" } } })),
            Seen::default()
        );
    }
}
