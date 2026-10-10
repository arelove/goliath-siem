//! Resolution measured on the generator's stream, against its truth.
//!
//! The generator knows which accounts and machines its events are about.
//! Its events are normalized by the shipped definitions, read as the graph
//! role reads them, and resolved; what was joined is then counted against
//! what is truly one entity. See "How it is measured" in
//! `docs/adr/0025-entity-graph.md`.
//!
//! `cargo test -p goliath-graph --test generated -- --nocapture` prints the
//! numbers.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use goliath_gen::{Generator, Options, Organization};
use goliath_graph::{
    Evidence, Form, Identifier, Kind, Measured, SHARED_OVER, Said, measure, observe, resolve,
};
use goliath_normalize::{Normalizer, Outcome};

/// Which entity each identifier the organization has is truly of.
///
/// An account is an entity: a person's administrative account is another
/// account, with its own SID, and is not to be joined to their own. Every
/// form an identifier may be read in is named; the measure counts only
/// those the events showed.
fn truth(org: &Organization) -> BTreeMap<Identifier, String> {
    let mut truth = BTreeMap::new();
    let mut name = |kind: Kind, form: Form, text: &str, entity: &str| {
        if let Ok(identifier) = Identifier::new(kind, form, text) {
            truth.insert(identifier, entity.to_owned());
        }
    };
    for user in &org.users {
        let account = format!("account {}", user.object_id);
        name(Kind::User, Form::Sid, &user.sid, &account);
        name(
            Kind::User,
            Form::Name,
            &format!("{}\\{}", org.netbios, user.sam),
            &account,
        );
        name(Kind::User, Form::Name, &user.upn, &account);
        name(Kind::User, Form::Email, &user.upn, &account);
        name(Kind::User, Form::Uid, &user.object_id, &account);
        if let (Some(sam), Some(sid)) = (&user.admin_sam, &user.admin_sid) {
            let admin = format!("admin account {}", user.object_id);
            name(Kind::User, Form::Sid, sid, &admin);
            name(
                Kind::User,
                Form::Name,
                &format!("{}\\{sam}", org.netbios),
                &admin,
            );
        }
    }
    for host in &org.hosts {
        let machine = format!("host {}", host.device_id);
        name(Kind::Host, Form::Name, &host.fqdn, &machine);
        name(Kind::Host, Form::Uid, &host.device_id, &machine);
    }
    truth
}

/// What `events` events of an organization of `users` people resolve to,
/// measured, and how many identifiers were seen.
fn measured(users: usize, events: usize) -> (Measured, usize) {
    let org = Organization::generate(&Options {
        users,
        ..Options::default()
    });
    let normalizers: HashMap<&str, Normalizer> = ["sysmon", "entra", "suricata"]
        .into_iter()
        .map(|source| {
            let definition = goliath_normalize::builtin(source).expect("a shipped definition");
            (source, Normalizer::from_yaml(definition).expect("it loads"))
        })
        .collect();
    let mut generator = Generator::new(&org, 7);
    // Two days, so that addresses change hands.
    let start = 1_790_244_000_000_i64;
    let step = 2 * 86_400_000 / i64::try_from(events).expect("a count of events");
    let mut seen: BTreeSet<Identifier> = BTreeSet::new();
    let mut claims: HashMap<(Identifier, Identifier, &'static str), u64> = HashMap::new();
    for index in 0..events {
        let time = start + i64::try_from(index).expect("a count of events") * step;
        let record = generator.next(time);
        let normalizer = normalizers.get(record.source).expect("a known source");
        normalizer.normalize(&record.bytes, |outcome| {
            let Outcome::Event(done) = outcome else {
                panic!("a generated record did not normalize: {outcome:?}");
            };
            let shown = observe(&done.event);
            for link in shown.links {
                seen.insert(link.from);
                seen.insert(link.to);
            }
            for claim in shown.claims {
                seen.insert(claim.one.clone());
                seen.insert(claim.other.clone());
                *claims
                    .entry((claim.one, claim.other, claim.rule))
                    .or_default() += 1;
            }
        });
    }
    let evidence: Vec<Evidence> = claims
        .into_iter()
        .map(|((one, other, rule), events)| Evidence {
            one,
            other,
            rule: rule.to_owned(),
            events,
            first_seen: 0,
            last_seen: 0,
        })
        .collect();
    let resolution = resolve(&evidence, &Said::default(), SHARED_OVER);
    (
        measure(&resolution.resolved, &seen, &truth(&org)),
        seen.len(),
    )
}

#[test]
fn what_is_joined_on_the_generators_stream_is_truly_one_entity() {
    let (measured, seen) = measured(300, 60_000);
    println!(
        "identifiers seen {seen}; pairs joined {}, right {}, truly one {}, unjudged {}",
        measured.joined, measured.right, measured.truly, measured.unjudged
    );
    println!(
        "precision {:?}, recall {:?}",
        measured.precision(),
        measured.recall()
    );
    for (one, other) in &measured.wrong {
        println!("wrong: {one} = {other}");
    }
    for (one, other) in measured.missed.iter().take(8) {
        println!("missed: {one} = {other}");
    }
    // The stream must hold something to be right about.
    assert!(measured.joined > 100, "{measured:?}");
    // The first target of ADR-0025 is the one that may not be missed.
    let precision = measured.precision().expect("pairs were joined");
    assert!(
        precision >= 0.999,
        "precision {precision}: {:?}",
        measured.wrong
    );
}
