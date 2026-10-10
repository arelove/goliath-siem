//! How right a resolution is, against a truth that is known.
//!
//! See "How it is measured" in `docs/adr/0025-entity-graph.md`. The measure
//! is over pairs of strong identifiers: precision is the share of joined
//! pairs that are truly one entity, and recall the share of true pairs that
//! were joined. They are reported apart and never as one number, and the
//! first is the one that may not be missed: a wrong merge shows a person
//! the acts of another.
//!
//! Weak identifiers are no part of it: resolution joins nothing by them, so
//! they are in no entity to be right or wrong about.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::identifier::{Identifier, Strength};
use crate::resolve::{Resolved, Standing};

/// What a resolution joined, counted against the truth.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Measured {
    /// Pairs of identifiers the resolution has in one entity, both known to
    /// the truth or one of them.
    pub joined: u64,
    /// Those of them that are truly one entity.
    pub right: u64,
    /// Pairs of identifiers that were seen and are truly one entity.
    pub truly: u64,
    /// Joined pairs the truth knows neither identifier of, which are
    /// counted as neither right nor wrong.
    pub unjudged: u64,
    /// Some of the pairs joined wrongly, to read.
    pub wrong: Vec<(Identifier, Identifier)>,
    /// Some of the true pairs not joined, to read.
    pub missed: Vec<(Identifier, Identifier)>,
}

/// Pairs kept to read of each kind of error.
const KEPT: usize = 20;

impl Measured {
    /// The share of joined pairs that are truly one entity; none if nothing
    /// was joined.
    #[allow(clippy::cast_precision_loss)] // Counts of pairs, far under 2^52.
    pub fn precision(&self) -> Option<f64> {
        (self.joined > 0).then(|| self.right as f64 / self.joined as f64)
    }

    /// The share of true pairs that were joined; none if the truth has no
    /// pair among what was seen.
    #[allow(clippy::cast_precision_loss)] // Counts of pairs, far under 2^52.
    pub fn recall(&self) -> Option<f64> {
        (self.truly > 0).then(|| self.right as f64 / self.truly as f64)
    }
}

fn pairs(count: usize) -> u64 {
    let count = count as u64;
    count * count.saturating_sub(1) / 2
}

/// Measures `resolved` against `truth`, which names the entity each
/// identifier truly is of. `seen` are the identifiers the events showed:
/// a true pair counts only if both were seen, since what no event showed
/// cannot be joined.
///
/// A joined pair of which the truth knows one identifier is wrong: what is
/// known was joined to something that is not it. A pair of which it knows
/// neither is unjudged.
pub fn measure(
    resolved: &[Resolved],
    seen: &BTreeSet<Identifier>,
    truth: &BTreeMap<Identifier, String>,
) -> Measured {
    let mut measured = Measured::default();
    let mut entity_of: HashMap<&Identifier, &Identifier> = HashMap::new();
    let mut groups: HashMap<&Identifier, Vec<&Identifier>> = HashMap::new();
    for one in resolved {
        if one.standing == Standing::Member && one.identifier.strength() == Strength::Strong {
            groups.entry(&one.entity).or_default().push(&one.identifier);
            entity_of.insert(&one.identifier, &one.entity);
        }
    }
    for members in groups.values() {
        let known = members
            .iter()
            .filter(|identifier| truth.contains_key(**identifier))
            .count();
        measured.unjudged += pairs(members.len() - known);
        measured.joined += pairs(members.len()) - pairs(members.len() - known);
        let mut of: HashMap<&str, usize> = HashMap::new();
        for identifier in members {
            if let Some(entity) = truth.get(*identifier) {
                *of.entry(entity.as_str()).or_default() += 1;
            }
        }
        measured.right += of.values().map(|count| pairs(*count)).sum::<u64>();
        if of.len() > 1 || known < members.len() {
            for (index, one) in members.iter().enumerate() {
                for other in &members[index + 1..] {
                    let same = match (truth.get(*one), truth.get(*other)) {
                        (None, None) => continue,
                        (one, other) => one == other,
                    };
                    if !same && measured.wrong.len() < KEPT {
                        measured.wrong.push(((*one).clone(), (*other).clone()));
                    }
                }
            }
        }
    }
    let mut truly: HashMap<&str, Vec<&Identifier>> = HashMap::new();
    for identifier in seen {
        if identifier.strength() != Strength::Strong {
            continue;
        }
        if let Some(entity) = truth.get(identifier) {
            truly.entry(entity.as_str()).or_default().push(identifier);
        }
    }
    for members in truly.values() {
        measured.truly += pairs(members.len());
        for (index, one) in members.iter().enumerate() {
            for other in &members[index + 1..] {
                let joined = match (entity_of.get(*one), entity_of.get(*other)) {
                    (Some(one), Some(other)) => one == other,
                    _ => false,
                };
                if !joined && measured.missed.len() < KEPT {
                    measured.missed.push(((*one).clone(), (*other).clone()));
                }
            }
        }
    }
    measured.wrong.sort();
    measured.missed.sort();
    measured
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::{Form, Kind};

    fn id(kind: Kind, form: Form, text: &str) -> Identifier {
        Identifier::new(kind, form, text).unwrap()
    }

    fn member(identifier: &Identifier, entity: &Identifier) -> Resolved {
        Resolved {
            identifier: identifier.clone(),
            entity: entity.clone(),
            standing: Standing::Member,
            with: None,
            rule: String::new(),
            by: None,
            events: 1,
            first_seen: 0,
            last_seen: 0,
        }
    }

    #[test]
    fn precision_and_recall_are_counted_over_pairs_and_apart() {
        let adam_sid = id(Kind::User, Form::Sid, "S-1-5-21-1-2-3-1104");
        let adam_name = id(Kind::User, Form::Name, "CORP\\adam");
        let adam_mail = id(Kind::User, Form::Email, "adam@corp.example");
        let eve_sid = id(Kind::User, Form::Sid, "S-1-5-21-1-2-3-1105");
        let eve_name = id(Kind::User, Form::Name, "CORP\\eve");
        let stranger = id(Kind::User, Form::Email, "who@elsewhere.example");
        let truth: BTreeMap<Identifier, String> = [
            (&adam_sid, "adam"),
            (&adam_name, "adam"),
            (&adam_mail, "adam"),
            (&eve_sid, "eve"),
            (&eve_name, "eve"),
        ]
        .into_iter()
        .map(|(identifier, entity)| (identifier.clone(), entity.to_owned()))
        .collect();
        let seen: BTreeSet<Identifier> = truth.keys().cloned().collect();

        // Adam's SID and name are joined, and Eve's name is joined to them
        // wrongly; Adam's email and Eve's SID are joined to nothing.
        let resolved = [
            member(&adam_sid, &adam_sid),
            member(&adam_name, &adam_sid),
            member(&eve_name, &adam_sid),
            member(&stranger, &stranger),
        ];
        let measured = measure(&resolved, &seen, &truth);
        // Three pairs joined, one right; four true pairs, one found.
        assert_eq!((measured.joined, measured.right, measured.truly), (3, 1, 4));
        assert_eq!(measured.precision(), Some(1.0 / 3.0));
        assert_eq!(measured.recall(), Some(0.25));
        assert_eq!(measured.wrong.len(), 2);
        assert_eq!(measured.missed.len(), 3);
        assert_eq!(measured.unjudged, 0);
    }

    #[test]
    fn what_the_truth_does_not_know_is_wrong_beside_what_it_knows() {
        let sid = id(Kind::User, Form::Sid, "S-1-5-21-1-2-3-1104");
        let name = id(Kind::User, Form::Name, "CORP\\adam");
        let stranger = id(Kind::User, Form::Email, "who@elsewhere.example");
        let other = id(Kind::User, Form::Email, "they@elsewhere.example");
        let truth: BTreeMap<Identifier, String> = [
            (sid.clone(), "adam".to_owned()),
            (name.clone(), "adam".to_owned()),
        ]
        .into();
        let seen: BTreeSet<Identifier> = truth.keys().cloned().collect();
        let resolved = [
            member(&sid, &sid),
            member(&name, &sid),
            member(&stranger, &sid),
            member(&other, &sid),
        ];
        let measured = measure(&resolved, &seen, &truth);
        // Six pairs: one right, four of a known with an unknown, and one of
        // two unknowns, which is not judged.
        assert_eq!(
            (measured.joined, measured.right, measured.unjudged),
            (5, 1, 1)
        );
        assert_eq!(measured.recall(), Some(1.0));
        // Nothing joined and nothing true is no number, not a perfect one.
        let nothing = measure(&[], &BTreeSet::new(), &truth);
        assert_eq!((nothing.precision(), nothing.recall()), (None, None));
    }
}
