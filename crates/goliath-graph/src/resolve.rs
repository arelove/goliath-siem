//! Resolution: which identifiers are one entity, decided from the claims
//! events made and from what people said, with the reason for each.
//!
//! See "How identifiers become an entity" in
//! `docs/adr/0025-entity-graph.md`. Nothing is merged in what was seen: the
//! result is a mapping, computed again from the evidence whenever it is
//! asked for, so a wrong answer is corrected by correcting its cause.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Deserialize;

use crate::identifier::{Identifier, IdentifierError, Strength};

/// Two identifiers seen as one thing, added up over the events that showed
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// One identifier.
    pub one: Identifier,
    /// The other.
    pub other: Identifier,
    /// What read them as one, such as `user`.
    pub rule: String,
    /// Events that showed it.
    pub events: u64,
    /// When it was first seen, in milliseconds since the epoch.
    pub first_seen: i64,
    /// When it was last seen.
    pub last_seen: i64,
}

/// What people said about identity, as a file: versioned, reviewed content
/// beside rules and allowlists.
///
/// ```yaml
/// name: identity
/// version: 2
/// decisions:
///   - same: ["user:name:corp\\adam", "user:email:a.smith@corp.example"]
///     reason: Renamed after marriage, HR ticket 4411
///   - different: ["user:email:helpdesk@corp.example", "user:sid:s-1-5-21-1-2-3-1107"]
///     reason: The helpdesk mailbox is shared
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decisions {
    /// The file's name, which a decision is reported with.
    pub name: String,
    /// The file's version.
    pub version: u32,
    /// What was decided.
    pub decisions: Vec<Decision>,
}

/// One thing a person decided, and why.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// Two identifiers that are one entity, whatever the events show.
    #[serde(default)]
    pub same: Option<[String; 2]>,
    /// Two identifiers that are not, whatever the events show.
    #[serde(default)]
    pub different: Option<[String; 2]>,
    /// Why. Required: a decision nobody can explain is removed by nobody.
    pub reason: String,
}

/// A decisions file that cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum DecisionsError {
    /// The YAML is malformed, or is not a decisions file.
    #[error(transparent)]
    Yaml(#[from] goliath_sigma::YamlError),
    /// A decision names something that is not an identifier.
    #[error("decision {index} of `{name}`: {error}")]
    Identifier {
        /// The file's name.
        name: String,
        /// The decision's place in the file, from 1.
        index: usize,
        /// What is wrong.
        error: IdentifierError,
    },
    /// A decision says both, or neither, or gives no reason.
    #[error("decision {index} of `{name}`: {why}")]
    Decision {
        /// The file's name.
        name: String,
        /// The decision's place in the file, from 1.
        index: usize,
        /// What is wrong.
        why: &'static str,
    },
}

/// What people said, read and checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Said {
    same: Vec<(Identifier, Identifier, String)>,
    different: BTreeSet<(Identifier, Identifier)>,
}

impl Decisions {
    /// Reads a file from YAML, as untrusted input.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionsError::Yaml`] if the YAML is malformed or is not
    /// a decisions file.
    pub fn from_yaml(source: &str) -> Result<Self, DecisionsError> {
        Ok(goliath_sigma::yaml::from_str(source)?)
    }
}

impl Said {
    /// What the files say together.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionsError`] for the first decision that names what is
    /// not an identifier, says both `same` and `different` or neither, or
    /// has no reason.
    pub fn new(files: &[Decisions]) -> Result<Self, DecisionsError> {
        let mut said = Self::default();
        for file in files {
            for (index, decision) in file.decisions.iter().enumerate() {
                let index = index + 1;
                let refuse = |why| DecisionsError::Decision {
                    name: file.name.clone(),
                    index,
                    why,
                };
                if decision.reason.trim().is_empty() {
                    return Err(refuse("it has no reason"));
                }
                let (pair, same) = match (&decision.same, &decision.different) {
                    (Some(pair), None) => (pair, true),
                    (None, Some(pair)) => (pair, false),
                    _ => return Err(refuse("it says one of `same` and `different`")),
                };
                let read = |text: &String| {
                    text.parse::<Identifier>()
                        .map_err(|error| DecisionsError::Identifier {
                            name: file.name.clone(),
                            index,
                            error,
                        })
                };
                let (one, other) = (read(&pair[0])?, read(&pair[1])?);
                if one == other {
                    return Err(refuse("it names one identifier twice"));
                }
                if same {
                    let by = format!(
                        "{} version {}: {}",
                        file.name, file.version, decision.reason
                    );
                    said.same.push((one, other, by));
                } else {
                    said.different.insert(ordered(one, other));
                }
            }
        }
        Ok(said)
    }
}

fn ordered(one: Identifier, other: Identifier) -> (Identifier, Identifier) {
    if one <= other {
        (one, other)
    } else {
        (other, one)
    }
}

/// How an identifier stands in a resolution.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Standing {
    /// It is one of the identifiers of its entity.
    Member,
    /// It is weak: it was seen with this entity, and may be seen with
    /// others.
    Alias,
    /// It was claimed with too many things to be evidence of any, and is
    /// an entity of its own.
    Shared,
}

impl Standing {
    /// The standing as it is stored.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Alias => "alias",
            Self::Shared => "shared",
        }
    }
}

/// One identifier's place in a resolution, and why it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The identifier.
    pub identifier: Identifier,
    /// The entity, as the strongest identifier it has.
    pub entity: Identifier,
    /// How the identifier stands in it.
    pub standing: Standing,
    /// The identifier it was seen as one thing with, which brought it in;
    /// `None` for the entity's own first identifier.
    pub with: Option<Identifier>,
    /// What says so: the rule that read the claim, or `said` for a
    /// person's word, with the word in `by`.
    pub rule: String,
    /// The file, its version, and the reason, for a person's word.
    pub by: Option<String>,
    /// Events that showed it.
    pub events: u64,
    /// When it was first seen, in milliseconds since the epoch.
    pub first_seen: i64,
    /// When it was last seen.
    pub last_seen: i64,
}

/// What a resolution found, counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Entities of more than one identifier.
    pub entities: u64,
    /// Identifiers that are members of those.
    pub members: u64,
    /// Weak identifiers attached to an entity, each attachment counted.
    pub aliases: u64,
    /// Identifiers set aside as shared.
    pub shared: u64,
    /// Claims of two strong identifiers not followed, since a person said
    /// the two sides are different.
    pub held_apart: u64,
}

/// Which identifiers are one entity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolution {
    /// Every identifier that is in an entity of more than one, is an alias
    /// of one, or is shared. An identifier that is not here is an entity of
    /// its own.
    pub resolved: Vec<Resolved>,
    /// The same, counted.
    pub summary: Summary,
}

/// How many strong identifiers of one form an identifier may be claimed
/// with and still be evidence, unless a caller says otherwise.
pub const SHARED_OVER: usize = 3;

/// Decides which identifiers are one entity, from `evidence` and from what
/// people `said`.
///
/// 1. Two strong identifiers in one claim are one entity. Nothing else
///    joins.
/// 2. An identifier claimed with more than `shared_over` strong identifiers
///    of one form is shared, and its claims join nothing: the mailbox of
///    forty accounts.
/// 3. A weak identifier joins nothing. It is an alias of each entity it was
///    claimed with.
/// 4. A person's word is last. `same` joins two identifiers with no claim.
///    `different` holds two apart: claims are followed from the most seen
///    to the least, and one that would bring the two into one entity is
///    not followed.
///
/// An entity is named by the strongest of its identifiers, by
/// [`Identifier::rank`] and then by its text, so that the name does not
/// depend on the order of the evidence.
pub fn resolve(evidence: &[Evidence], said: &Said, shared_over: usize) -> Resolution {
    let shared = shared(evidence, shared_over);
    let joins = |identifier: &Identifier| {
        identifier.strength() == Strength::Strong && !shared.contains(identifier)
    };

    let edges = edges(evidence, said, &joins);

    let mut groups = Groups::default();
    let mut joined: Vec<&Edge<'_>> = Vec::new();
    let mut summary = Summary::default();
    for edge in &edges {
        let (one, other) = (groups.of(edge.one), groups.of(edge.other));
        if one == other {
            continue;
        }
        if groups.apart(one, other, &said.different) {
            summary.held_apart += 1;
            continue;
        }
        groups.join(one, other);
        joined.push(edge);
    }

    // For each identifier, the first claim followed that names it.
    let mut brought: HashMap<&Identifier, usize> = HashMap::new();
    for (at, edge) in joined.iter().enumerate() {
        brought.entry(edge.one).or_insert(at);
        brought.entry(edge.other).or_insert(at);
    }

    let mut resolution = Resolution::default();
    let members = groups.members();
    // The name of each group: its strongest identifier.
    let mut named: HashMap<usize, &Identifier> = HashMap::new();
    for (group, identifiers) in &members {
        if let Some(first) = identifiers
            .iter()
            .min_by_key(|identifier| (identifier.rank(), identifier.to_string()))
        {
            named.insert(*group, first);
        }
    }
    let entity_of = |groups: &mut Groups<'_>, identifier: &Identifier| -> Option<Identifier> {
        let group = groups.find(identifier)?;
        named.get(&group).map(|name| (*name).clone())
    };

    for (group, identifiers) in &members {
        if identifiers.len() < 2 {
            continue;
        }
        summary.entities += 1;
        let Some(name) = named.get(group) else {
            continue;
        };
        for identifier in identifiers {
            summary.members += 1;
            // What brought it in: the first claim followed that names it.
            let through = brought.get(*identifier).map(|at| joined[*at]);
            let own = *identifier == *name;
            resolution.resolved.push(Resolved {
                identifier: (*identifier).clone(),
                entity: (*name).clone(),
                standing: Standing::Member,
                with: through.filter(|_| !own).map(|edge| {
                    if edge.one == *identifier {
                        edge.other.clone()
                    } else {
                        edge.one.clone()
                    }
                }),
                rule: through
                    .filter(|_| !own)
                    .map_or_else(String::new, |edge| edge.rule.to_owned()),
                by: through.filter(|_| !own).and_then(|edge| edge.by.cloned()),
                events: through.filter(|_| !own).map_or(0, |edge| edge.events),
                first_seen: through.filter(|_| !own).map_or(0, |edge| edge.first_seen),
                last_seen: through.filter(|_| !own).map_or(0, |edge| edge.last_seen),
            });
        }
    }
    for identifier in &shared {
        summary.shared += 1;
        resolution.resolved.push(Resolved {
            identifier: (*identifier).clone(),
            entity: (*identifier).clone(),
            standing: Standing::Shared,
            with: None,
            rule: String::new(),
            by: None,
            events: 0,
            first_seen: 0,
            last_seen: 0,
        });
    }
    let aliases = aliases(evidence, &joins, |strong| entity_of(&mut groups, strong));
    summary.aliases = aliases.len() as u64;
    resolution.resolved.extend(aliases.into_values());
    resolution.resolved.sort_by(|a, b| {
        (&a.entity, a.standing, &a.identifier).cmp(&(&b.entity, b.standing, &b.identifier))
    });
    resolution.summary = summary;
    resolution
}

/// The identifiers claimed with more than `over` strong identifiers of one
/// form: too many to be evidence of any.
fn shared(evidence: &[Evidence], over: usize) -> BTreeSet<&Identifier> {
    // What each identifier was claimed with, by the other's form.
    let mut partners: HashMap<&Identifier, BTreeMap<u8, BTreeSet<&Identifier>>> = HashMap::new();
    for claim in evidence {
        for (this, that) in [(&claim.one, &claim.other), (&claim.other, &claim.one)] {
            if that.strength() == Strength::Strong {
                partners
                    .entry(this)
                    .or_default()
                    .entry(that.form() as u8)
                    .or_default()
                    .insert(that);
            }
        }
    }
    partners
        .iter()
        .filter(|(_, by_form)| by_form.values().any(|with| with.len() > over))
        .map(|(identifier, _)| *identifier)
        .collect()
}

/// The claims that may join: a person's word first, then the claims of two
/// identifiers that both join, the most seen first.
fn edges<'a>(
    evidence: &'a [Evidence],
    said: &'a Said,
    joins: &impl Fn(&Identifier) -> bool,
) -> Vec<Edge<'a>> {
    let mut edges: Vec<Edge<'_>> = said
        .same
        .iter()
        .map(|(one, other, by)| Edge {
            one,
            other,
            rule: "said",
            by: Some(by),
            events: 0,
            first_seen: 0,
            last_seen: 0,
        })
        .collect();
    let mut claimed: Vec<Edge<'_>> = evidence
        .iter()
        .filter(|claim| claim.one != claim.other && joins(&claim.one) && joins(&claim.other))
        .map(|claim| Edge {
            one: &claim.one,
            other: &claim.other,
            rule: &claim.rule,
            by: None,
            events: claim.events,
            first_seen: claim.first_seen,
            last_seen: claim.last_seen,
        })
        .collect();
    claimed.sort_by(|a, b| {
        (b.events, a.one, a.other, a.rule).cmp(&(a.events, b.one, b.other, b.rule))
    });
    edges.extend(claimed);
    edges
}

/// Each weak identifier as an alias of each entity it was claimed with,
/// where `entity_of` names the entity a strong identifier is in.
fn aliases(
    evidence: &[Evidence],
    joins: &impl Fn(&Identifier) -> bool,
    mut entity_of: impl FnMut(&Identifier) -> Option<Identifier>,
) -> BTreeMap<(Identifier, Identifier), Resolved> {
    let mut aliases: BTreeMap<(Identifier, Identifier), Resolved> = BTreeMap::new();
    for claim in evidence {
        for (weak, strong) in [(&claim.one, &claim.other), (&claim.other, &claim.one)] {
            if weak.strength() != Strength::Weak || !joins(strong) {
                continue;
            }
            let entity = entity_of(strong).unwrap_or_else(|| strong.clone());
            aliases
                .entry((weak.clone(), entity.clone()))
                .and_modify(|alias| {
                    alias.events += claim.events;
                    alias.first_seen = alias.first_seen.min(claim.first_seen);
                    alias.last_seen = alias.last_seen.max(claim.last_seen);
                })
                .or_insert_with(|| Resolved {
                    identifier: weak.clone(),
                    entity,
                    standing: Standing::Alias,
                    with: Some(strong.clone()),
                    rule: claim.rule.clone(),
                    by: None,
                    events: claim.events,
                    first_seen: claim.first_seen,
                    last_seen: claim.last_seen,
                });
        }
    }
    aliases
}

/// A claim that may join two identifiers.
struct Edge<'a> {
    one: &'a Identifier,
    other: &'a Identifier,
    rule: &'a str,
    by: Option<&'a String>,
    events: u64,
    first_seen: i64,
    last_seen: i64,
}

/// Identifiers in groups that only grow: a union-find, with the members of
/// each group kept so that a join can be refused.
#[derive(Default)]
struct Groups<'a> {
    index: HashMap<&'a Identifier, usize>,
    parent: Vec<usize>,
    members: Vec<Vec<&'a Identifier>>,
}

impl<'a> Groups<'a> {
    /// The group `identifier` is in, a group of its own if it is new.
    fn of(&mut self, identifier: &'a Identifier) -> usize {
        let at = *self.index.entry(identifier).or_insert_with(|| {
            self.parent.push(self.parent.len());
            self.members.push(vec![identifier]);
            self.parent.len() - 1
        });
        self.root(at)
    }

    /// The group `identifier` is in, if it is in any.
    fn find(&mut self, identifier: &Identifier) -> Option<usize> {
        let at = *self.index.get(identifier)?;
        Some(self.root(at))
    }

    fn root(&mut self, mut at: usize) -> usize {
        while self.parent[at] != at {
            self.parent[at] = self.parent[self.parent[at]];
            at = self.parent[at];
        }
        at
    }

    /// Whether a person said that something in `one` is different from
    /// something in `other`.
    fn apart(
        &self,
        one: usize,
        other: usize,
        different: &BTreeSet<(Identifier, Identifier)>,
    ) -> bool {
        !different.is_empty()
            && different.iter().any(|(a, b)| {
                let holds = |group: usize, identifier: &Identifier| {
                    self.members[group].contains(&identifier)
                };
                (holds(one, a) && holds(other, b)) || (holds(one, b) && holds(other, a))
            })
    }

    fn join(&mut self, one: usize, other: usize) {
        // The smaller into the larger, so that members move seldom.
        let (from, into) = if self.members[one].len() < self.members[other].len() {
            (one, other)
        } else {
            (other, one)
        };
        self.parent[from] = into;
        let moved = std::mem::take(&mut self.members[from]);
        self.members[into].extend(moved);
    }

    /// Every group that holds anything, with what it holds.
    fn members(&self) -> BTreeMap<usize, Vec<&'a Identifier>> {
        self.members
            .iter()
            .enumerate()
            .filter(|(_, members)| !members.is_empty())
            .map(|(group, members)| (group, members.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(text: &str) -> Identifier {
        text.parse().unwrap()
    }

    fn claim(one: &str, other: &str, events: u64) -> Evidence {
        Evidence {
            one: id(one),
            other: id(other),
            rule: "user".to_owned(),
            events,
            first_seen: 1_000,
            last_seen: 2_000,
        }
    }

    fn said(yaml: &str) -> Said {
        Said::new(&[Decisions::from_yaml(yaml).unwrap()]).unwrap()
    }

    /// Each entity with what it holds, as text.
    fn entities(resolution: &Resolution) -> BTreeMap<String, Vec<String>> {
        let mut entities: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for resolved in &resolution.resolved {
            entities
                .entry(resolved.entity.to_string())
                .or_default()
                .push(format!(
                    "{} {}",
                    resolved.standing.as_str(),
                    resolved.identifier
                ));
        }
        entities
    }

    const SID: &str = "user:sid:s-1-5-21-1-2-3-1104";
    const NAME: &str = "user:name:corp\\adam";
    const UPN: &str = "user:name:adam@corp.example";
    const OID: &str = "user:uid:6f1c0d6e-0000-0000-0000-000000000001";

    #[test]
    fn one_person_under_the_names_of_three_sources_is_one_entity() {
        let resolution = resolve(
            &[
                claim(SID, NAME, 40),
                claim(OID, UPN, 9),
                claim(UPN, NAME, 2),
            ],
            &Said::default(),
            SHARED_OVER,
        );
        assert_eq!(
            entities(&resolution),
            BTreeMap::from([(
                SID.to_owned(),
                vec![
                    format!("member {SID}"),
                    format!("member {OID}"),
                    format!("member {UPN}"),
                    format!("member {NAME}"),
                ]
            )])
        );
        assert_eq!(
            resolution.summary,
            Summary {
                entities: 1,
                members: 4,
                ..Summary::default()
            }
        );
        // Every member but the entity's own name says what brought it in.
        let name = resolution
            .resolved
            .iter()
            .find(|resolved| resolved.identifier == id(NAME))
            .unwrap();
        assert_eq!(name.with, Some(id(SID)));
        assert_eq!((name.rule.as_str(), name.events), ("user", 40));
        let own = &resolution.resolved[0];
        assert_eq!((own.with.clone(), own.events), (None, 0));
    }

    #[test]
    fn a_weak_identifier_joins_nothing_and_is_an_alias_of_each() {
        // `adam` is the bare name of two accounts of two domains.
        let other = "user:sid:s-1-5-21-9-9-9-2001";
        let resolution = resolve(
            &[
                claim(SID, "user:name:adam", 5),
                claim(other, "user:name:adam", 3),
                claim(SID, "user:sid:s-1-5-18", 1),
            ],
            &Said::default(),
            SHARED_OVER,
        );
        assert_eq!(
            entities(&resolution),
            BTreeMap::from([
                (
                    SID.to_owned(),
                    vec![
                        "alias user:sid:s-1-5-18".to_owned(),
                        "alias user:name:adam".to_owned()
                    ]
                ),
                (other.to_owned(), vec!["alias user:name:adam".to_owned()]),
            ])
        );
        assert_eq!(resolution.summary.entities, 0);
        assert_eq!(resolution.summary.aliases, 3);
    }

    #[test]
    fn an_identifier_claimed_with_many_is_shared_and_joins_none() {
        // A mailbox that forty accounts list as their address.
        let mailbox = "user:email:helpdesk@corp.example";
        let mut evidence: Vec<Evidence> = (0..40)
            .map(|account| claim(&format!("user:sid:s-1-5-21-1-2-3-{account}"), mailbox, 2))
            .collect();
        evidence.push(claim(SID, NAME, 7));
        let resolution = resolve(&evidence, &Said::default(), SHARED_OVER);
        assert_eq!(
            entities(&resolution),
            BTreeMap::from([
                (
                    SID.to_owned(),
                    vec![format!("member {SID}"), format!("member {NAME}")]
                ),
                (mailbox.to_owned(), vec![format!("shared {mailbox}")]),
            ])
        );
        assert_eq!(resolution.summary.shared, 1);

        // Three accounts with one address are within the limit: a person's
        // own, an administrator's, and a third.
        let few: Vec<Evidence> = (0..3)
            .map(|account| claim(&format!("user:sid:s-1-5-21-1-2-3-{account}"), mailbox, 2))
            .collect();
        let resolution = resolve(&few, &Said::default(), SHARED_OVER);
        assert_eq!(
            (resolution.summary.entities, resolution.summary.members),
            (1, 4)
        );
    }

    #[test]
    fn a_persons_word_joins_what_no_event_shows_and_parts_what_events_join() {
        let old = "user:name:corp\\a.jones";
        let joined = resolve(
            &[claim(SID, NAME, 4)],
            &said(&format!(
                "name: identity\nversion: 2\ndecisions:\n  - same: ['{NAME}', '{old}']\n    reason: Renamed, ticket 4411\n"
            )),
            SHARED_OVER,
        );
        assert_eq!(joined.summary.members, 3);
        let renamed = joined
            .resolved
            .iter()
            .find(|resolved| resolved.identifier == id(old))
            .unwrap();
        assert_eq!(renamed.rule, "said");
        assert_eq!(
            renamed.by.as_deref(),
            Some("identity version 2: Renamed, ticket 4411")
        );

        // The events join the SID to the name through the address; a person
        // says that the name is not that account's.
        let evidence = [claim(SID, UPN, 9), claim(UPN, NAME, 2)];
        assert_eq!(
            resolve(&evidence, &Said::default(), SHARED_OVER)
                .summary
                .members,
            3
        );
        let parted = resolve(
            &evidence,
            &said(&format!(
                "name: identity\nversion: 3\ndecisions:\n  - different: ['{SID}', '{NAME}']\n    reason: Two people of one name\n"
            )),
            SHARED_OVER,
        );
        // The claim seen most is kept, and the one that would join the two
        // is not followed.
        assert_eq!(
            entities(&parted),
            BTreeMap::from([(
                SID.to_owned(),
                vec![format!("member {SID}"), format!("member {UPN}")]
            )])
        );
        assert_eq!(parted.summary.held_apart, 1);
    }

    #[test]
    fn the_answer_does_not_depend_on_the_order_of_the_evidence() {
        let mut evidence = vec![
            claim(SID, NAME, 4),
            claim(OID, UPN, 4),
            claim(UPN, NAME, 4),
            claim(SID, "user:name:adam", 1),
            claim("host:uid:agent-7", "host:name:ws-7.corp.example", 3),
        ];
        let first = resolve(&evidence, &Said::default(), SHARED_OVER);
        evidence.reverse();
        for claim in &mut evidence {
            std::mem::swap(&mut claim.one, &mut claim.other);
        }
        let second = resolve(&evidence, &Said::default(), SHARED_OVER);
        assert_eq!(entities(&first), entities(&second));
        assert_eq!(first.summary, second.summary);
        assert_eq!(first.summary.entities, 2);
    }

    #[test]
    fn a_decision_that_cannot_be_used_is_refused_with_its_place() {
        let read = |decisions: &str| {
            Said::new(&[Decisions::from_yaml(&format!(
                "name: identity\nversion: 1\ndecisions:\n{decisions}"
            ))
            .unwrap()])
            .unwrap_err()
            .to_string()
        };
        assert_eq!(
            read(&format!("  - same: ['{SID}', 'adam']\n    reason: x\n")),
            "decision 1 of `identity`: `adam` is not an identifier: it is written kind:form:value"
        );
        assert_eq!(
            read(&format!("  - same: ['{SID}', '{NAME}']\n    reason: ' '\n")),
            "decision 1 of `identity`: it has no reason"
        );
        assert_eq!(
            read(&format!(
                "  - same: ['{SID}', '{NAME}']\n    reason: x\n  - reason: y\n"
            )),
            "decision 2 of `identity`: it says one of `same` and `different`"
        );
        assert_eq!(
            read(&format!(
                "  - different: ['{SID}', '{SID}']\n    reason: x\n"
            )),
            "decision 1 of `identity`: it names one identifier twice"
        );
        assert!(Decisions::from_yaml("name: x\nversion: 1\nrules: []\n").is_err());
    }
}
