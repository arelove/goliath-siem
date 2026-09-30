//! Coverage against capability: for each technique, whether a rule detects
//! it, and whether the data that rule needs is collected. See
//! docs/adr/0009-attack-knowledge-model.md.

use std::collections::{BTreeMap, BTreeSet};

use crate::AttackError;
use crate::framework::{Framework, State};

/// A detection rule, as coverage sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRef {
    /// The rule's title, to name it in a report.
    pub title: String,
    /// The techniques it is tagged with, such as `T1059.001`.
    pub techniques: Vec<String>,
    /// Whether a configured source supplies the log source the rule reads,
    /// so that it can fire.
    pub collected: bool,
}

impl RuleRef {
    /// A rule named `title` with Sigma tags such as `attack.t1059.001`; tags
    /// of tactics, groups, and software are not techniques and are left out.
    /// `collected` says whether a configured source supplies its log source.
    pub fn from_sigma_tags(title: &str, tags: &[String], collected: bool) -> Self {
        Self {
            title: title.to_owned(),
            techniques: tags
                .iter()
                .filter_map(|tag| technique_of_tag(tag))
                .collect(),
            collected,
        }
    }
}

/// The technique a Sigma tag names, such as `T1059.001` for
/// `attack.t1059.001`.
pub fn technique_of_tag(tag: &str) -> Option<String> {
    let id = tag.strip_prefix("attack.")?;
    let (letter, rest) = id.split_at_checked(1)?;
    let (number, sub) = match rest.split_once('.') {
        Some((number, sub)) => (number, Some(sub)),
        None => (rest, None),
    };
    let digits = |text: &str, count: usize| {
        text.len() == count && text.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !letter.eq_ignore_ascii_case("t")
        || !digits(number, 4)
        || sub.is_some_and(|sub| !digits(sub, 3))
    {
        return None;
    }
    Some(id.to_ascii_uppercase())
}

/// What a technique's rules and collected data add up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// A rule detects it whose log source a configured source supplies.
    Detected,
    /// Rules detect it, but no configured source supplies the log source of
    /// any of them, so none can fire.
    Blind,
    /// No rule detects it, but data its detection strategies read is
    /// collected: a rule could be written.
    Collected,
    /// Neither.
    Uncovered,
}

/// One technique's coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniqueCoverage {
    /// The technique, such as `T1059.001`.
    pub technique: String,
    /// The titles of the rules tagged with it that can fire.
    pub rules: Vec<String>,
    /// The titles of the rules tagged with it whose log source no
    /// configured source supplies.
    pub blind_rules: Vec<String>,
    /// The data components its detection strategies read, by identifier.
    pub needs: BTreeSet<String>,
    /// Of those, the ones collected.
    pub collected: BTreeSet<String>,
    /// What they add up to.
    pub verdict: Verdict,
}

/// Why a rule's technique reference no longer counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Broken {
    /// The framework replaced the technique, with the one named if it says
    /// which.
    Revoked {
        /// The replacement, such as `T1059.001`.
        by: Option<String>,
    },
    /// The framework withdrew the technique.
    Deprecated,
    /// The framework has no such technique.
    Unknown,
}

/// A rule tagged with a technique that does not count toward coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokenReference {
    /// The rule's title.
    pub rule: String,
    /// The technique as tagged.
    pub technique: String,
    /// Why it does not count.
    pub why: Broken,
}

/// Coverage of every current technique of a framework version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// The framework version it was assessed against, such as `19.2`, which
    /// every coverage figure must state.
    pub version: String,
    /// Every current technique, by identifier.
    pub techniques: BTreeMap<String, TechniqueCoverage>,
    /// Rule references that did not count, reported as debt rather than
    /// silently dropped or remapped.
    pub broken: Vec<BrokenReference>,
}

impl Coverage {
    /// The techniques with a verdict.
    pub fn with(&self, verdict: Verdict) -> impl Iterator<Item = &TechniqueCoverage> {
        self.techniques
            .values()
            .filter(move |technique| technique.verdict == verdict)
    }
}

/// Assesses `rules` against the data components named in `collected`, such
/// as `Process Creation`, which the configured sources supply.
///
/// A technique is detected when a rule for it can fire, which each rule
/// says, and blind when it has rules and none can. Without a rule, it could
/// be detected when data read by at least one of its detection strategies
/// is collected. A rule tagged with a revoked, deprecated, or unknown
/// technique counts for nothing and is reported.
///
/// # Errors
///
/// Returns [`AttackError::UnknownDataComponent`] if a name in `collected`
/// is not a current data component of the framework, so that a misspelled
/// source declaration fails rather than reads as missing data.
pub fn assess(
    framework: &Framework,
    rules: &[RuleRef],
    collected: &[String],
) -> Result<Coverage, AttackError> {
    let collected: BTreeSet<String> = collected
        .iter()
        .map(|name| {
            framework
                .data_component_named(name)
                .map(|component| component.id.clone())
                .ok_or_else(|| AttackError::UnknownDataComponent {
                    name: name.clone(),
                    version: framework.version().to_owned(),
                })
        })
        .collect::<Result<_, _>>()?;

    let mut by_technique: BTreeMap<String, Vec<&RuleRef>> = BTreeMap::new();
    let mut broken = Vec::new();
    for rule in rules {
        for tagged in &rule.techniques {
            let why = match framework
                .technique(tagged)
                .map(|technique| &technique.state)
            {
                Some(State::Active) => None,
                Some(State::Revoked { by }) => Some(Broken::Revoked { by: by.clone() }),
                Some(State::Deprecated) => Some(Broken::Deprecated),
                None => Some(Broken::Unknown),
            };
            match why {
                None => by_technique
                    .entry(tagged.to_ascii_uppercase())
                    .or_default()
                    .push(rule),
                Some(why) => broken.push(BrokenReference {
                    rule: rule.title.clone(),
                    technique: tagged.clone(),
                    why,
                }),
            }
        }
    }

    let techniques = framework
        .techniques()
        .filter(|technique| technique.state == State::Active)
        .map(|technique| {
            let (firing, blind): (Vec<&RuleRef>, Vec<&RuleRef>) = by_technique
                .remove(&technique.id)
                .unwrap_or_default()
                .into_iter()
                .partition(|rule| rule.collected);
            let titles = |rules: Vec<&RuleRef>| -> Vec<String> {
                rules.into_iter().map(|rule| rule.title.clone()).collect()
            };
            let (rules, blind_rules) = (titles(firing), titles(blind));
            let observed: BTreeSet<String> = technique
                .data_components
                .intersection(&collected)
                .cloned()
                .collect();
            let verdict = if !rules.is_empty() {
                Verdict::Detected
            } else if !blind_rules.is_empty() {
                Verdict::Blind
            } else if !observed.is_empty() {
                Verdict::Collected
            } else {
                Verdict::Uncovered
            };
            (
                technique.id.clone(),
                TechniqueCoverage {
                    technique: technique.id.clone(),
                    rules,
                    blind_rules,
                    needs: technique.data_components.clone(),
                    collected: observed,
                    verdict,
                },
            )
        })
        .collect();

    Ok(Coverage {
        version: framework.version().to_owned(),
        techniques,
        broken,
    })
}
