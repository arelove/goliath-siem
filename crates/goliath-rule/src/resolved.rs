//! The resolved form of a rule.
//!
//! Everything here refers to OCSF paths. Field names, modifiers, and
//! transformations of the source rule language are gone by the time a rule
//! reaches this form: `CommandLine|base64offset|contains` has become three
//! wildcard patterns over `process.cmd_line`. An execution path only has to
//! answer the questions in [`Test`].
//!
//! The enumerations here are deliberately not `#[non_exhaustive]`. Every
//! execution path must answer every question, so a new kind of test has to
//! stop an evaluator from compiling until it handles it, rather than fall into
//! a catch-all arm that answers `false` and misses a detection. Adding one is
//! a breaking change, and is released as one.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use goliath_sigma::{Pattern, RegexFlags};
use serde::{Deserialize, Serialize};

use crate::error::NetworkError;
use crate::mapping::ClassValue;
use crate::path::FieldPath;

/// A rule ready for evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedRule {
    /// The rule's title.
    pub title: String,
    /// The rule's identifier, if it has one.
    pub id: Option<String>,
    /// The mapping set that resolved it, recorded on every alert.
    pub mapping: MappingVersion,
    /// Attribute values an event must have for the rule to apply at all.
    pub class: BTreeMap<FieldPath, ClassValue>,
    /// What the rule detects.
    pub condition: Expr,
}

/// Which mapping set, at which version, resolved a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingVersion {
    /// The mapping set's name.
    pub name: String,
    /// Its version.
    pub version: u32,
}

/// A boolean expression over tests on an event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    /// Every operand holds. Empty holds.
    And(Vec<Expr>),
    /// At least one operand holds. Empty does not hold.
    Or(Vec<Expr>),
    /// The operand does not hold.
    Not(Box<Expr>),
    /// A test on the values some paths reach.
    Field(Predicate),
    /// A string test on any string value anywhere in the event.
    Keyword(StringTest),
}

impl Expr {
    /// Builds a conjunction, splicing in nested conjunctions and not wrapping
    /// a single operand.
    pub fn all(operands: Vec<Expr>) -> Self {
        let mut flat = Vec::with_capacity(operands.len());
        for operand in operands {
            match operand {
                Self::And(nested) => flat.extend(nested),
                other => flat.push(other),
            }
        }
        if flat.len() == 1 {
            flat.remove(0)
        } else {
            Self::And(flat)
        }
    }

    /// Builds a disjunction, splicing in nested disjunctions and not wrapping
    /// a single operand.
    pub fn any(operands: Vec<Expr>) -> Self {
        let mut flat = Vec::with_capacity(operands.len());
        for operand in operands {
            match operand {
                Self::Or(nested) => flat.extend(nested),
                other => flat.push(other),
            }
        }
        if flat.len() == 1 {
            flat.remove(0)
        } else {
            Self::Or(flat)
        }
    }
}

/// A test on the values reached by any of several paths.
///
/// The paths are alternatives for the same fact, so their values are pooled
/// before the test: a test that asks whether some value satisfies it holds if
/// any path reaches one that does, and [`Test::Exists`] and [`Test::Null`] ask
/// about the pool as a whole.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    /// Where to look.
    pub paths: Vec<FieldPath>,
    /// What to ask.
    pub test: Test,
}

/// A question about the values a predicate's paths reach.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Test {
    /// Some string value matches the pattern.
    String(StringTest),
    /// Some string value matches the regular expression.
    Regex {
        /// The expression, as written in the rule.
        pattern: String,
        /// Flags from the rule.
        flags: RegexFlags,
    },
    /// Some value is an IP address inside the network.
    Cidr(Network),
    /// Some non-null value exists, or, when `false`, none does.
    Exists(bool),
    /// No non-null value exists.
    Null,
    /// Some value equals the number, whether stored as a number or as its
    /// decimal text.
    Equals(Number),
    /// Some value is the boolean.
    Boolean(bool),
    /// Some numeric value compares to the number as stated.
    Compare {
        /// The comparison.
        op: Comparison,
        /// The right-hand side.
        value: Number,
    },
    /// Some value equals some value reached by another set of paths.
    FieldRef {
        /// The other field's paths.
        paths: Vec<FieldPath>,
        /// Whether case matters.
        cased: bool,
    },
}

/// A wildcard pattern and whether case matters.
///
/// When `cased` is false the pattern's literals are already folded with
/// [`fold`](fn@crate::fold), so an execution path folds the event value and
/// compares; it never folds the pattern again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringTest {
    /// The pattern.
    pub pattern: Pattern,
    /// Whether case matters.
    pub cased: bool,
}

/// A number from a rule.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Number {
    /// An integer.
    Integer(i64),
    /// A floating point number.
    Float(f64),
}

/// An ordering comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Comparison {
    /// `<`
    Less,
    /// `<=`
    LessOrEqual,
    /// `>`
    Greater,
    /// `>=`
    GreaterOrEqual,
}

/// An IP network: an address and a prefix length.
///
/// Deserialized from its text form through [`Network::parse`], so a prefix
/// longer than the address cannot be constructed from a stored rule either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    /// Parses `address` or `address/prefix`.
    ///
    /// Returns `None` if the address does not parse or the prefix is longer
    /// than the address.
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address.parse().ok()?;
        let max = Self::max_prefix(address);
        let prefix = match prefix {
            None => max,
            Some(prefix) => prefix.parse::<u8>().ok().filter(|&p| p <= max)?,
        };
        Some(Self { address, prefix })
    }

    fn max_prefix(address: IpAddr) -> u8 {
        match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    /// Reports whether `candidate` lies inside this network.
    ///
    /// An IPv4 address never lies inside an IPv6 network or the reverse,
    /// including IPv4-mapped IPv6 addresses; a rule author who wants both
    /// writes both.
    pub fn contains(&self, candidate: IpAddr) -> bool {
        let (network, candidate) = match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => (
                u128::from(network.to_bits()),
                u128::from(candidate.to_bits()),
            ),
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                (network.to_bits(), candidate.to_bits())
            }
            _ => return false,
        };
        let host_bits = u32::from(Self::max_prefix(self.address) - self.prefix);
        let shift = |bits: u128| bits.checked_shr(host_bits).unwrap_or(0);
        shift(network) == shift(candidate)
    }
}

impl TryFrom<String> for Network {
    type Error = NetworkError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text).ok_or(NetworkError(text))
    }
}

impl From<Network> for String {
    fn from(network: Network) -> Self {
        network.to_string()
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(text: &str) -> Network {
        Network::parse(text).expect("valid network")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid address")
    }

    #[test]
    fn parses_networks_and_single_addresses() {
        assert_eq!(network("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(network("10.1.2.3").to_string(), "10.1.2.3/32");
        assert_eq!(network("fe80::/10").to_string(), "fe80::/10");
        assert!(Network::parse("10.0.0.0/33").is_none());
        assert!(Network::parse("fe80::/129").is_none());
        assert!(Network::parse("10.0.0/8").is_none());
    }

    #[test]
    fn contains_addresses_inside_the_prefix() {
        let private = network("10.0.0.0/8");
        assert!(private.contains(ip("10.255.1.2")));
        assert!(!private.contains(ip("11.0.0.1")));

        let link_local = network("fe80::/10");
        assert!(link_local.contains(ip("fe80::1")));
        assert!(!link_local.contains(ip("2001:db8::1")));
    }

    #[test]
    fn edge_prefixes() {
        assert!(network("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(network("::/0").contains(ip("2001:db8::1")));
        assert!(network("192.0.2.7/32").contains(ip("192.0.2.7")));
        assert!(!network("192.0.2.7/32").contains(ip("192.0.2.8")));
    }

    #[test]
    fn address_families_never_mix() {
        assert!(!network("0.0.0.0/0").contains(ip("::ffff:10.0.0.1")));
        assert!(!network("::/0").contains(ip("10.0.0.1")));
    }

    #[test]
    fn deserializing_checks_the_prefix() {
        let parsed: Network = serde_json::from_str(r#""10.0.0.0/8""#).expect("valid");
        assert_eq!(parsed, network("10.0.0.0/8"));
        assert!(serde_json::from_str::<Network>(r#""10.0.0.0/200""#).is_err());
    }

    #[test]
    fn single_operands_are_not_wrapped() {
        let leaf = Expr::Keyword(StringTest {
            pattern: Pattern::parse("x"),
            cased: false,
        });
        assert_eq!(Expr::all(vec![leaf.clone()]), leaf);
        assert_eq!(Expr::any(vec![leaf.clone()]), leaf);
        assert_eq!(Expr::all(vec![]), Expr::And(vec![]));
    }

    #[test]
    fn nested_operators_of_the_same_kind_are_spliced() {
        let leaf = |text: &str| {
            Expr::Keyword(StringTest {
                pattern: Pattern::parse(text),
                cased: false,
            })
        };
        let nested = Expr::all(vec![
            Expr::And(vec![leaf("a"), leaf("b")]),
            Expr::Or(vec![leaf("c"), leaf("d")]),
        ]);
        assert_eq!(
            nested,
            Expr::And(vec![
                leaf("a"),
                leaf("b"),
                Expr::Or(vec![leaf("c"), leaf("d")])
            ])
        );
        // An empty nested conjunction holds, so splicing it away is exact.
        assert_eq!(Expr::all(vec![Expr::And(vec![]), leaf("a")]), leaf("a"));
    }
}
