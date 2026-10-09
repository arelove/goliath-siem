//! What the snapshot holds: records, and the identifiers they are found by.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use goliath_intel::{Key, Kind as Observable};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::EnrichError;

/// What a record describes.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A range of addresses: a subnet, a site's network, a zone.
    Network,
    /// A machine, or a resource of a cloud.
    Asset,
    /// A person, or an account that is not one.
    Identity,
    /// A group of identities or of assets.
    Group,
    /// A row of a context list: a value that is described, not accused.
    List,
}

impl Kind {
    /// The kind as an enrichment's `type` names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Asset => "asset",
            Self::Identity => "identity",
            Self::Group => "group",
            Self::List => "list",
        }
    }

    /// The typed fields a record of this kind can have. The names are those
    /// of OCSF's device, user, and group objects where it has one.
    pub fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Network => &["name", "zone", "region", "site"],
            Self::Asset => &[
                "name",
                "type",
                "owner",
                "org",
                "criticality",
                "is_managed",
                "zone",
                "region",
            ],
            Self::Identity => &[
                "name",
                "type",
                "org",
                "department",
                "manager",
                "criticality",
                "is_privileged",
                "is_enabled",
            ],
            Self::Group => &["name", "type", "is_privileged"],
            Self::List => &["label"],
        }
    }
}

/// What an identifier is a value of.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdKind {
    /// An IPv4 or IPv6 address.
    Address,
    /// A host name, short or qualified.
    Host,
    /// A MAC address.
    Mac,
    /// An identifier a product gives: an agent's, an instance's, a
    /// resource name, a SID, an object identifier of a directory.
    Uid,
    /// A user name, in any form a source writes it.
    User,
    /// An email address.
    Email,
    /// The name of a group.
    Group,
}

impl IdKind {
    /// The kind as an enrichment's `name` says what was looked up.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Address => "ip",
            Self::Host => "hostname",
            Self::Mac => "mac",
            Self::Uid => "uid",
            Self::User => "user",
            Self::Email => "email",
            Self::Group => "group",
        }
    }
}

/// An identifier in the one form it is compared in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id {
    kind: IdKind,
    value: String,
}

impl Id {
    /// The identifier of `kind` that `text` writes. Addresses, host names,
    /// user names, and email addresses take the canonical form indicators
    /// have, so a record and an event that write one name differently give
    /// one identifier.
    ///
    /// # Errors
    ///
    /// Returns [`EnrichError::Value`] if `text` is empty or cannot be of
    /// its kind.
    pub fn new(kind: IdKind, text: &str) -> Result<Self, EnrichError> {
        let text = text.trim();
        let refuse = |why: &str| EnrichError::Value {
            kind: kind.as_str(),
            value: text.to_owned(),
            why: why.to_owned(),
        };
        if text.is_empty() {
            return Err(refuse("it is empty"));
        }
        let through = |observable: Observable| {
            Key::new(observable, text)
                .map(|key| key.value().to_owned())
                .map_err(|error| refuse(&error.to_string()))
        };
        let value = match kind {
            IdKind::Address => through(Observable::Ip)?,
            IdKind::Host => through(Observable::Domain)?,
            IdKind::User => through(Observable::User)?,
            IdKind::Email => through(Observable::Email)?,
            IdKind::Mac => {
                let digits: String = text
                    .chars()
                    .filter(|character| !":-.".contains(*character))
                    .map(|character| character.to_ascii_lowercase())
                    .collect();
                if digits.len() != 12 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(refuse("it is not a MAC address"));
                }
                digits
            }
            // A product's identifier is compared as it is written; a SID
            // and an instance identifier differ by case in no product, but
            // some write them in either.
            IdKind::Uid | IdKind::Group => text.to_lowercase(),
        };
        Ok(Self { kind, value })
    }

    /// The identifier an observable of an event is looked up as, if context
    /// is kept for its kind.
    pub fn of(observable: Observable, text: &str) -> Option<Self> {
        let kind = match observable {
            Observable::Ip => IdKind::Address,
            Observable::Domain => IdKind::Host,
            Observable::User => IdKind::User,
            Observable::Email => IdKind::Email,
            _ => return None,
        };
        Self::new(kind, text).ok()
    }

    /// What it is a value of.
    pub fn kind(&self) -> IdKind {
        self.kind
    }

    /// The value, in canonical form.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The address, if this is one.
    pub(crate) fn address(&self) -> Option<IpAddr> {
        (self.kind == IdKind::Address)
            .then(|| self.value.parse().ok())
            .flatten()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.kind.as_str(), self.value)
    }
}

/// A range of addresses: its first address and the length of its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Range {
    pub(crate) network: IpAddr,
    pub(crate) length: u8,
}

impl Range {
    /// The range `text` writes, such as `10.20.0.0/16`. An address alone is
    /// the range of that one address.
    ///
    /// # Errors
    ///
    /// Returns [`EnrichError::Value`] if `text` is not a network.
    pub fn new(text: &str) -> Result<Self, EnrichError> {
        let text = text.trim();
        let refuse = || EnrichError::Value {
            kind: "range",
            value: text.to_owned(),
            why: "it is not a network, such as 10.20.0.0/16".to_owned(),
        };
        let (address, length) = match text.split_once('/') {
            Some((address, length)) => (address, Some(length)),
            None => (text, None),
        };
        let address: IpAddr = address.trim().parse().map_err(|_| refuse())?;
        let most = if address.is_ipv4() { 32 } else { 128 };
        let length = match length {
            Some(length) => length.trim().parse::<u8>().map_err(|_| refuse())?,
            None => most,
        };
        if length > most {
            return Err(refuse());
        }
        Ok(Self {
            network: masked(address, length),
            length,
        })
    }

    /// The range of `length` bits that holds `address`.
    pub(crate) fn holding(address: IpAddr, length: u8) -> Self {
        Self {
            network: masked(address, length),
            length,
        }
    }
}

impl fmt::Display for Range {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.length)
    }
}

/// `address` with every bit after the first `length` cleared.
fn masked(address: IpAddr, length: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let bits = u32::from(address);
            let mask = u32::MAX
                .checked_shl(32 - u32::from(length.min(32)))
                .unwrap_or(0);
            IpAddr::V4((bits & mask).into())
        }
        IpAddr::V6(address) => {
            let bits = u128::from(address);
            let mask = u128::MAX
                .checked_shl(128 - u32::from(length.min(128)))
                .unwrap_or(0);
            IpAddr::V6((bits & mask).into())
        }
    }
}

/// One thing a source knows: what it is found by, and what is said of it.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// What it describes.
    pub kind: Kind,
    /// Every identifier it is found by.
    pub ids: Vec<Id>,
    /// The ranges of addresses it is found by: a network's own, or those of
    /// a context list's row.
    pub ranges: Vec<Range>,
    /// The scope it is found within, such as a customer or a site; `None`
    /// for every scope.
    pub scope: Option<String>,
    /// From when it holds, in seconds since the epoch; `None` for always.
    pub valid_from: Option<i64>,
    /// Until when it holds, exclusive; `None` for without end.
    pub valid_until: Option<i64>,
    /// Its typed fields, by the names of [`Kind::fields`].
    pub fields: Map<String, Value>,
    /// The site's own names and values.
    pub labels: BTreeMap<String, String>,
    /// The groups it is a member of, as the source names them.
    pub groups: Vec<String>,
}

impl Record {
    /// A record of `kind` with nothing said of it yet.
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            ids: Vec::new(),
            ranges: Vec::new(),
            scope: None,
            valid_from: None,
            valid_until: None,
            fields: Map::new(),
            labels: BTreeMap::new(),
            groups: Vec::new(),
        }
    }

    /// Whether it is found for an event of `scope` at `at`.
    pub(crate) fn holds(&self, scope: Option<&str>, at: i64) -> bool {
        self.scope.as_deref().is_none_or(|own| Some(own) == scope)
            && self.valid_from.is_none_or(|from| from <= at)
            && self.valid_until.is_none_or(|until| at < until)
    }
}
