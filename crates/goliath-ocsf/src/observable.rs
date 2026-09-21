//! Observables: the pivot points of an event.
//!
//! An observable is a value an analyst can pivot on and an indicator feed can
//! match against: an address, a hash, a user name. Extracting them is the input
//! to per-event indicator lookup, so this module is on the hot path and avoids
//! allocation wherever the borrow checker allows.

use serde::{Deserialize, Serialize};

/// An OCSF observable type identifier.
///
/// Values follow OCSF 1.5.0. The [`Unrecognized`](ObservableType::Unrecognized)
/// variant exists so that events produced against a newer schema deserialize
/// rather than fail: a type we do not know is still a value an analyst can see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObservableType {
    /// The type is not known to the producer.
    Unknown,
    /// A host name, including a fully qualified domain name.
    Hostname,
    /// An IP address, in either v4 or v6 notation.
    IpAddress,
    /// A hardware address.
    MacAddress,
    /// A principal name.
    UserName,
    /// An email address.
    EmailAddress,
    /// A URL in string form.
    UrlString,
    /// A file name without its path.
    FileName,
    /// A digest of file contents.
    Hash,
    /// A process name.
    ProcessName,
    /// An identifier of a cloud or platform resource.
    ResourceUid,
    /// A transport port number.
    Port,
    /// A network range in CIDR notation.
    Subnet,
    /// A full command line, including arguments.
    CommandLine,
    /// A country, by code or name.
    Country,
    /// An operating system process identifier.
    ProcessId,
    /// An HTTP `User-Agent` header value.
    HttpUserAgent,
    /// A Common Weakness Enumeration identifier.
    CweUid,
    /// A Common Vulnerabilities and Exposures identifier.
    CveUid,
    /// An identifier of a credential used to authenticate.
    UserCredentialId,
    /// An endpoint object.
    Endpoint,
    /// A user object.
    User,
    /// An email object.
    Email,
    /// A structured URL object.
    Url,
    /// A file object.
    File,
    /// A process object.
    Process,
    /// A geographic location object.
    GeoLocation,
    /// A container object.
    Container,
    /// A registry key object.
    RegistryKey,
    /// A registry value object.
    RegistryValue,
    /// A fingerprint object, such as JA3 or JARM.
    Fingerprint,
    /// The unique identifier of a user object.
    UserUid,
    /// The name of a group object.
    GroupName,
    /// The unique identifier of a group object.
    GroupUid,
    /// The name of an account object.
    AccountName,
    /// The unique identifier of an account object.
    AccountUid,
    /// The body of a script.
    ScriptContent,
    /// A hardware or certificate serial number.
    SerialNumber,
    /// The name of a resource details object.
    ResourceDetailsName,
    /// The unique identifier of a process entity object.
    ProcessEntityUid,
    /// The subject line of an email object.
    EmailSubject,
    /// The unique identifier of an email object.
    EmailUid,
    /// The unique identifier of a message.
    MessageUid,
    /// The name of a registry value object.
    RegistryValueName,
    /// The unique identifier of an advisory object.
    AdvisoryUid,
    /// A full path to a file.
    FilePath,
    /// A full path to a registry key.
    RegistryKeyPath,
    /// A type the schema defines as outside the enumerated set.
    Other,
    /// A type identifier introduced by a schema version newer than this build.
    Unrecognized(u32),
}

impl ObservableType {
    /// Returns the OCSF numeric identifier for this type.
    pub const fn to_id(self) -> u32 {
        match self {
            Self::Unknown => 0,
            Self::Hostname => 1,
            Self::IpAddress => 2,
            Self::MacAddress => 3,
            Self::UserName => 4,
            Self::EmailAddress => 5,
            Self::UrlString => 6,
            Self::FileName => 7,
            Self::Hash => 8,
            Self::ProcessName => 9,
            Self::ResourceUid => 10,
            Self::Port => 11,
            Self::Subnet => 12,
            Self::CommandLine => 13,
            Self::Country => 14,
            Self::ProcessId => 15,
            Self::HttpUserAgent => 16,
            Self::CweUid => 17,
            Self::CveUid => 18,
            Self::UserCredentialId => 19,
            Self::Endpoint => 20,
            Self::User => 21,
            Self::Email => 22,
            Self::Url => 23,
            Self::File => 24,
            Self::Process => 25,
            Self::GeoLocation => 26,
            Self::Container => 27,
            Self::RegistryKey => 28,
            Self::RegistryValue => 29,
            Self::Fingerprint => 30,
            Self::UserUid => 31,
            Self::GroupName => 32,
            Self::GroupUid => 33,
            Self::AccountName => 34,
            Self::AccountUid => 35,
            Self::ScriptContent => 36,
            Self::SerialNumber => 37,
            Self::ResourceDetailsName => 38,
            Self::ProcessEntityUid => 39,
            Self::EmailSubject => 40,
            Self::EmailUid => 41,
            Self::MessageUid => 42,
            Self::RegistryValueName => 43,
            Self::AdvisoryUid => 44,
            Self::FilePath => 45,
            Self::RegistryKeyPath => 46,
            Self::Other => 99,
            Self::Unrecognized(id) => id,
        }
    }

    /// Returns the type for an OCSF numeric identifier.
    ///
    /// Identifiers outside the known set map to
    /// [`Unrecognized`](ObservableType::Unrecognized) rather than failing, so
    /// that a newer schema does not break ingestion.
    pub const fn from_id(id: u32) -> Self {
        match id {
            0 => Self::Unknown,
            1 => Self::Hostname,
            2 => Self::IpAddress,
            3 => Self::MacAddress,
            4 => Self::UserName,
            5 => Self::EmailAddress,
            6 => Self::UrlString,
            7 => Self::FileName,
            8 => Self::Hash,
            9 => Self::ProcessName,
            10 => Self::ResourceUid,
            11 => Self::Port,
            12 => Self::Subnet,
            13 => Self::CommandLine,
            14 => Self::Country,
            15 => Self::ProcessId,
            16 => Self::HttpUserAgent,
            17 => Self::CweUid,
            18 => Self::CveUid,
            19 => Self::UserCredentialId,
            20 => Self::Endpoint,
            21 => Self::User,
            22 => Self::Email,
            23 => Self::Url,
            24 => Self::File,
            25 => Self::Process,
            26 => Self::GeoLocation,
            27 => Self::Container,
            28 => Self::RegistryKey,
            29 => Self::RegistryValue,
            30 => Self::Fingerprint,
            31 => Self::UserUid,
            32 => Self::GroupName,
            33 => Self::GroupUid,
            34 => Self::AccountName,
            35 => Self::AccountUid,
            36 => Self::ScriptContent,
            37 => Self::SerialNumber,
            38 => Self::ResourceDetailsName,
            39 => Self::ProcessEntityUid,
            40 => Self::EmailSubject,
            41 => Self::EmailUid,
            42 => Self::MessageUid,
            43 => Self::RegistryValueName,
            44 => Self::AdvisoryUid,
            45 => Self::FilePath,
            46 => Self::RegistryKeyPath,
            99 => Self::Other,
            other => Self::Unrecognized(other),
        }
    }

    /// Reports whether indicator feeds carry values of this type.
    ///
    /// Types that address structured objects rather than scalar values are not
    /// matchable, and the match engine skips them without a lookup. See
    /// ADR-0008.
    pub const fn is_matchable(self) -> bool {
        matches!(
            self,
            Self::Hostname
                | Self::IpAddress
                | Self::MacAddress
                | Self::UserName
                | Self::EmailAddress
                | Self::UrlString
                | Self::FileName
                | Self::Hash
                | Self::ProcessName
                | Self::Subnet
                | Self::CommandLine
                | Self::HttpUserAgent
                | Self::CveUid
                | Self::Fingerprint
                | Self::SerialNumber
                | Self::FilePath
                | Self::RegistryKeyPath
        )
    }
}

impl From<u32> for ObservableType {
    fn from(id: u32) -> Self {
        Self::from_id(id)
    }
}

impl From<ObservableType> for u32 {
    fn from(kind: ObservableType) -> Self {
        kind.to_id()
    }
}

impl Serialize for ObservableType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.to_id())
    }
}

impl<'de> Deserialize<'de> for ObservableType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u32::deserialize(deserializer).map(Self::from_id)
    }
}

/// A value an analyst can pivot on, extracted from an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observable {
    /// The path of the field this value came from, such as `actor.user.name`.
    ///
    /// Provenance within the event matters: the same string carries different
    /// weight as a source address than as a destination address.
    pub name: String,

    /// The kind of value.
    #[serde(rename = "type_id")]
    pub kind: ObservableType,

    /// The value itself, as it appeared in the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl Observable {
    /// Builds an observable from a field path, type, and value.
    pub fn new(name: impl Into<String>, kind: ObservableType, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind,
            value: Some(value.into()),
        }
    }

    /// Reports whether this observable should be looked up against indicators.
    ///
    /// An observable with no value carries no lookup key, and object types are
    /// not carried by feeds.
    pub fn is_matchable(&self) -> bool {
        self.kind.is_matchable() && self.value.as_ref().is_some_and(|v| !v.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_round_trip() {
        for id in (0..=46).chain(std::iter::once(99)) {
            let kind = ObservableType::from_id(id);
            assert_ne!(
                kind,
                ObservableType::Unrecognized(id),
                "id {id} is documented in OCSF 1.5.0 and must be mapped"
            );
            assert_eq!(kind.to_id(), id);
        }
    }

    #[test]
    fn unknown_ids_survive_round_trip() {
        // A schema newer than this build must not break ingestion.
        let future = ObservableType::from_id(4711);
        assert_eq!(future, ObservableType::Unrecognized(4711));
        assert_eq!(future.to_id(), 4711);
        assert!(!future.is_matchable());
    }

    #[test]
    fn serializes_as_the_numeric_id() {
        let json = serde_json::to_string(&ObservableType::Hash).expect("serialize");
        assert_eq!(json, "8");

        let parsed: ObservableType = serde_json::from_str("8").expect("deserialize");
        assert_eq!(parsed, ObservableType::Hash);
    }

    #[test]
    fn object_types_are_not_matchable() {
        assert!(!ObservableType::Endpoint.is_matchable());
        assert!(!ObservableType::User.is_matchable());
        assert!(ObservableType::IpAddress.is_matchable());
    }

    #[test]
    fn empty_value_is_not_matchable() {
        let empty = Observable::new("src_endpoint.ip", ObservableType::IpAddress, "");
        assert!(!empty.is_matchable());

        let present = Observable::new("src_endpoint.ip", ObservableType::IpAddress, "10.0.0.1");
        assert!(present.is_matchable());
    }
}
