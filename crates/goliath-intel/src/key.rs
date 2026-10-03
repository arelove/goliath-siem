//! What an indicator is of, and the one spelling its value is kept and
//! looked up in.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use crate::IntelError;

/// What an indicator is of: the classes of
/// `docs/adr/0008-threat-intelligence-model.md` that are compared for
/// equality. Fuzzy hashes such as ssdeep are compared for similarity and are
/// not indicators here.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// An IPv4 or IPv6 address.
    Ip,
    /// A network, such as `203.0.113.0/24`; an address inside it matches.
    Cidr,
    /// A domain name.
    Domain,
    /// A URL.
    Url,
    /// An autonomous system number.
    Asn,
    /// The MD5 of a file.
    Md5,
    /// The SHA-1 of a file.
    Sha1,
    /// The SHA-256 of a file.
    Sha256,
    /// The import hash of a portable executable.
    Imphash,
    /// The full path of a file.
    FilePath,
    /// The name of a file.
    FileName,
    /// A registry key.
    RegistryKey,
    /// A mutex.
    Mutex,
    /// A named pipe.
    NamedPipe,
    /// The name of a service.
    Service,
    /// An email address.
    Email,
    /// A user name.
    User,
    /// The subject of a certificate.
    CertificateSubject,
    /// The SHA-1 or SHA-256 of a certificate.
    CertificateHash,
    /// The JA3 fingerprint of a TLS client.
    Ja3,
    /// The JA3S fingerprint of a TLS server.
    Ja3s,
    /// The JARM fingerprint of a TLS server.
    Jarm,
}

impl Kind {
    /// Every kind, in the order of their tags.
    pub const ALL: [Self; 22] = [
        Self::Ip,
        Self::Cidr,
        Self::Domain,
        Self::Url,
        Self::Asn,
        Self::Md5,
        Self::Sha1,
        Self::Sha256,
        Self::Imphash,
        Self::FilePath,
        Self::FileName,
        Self::RegistryKey,
        Self::Mutex,
        Self::NamedPipe,
        Self::Service,
        Self::Email,
        Self::User,
        Self::CertificateSubject,
        Self::CertificateHash,
        Self::Ja3,
        Self::Ja3s,
        Self::Jarm,
    ];

    /// The name feeds and allowlists give it, such as `sha256`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Cidr => "cidr",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Asn => "asn",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Imphash => "imphash",
            Self::FilePath => "file-path",
            Self::FileName => "file-name",
            Self::RegistryKey => "registry-key",
            Self::Mutex => "mutex",
            Self::NamedPipe => "named-pipe",
            Self::Service => "service",
            Self::Email => "email",
            Self::User => "user",
            Self::CertificateSubject => "certificate-subject",
            Self::CertificateHash => "certificate-hash",
            Self::Ja3 => "ja3",
            Self::Ja3s => "ja3s",
            Self::Jarm => "jarm",
        }
    }

    /// The byte a stored key of this kind begins with. Never reused for
    /// another kind.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Ip => 1,
            Self::Cidr => 2,
            Self::Domain => 3,
            Self::Url => 4,
            Self::Asn => 5,
            Self::Md5 => 6,
            Self::Sha1 => 7,
            Self::Sha256 => 8,
            Self::Imphash => 9,
            Self::FilePath => 10,
            Self::FileName => 11,
            Self::RegistryKey => 12,
            Self::Mutex => 13,
            Self::NamedPipe => 14,
            Self::Service => 15,
            Self::Email => 16,
            Self::User => 17,
            Self::CertificateSubject => 18,
            Self::CertificateHash => 19,
            Self::Ja3 => 20,
            Self::Ja3s => 21,
            Self::Jarm => 22,
        }
    }

    /// The hexadecimal lengths a value of this kind may have, if it is a
    /// hash or a fingerprint.
    const fn hex_lengths(self) -> Option<&'static [usize]> {
        match self {
            Self::Md5 | Self::Imphash | Self::Ja3 | Self::Ja3s => Some(&[32]),
            Self::Sha1 => Some(&[40]),
            Self::Sha256 => Some(&[64]),
            Self::CertificateHash => Some(&[40, 64]),
            Self::Jarm => Some(&[62]),
            _ => None,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An indicator's kind and its value in canonical form: what is stored, and
/// what an observable is turned into before it is looked up, so that
/// `EXAMPLE.com.` in an event meets `example.com` in a feed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    kind: Kind,
    value: String,
}

impl Key {
    /// The key of `value` as a `kind`.
    ///
    /// - Addresses and networks are written as the standard library writes
    ///   them; an IPv4 address mapped into IPv6 is the IPv4 address; a
    ///   network loses its host bits, and one of a single address is that
    ///   address, an [`Kind::Ip`].
    /// - Domains, URL schemes and hosts, email addresses, hashes, and the
    ///   names Windows compares without case are lowercased.
    /// - The defanged spellings feeds use, `[.]` and `hxxp`, are undone.
    /// - A URL loses its fragment, and a domain its final dot.
    ///
    /// # Errors
    ///
    /// Returns [`IntelError::Value`] if `value` cannot be a `kind`: an
    /// address that does not parse, a hash of the wrong length, a domain
    /// with a space in it.
    pub fn new(kind: Kind, value: &str) -> Result<Self, IntelError> {
        let refuse = |why: &'static str| IntelError::Value {
            kind,
            value: value.to_owned(),
            why,
        };
        let text = value.trim();
        if text.is_empty() {
            return Err(refuse("it is empty"));
        }
        let (kind, value) = match kind {
            Kind::Ip => (
                kind,
                address(&text.replace("[.]", "."))
                    .ok_or_else(|| refuse("it is not an address"))?
                    .to_string(),
            ),
            Kind::Cidr => network(&text.replace("[.]", "."))
                .ok_or_else(|| refuse("it is not a network, such as 203.0.113.0/24"))?,
            Kind::Domain => (
                kind,
                domain(text).ok_or_else(|| refuse("it is not a domain name"))?,
            ),
            Kind::Url => (
                kind,
                url(text).ok_or_else(|| refuse("it is not a URL with a scheme and a host"))?,
            ),
            Kind::Asn => {
                let digits = text
                    .strip_prefix("AS")
                    .or_else(|| text.strip_prefix("as"))
                    .unwrap_or(text);
                let number: u32 = digits.parse().map_err(|_| refuse("it is not a number"))?;
                (kind, number.to_string())
            }
            _ => match kind.hex_lengths() {
                Some(lengths) => {
                    if !lengths.contains(&text.len()) {
                        return Err(refuse("it has the wrong length"));
                    }
                    if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return Err(refuse("it is not hexadecimal"));
                    }
                    (kind, text.to_ascii_lowercase())
                }
                None => (kind, text.to_lowercase()),
            },
        };
        Ok(Self { kind, value })
    }

    /// Its kind.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Its value, in canonical form.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The bytes it is stored under: the kind's tag, then the value.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.value.len());
        bytes.push(self.kind.tag());
        bytes.extend_from_slice(self.value.as_bytes());
        bytes
    }

    /// The address, if this is one.
    pub(crate) fn address(&self) -> Option<IpAddr> {
        (self.kind == Kind::Ip)
            .then(|| self.value.parse().ok())
            .flatten()
    }

    /// The host of a URL, as the key of a domain or of an address.
    pub(crate) fn host(&self) -> Option<Self> {
        if self.kind != Kind::Url {
            return None;
        }
        let (_, rest) = self.value.split_once("://")?;
        let authority = rest.split(['/', '?']).next()?;
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        if let Some(bracketed) = host.strip_prefix('[') {
            return Self::new(Kind::Ip, bracketed.split(']').next()?).ok();
        }
        let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
        Self::new(Kind::Ip, host)
            .or_else(|_| Self::new(Kind::Domain, host))
            .ok()
    }

    /// The network of `length` bits that holds `address`, as a key.
    pub(crate) fn network_of(address: IpAddr, length: u8) -> Self {
        Self {
            kind: Kind::Cidr,
            value: format!("{}/{length}", masked(address, length)),
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.kind, self.value)
    }
}

/// The prefix lengths of the networks in a set, so that an address is looked
/// up in a network of each length in use and no other. A network of a single
/// address is kept as the address, so IPv4 lengths are 0 to 31 and IPv6
/// lengths 0 to 127.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefixLengths {
    v4: u32,
    v6: u128,
}

impl PrefixLengths {
    /// Adds the length of `key`, if it is a network.
    pub fn add(&mut self, key: &Key) {
        if key.kind != Kind::Cidr {
            return;
        }
        let Some((network, length)) = key.value.split_once('/') else {
            return;
        };
        let Ok(length) = length.parse::<u8>() else {
            return;
        };
        if network.contains(':') {
            self.v6 |= 1u128.checked_shl(u32::from(length)).unwrap_or(0);
        } else {
            self.v4 |= 1u32.checked_shl(u32::from(length)).unwrap_or(0);
        }
    }

    /// The networks that could hold `address`, longest prefix first.
    pub(crate) fn networks(self, address: IpAddr) -> impl Iterator<Item = Key> {
        let (bits, count): (u128, u8) = match address {
            IpAddr::V4(_) => (u128::from(self.v4), 32),
            IpAddr::V6(_) => (self.v6, 128),
        };
        (0..count)
            .rev()
            .filter(move |length| bits >> length & 1 == 1)
            .map(move |length| Key::network_of(address, length))
    }
}

/// An address, with an IPv4 address mapped into IPv6 as the IPv4 address.
fn address(text: &str) -> Option<IpAddr> {
    let address: IpAddr = text.parse().ok()?;
    Some(match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    })
}

/// `address` with every bit after the first `length` cleared.
fn masked(address: IpAddr, length: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// A network without its host bits, or the address if it holds only one.
fn network(text: &str) -> Option<(Kind, String)> {
    let (network, length) = text.split_once('/')?;
    let network = address(network)?;
    let length: u8 = length.parse().ok()?;
    let full = if network.is_ipv4() { 32 } else { 128 };
    match length {
        length if length == full => Some((Kind::Ip, network.to_string())),
        length if length < full => {
            Some((Kind::Cidr, format!("{}/{length}", masked(network, length))))
        }
        _ => None,
    }
}

/// A domain name in lowercase, without its final dot.
fn domain(text: &str) -> Option<String> {
    let name = text.replace("[.]", ".").to_lowercase();
    let name = name.strip_suffix('.').unwrap_or(&name);
    let plausible = !name.is_empty()
        && !name.starts_with('.')
        && !name.contains("..")
        && !name
            .chars()
            .any(|character| character.is_whitespace() || "/:@?#".contains(character));
    plausible.then(|| name.to_owned())
}

/// A URL with its scheme and host in lowercase, and without its fragment.
fn url(text: &str) -> Option<String> {
    let text = text.replace("[.]", ".");
    let (scheme, rest) = text.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase().replace("hxxp", "http");
    if scheme.is_empty() || !scheme.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or_default();
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.is_empty() || authority.chars().any(char::is_whitespace) {
        return None;
    }
    Some(format!("{scheme}://{}{path}", authority.to_lowercase()))
}
