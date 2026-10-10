//! Identifiers: what an event or a record calls a thing, in the one form it
//! is compared in, and whether it names one thing without doubt.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// What a thing is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// An account: of a person, of a service, of a workload.
    User,
    /// A machine, or a resource of a cloud that acts as one.
    Host,
    /// An IP address.
    Address,
    /// A DNS name.
    Domain,
    /// A file's content.
    File,
}

impl Kind {
    /// The kind as an identifier's text begins.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Host => "host",
            Self::Address => "address",
            Self::Domain => "domain",
            Self::File => "file",
        }
    }
}

/// What an identifier is a value of.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Form {
    /// A Windows security identifier.
    Sid,
    /// An identifier a product or a directory gives: an object identifier,
    /// an agent's, an instance's.
    Uid,
    /// An email address.
    Email,
    /// A name: of an account, with its domain or without; of a host,
    /// qualified or short; of a domain.
    Name,
    /// An account of one host: the host's name and the account's, or its
    /// well known SID.
    Local,
    /// A MAC address.
    Mac,
    /// An IP address.
    Ip,
    /// A hash of a file's content.
    Hash,
}

impl Form {
    /// The form as an identifier's text names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sid => "sid",
            Self::Uid => "uid",
            Self::Email => "email",
            Self::Name => "name",
            Self::Local => "local",
            Self::Mac => "mac",
            Self::Ip => "ip",
            Self::Hash => "hash",
        }
    }
}

/// Whether an identifier names one thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Strength {
    /// It names one thing without doubt. Two strong identifiers seen as one
    /// thing are one entity.
    Strong,
    /// It names one thing only at times: a bare name, a short host name, a
    /// MAC. It joins nothing.
    Weak,
}

/// Text that is not an identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{text}` is not an identifier: {why}")]
pub struct IdentifierError {
    text: String,
    why: &'static str,
}

/// The domains of accounts that every Windows machine has, so that a name
/// under one of them is an account of the machine and not of a directory.
const AUTHORITIES: [&str; 8] = [
    "nt authority",
    "nt service",
    "builtin",
    "window manager",
    "font driver host",
    "iis apppool",
    "workgroup",
    ".",
];

/// An identifier in the one form it is compared in.
///
/// Its text is its kind, its form, and its value, such as
/// `user:sid:s-1-5-21-1-2-3-1104` or `host:name:ws-7.corp.example`, and an
/// entity is referred to by any identifier it has.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifier {
    kind: Kind,
    form: Form,
    value: String,
}

impl Identifier {
    /// The identifier of `kind` that `text` writes as a `form`.
    ///
    /// - Names, email addresses, SIDs, and products' identifiers are
    ///   lowercased: no system in use tells two of them apart by case.
    /// - An address is written as its type prints it, and an IPv4 address
    ///   mapped into IPv6 is the IPv4 address.
    /// - A MAC loses its separators, a host or a domain its final dot.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] if a `kind` has no such `form`, or
    /// `text` is empty or cannot be one: a SID that does not begin `S-1-`,
    /// a hash that is not hexadecimal.
    pub fn new(kind: Kind, form: Form, text: &str) -> Result<Self, IdentifierError> {
        let text = text.trim();
        let refuse = |why: &'static str| IdentifierError {
            text: text.chars().take(64).collect(),
            why,
        };
        if text.is_empty() {
            return Err(refuse("it is empty"));
        }
        if text.chars().any(char::is_control) {
            return Err(refuse("it holds a control character"));
        }
        let lower = text.to_lowercase();
        let value = match (kind, form) {
            (Kind::User, Form::Sid) => {
                if !lower.starts_with("s-1-") {
                    return Err(refuse("a SID begins S-1-"));
                }
                lower
            }
            (Kind::User, Form::Email) => {
                if !lower.contains('@') {
                    return Err(refuse("an email address has an @"));
                }
                lower
            }
            (Kind::User | Kind::Host, Form::Uid) | (Kind::User, Form::Name | Form::Local) => lower,
            (Kind::Host | Kind::Domain, Form::Name) => {
                let name = lower.strip_suffix('.').unwrap_or(&lower);
                if name.is_empty() || name.contains(char::is_whitespace) {
                    return Err(refuse("a name of a host has no space"));
                }
                name.to_owned()
            }
            (Kind::Host, Form::Mac) => {
                let digits: String = lower.chars().filter(|one| !":-.".contains(*one)).collect();
                if digits.len() != 12 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(refuse("it is not a MAC address"));
                }
                digits
            }
            (Kind::Address, Form::Ip) => address(text)
                .ok_or_else(|| refuse("it is not an address"))?
                .to_string(),
            (Kind::File, Form::Hash) => {
                let known = matches!(lower.len(), 32 | 40 | 64 | 128);
                if !known || !lower.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(refuse("it is not a hash"));
                }
                lower
            }
            _ => return Err(refuse("its kind has no such form")),
        };
        Ok(Self { kind, form, value })
    }

    /// The account `name` of the one host `host`: a bare name, or a well
    /// known SID, which every machine has and which is another account on
    /// each.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] if `host` is not a host or `name` is
    /// empty.
    pub fn local(host: &Self, name: &str) -> Result<Self, IdentifierError> {
        if host.kind != Kind::Host {
            return Err(IdentifierError {
                text: host.to_string(),
                why: "a local account is of a host",
            });
        }
        let bare = name.rsplit_once('\\').map_or(name, |(_, bare)| bare).trim();
        if bare.is_empty() {
            return Err(IdentifierError {
                text: name.chars().take(64).collect(),
                why: "it is empty",
            });
        }
        Self::new(Kind::User, Form::Local, &format!("{}\\{bare}", host.value))
    }

    /// What it is an identifier of.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// What it is a value of.
    pub fn form(&self) -> Form {
        self.form
    }

    /// The value, in its canonical form.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether it names one thing without doubt.
    ///
    /// - A SID is strong if a domain or a directory gave it, and weak if
    ///   it is well known, as `S-1-5-18` is.
    /// - A name of an account is strong with its domain, as `corp\adam`
    ///   and `adam@corp.example` are, and weak bare or under a domain every
    ///   machine has, as `nt authority\system` is.
    /// - A name of a host is strong qualified and weak short.
    /// - A MAC is weak: it is copied and made up.
    /// - An address, a domain, and a hash are their own value.
    pub fn strength(&self) -> Strength {
        let strong = match (self.kind, self.form) {
            (Kind::User, Form::Sid) => {
                self.value.starts_with("s-1-5-21-") || self.value.starts_with("s-1-12-1-")
            }
            (Kind::User, Form::Name) => match self.value.split_once('\\') {
                Some((domain, name)) => !name.is_empty() && !AUTHORITIES.contains(&domain),
                None => self
                    .value
                    .split_once('@')
                    .is_some_and(|(name, domain)| !name.is_empty() && !domain.is_empty()),
            },
            (Kind::Host, Form::Name) => self.value.contains('.'),
            (Kind::Host, Form::Mac) => false,
            _ => true,
        };
        if strong {
            Strength::Strong
        } else {
            Strength::Weak
        }
    }

    /// Where it stands among the identifiers of one thing, the lowest
    /// first: the one an entity is shown under, and a link written under.
    /// The order is fixed, so that learning a weaker identifier changes
    /// neither.
    pub fn rank(&self) -> u8 {
        let weak = u8::from(self.strength() == Strength::Weak) * 10;
        weak + match self.form {
            Form::Sid => 0,
            Form::Uid => 1,
            Form::Email => 2,
            Form::Name => 3,
            Form::Local => 4,
            Form::Mac => 5,
            Form::Ip | Form::Hash => 6,
        }
    }
}

/// The address `text` writes, an IPv4 address mapped into IPv6 as IPv4.
fn address(text: &str) -> Option<IpAddr> {
    match text.parse().ok()? {
        IpAddr::V6(six) => Some(six.to_ipv4_mapped().map_or(IpAddr::V6(six), IpAddr::V4)),
        four @ IpAddr::V4(_) => Some(four),
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.kind.as_str(),
            self.form.as_str(),
            self.value
        )
    }
}

impl FromStr for Identifier {
    type Err = IdentifierError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let refuse = |why: &'static str| IdentifierError {
            text: text.chars().take(64).collect(),
            why,
        };
        // The value may hold colons, as an IPv6 address does.
        let mut parts = text.splitn(3, ':');
        let (Some(kind), Some(form), Some(value)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(refuse("it is written kind:form:value"));
        };
        let kind = [
            Kind::User,
            Kind::Host,
            Kind::Address,
            Kind::Domain,
            Kind::File,
        ]
        .into_iter()
        .find(|one| one.as_str() == kind)
        .ok_or_else(|| refuse("its kind is not known"))?;
        let form = [
            Form::Sid,
            Form::Uid,
            Form::Email,
            Form::Name,
            Form::Local,
            Form::Mac,
            Form::Ip,
            Form::Hash,
        ]
        .into_iter()
        .find(|one| one.as_str() == form)
        .ok_or_else(|| refuse("its form is not known"))?;
        Self::new(kind, form, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(kind: Kind, form: Form, text: &str) -> Identifier {
        Identifier::new(kind, form, text).unwrap()
    }

    #[test]
    fn one_thing_written_two_ways_is_one_identifier() {
        assert_eq!(
            id(Kind::User, Form::Name, "CORP\\Adam"),
            id(Kind::User, Form::Name, " corp\\adam ")
        );
        assert_eq!(
            id(Kind::Host, Form::Name, "WS-7.Corp.Example."),
            id(Kind::Host, Form::Name, "ws-7.corp.example")
        );
        assert_eq!(
            id(Kind::Host, Form::Mac, "00-1A-2B-3C-4D-5E").value(),
            "001a2b3c4d5e"
        );
        assert_eq!(
            id(Kind::Address, Form::Ip, "::ffff:10.0.0.1").value(),
            "10.0.0.1"
        );
        assert_eq!(
            id(Kind::Address, Form::Ip, "2001:DB8::1").value(),
            "2001:db8::1"
        );
    }

    #[test]
    fn what_cannot_be_an_identifier_is_refused() {
        for (kind, form, text) in [
            (Kind::User, Form::Sid, "adam"),
            (Kind::User, Form::Email, "adam"),
            (Kind::User, Form::Name, "  "),
            (Kind::User, Form::Name, "a\u{0}b"),
            (Kind::Host, Form::Name, "two words"),
            (Kind::Host, Form::Mac, "00:1a:2b"),
            (Kind::Address, Form::Ip, "ws-7"),
            (Kind::File, Form::Hash, "abc"),
            (Kind::File, Form::Hash, &"g".repeat(64)),
            (Kind::Address, Form::Name, "10.0.0.1"),
            (Kind::Domain, Form::Sid, "s-1-5-18"),
        ] {
            assert!(Identifier::new(kind, form, text).is_err(), "{text}");
        }
    }

    #[test]
    fn strength_belongs_to_the_identifier() {
        use Strength::{Strong, Weak};
        for (kind, form, text, strength) in [
            (Kind::User, Form::Sid, "S-1-5-21-1-2-3-1104", Strong),
            (Kind::User, Form::Sid, "S-1-12-1-1-2-3-4", Strong),
            // Well known: the same on every machine.
            (Kind::User, Form::Sid, "S-1-5-18", Weak),
            (Kind::User, Form::Sid, "S-1-5-32-544", Weak),
            (
                Kind::User,
                Form::Uid,
                "6f1c0d6e-1111-2222-3333-444444444444",
                Strong,
            ),
            (Kind::User, Form::Email, "adam@corp.example", Strong),
            (Kind::User, Form::Name, "CORP\\adam", Strong),
            (Kind::User, Form::Name, "adam@corp.example", Strong),
            (Kind::User, Form::Name, "adam", Weak),
            (Kind::User, Form::Name, "NT AUTHORITY\\SYSTEM", Weak),
            (Kind::User, Form::Name, ".\\Administrator", Weak),
            (Kind::Host, Form::Uid, "i-0abc", Strong),
            (Kind::Host, Form::Name, "ws-7.corp.example", Strong),
            (Kind::Host, Form::Name, "WS-7", Weak),
            (Kind::Host, Form::Mac, "00:1a:2b:3c:4d:5e", Weak),
            (Kind::Address, Form::Ip, "10.0.0.1", Strong),
            (Kind::Domain, Form::Name, "example.com", Strong),
        ] {
            assert_eq!(id(kind, form, text).strength(), strength, "{text}");
        }
    }

    #[test]
    fn a_name_on_a_host_is_an_account_of_that_host() {
        let host = id(Kind::Host, Form::Name, "WS-7.corp.example");
        let local = Identifier::local(&host, "NT AUTHORITY\\SYSTEM").unwrap();
        assert_eq!(local.to_string(), "user:local:ws-7.corp.example\\system");
        assert_eq!(local.strength(), Strength::Strong);
        // The same name on another host is another account.
        let other = id(Kind::Host, Form::Name, "ws-8.corp.example");
        assert_ne!(Identifier::local(&other, "system").unwrap(), local);
        assert!(Identifier::local(&local, "x").is_err());
        assert!(Identifier::local(&host, "corp\\").is_err());
    }

    #[test]
    fn an_identifier_reads_back_from_its_text() {
        for one in [
            id(Kind::User, Form::Sid, "S-1-5-21-1-2-3-1104"),
            id(Kind::User, Form::Name, "corp\\adam"),
            id(Kind::Address, Form::Ip, "2001:db8::1"),
            id(Kind::File, Form::Hash, &"ab".repeat(32)),
        ] {
            assert_eq!(one.to_string().parse(), Ok(one));
        }
        for text in ["", "user", "user:sid", "thing:sid:s-1-5-18", "user:nope:x"] {
            assert!(text.parse::<Identifier>().is_err(), "{text}");
        }
    }

    #[test]
    fn the_strongest_identifier_of_a_thing_comes_first() {
        let mut several = [
            id(Kind::User, Form::Name, "adam"),
            id(Kind::User, Form::Name, "corp\\adam"),
            id(Kind::User, Form::Email, "adam@corp.example"),
            id(Kind::User, Form::Sid, "S-1-5-18"),
            id(Kind::User, Form::Sid, "S-1-5-21-1-2-3-1104"),
        ];
        several.sort_by_key(Identifier::rank);
        let forms: Vec<String> = several.iter().map(ToString::to_string).collect();
        assert_eq!(
            forms,
            [
                "user:sid:s-1-5-21-1-2-3-1104",
                "user:email:adam@corp.example",
                "user:name:corp\\adam",
                "user:sid:s-1-5-18",
                "user:name:adam",
            ]
        );
    }
}
