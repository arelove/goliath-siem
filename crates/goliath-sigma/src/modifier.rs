//! Field modifiers.
//!
//! A detection map key carries the field name and, after `|`, the modifiers
//! that change how its value is matched:
//!
//! ```text
//! CommandLine|base64offset|contains
//! Image|endswith
//! DestinationIp|cidr
//! ProcessName|re|i
//! ```
//!
//! Order is significant. Transformations apply left to right, and the match
//! modifier applies to the result, so `base64offset|contains` encodes the value
//! and then looks for it anywhere in the field. Reversing them would compare an
//! encoded value against the raw field and silently never match.

use serde::{Deserialize, Serialize};

use crate::error::ModifierError;

/// Flags that change how a regular expression is interpreted.
///
/// Written as separate segments after `re`, as in `Field|re|i|m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct RegexFlags {
    /// `i` - match without regard to case.
    pub case_insensitive: bool,
    /// `m` - `^` and `$` match at line boundaries.
    pub multiline: bool,
    /// `s` - `.` also matches a newline.
    pub dot_all: bool,
}

/// What role a modifier plays in a field expression.
///
/// The distinction exists to catch contradictions: a field can be transformed
/// any number of times, but asking it to both start with and contain a value is
/// two different questions written as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModifierKind {
    /// Decides how the value is compared. At most one per field.
    Match,
    /// Rewrites the value before comparison. Any number, applied in order.
    Transform,
    /// Changes how a list of values combines. At most one per field.
    Connective,
    /// Changes what the value denotes. At most one per field.
    Interpretation,
}

/// A Sigma field modifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Modifier {
    /// `contains` - the value appears anywhere in the field.
    Contains,
    /// `startswith` - the field begins with the value.
    StartsWith,
    /// `endswith` - the field ends with the value.
    EndsWith,
    /// `re` - the value is a regular expression.
    Re(RegexFlags),
    /// `cidr` - the value is a network in CIDR notation.
    Cidr,
    /// `exists` - the value is a boolean asserting the field's presence.
    Exists,
    /// `lt` - the field is less than the value.
    Lt,
    /// `lte` - the field is less than or equal to the value.
    Lte,
    /// `gt` - the field is greater than the value.
    Gt,
    /// `gte` - the field is greater than or equal to the value.
    Gte,

    /// `base64` - compare against the base64 encoding of the value.
    Base64,
    /// `base64offset` - compare against the encodings of the value at each of
    /// the three byte alignments.
    ///
    /// Produces partial strings by construction, so it is only useful combined
    /// with [`Contains`](Modifier::Contains).
    Base64Offset,
    /// `utf16` - encode as UTF-16 with a byte order mark.
    Utf16,
    /// `utf16le`, and its alias `wide` - encode as little endian UTF-16.
    Utf16Le,
    /// `utf16be` - encode as big endian UTF-16.
    Utf16Be,
    /// `windash` - also match the other dash characters accepted as command
    /// line option prefixes.
    WinDash,

    /// `all` - every value in the list must match, instead of any.
    All,

    /// `cased` - compare with regard to case.
    Cased,
    /// `fieldref` - the value names another field to compare against.
    FieldRef,
    /// `expand` - the value contains `%placeholder%` markers to expand.
    Expand,
}

impl Modifier {
    /// Returns the role this modifier plays.
    pub fn kind(&self) -> ModifierKind {
        match self {
            Self::Contains
            | Self::StartsWith
            | Self::EndsWith
            | Self::Re(_)
            | Self::Cidr
            | Self::Exists
            | Self::Lt
            | Self::Lte
            | Self::Gt
            | Self::Gte => ModifierKind::Match,

            Self::Base64
            | Self::Base64Offset
            | Self::Utf16
            | Self::Utf16Le
            | Self::Utf16Be
            | Self::WinDash => ModifierKind::Transform,

            Self::All => ModifierKind::Connective,

            Self::Cased | Self::FieldRef | Self::Expand => ModifierKind::Interpretation,
        }
    }

    /// Returns the modifier as it is written in a rule.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Contains => "contains",
            Self::StartsWith => "startswith",
            Self::EndsWith => "endswith",
            Self::Re(_) => "re",
            Self::Cidr => "cidr",
            Self::Exists => "exists",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Base64 => "base64",
            Self::Base64Offset => "base64offset",
            Self::Utf16 => "utf16",
            Self::Utf16Le => "utf16le",
            Self::Utf16Be => "utf16be",
            Self::WinDash => "windash",
            Self::All => "all",
            Self::Cased => "cased",
            Self::FieldRef => "fieldref",
            Self::Expand => "expand",
        }
    }
}

/// A detection map key: a field name and the modifiers applied to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldKey {
    /// The field name, before the first `|`.
    pub field: String,
    /// The modifiers, in the order written.
    pub modifiers: Vec<Modifier>,
}

impl FieldKey {
    /// Returns the match modifier, if the key names one.
    ///
    /// Absent means equality, which is the Sigma default.
    pub fn match_modifier(&self) -> Option<&Modifier> {
        self.modifiers
            .iter()
            .find(|m| m.kind() == ModifierKind::Match)
    }

    /// Returns the transformations, in the order they apply.
    pub fn transforms(&self) -> impl Iterator<Item = &Modifier> {
        self.modifiers
            .iter()
            .filter(|m| m.kind() == ModifierKind::Transform)
    }

    /// Reports whether every value in a list must match, rather than any.
    pub fn requires_all(&self) -> bool {
        self.modifiers.contains(&Modifier::All)
    }

    /// Reports whether the key names no field, as in `'|all'`.
    ///
    /// Its values are then keywords searched in any field, and the modifiers
    /// apply to them.
    pub fn is_keyword(&self) -> bool {
        self.field.is_empty()
    }
}

/// Parses a detection map key into a field name and its modifiers.
///
/// An empty field name followed by modifiers, as in `'|all'`, is accepted and
/// means the values are keywords; see [`FieldKey::is_keyword`].
///
/// # Errors
///
/// Returns [`ModifierError`] if the key has neither a field nor a modifier, a
/// modifier is not recognized, a regex flag appears without a preceding `re`,
/// or two modifiers of the same exclusive role are combined.
///
/// # Examples
///
/// ```
/// use goliath_sigma::{Modifier, parse_field_key};
///
/// let key = parse_field_key("CommandLine|base64offset|contains")?;
/// assert_eq!(key.field, "CommandLine");
/// assert_eq!(key.modifiers, [Modifier::Base64Offset, Modifier::Contains]);
/// # Ok::<(), goliath_sigma::ModifierError>(())
/// ```
pub fn parse_field_key(key: &str) -> Result<FieldKey, ModifierError> {
    let mut segments = key.split('|');

    let field = segments.next().unwrap_or_default().trim();
    // `'|all'` has no field: its values are keywords, and the modifiers apply
    // to them. A key with neither a field nor a modifier means nothing.
    if field.is_empty() && !key.contains('|') {
        return Err(ModifierError::EmptyFieldName {
            key: key.to_owned(),
        });
    }

    let mut modifiers: Vec<Modifier> = Vec::new();

    for (index, segment) in segments.enumerate() {
        let name = segment.trim();

        // Regex flags are not modifiers in their own right: they qualify the
        // `re` that must precede them.
        if let Some(flag) = RegexFlag::parse(name) {
            let Some(Modifier::Re(flags)) = modifiers.last_mut() else {
                return Err(ModifierError::RegexFlagWithoutRe {
                    flag: name.to_owned(),
                    key: key.to_owned(),
                });
            };
            flag.apply(flags);
            continue;
        }

        let modifier = parse_modifier(name).ok_or_else(|| ModifierError::Unknown {
            modifier: name.to_owned(),
            position: index,
            key: key.to_owned(),
        })?;

        let kind = modifier.kind();
        if kind != ModifierKind::Transform
            && let Some(existing) = modifiers.iter().find(|m| m.kind() == kind)
        {
            return Err(ModifierError::Conflicting {
                first: existing.name().to_owned(),
                second: modifier.name().to_owned(),
                key: key.to_owned(),
            });
        }

        modifiers.push(modifier);
    }

    Ok(FieldKey {
        field: field.to_owned(),
        modifiers,
    })
}

/// A regex flag segment, valid only directly after `re`.
#[derive(Debug, Clone, Copy)]
enum RegexFlag {
    CaseInsensitive,
    Multiline,
    DotAll,
}

impl RegexFlag {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "i" => Some(Self::CaseInsensitive),
            "m" => Some(Self::Multiline),
            "s" => Some(Self::DotAll),
            _ => None,
        }
    }

    fn apply(self, flags: &mut RegexFlags) {
        match self {
            Self::CaseInsensitive => flags.case_insensitive = true,
            Self::Multiline => flags.multiline = true,
            Self::DotAll => flags.dot_all = true,
        }
    }
}

/// Maps a modifier name to its variant.
///
/// `wide` normalizes to [`Utf16Le`](Modifier::Utf16Le): the specification
/// defines it as an alias, and keeping both spellings would force every
/// consumer to handle two names for one behaviour.
fn parse_modifier(name: &str) -> Option<Modifier> {
    Some(match name {
        "contains" => Modifier::Contains,
        "startswith" => Modifier::StartsWith,
        "endswith" => Modifier::EndsWith,
        "re" => Modifier::Re(RegexFlags::default()),
        "cidr" => Modifier::Cidr,
        "exists" => Modifier::Exists,
        "lt" => Modifier::Lt,
        "lte" => Modifier::Lte,
        "gt" => Modifier::Gt,
        "gte" => Modifier::Gte,
        "base64" => Modifier::Base64,
        "base64offset" => Modifier::Base64Offset,
        "utf16" => Modifier::Utf16,
        "utf16le" | "wide" => Modifier::Utf16Le,
        "utf16be" => Modifier::Utf16Be,
        "windash" => Modifier::WinDash,
        "all" => Modifier::All,
        "cased" => Modifier::Cased,
        "fieldref" => Modifier::FieldRef,
        "expand" => Modifier::Expand,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_field_has_no_modifiers() {
        let key = parse_field_key("EventID").expect("parse");
        assert_eq!(key.field, "EventID");
        assert!(key.modifiers.is_empty());
        assert_eq!(key.match_modifier(), None, "absent means equality");
    }

    #[test]
    fn parses_a_single_modifier() {
        let key = parse_field_key("Image|endswith").expect("parse");
        assert_eq!(key.field, "Image");
        assert_eq!(key.match_modifier(), Some(&Modifier::EndsWith));
    }

    #[test]
    fn preserves_modifier_order() {
        // Order decides what is compared: encode, then search within.
        let key = parse_field_key("CommandLine|base64offset|contains").expect("parse");
        assert_eq!(key.modifiers, [Modifier::Base64Offset, Modifier::Contains]);

        let transforms: Vec<_> = key.transforms().collect();
        assert_eq!(transforms, [&Modifier::Base64Offset]);
    }

    #[test]
    fn chains_several_transformations() {
        let key = parse_field_key("CommandLine|utf16le|base64offset|contains").expect("parse");
        let transforms: Vec<_> = key.transforms().map(Modifier::name).collect();
        assert_eq!(transforms, ["utf16le", "base64offset"]);
    }

    #[test]
    fn wide_normalizes_to_utf16le() {
        let wide = parse_field_key("CommandLine|wide").expect("parse");
        let explicit = parse_field_key("CommandLine|utf16le").expect("parse");
        assert_eq!(wide.modifiers, explicit.modifiers);
    }

    #[test]
    fn regex_flags_attach_to_the_preceding_re() {
        let key = parse_field_key("ProcessName|re|i|s").expect("parse");
        assert_eq!(
            key.modifiers,
            [Modifier::Re(RegexFlags {
                case_insensitive: true,
                multiline: false,
                dot_all: true,
            })]
        );
    }

    #[test]
    fn a_regex_flag_without_re_is_rejected() {
        // `Field|i` would otherwise parse as an unknown modifier, which is a
        // less useful message than naming the missing `re`.
        let err = parse_field_key("ProcessName|i").expect_err("flag needs a preceding re");
        assert!(matches!(err, ModifierError::RegexFlagWithoutRe { .. }));
    }

    #[test]
    fn all_is_a_connective_not_a_match() {
        let key = parse_field_key("CommandLine|contains|all").expect("parse");
        assert!(key.requires_all());
        assert_eq!(key.match_modifier(), Some(&Modifier::Contains));
    }

    #[test]
    fn two_match_modifiers_conflict() {
        let err = parse_field_key("Image|startswith|endswith").expect_err("two match modifiers");

        let ModifierError::Conflicting { first, second, .. } = err else {
            panic!("expected a conflict");
        };
        assert_eq!(first, "startswith");
        assert_eq!(second, "endswith");
    }

    #[test]
    fn transformations_do_not_conflict_with_each_other() {
        parse_field_key("CommandLine|base64|utf16le|windash|contains")
            .expect("transforms may be chained freely");
    }

    #[test]
    fn rejects_an_unknown_modifier() {
        let err = parse_field_key("Image|endswidth").expect_err("typo must be caught");

        let ModifierError::Unknown {
            modifier, position, ..
        } = err
        else {
            panic!("expected an unknown modifier error");
        };
        assert_eq!(modifier, "endswidth");
        assert_eq!(position, 0, "position is the index among modifiers");
    }

    #[test]
    fn rejects_a_key_with_neither_field_nor_modifier() {
        assert!(matches!(
            parse_field_key(""),
            Err(ModifierError::EmptyFieldName { .. })
        ));
        assert!(matches!(
            parse_field_key("  "),
            Err(ModifierError::EmptyFieldName { .. })
        ));
    }

    #[test]
    fn a_key_without_a_field_applies_its_modifiers_to_keywords() {
        // As in SigmaHQ's `'|all': [...]`: every keyword must appear.
        let key = parse_field_key("|all").expect("parse");
        assert!(key.is_keyword());
        assert_eq!(key.modifiers, [Modifier::All]);
        assert!(
            !parse_field_key("CommandLine|all")
                .expect("parse")
                .is_keyword()
        );
    }

    #[test]
    fn comparison_modifiers_are_match_modifiers() {
        for name in ["lt", "lte", "gt", "gte"] {
            let key = parse_field_key(&format!("Value|{name}")).expect("parse");
            assert_eq!(key.match_modifier().map(Modifier::name), Some(name));
        }
    }
}
