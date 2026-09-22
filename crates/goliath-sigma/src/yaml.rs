//! Loading rule YAML as untrusted input.
//!
//! Every rule passes through [`from_str`], and nothing else in the crate calls
//! the YAML library directly, so the settings below apply to all of them. The
//! reasoning behind each setting is in `docs/adr/0011-untrusted-yaml.md`.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::error::YamlError;

/// The only deserialization settings rules are ever parsed with.
fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        // A duplicate key in a selection would silently drop a condition.
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        // Otherwise `NO` and `off` deserialize to `false`.
        strict_booleans: true,
        // Tags such as `!python/object` have no meaning in a rule.
        reject_unsupported_tags: true,
        // Location is reported separately; keep the message to one line.
        with_snippet: false,
    }
}

/// Deserializes untrusted YAML with the hardened settings.
pub(crate) fn from_str<T: DeserializeOwned>(source: &str) -> Result<T, YamlError> {
    serde_saphyr::from_str_with_options(source, options()).map_err(|error| {
        let location = error.location();
        YamlError {
            message: error.to_string(),
            line: location.as_ref().map(serde_saphyr::Location::line),
            column: location.as_ref().map(serde_saphyr::Location::column),
        }
    })
}

/// A YAML value with its type preserved exactly as written.
///
/// Rules are deserialized into this before interpretation, so that the
/// difference between `123` and `'123'`, or between `null` and `'null'`, is
/// decided by the YAML and not guessed later.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub(crate) enum RawValue {
    Null(()),
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
    List(Vec<RawValue>),
    Map(BTreeMap<String, RawValue>),
}

impl RawValue {
    /// Names the kind of value, for error messages.
    pub(crate) fn describe(&self) -> &'static str {
        match self {
            Self::Null(()) => "null",
            Self::Boolean(_) => "a boolean",
            Self::Integer(_) => "an integer",
            Self::Float(_) => "a number",
            Self::String(_) => "a string",
            Self::List(_) => "a list",
            Self::Map(_) => "a mapping",
        }
    }
}

#[cfg(test)]
mod tests {
    //! These pin the behaviour ADR-0011 relies on. If an upgrade of the YAML
    //! library changes any of it, a test here fails before a rule misbehaves.

    use std::fmt::Write as _;

    use super::*;

    type Doc = BTreeMap<String, RawValue>;

    #[test]
    fn rejects_duplicate_keys_with_their_location() {
        let err = from_str::<Doc>("a: 1\nb: 2\na: 3\n").expect_err("duplicate key");
        assert_eq!(err.line, Some(3));
        assert_eq!(err.column, Some(1));
    }

    #[test]
    fn rejects_duplicate_keys_in_nested_mappings() {
        // The case that matters: a repeated field inside a selection.
        let source = "detection:\n  selection:\n    Image: a.exe\n    Image: b.exe\n";
        let err = from_str::<Doc>(source).expect_err("duplicate nested key");
        assert_eq!(err.line, Some(4));
    }

    #[test]
    fn yaml_1_1_booleans_stay_strings() {
        let doc: Doc = from_str("country: NO\nflag: off\nanswer: yes\n").expect("parse");
        assert_eq!(doc["country"], RawValue::String("NO".to_owned()));
        assert_eq!(doc["flag"], RawValue::String("off".to_owned()));
        assert_eq!(doc["answer"], RawValue::String("yes".to_owned()));
    }

    #[test]
    fn true_and_false_are_still_booleans() {
        let doc: Doc = from_str("a: true\nb: false\n").expect("parse");
        assert_eq!(doc["a"], RawValue::Boolean(true));
        assert_eq!(doc["b"], RawValue::Boolean(false));
    }

    #[test]
    fn quoting_decides_the_type() {
        let doc: Doc = from_str("n: 123\ns: '123'\nnull_value: null\ntilde: ~\nquoted: 'null'\n")
            .expect("parse");
        assert_eq!(doc["n"], RawValue::Integer(123));
        assert_eq!(doc["s"], RawValue::String("123".to_owned()));
        assert_eq!(doc["null_value"], RawValue::Null(()));
        assert_eq!(doc["tilde"], RawValue::Null(()));
        assert_eq!(doc["quoted"], RawValue::String("null".to_owned()));
    }

    #[test]
    fn rejects_alias_expansion_bombs() {
        let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        let mut previous = 'a';
        for level in 'b'..='k' {
            let refs = vec![format!("*{previous}"); 10].join(", ");
            writeln!(bomb, "{level}: &{level} [{refs}]").expect("writing to a String");
            previous = level;
        }
        from_str::<Doc>(&bomb).expect_err("exponential alias expansion must be bounded");
    }

    #[test]
    fn rejects_unknown_tags() {
        from_str::<Doc>("x: !python/object foo\n").expect_err("tags have no meaning in a rule");
    }

    #[test]
    fn error_messages_are_a_single_line() {
        let err = from_str::<Doc>("a: 1\na: 2\n").expect_err("duplicate key");
        assert!(!err.message.contains('\n'), "got: {}", err.message);
    }
}
