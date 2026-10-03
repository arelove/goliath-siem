//! Indicators from a STIX 2.1 bundle.
//!
//! An `indicator` object is read if its pattern is in the STIX pattern
//! language and compares one or more values for equality, joined by `OR`,
//! such as `[domain-name:value = 'bad.example.com']`. Patterns that join
//! with `AND`, follow in time, or compare otherwise are detection logic, not
//! indicators, and are ignored.

use serde_json::Value;

use crate::feed::{Feed, Parsed, key, time};
use crate::key::Kind;

/// Adds the indicators of the bundle `text` to `parsed`.
pub(crate) fn indicators(
    feed: &Feed,
    text: &str,
    fetched_at: i64,
    parsed: &mut Parsed,
) -> Result<(), String> {
    let bundle: Value =
        serde_json::from_str(text).map_err(|error| format!("it is not JSON: {error}"))?;
    let objects = bundle
        .get("objects")
        .and_then(Value::as_array)
        .ok_or("it is not a STIX bundle")?;
    for object in objects {
        let text_of = |name: &str| object.get(name).and_then(Value::as_str);
        if text_of("type") != Some("indicator") {
            continue;
        }
        let revoked = object.get("revoked").and_then(Value::as_bool) == Some(true);
        let Some(comparisons) = text_of("pattern")
            .filter(|_| !revoked && text_of("pattern_type").is_none_or(|kind| kind == "stix"))
            .and_then(comparisons)
        else {
            parsed.ignored += 1;
            continue;
        };

        let confidence = object
            .get("confidence")
            .and_then(Value::as_u64)
            .and_then(|confidence| u8::try_from(confidence).ok());
        let mut assertion = feed.assertion(
            confidence,
            text_of("created").and_then(time),
            text_of("modified").and_then(time),
            fetched_at,
        );
        // What the indicator says of its own validity is kept.
        assertion.valid_from = text_of("valid_from").and_then(time);
        if let Some(until) = text_of("valid_until").and_then(time) {
            assertion.valid_until = Some(until);
        }

        for (path, value) in comparisons {
            let Some(kind) = kind_of(&path, &value) else {
                parsed.ignored += 1;
                continue;
            };
            match key(kind, &value) {
                Ok(key) => parsed.indicators.push((key, assertion.clone())),
                Err(error) => parsed.reject(|| error.to_string()),
            }
        }
    }
    Ok(())
}

/// What the object path of a comparison holds.
fn kind_of(path: &str, value: &str) -> Option<Kind> {
    let path = path.replace('\'', "").to_ascii_lowercase();
    Some(match path.as_str() {
        "ipv4-addr:value" | "ipv6-addr:value" => {
            if value.contains('/') {
                Kind::Cidr
            } else {
                Kind::Ip
            }
        }
        "domain-name:value" => Kind::Domain,
        "url:value" => Kind::Url,
        "email-addr:value" => Kind::Email,
        "autonomous-system:number" => Kind::Asn,
        "file:hashes.md5" => Kind::Md5,
        "file:hashes.sha-1" | "file:hashes.sha1" => Kind::Sha1,
        "file:hashes.sha-256" | "file:hashes.sha256" => Kind::Sha256,
        "file:name" => Kind::FileName,
        "windows-registry-key:key" => Kind::RegistryKey,
        "mutex:name" => Kind::Mutex,
        "x509-certificate:hashes.sha-1"
        | "x509-certificate:hashes.sha1"
        | "x509-certificate:hashes.sha-256"
        | "x509-certificate:hashes.sha256" => Kind::CertificateHash,
        "x509-certificate:subject" => Kind::CertificateSubject,
        _ => return None,
    })
}

/// The comparisons of a pattern, each an object path and a value, if the
/// pattern is nothing but equalities joined by `OR`.
fn comparisons(pattern: &str) -> Option<Vec<(String, String)>> {
    let mut found = Vec::new();
    let mut rest = pattern.trim();
    loop {
        rest = rest.strip_prefix('[')?.trim_start();
        loop {
            let (path, after) = rest.split_once('=')?;
            let path = path.trim();
            if path.is_empty() || path.contains(|character: char| "[]!<>".contains(character)) {
                return None;
            }
            let (value, after) = literal(after.trim_start())?;
            found.push((path.to_owned(), value));
            rest = after.trim_start();
            match rest.strip_prefix("OR ") {
                Some(more) => rest = more.trim_start(),
                None => break,
            }
        }
        rest = rest.strip_prefix(']')?.trim_start();
        if rest.is_empty() {
            return Some(found);
        }
        rest = rest.strip_prefix("OR ")?.trim_start();
    }
}

/// A literal at the start of `text`, a quoted string or a number, and what
/// follows it.
fn literal(text: &str) -> Option<(String, &str)> {
    let Some(quoted) = text.strip_prefix('\'') else {
        let end = text
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(text.len());
        return (end > 0).then(|| (text[..end].to_owned(), &text[end..]));
    };
    let mut value = String::new();
    let mut characters = quoted.char_indices();
    while let Some((index, character)) = characters.next() {
        match character {
            '\\' => value.push(characters.next()?.1),
            '\'' => return Some((value, quoted.get(index + 1..)?)),
            other => value.push(other),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::comparisons;

    fn pairs(pattern: &str) -> Option<Vec<(String, String)>> {
        comparisons(pattern)
    }

    #[test]
    fn equalities_joined_by_or_are_read_and_nothing_else() {
        let one = |path: &str, value: &str| (path.to_owned(), value.to_owned());
        assert_eq!(
            pairs("[domain-name:value = 'bad.example.com']"),
            Some(vec![one("domain-name:value", "bad.example.com")])
        );
        assert_eq!(
            pairs(
                "[file:hashes.'SHA-256' = 'ab' OR file:hashes.MD5 = 'cd'] OR [url:value = 'http://x/it\\'s']"
            ),
            Some(vec![
                one("file:hashes.'SHA-256'", "ab"),
                one("file:hashes.MD5", "cd"),
                one("url:value", "http://x/it's"),
            ])
        );
        assert_eq!(
            pairs("[autonomous-system:number = 64496]"),
            Some(vec![one("autonomous-system:number", "64496")])
        );
        for other in [
            "[ipv4-addr:value = '203.0.113.7' AND domain-name:value = 'x.example']",
            "[ipv4-addr:value = '203.0.113.7'] FOLLOWEDBY [domain-name:value = 'x.example']",
            "[file:size > 100]",
            "[file:name != 'a']",
            "[file:name LIKE 'a%']",
            "[domain-name:value = 'unclosed]",
            "domain-name:value = 'x.example'",
            "",
        ] {
            assert_eq!(pairs(other), None, "{other}");
        }
    }
}
