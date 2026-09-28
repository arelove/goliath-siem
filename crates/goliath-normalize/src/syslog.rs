//! Syslog messages, as RFC 5424 and RFC 3164 lay them out.
//!
//! [`messages`] frames a stream as RFC 6587 describes: a message that starts
//! with its length in digits and a space is that many bytes long, and any
//! other runs to the end of its line. Senders over TCP use either.
//!
//! [`decode`] turns a message into one object with its header's fields:
//!
//! ```text
//! <165>1 2026-09-28T10:00:00.123Z web-01 nginx 4121 ACCESS [origin ip="10.0.0.7"] GET /
//!
//! { "facility": 20, "severity": 5, "version": 1,
//!   "timestamp": "2026-09-28T10:00:00.123Z", "hostname": "web-01",
//!   "app_name": "nginx", "proc_id": "4121", "msg_id": "ACCESS",
//!   "structured_data": { "origin": { "ip": "10.0.0.7" } },
//!   "message": "GET /" }
//! ```
//!
//! A header field RFC 5424 writes as `-` is left out. An RFC 3164 message
//! gives `app_name` and `proc_id` from its tag, as in `sshd[812]: ...`. Its
//! timestamp, such as `Sep 28 10:00:00`, has neither year nor zone: it is
//! taken as UTC, in the latest year that does not put it more than a day
//! ahead of now. A sender that can write RFC 3339 times should.
//!
//! The message is text, or with [`Message::Json`] a JSON value, so that a
//! definition reads the fields of an application that logs JSON over syslog.

use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use serde_json::{Map, Value};

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// How the message after the header decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Message {
    /// Kept as text.
    Text,
    /// Parsed as JSON.
    Json,
}

/// The messages in `bytes`, framed by octet counting or by line. A count
/// that runs past the end of `bytes` is returned as an error with the rest.
pub(crate) fn messages(bytes: &[u8]) -> Vec<Result<&[u8], &[u8]>> {
    let mut found = Vec::new();
    let mut rest = bytes;
    loop {
        let start = rest
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(rest.len());
        rest = &rest[start..];
        if rest.is_empty() {
            return found;
        }
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if digits > 0 && rest.get(digits) == Some(&b' ') {
            let length = std::str::from_utf8(&rest[..digits])
                .ok()
                .and_then(|text| text.parse::<usize>().ok());
            let body = &rest[digits + 1..];
            match length {
                Some(length) if length <= body.len() => {
                    found.push(Ok(&body[..length]));
                    rest = &body[length..];
                }
                _ => {
                    found.push(Err(rest));
                    return found;
                }
            }
        } else {
            let end = rest
                .iter()
                .position(|&byte| byte == b'\n')
                .unwrap_or(rest.len());
            let line = &rest[..end];
            found.push(Ok(line.strip_suffix(b"\r").unwrap_or(line)));
            rest = &rest[end..];
        }
    }
}

/// Decodes one message, with `now` giving the year of an RFC 3164 time.
pub(crate) fn decode(
    raw: &[u8],
    message: Message,
    now: impl FnOnce() -> Timestamp,
) -> Result<Value, String> {
    let raw = trim_end(raw);
    let (priority, rest) =
        priority(raw).ok_or("the message has no syslog priority, as in `<13>`")?;
    let mut record = Map::new();
    record.insert("facility".to_owned(), Value::from(priority / 8));
    record.insert("severity".to_owned(), Value::from(priority % 8));
    let text = match rest.split_first() {
        Some((b'1', after)) if after.first().is_none_or(|&byte| byte == b' ') => {
            record.insert("version".to_owned(), Value::from(1));
            rfc5424(after.get(1..).unwrap_or_default(), &mut record)?
        }
        _ => rfc3164(rest, &mut record, now),
    };
    let text = text.strip_prefix("\u{feff}").unwrap_or(&text);
    let body = match message {
        Message::Text => Value::from(text),
        Message::Json => serde_json::from_str(text)
            .map_err(|error| format!("the syslog message is not JSON: {error}"))?,
    };
    record.insert("message".to_owned(), body);
    Ok(Value::Object(record))
}

fn trim_end(raw: &[u8]) -> &[u8] {
    let end = raw
        .iter()
        .rposition(|&byte| !matches!(byte, b'\r' | b'\n' | b'\0'))
        .map_or(0, |last| last + 1);
    &raw[..end]
}

/// The priority in `<PRI>` and what follows it.
fn priority(raw: &[u8]) -> Option<(u8, &[u8])> {
    let rest = raw.strip_prefix(b"<")?;
    let close = rest.iter().take(4).position(|&byte| byte == b'>')?;
    let digits = std::str::from_utf8(&rest[..close]).ok()?;
    let priority: u8 = digits.parse().ok().filter(|&value| value <= 191)?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then_some((priority, &rest[close + 1..]))
}

/// The next field up to a space, and what follows the space.
fn field(rest: &[u8]) -> (&[u8], &[u8]) {
    match rest.iter().position(|&byte| byte == b' ') {
        Some(space) => (&rest[..space], &rest[space + 1..]),
        None => (rest, &[]),
    }
}

/// Reads the header after `1 ` into `record`, returning the message.
fn rfc5424(rest: &[u8], record: &mut Map<String, Value>) -> Result<String, String> {
    let mut rest = rest;
    for name in ["timestamp", "hostname", "app_name", "proc_id", "msg_id"] {
        let (value, after) = field(rest);
        if value.is_empty() {
            return Err(format!("the syslog header ends before its {name}"));
        }
        if value != b"-" {
            let value = String::from_utf8_lossy(value).into_owned();
            if name == "timestamp" && value.parse::<Timestamp>().is_err() {
                return Err(format!("the syslog timestamp `{value}` is not RFC 3339"));
            }
            record.insert(name.to_owned(), Value::from(value));
        }
        rest = after;
    }
    let (data, rest) = structured_data(rest)?;
    if !data.is_empty() {
        record.insert("structured_data".to_owned(), Value::Object(data));
    }
    Ok(String::from_utf8_lossy(rest.strip_prefix(b" ").unwrap_or(rest)).into_owned())
}

/// Structured data, `-` or elements such as `[id name="value" ...]`, and
/// what follows it.
fn structured_data(rest: &[u8]) -> Result<(Map<String, Value>, &[u8]), String> {
    let mut elements = Map::new();
    if let Some(after) = rest.strip_prefix(b"-") {
        return Ok((elements, after));
    }
    let broken = || "the syslog structured data is not closed".to_owned();
    let mut rest = rest;
    while let Some(after) = rest.strip_prefix(b"[") {
        let end = after
            .iter()
            .position(|&byte| byte == b' ' || byte == b']')
            .ok_or_else(broken)?;
        let id = String::from_utf8_lossy(&after[..end]).into_owned();
        let mut params = Map::new();
        rest = &after[end..];
        loop {
            match rest.split_first() {
                Some((b']', after)) => {
                    rest = after;
                    break;
                }
                Some((b' ', after)) => {
                    let equals = after
                        .iter()
                        .position(|&byte| byte == b'=')
                        .ok_or_else(broken)?;
                    let name = String::from_utf8_lossy(&after[..equals]).into_owned();
                    let quoted = after[equals + 1..].strip_prefix(b"\"").ok_or_else(broken)?;
                    let (value, after) = quoted_value(quoted).ok_or_else(broken)?;
                    params.insert(name, Value::from(value));
                    rest = after;
                }
                _ => return Err(broken()),
            }
        }
        match elements.get_mut(&id) {
            Some(Value::Object(existing)) => existing.extend(params),
            _ => {
                elements.insert(id, Value::Object(params));
            }
        }
    }
    if elements.is_empty() {
        return Err("the syslog structured data is neither `-` nor `[...]`".to_owned());
    }
    Ok((elements, rest))
}

/// A parameter value up to its closing quote, with `\"`, `\\`, and `\]`
/// unescaped, and what follows the quote.
fn quoted_value(rest: &[u8]) -> Option<(String, &[u8])> {
    let mut value = Vec::new();
    let mut bytes = rest.iter().enumerate();
    while let Some((index, &byte)) = bytes.next() {
        match byte {
            b'"' => {
                return Some((
                    String::from_utf8_lossy(&value).into_owned(),
                    &rest[index + 1..],
                ));
            }
            b'\\' => match bytes.next() {
                Some((_, &next @ (b'"' | b'\\' | b']'))) => value.push(next),
                Some((_, &next)) => value.extend_from_slice(&[b'\\', next]),
                None => return None,
            },
            _ => value.push(byte),
        }
    }
    None
}

/// Reads the header of an RFC 3164 message into `record`, returning the
/// message. Parts that are missing are left out rather than refused, since
/// senders of this format vary.
fn rfc3164(
    rest: &[u8],
    record: &mut Map<String, Value>,
    now: impl FnOnce() -> Timestamp,
) -> String {
    let (first, after) = field(rest);
    let rest = if let Some(time) = std::str::from_utf8(first)
        .ok()
        .and_then(|text| text.parse::<Timestamp>().ok())
    {
        record.insert("timestamp".to_owned(), Value::from(time.to_string()));
        after
    } else if let Some(time) = rest.get(..15).and_then(|stamp| bsd_time(stamp, now)) {
        record.insert("timestamp".to_owned(), Value::from(time.to_string()));
        rest[15..].strip_prefix(b" ").unwrap_or(&rest[15..])
    } else {
        return String::from_utf8_lossy(rest).into_owned();
    };
    let (host, rest) = field(rest);
    if !host.is_empty() {
        record.insert(
            "hostname".to_owned(),
            Value::from(String::from_utf8_lossy(host).into_owned()),
        );
    }
    let text = String::from_utf8_lossy(rest).into_owned();
    match tag(&text) {
        Some((app, pid, message)) => {
            record.insert("app_name".to_owned(), Value::from(app));
            if let Some(pid) = pid {
                record.insert("proc_id".to_owned(), Value::from(pid));
            }
            message.to_owned()
        }
        None => text,
    }
}

/// The tag of `text`, as in `sshd[812]: message` or `cron: message`: the
/// program, its process if given, and the message.
fn tag(text: &str) -> Option<(&str, Option<&str>, &str)> {
    let end = text.find(|c: char| c == '[' || c == ':' || c.is_whitespace())?;
    let program = &text[..end];
    if program.is_empty() {
        return None;
    }
    let rest = &text[end..];
    let (pid, rest) = match rest.strip_prefix('[') {
        Some(inner) => {
            let close = inner.find(']')?;
            (Some(&inner[..close]), &inner[close + 1..])
        }
        None => (None, rest),
    };
    let message = rest.strip_prefix(':')?;
    Some((program, pid, message.strip_prefix(' ').unwrap_or(message)))
}

/// An RFC 3164 time such as `Sep 28 10:00:00` or `Sep  8 10:00:00`, in UTC,
/// in the latest year that puts it no more than a day ahead of `now`.
fn bsd_time(stamp: &[u8], now: impl FnOnce() -> Timestamp) -> Option<Timestamp> {
    let stamp = std::str::from_utf8(stamp).ok()?;
    let month = MONTHS
        .iter()
        .position(|&name| stamp.get(..3) == Some(name))?;
    let day: i8 = stamp.get(4..6)?.trim_start().parse().ok()?;
    let clock = stamp.get(7..)?.as_bytes();
    if stamp.as_bytes()[3] != b' '
        || stamp.as_bytes()[6] != b' '
        || clock[2] != b':'
        || clock[5] != b':'
    {
        return None;
    }
    let part = |range: std::ops::Range<usize>| -> Option<i8> {
        std::str::from_utf8(&clock[range]).ok()?.parse().ok()
    };
    let (hour, minute, second) = (part(0..2)?, part(3..5)?, part(6..8)?);
    let now = now();
    let year = now.to_zoned(TimeZone::UTC).year();
    let month = i8::try_from(month + 1).ok()?;
    let at = |year: i16| -> Option<Timestamp> {
        Date::new(year, month, day)
            .ok()?
            .at(hour, minute, second, 0)
            .to_zoned(TimeZone::UTC)
            .ok()
            .map(|zoned| zoned.timestamp())
    };
    let ahead = jiff::SignedDuration::from_hours(24);
    match at(year) {
        Some(time) if time.duration_since(now) <= ahead => Some(time),
        // Such as `Dec 31` read on the first of January, or `Feb 29` in a
        // year that has none.
        _ => at(year - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn now() -> Timestamp {
        "2026-09-28T12:00:00Z".parse().unwrap()
    }

    fn text(raw: &str) -> Value {
        decode(raw.as_bytes(), Message::Text, now).unwrap()
    }

    #[test]
    fn frames_by_octet_count_and_by_line() {
        let stream = b"11 <13>1 - - x\n<13>two\r\n\n26 <13>1 - - - - - \nmultiline";
        let found: Vec<_> = messages(stream).into_iter().map(Result::unwrap).collect();
        assert_eq!(
            found,
            [
                &b"<13>1 - - x"[..],
                b"<13>two",
                b"<13>1 - - - - - \nmultiline"
            ]
        );
        let cut = messages(b"<13>one\n40 <13>1 short");
        assert_eq!(cut[0], Ok(&b"<13>one"[..]));
        assert_eq!(cut[1], Err(&b"40 <13>1 short"[..]));
    }

    #[test]
    fn decodes_an_rfc_5424_header_and_its_structured_data() {
        let raw = r#"<165>1 2026-09-28T10:00:00.123Z web-01 nginx 4121 ACCESS [origin ip="10.0.0.7"][meta note="a \"b\" \] c"] GET /"#;
        assert_eq!(
            text(raw),
            json!({
                "facility": 20, "severity": 5, "version": 1,
                "timestamp": "2026-09-28T10:00:00.123Z", "hostname": "web-01",
                "app_name": "nginx", "proc_id": "4121", "msg_id": "ACCESS",
                "structured_data": {
                    "origin": { "ip": "10.0.0.7" },
                    "meta": { "note": "a \"b\" ] c" },
                },
                "message": "GET /",
            })
        );
    }

    #[test]
    fn leaves_out_nil_fields_and_a_byte_order_mark() {
        assert_eq!(
            text("<14>1 - - - - - - \u{feff}hello\n"),
            json!({ "facility": 1, "severity": 6, "version": 1, "message": "hello" })
        );
    }

    #[test]
    fn decodes_an_rfc_3164_header_with_its_tag() {
        assert_eq!(
            text("<38>Sep 28 10:00:00 bastion sshd[812]: Accepted publickey for adam"),
            json!({
                "facility": 4, "severity": 6,
                "timestamp": "2026-09-28T10:00:00Z", "hostname": "bastion",
                "app_name": "sshd", "proc_id": "812",
                "message": "Accepted publickey for adam",
            })
        );
        assert_eq!(
            text("<78>Sep  8 01:02:03 host CRON: done")["timestamp"],
            "2026-09-08T01:02:03Z"
        );
        // More than a day ahead of now: last year's.
        assert_eq!(
            text("<13>Dec 31 23:59:59 host app: x")["timestamp"],
            "2025-12-31T23:59:59Z"
        );
        assert_eq!(
            text("<13>2026-09-28T10:00:00+02:00 host app: x")["timestamp"],
            "2026-09-28T08:00:00Z"
        );
        assert_eq!(
            text("<13>no header at all"),
            json!({ "facility": 1, "severity": 5, "message": "no header at all" })
        );
        assert_eq!(
            text("<13>Sep 28 10:00:00 host just words")["message"],
            "just words"
        );
    }

    #[test]
    fn decodes_the_message_as_json_when_asked() {
        let record = decode(
            br#"<14>1 - - app - - - {"user":"adam","ok":true}"#,
            Message::Json,
            now,
        )
        .unwrap();
        assert_eq!(record["message"], json!({ "user": "adam", "ok": true }));
        assert!(decode(b"<14>1 - - app - - - not json", Message::Json, now).is_err());
    }

    #[test]
    fn refuses_what_is_not_syslog() {
        for raw in [
            "no priority",
            "<192>1 - - - - - -",
            "<13>1 yesterday - - - - -",
            "<13>1 - host",
            "<13>1 - - - - - [open",
            "<13>1 - - - - - junk",
        ] {
            assert!(decode(raw.as_bytes(), Message::Text, now).is_err(), "{raw}");
        }
    }
}
