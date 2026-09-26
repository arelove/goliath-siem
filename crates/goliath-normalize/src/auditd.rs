//! Linux audit records, as auditd writes them to `audit.log`.
//!
//! The kernel reports one event as several records, each a line of
//! `key=value` fields, which share the event's `msg=audit(time:serial)`:
//!
//! ```text
//! type=SYSCALL msg=audit(1727251200.123:4521): arch=c000003e syscall=59 success=yes exe="/usr/bin/id" ...
//! type=EXECVE msg=audit(1727251200.123:4521): argc=1 a0="id"
//! type=CWD msg=audit(1727251200.123:4521): cwd="/root"
//! type=PATH msg=audit(1727251200.123:4521): item=0 name="/usr/bin/id" ...
//! type=PROCTITLE msg=audit(1727251200.123:4521): proctitle=6964
//! ```
//!
//! [`events`] frames them: lines are grouped by event, whether or not they
//! are adjacent. [`decode`] turns an event into one object, with each record
//! under its type:
//!
//! ```text
//! { "time": "1727251200.123", "serial": "4521",
//!   "SYSCALL": { "arch": "c000003e", "syscall": "59", ... },
//!   "EXECVE": { "argc": "1", "a0": "id" },
//!   "PATH": { "0": { "name": "/usr/bin/id", ... } }, ... }
//! ```
//!
//! Values stay text, as auditd writes them; a definition converts what it
//! needs. Fields auditd writes as hexadecimal because they hold spaces or
//! other bytes it will not print, such as `proctitle` and the arguments of
//! `EXECVE`, are decoded. A record whose `msg` is itself fields, as the
//! `USER_*` records are, has them as an object under `msg`.

use std::collections::HashMap;

use serde_json::{Map, Value};

const EVENT: &str = "msg=audit(";

/// The `time:serial` of the event `line` belongs to.
fn event_of(line: &[u8]) -> Option<&[u8]> {
    let start = line
        .windows(EVENT.len())
        .position(|window| window == EVENT.as_bytes())?
        + EVENT.len();
    let rest = &line[start..];
    let id = &rest[..rest.iter().position(|&byte| byte == b')')?];
    id.contains(&b':').then_some(id)
}

/// The events in `bytes`, each its lines joined by newlines, in the order
/// each event first appears. A line that names no event is returned alone,
/// as an error.
pub(crate) fn events(bytes: &[u8]) -> Vec<Result<Vec<u8>, &[u8]>> {
    let mut events: Vec<Result<Vec<u8>, &[u8]>> = Vec::new();
    let mut positions: HashMap<&[u8], usize> = HashMap::new();
    for line in bytes.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Some(id) = event_of(line) else {
            events.push(Err(line));
            continue;
        };
        if let Some(&position) = positions.get(id) {
            if let Some(Ok(event)) = events.get_mut(position) {
                event.push(b'\n');
                event.extend_from_slice(line);
            }
        } else {
            positions.insert(id, events.len());
            events.push(Ok(line.to_vec()));
        }
    }
    events
}

/// Decodes the lines of one event into an object.
///
/// # Errors
///
/// Returns why a line is not an audit record.
pub(crate) fn decode(raw: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(raw).map_err(|error| format!("not UTF-8: {error}"))?;
    let mut event = Map::new();
    for line in text.lines() {
        let start = line
            .find(EVENT)
            .ok_or_else(|| format!("`{line}` names no audit event"))?;
        let after = &line[start + EVENT.len()..];
        let close = after
            .find(')')
            .ok_or_else(|| format!("`{line}` names no audit event"))?;
        let (time, serial) = after[..close]
            .split_once(':')
            .ok_or_else(|| format!("`{line}` names no audit event"))?;
        let head = fields(&line[..start], "");
        let record_type = match head.get("type") {
            Some(Value::String(record_type)) => record_type.clone(),
            _ => return Err(format!("`{line}` has no type")),
        };
        if event.is_empty() {
            event.insert("time".to_owned(), Value::from(time));
            event.insert("serial".to_owned(), Value::from(serial));
            if let Some(node) = head.get("node") {
                event.insert("node".to_owned(), node.clone());
            }
        }
        if record_type == "EOE" {
            continue;
        }

        // Fields the kernel wrote, then, after a group separator, what
        // auditd added in its enriched format, such as `UID="root"`.
        let body = after[close + 1..].strip_prefix(':').unwrap_or("");
        let (written, enriched) = body.split_once('\u{1d}').unwrap_or((body, ""));
        let mut record = fields(written, &record_type);
        for (key, value) in fields(enriched, &record_type) {
            record.entry(key).or_insert(value);
        }
        place(&mut event, &record_type, record);
    }
    Ok(Value::Object(event))
}

/// Puts a record under its type: by its `item` where it has one, as `PATH`
/// records do, and otherwise as `TYPE`, then `TYPE#2`, and so on.
fn place(event: &mut Map<String, Value>, record_type: &str, record: Map<String, Value>) {
    if let Some(Value::String(item)) = record.get("item") {
        let item = item.clone();
        let items = event
            .entry(record_type.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(items) = items {
            items.entry(item).or_insert(Value::Object(record));
        }
        return;
    }
    let mut name = record_type.to_owned();
    let mut occurrence = 1;
    while event.contains_key(&name) {
        occurrence += 1;
        name = format!("{record_type}#{occurrence}");
    }
    event.insert(name, Value::Object(record));
}

/// The `key=value` fields of `text`. A value is quoted with `"`, or with `'`
/// around further fields, or runs to the next space. Words that are not
/// fields, as in `avc:  denied  { read } for pid=1`, are kept in order under
/// `words`. The first of two fields with one name is kept.
fn fields(text: &str, record_type: &str) -> Map<String, Value> {
    let mut found = Map::new();
    let mut words: Vec<&str> = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let Some(equals) = rest[..token_end].find('=').filter(|&at| at > 0) else {
            words.push(&rest[..token_end]);
            rest = rest[token_end..].trim_start();
            continue;
        };
        let key = &rest[..equals];
        let after = &rest[equals + 1..];
        let (value, next) = if let Some((inner, next)) = quoted(after, '"') {
            (Value::from(inner), next)
        } else if let Some((inner, next)) = quoted(after, '\'') {
            let nested = fields(inner, record_type);
            let value = if nested.is_empty() || nested.contains_key("words") {
                Value::from(inner)
            } else {
                Value::Object(nested)
            };
            (value, next)
        } else {
            let end = after.find(char::is_whitespace).unwrap_or(after.len());
            (
                Value::from(bare(key, &after[..end], record_type)),
                &after[end..],
            )
        };
        found.entry(key.to_owned()).or_insert(value);
        rest = next.trim_start();
    }
    if !words.is_empty() {
        found
            .entry("words".to_owned())
            .or_insert_with(|| Value::from(words.join(" ")));
    }
    found
}

/// The text inside `quote` at the start of `text`, and what follows it.
fn quoted(text: &str, quote: char) -> Option<(&str, &str)> {
    let inner = text.strip_prefix(quote)?;
    let end = inner.find(quote)?;
    Some((&inner[..end], &inner[end + 1..]))
}

/// An unquoted value, decoded from hexadecimal if auditd encodes this field.
fn bare(key: &str, value: &str, record_type: &str) -> String {
    let hex = !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !hex || !encoded(key, record_type) {
        return value.to_owned();
    }
    let bytes: Vec<u8> = value
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect();
    let text = String::from_utf8_lossy(&bytes);
    if key == "proctitle" {
        // The arguments, separated by the NULs that end each in memory.
        text.trim_end_matches('\0').replace('\0', " ")
    } else {
        text.into_owned()
    }
}

/// Whether auditd writes `key` as hexadecimal when its value holds bytes it
/// will not print. In `EXECVE`, `a0`, `a1`, ... are the arguments; in other
/// records they are numbers, and stay as written.
fn encoded(key: &str, record_type: &str) -> bool {
    const TEXT: &[&str] = &[
        "acct",
        "cmd",
        "comm",
        "cwd",
        "data",
        "exe",
        "key",
        "name",
        "path",
        "proctitle",
    ];
    if TEXT.contains(&key) {
        return true;
    }
    record_type == "EXECVE"
        && key
            .strip_prefix('a')
            .map(|rest| rest.split('[').next().unwrap_or(rest))
            .is_some_and(|number| {
                !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
            })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const EXEC: &str = r#"type=SYSCALL msg=audit(1727251200.123:4521): arch=c000003e syscall=59 success=yes exit=0 a0=55d5 ppid=1200 pid=1234 auid=1000 uid=0 comm="id" exe="/usr/bin/id" key=(null)
type=EXECVE msg=audit(1727251200.123:4521): argc=2 a0="id" a1=2D2D68656C6C6F20776F726C64
type=CWD msg=audit(1727251200.123:4521): cwd="/root"
type=PATH msg=audit(1727251200.123:4521): item=0 name="/usr/bin/id" nametype=NORMAL
type=PATH msg=audit(1727251200.123:4521): item=1 name="/lib64/ld-linux-x86-64.so.2" nametype=NORMAL
type=PROCTITLE msg=audit(1727251200.123:4521): proctitle=6964002D2D68656C6C6F20776F726C64
type=EOE msg=audit(1727251200.123:4521): "#;

    #[test]
    fn an_event_becomes_one_object_with_its_records_by_type() {
        let event = decode(EXEC.as_bytes()).unwrap();
        assert_eq!(event["time"], "1727251200.123");
        assert_eq!(event["serial"], "4521");
        assert_eq!(event["SYSCALL"]["exe"], "/usr/bin/id");
        // Numbers in SYSCALL stay as written; EXECVE arguments are decoded.
        assert_eq!(event["SYSCALL"]["a0"], "55d5");
        assert_eq!(event["EXECVE"]["a1"], "--hello world");
        assert_eq!(event["SYSCALL"]["key"], "(null)");
        assert_eq!(event["PATH"]["1"]["name"], "/lib64/ld-linux-x86-64.so.2");
        assert_eq!(event["PROCTITLE"]["proctitle"], "id --hello world");
        assert!(event.get("EOE").is_none());
    }

    #[test]
    fn records_are_grouped_by_event_even_when_interleaved() {
        let log = "type=SYSCALL msg=audit(1.0:1): pid=1\n\
                   type=SYSCALL msg=audit(1.0:2): pid=2\n\
                   not an audit line\n\
                   type=CWD msg=audit(1.0:1): cwd=\"/\"\n";
        let events = events(log.as_bytes());
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].as_deref(),
            Ok(&b"type=SYSCALL msg=audit(1.0:1): pid=1\ntype=CWD msg=audit(1.0:1): cwd=\"/\""[..])
        );
        assert_eq!(events[2], Err(&b"not an audit line"[..]));
    }

    #[test]
    fn a_message_of_fields_becomes_an_object() {
        let line = "node=web-1 type=USER_AUTH msg=audit(1727251300.000:88): pid=4410 uid=0 \
                    msg='op=PAM:authentication grantors=? acct=\"alice\" exe=\"/usr/sbin/sshd\" \
                    hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=failed'\u{1d}UID=\"root\"";
        let event = decode(line.as_bytes()).unwrap();
        assert_eq!(event["node"], "web-1");
        assert_eq!(
            event["USER_AUTH"],
            json!({
                "pid": "4410",
                "uid": "0",
                "msg": {
                    "op": "PAM:authentication", "grantors": "?", "acct": "alice",
                    "exe": "/usr/sbin/sshd", "hostname": "203.0.113.9",
                    "addr": "203.0.113.9", "terminal": "ssh", "res": "failed",
                },
                "UID": "root",
            })
        );
    }

    #[test]
    fn words_and_repeated_records_are_kept() {
        let log = "type=AVC msg=audit(1.0:5): avc:  denied  { read } for  pid=7 comm=\"cat\"\n\
                   type=AVC msg=audit(1.0:5): avc:  denied  { open } for  pid=7";
        let event = decode(log.as_bytes()).unwrap();
        assert_eq!(event["AVC"]["words"], "avc: denied { read } for");
        assert_eq!(event["AVC"]["pid"], "7");
        assert_eq!(event["AVC#2"]["words"], "avc: denied { open } for");
    }

    #[test]
    fn a_line_without_an_event_is_an_error() {
        assert!(decode(b"type=SYSCALL pid=1").is_err());
        assert!(decode(b"msg=audit(1.0:1): pid=1").is_err());
    }
}
