//! OpenTelemetry logs, as an OTLP/HTTP export request carries them.
//!
//! A request, protobuf or JSON, becomes JSON lines, one per log record, so
//! that a source definition reads them with `lines` framing and `json`
//! decoding:
//!
//! ```text
//! { "time": "2026-09-28T10:00:00.123Z", "observed_time": "...",
//!   "severity_number": 9, "severity_text": "INFO",
//!   "body": "user adam signed in",
//!   "attributes": { "user.name": "adam", "http.status_code": 200 },
//!   "resource": { "service.name": "auth", "host.name": "web-01" },
//!   "scope": { "name": "auth.login", "version": "1.2.0" },
//!   "trace_id": "5b8efff798038103d269b633813fc60c", "span_id": "eee19b7ec3c1b174",
//!   "event_name": "login" }
//! ```
//!
//! Members that are empty or zero in the record are left out. Values keep
//! their OTLP types: a string, a boolean, an integer, a floating point
//! number, an array, an object for a key-value list, and base64 text for
//! bytes. `time` falls back to `observed_time` when the sender set none.

use jiff::Timestamp;
use prost::Message as _;
use serde_json::{Map, Value};

/// `opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest`, and
/// the messages under it, with only the fields a record is made of.
mod proto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct ExportLogsServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub(super) resource_logs: Vec<ResourceLogs>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct ResourceLogs {
        #[prost(message, optional, tag = "1")]
        pub(super) resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub(super) scope_logs: Vec<ScopeLogs>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct Resource {
        #[prost(message, repeated, tag = "1")]
        pub(super) attributes: Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct ScopeLogs {
        #[prost(message, optional, tag = "1")]
        pub(super) scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")]
        pub(super) log_records: Vec<LogRecord>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct InstrumentationScope {
        #[prost(string, tag = "1")]
        pub(super) name: String,
        #[prost(string, tag = "2")]
        pub(super) version: String,
        #[prost(message, repeated, tag = "3")]
        pub(super) attributes: Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct LogRecord {
        #[prost(fixed64, tag = "1")]
        pub(super) time_unix_nano: u64,
        #[prost(fixed64, tag = "11")]
        pub(super) observed_time_unix_nano: u64,
        #[prost(int32, tag = "2")]
        pub(super) severity_number: i32,
        #[prost(string, tag = "3")]
        pub(super) severity_text: String,
        #[prost(message, optional, tag = "5")]
        pub(super) body: Option<AnyValue>,
        #[prost(message, repeated, tag = "6")]
        pub(super) attributes: Vec<KeyValue>,
        #[prost(bytes = "vec", tag = "9")]
        pub(super) trace_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "10")]
        pub(super) span_id: Vec<u8>,
        #[prost(string, tag = "12")]
        pub(super) event_name: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct AnyValue {
        #[prost(oneof = "Value", tags = "1, 2, 3, 4, 5, 6, 7")]
        pub(super) value: Option<Value>,
    }

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Value {
        #[prost(string, tag = "1")]
        String(String),
        #[prost(bool, tag = "2")]
        Bool(bool),
        #[prost(int64, tag = "3")]
        Int(i64),
        #[prost(double, tag = "4")]
        Double(f64),
        #[prost(message, tag = "5")]
        Array(ArrayValue),
        #[prost(message, tag = "6")]
        KeyValues(KeyValueList),
        #[prost(bytes = "vec", tag = "7")]
        Bytes(Vec<u8>),
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct ArrayValue {
        #[prost(message, repeated, tag = "1")]
        pub(super) values: Vec<AnyValue>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct KeyValueList {
        #[prost(message, repeated, tag = "1")]
        pub(super) values: Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub(super) struct KeyValue {
        #[prost(string, tag = "1")]
        pub(super) key: String,
        #[prost(message, optional, tag = "2")]
        pub(super) value: Option<AnyValue>,
    }
}

use proto::{AnyValue, ExportLogsServiceRequest, KeyValue, LogRecord};

/// How a request body is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// `application/x-protobuf`.
    Protobuf,
    /// `application/json`.
    Json,
}

impl Encoding {
    /// The encoding a `Content-Type` names, if OTLP/HTTP has it.
    pub(crate) fn of(content_type: &str) -> Option<Self> {
        match content_type.split(';').next().unwrap_or_default().trim() {
            "application/x-protobuf" => Some(Self::Protobuf),
            "application/json" => Some(Self::Json),
            _ => None,
        }
    }

    /// The content type of an answer in this encoding.
    pub(crate) fn content_type(self) -> &'static str {
        match self {
            Self::Protobuf => "application/x-protobuf",
            Self::Json => "application/json",
        }
    }

    /// An empty `ExportLogsServiceResponse`: every record was taken.
    pub(crate) fn success(self) -> &'static [u8] {
        match self {
            Self::Protobuf => b"",
            Self::Json => b"{}",
        }
    }
}

/// The log records of an export request as JSON lines, and how many.
///
/// # Errors
///
/// Returns why, if `body` is not an export request in `encoding`.
pub(crate) fn lines(body: &[u8], encoding: Encoding) -> Result<(Vec<u8>, usize), String> {
    let request = match encoding {
        Encoding::Protobuf => ExportLogsServiceRequest::decode(body)
            .map_err(|error| format!("not an OTLP logs export request: {error}"))?,
        Encoding::Json => {
            let value: Value =
                serde_json::from_slice(body).map_err(|error| format!("not JSON: {error}"))?;
            from_json::request(&value)?
        }
    };
    let mut out = Vec::new();
    let mut count = 0;
    for resource_logs in &request.resource_logs {
        let resource = resource_logs
            .resource
            .as_ref()
            .map(|resource| attributes(&resource.attributes))
            .unwrap_or_default();
        for scope_logs in &resource_logs.scope_logs {
            let mut scope = Map::new();
            if let Some(found) = &scope_logs.scope {
                insert_text(&mut scope, "name", &found.name);
                insert_text(&mut scope, "version", &found.version);
                if !found.attributes.is_empty() {
                    scope.insert(
                        "attributes".to_owned(),
                        Value::Object(attributes(&found.attributes)),
                    );
                }
            }
            for record in &scope_logs.log_records {
                let line = self::record(record, &resource, &scope);
                serde_json::to_writer(&mut out, &line).map_err(|error| error.to_string())?;
                out.push(b'\n');
                count += 1;
            }
        }
    }
    Ok((out, count))
}

fn record(record: &LogRecord, resource: &Map<String, Value>, scope: &Map<String, Value>) -> Value {
    let mut line = Map::new();
    let time = if record.time_unix_nano == 0 {
        record.observed_time_unix_nano
    } else {
        record.time_unix_nano
    };
    insert_time(&mut line, "time", time);
    insert_time(&mut line, "observed_time", record.observed_time_unix_nano);
    if record.severity_number != 0 {
        line.insert(
            "severity_number".to_owned(),
            Value::from(record.severity_number),
        );
    }
    insert_text(&mut line, "severity_text", &record.severity_text);
    if let Some(body) = &record.body {
        line.insert("body".to_owned(), any(body));
    }
    if !record.attributes.is_empty() {
        line.insert(
            "attributes".to_owned(),
            Value::Object(attributes(&record.attributes)),
        );
    }
    if !resource.is_empty() {
        line.insert("resource".to_owned(), Value::Object(resource.clone()));
    }
    if !scope.is_empty() {
        line.insert("scope".to_owned(), Value::Object(scope.clone()));
    }
    insert_text(&mut line, "trace_id", &hex(&record.trace_id));
    insert_text(&mut line, "span_id", &hex(&record.span_id));
    insert_text(&mut line, "event_name", &record.event_name);
    Value::Object(line)
}

fn insert_text(map: &mut Map<String, Value>, name: &str, text: &str) {
    if !text.is_empty() {
        map.insert(name.to_owned(), Value::from(text));
    }
}

fn insert_time(map: &mut Map<String, Value>, name: &str, nanoseconds: u64) {
    if nanoseconds != 0
        && let Ok(time) = Timestamp::from_nanosecond(i128::from(nanoseconds))
    {
        map.insert(name.to_owned(), Value::from(time.to_string()));
    }
}

fn attributes(pairs: &[KeyValue]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|pair| {
            let value = pair.value.as_ref().map_or(Value::Null, any);
            (pair.key.clone(), value)
        })
        .collect()
}

fn any(value: &AnyValue) -> Value {
    use proto::Value as V;
    match &value.value {
        None => Value::Null,
        Some(V::String(text)) => Value::from(text.as_str()),
        Some(V::Bool(flag)) => Value::from(*flag),
        Some(V::Int(number)) => Value::from(*number),
        Some(V::Double(number)) => Value::from(*number),
        Some(V::Array(array)) => Value::Array(array.values.iter().map(any).collect()),
        Some(V::KeyValues(list)) => Value::Object(attributes(&list.values)),
        Some(V::Bytes(bytes)) => Value::from(base64(bytes)),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |group, (index, &byte)| {
                group | u32::from(byte) << (16 - 8 * index)
            });
        for index in 0..4 {
            if index <= chunk.len() {
                text.push(char::from(
                    BASE64[(group >> (18 - 6 * index) & 63) as usize],
                ));
            } else {
                text.push('=');
            }
        }
    }
    text
}

fn unbase64(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut bytes = Vec::with_capacity(text.len() * 3 / 4);
    let (mut group, mut bits) = (0_u32, 0);
    for byte in text.bytes() {
        let digit = BASE64.iter().position(|&known| known == byte)?;
        group = group << 6 | u32::try_from(digit).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from(group >> bits & 0xff).ok()?);
        }
    }
    Some(bytes)
}

/// The JSON encoding of OTLP, as protobuf's JSON mapping gives it: members
/// in lower camel case, or as the proto names them, 64-bit integers as
/// numbers or strings, trace and span identifiers in hexadecimal, and bytes
/// in base64.
mod from_json {
    use serde_json::Value;

    use super::proto::{
        AnyValue, ArrayValue, ExportLogsServiceRequest, InstrumentationScope, KeyValue,
        KeyValueList, LogRecord, Resource, ResourceLogs, ScopeLogs, Value as V,
    };

    fn member<'a>(object: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
        object.get(camel).or_else(|| object.get(snake))
    }

    fn list<'a>(object: &'a Value, camel: &str, snake: &str) -> Result<&'a [Value], String> {
        match member(object, camel, snake) {
            None | Some(Value::Null) => Ok(&[]),
            Some(Value::Array(items)) => Ok(items),
            Some(_) => Err(format!("`{camel}` is not an array")),
        }
    }

    fn text(object: &Value, camel: &str, snake: &str) -> String {
        member(object, camel, snake)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    fn integer(value: Option<&Value>, name: &str) -> Result<Option<i128>, String> {
        match value {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(number)) => number
                .as_i64()
                .map(i128::from)
                .or_else(|| number.as_u64().map(i128::from))
                .map(Some)
                .ok_or_else(|| format!("`{name}` is not an integer")),
            Some(Value::String(digits)) => digits
                .parse()
                .map(Some)
                .map_err(|_| format!("`{name}` is not an integer")),
            Some(_) => Err(format!("`{name}` is not an integer")),
        }
    }

    fn nanoseconds(object: &Value, camel: &str, snake: &str) -> Result<u64, String> {
        Ok(integer(member(object, camel, snake), camel)?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| format!("`{camel}` is out of range"))?
            .unwrap_or(0))
    }

    fn identifier(object: &Value, camel: &str, snake: &str) -> Result<Vec<u8>, String> {
        let hex = text(object, camel, snake);
        if !hex.len().is_multiple_of(2) {
            return Err(format!("`{camel}` is not hexadecimal"));
        }
        (0..hex.len())
            .step_by(2)
            .map(|index| {
                hex.get(index..index + 2)
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or_else(|| format!("`{camel}` is not hexadecimal"))
            })
            .collect()
    }

    pub(super) fn request(value: &Value) -> Result<ExportLogsServiceRequest, String> {
        if !value.is_object() {
            return Err("the request is not a JSON object".to_owned());
        }
        let resource_logs = list(value, "resourceLogs", "resource_logs")?
            .iter()
            .map(resource_logs)
            .collect::<Result<_, _>>()?;
        Ok(ExportLogsServiceRequest { resource_logs })
    }

    fn resource_logs(value: &Value) -> Result<ResourceLogs, String> {
        let resource = match value.get("resource") {
            Some(resource) if resource.is_object() => Some(Resource {
                attributes: key_values(list(resource, "attributes", "attributes")?)?,
            }),
            _ => None,
        };
        let scope_logs = list(value, "scopeLogs", "scope_logs")?
            .iter()
            .map(scope_logs)
            .collect::<Result<_, _>>()?;
        Ok(ResourceLogs {
            resource,
            scope_logs,
        })
    }

    fn scope_logs(value: &Value) -> Result<ScopeLogs, String> {
        let scope = match value.get("scope") {
            Some(scope) if scope.is_object() => Some(InstrumentationScope {
                name: text(scope, "name", "name"),
                version: text(scope, "version", "version"),
                attributes: key_values(list(scope, "attributes", "attributes")?)?,
            }),
            _ => None,
        };
        let log_records = list(value, "logRecords", "log_records")?
            .iter()
            .map(log_record)
            .collect::<Result<_, _>>()?;
        Ok(ScopeLogs { scope, log_records })
    }

    fn log_record(value: &Value) -> Result<LogRecord, String> {
        let severity = integer(
            member(value, "severityNumber", "severity_number"),
            "severityNumber",
        )?
        .unwrap_or(0);
        Ok(LogRecord {
            time_unix_nano: nanoseconds(value, "timeUnixNano", "time_unix_nano")?,
            observed_time_unix_nano: nanoseconds(
                value,
                "observedTimeUnixNano",
                "observed_time_unix_nano",
            )?,
            severity_number: i32::try_from(severity)
                .map_err(|_| "`severityNumber` is out of range".to_owned())?,
            severity_text: text(value, "severityText", "severity_text"),
            body: value.get("body").map(any_value).transpose()?,
            attributes: key_values(list(value, "attributes", "attributes")?)?,
            trace_id: identifier(value, "traceId", "trace_id")?,
            span_id: identifier(value, "spanId", "span_id")?,
            event_name: text(value, "eventName", "event_name"),
        })
    }

    fn key_values(items: &[Value]) -> Result<Vec<KeyValue>, String> {
        items
            .iter()
            .map(|item| {
                Ok(KeyValue {
                    key: text(item, "key", "key"),
                    value: item.get("value").map(any_value).transpose()?,
                })
            })
            .collect()
    }

    fn any_value(value: &Value) -> Result<AnyValue, String> {
        let pick = |camel, snake| member(value, camel, snake);
        let found = if let Some(text) = pick("stringValue", "string_value") {
            Some(V::String(text.as_str().unwrap_or_default().to_owned()))
        } else if let Some(flag) = pick("boolValue", "bool_value") {
            Some(V::Bool(flag.as_bool().unwrap_or_default()))
        } else if let Some(number) = pick("intValue", "int_value") {
            let number = integer(Some(number), "intValue")?.unwrap_or(0);
            Some(V::Int(
                i64::try_from(number).map_err(|_| "`intValue` is out of range".to_owned())?,
            ))
        } else if let Some(number) = pick("doubleValue", "double_value") {
            Some(V::Double(match number {
                Value::String(text) => text
                    .parse()
                    .map_err(|_| "`doubleValue` is not a number".to_owned())?,
                other => other.as_f64().unwrap_or_default(),
            }))
        } else if let Some(array) = pick("arrayValue", "array_value") {
            Some(V::Array(ArrayValue {
                values: list(array, "values", "values")?
                    .iter()
                    .map(any_value)
                    .collect::<Result<_, _>>()?,
            }))
        } else if let Some(pairs) = pick("kvlistValue", "kvlist_value") {
            Some(V::KeyValues(KeyValueList {
                values: key_values(list(pairs, "values", "values")?)?,
            }))
        } else if let Some(bytes) = pick("bytesValue", "bytes_value") {
            let text = bytes.as_str().unwrap_or_default();
            Some(V::Bytes(
                super::unbase64(text).ok_or_else(|| "`bytesValue` is not base64".to_owned())?,
            ))
        } else {
            None
        };
        Ok(AnyValue { value: found })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::proto::{
        ArrayValue, InstrumentationScope, KeyValueList, Resource, ResourceLogs, ScopeLogs,
        Value as V,
    };
    use super::*;

    fn pair(key: &str, value: V) -> KeyValue {
        KeyValue {
            key: key.to_owned(),
            value: Some(AnyValue { value: Some(value) }),
        }
    }

    fn request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![pair("service.name", V::String("auth".to_owned()))],
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: "auth.login".to_owned(),
                        version: "1.2.0".to_owned(),
                        attributes: vec![],
                    }),
                    log_records: vec![
                        LogRecord {
                            time_unix_nano: 1_790_589_600_123_000_000,
                            observed_time_unix_nano: 1_790_589_600_200_000_000,
                            severity_number: 9,
                            severity_text: "INFO".to_owned(),
                            body: Some(AnyValue {
                                value: Some(V::String("user adam signed in".to_owned())),
                            }),
                            attributes: vec![
                                pair("user.name", V::String("adam".to_owned())),
                                pair("http.status_code", V::Int(200)),
                                pair("ok", V::Bool(true)),
                                pair("ratio", V::Double(0.5)),
                                pair(
                                    "roles",
                                    V::Array(ArrayValue {
                                        values: vec![AnyValue {
                                            value: Some(V::String("admin".to_owned())),
                                        }],
                                    }),
                                ),
                                pair(
                                    "client",
                                    V::KeyValues(KeyValueList {
                                        values: vec![pair("ip", V::String("10.0.0.7".to_owned()))],
                                    }),
                                ),
                                pair("raw", V::Bytes(b"hi!?".to_vec())),
                            ],
                            trace_id: vec![0x5b, 0x8e, 0xff, 0xf7],
                            span_id: vec![0xee, 0xe1],
                            event_name: "login".to_owned(),
                        },
                        LogRecord {
                            observed_time_unix_nano: 1_790_589_601_000_000_000,
                            ..LogRecord::default()
                        },
                    ],
                }],
            }],
        }
    }

    fn expected() -> [Value; 2] {
        [
            json!({
                "time": "2026-09-28T10:00:00.123Z",
                "observed_time": "2026-09-28T10:00:00.2Z",
                "severity_number": 9,
                "severity_text": "INFO",
                "body": "user adam signed in",
                "attributes": {
                    "user.name": "adam", "http.status_code": 200, "ok": true, "ratio": 0.5,
                    "roles": ["admin"], "client": { "ip": "10.0.0.7" }, "raw": "aGkhPw==",
                },
                "resource": { "service.name": "auth" },
                "scope": { "name": "auth.login", "version": "1.2.0" },
                "trace_id": "5b8efff7",
                "span_id": "eee1",
                "event_name": "login",
            }),
            json!({
                "time": "2026-09-28T10:00:01Z",
                "observed_time": "2026-09-28T10:00:01Z",
                "resource": { "service.name": "auth" },
                "scope": { "name": "auth.login", "version": "1.2.0" },
            }),
        ]
    }

    fn parsed(lines: &[u8]) -> Vec<Value> {
        lines
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    #[test]
    fn a_protobuf_request_becomes_one_json_line_per_record() {
        let (lines, count) = lines(&request().encode_to_vec(), Encoding::Protobuf).unwrap();
        assert_eq!(count, 2);
        assert_eq!(parsed(&lines), expected());
    }

    #[test]
    fn the_json_encoding_gives_the_same_lines() {
        let body = json!({
            "resourceLogs": [{
                "resource": { "attributes": [{ "key": "service.name", "value": { "stringValue": "auth" } }] },
                "scopeLogs": [{
                    "scope": { "name": "auth.login", "version": "1.2.0" },
                    "logRecords": [
                        {
                            "timeUnixNano": "1790589600123000000",
                            "observedTimeUnixNano": 1_790_589_600_200_000_000_u64,
                            "severityNumber": 9,
                            "severityText": "INFO",
                            "body": { "stringValue": "user adam signed in" },
                            "attributes": [
                                { "key": "user.name", "value": { "stringValue": "adam" } },
                                { "key": "http.status_code", "value": { "intValue": "200" } },
                                { "key": "ok", "value": { "boolValue": true } },
                                { "key": "ratio", "value": { "doubleValue": 0.5 } },
                                { "key": "roles", "value": { "arrayValue": { "values": [{ "stringValue": "admin" }] } } },
                                { "key": "client", "value": { "kvlistValue": { "values": [{ "key": "ip", "value": { "stringValue": "10.0.0.7" } }] } } },
                                { "key": "raw", "value": { "bytesValue": "aGkhPw==" } }
                            ],
                            "traceId": "5B8EFFF7",
                            "spanId": "eee1",
                            "eventName": "login"
                        },
                        { "observed_time_unix_nano": "1790589601000000000" }
                    ]
                }]
            }]
        });
        let (lines, count) = lines(&serde_json::to_vec(&body).unwrap(), Encoding::Json).unwrap();
        assert_eq!(count, 2);
        assert_eq!(parsed(&lines), expected());
    }

    #[test]
    fn what_is_not_an_export_request_is_refused() {
        assert!(lines(b"\xff\xff\xff", Encoding::Protobuf).is_err());
        assert!(lines(b"[]", Encoding::Json).is_err());
        assert!(lines(br#"{"resourceLogs": 1}"#, Encoding::Json).is_err());
        assert!(
            lines(
                br#"{"resourceLogs": [{"scopeLogs": [{"logRecords": [{"traceId": "xyz"}]}]}]}"#,
                Encoding::Json
            )
            .is_err()
        );
        assert_eq!(lines(b"{}", Encoding::Json).unwrap().1, 0);
        assert_eq!(lines(b"", Encoding::Protobuf).unwrap().1, 0);
    }

    #[test]
    fn base64_goes_both_ways() {
        for bytes in [&b""[..], b"h", b"hi", b"hi!", b"hi!?", &[0, 255, 128, 7, 9]] {
            assert_eq!(unbase64(&base64(bytes)).unwrap(), bytes);
        }
        assert_eq!(base64(b"hi!?"), "aGkhPw==");
        assert_eq!(
            Encoding::of("application/json; charset=utf-8"),
            Some(Encoding::Json)
        );
        assert_eq!(Encoding::of("text/plain"), None);
    }
}
