//! What a search may say, and what is refused before any query runs.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]

use goliath_search::{Checked, Cursor, Kind, Limits, Op, Scalar, Search, SearchError};
use serde_json::{Value, json};

fn search(value: Value) -> Search {
    serde_json::from_value(value).expect("the search parses")
}

fn day(extra: Value) -> Search {
    let mut base = json!({
        "from": "2026-09-25T00:00:00Z",
        "to": "2026-09-26T00:00:00Z",
    });
    if let (Value::Object(base), Value::Object(extra)) = (&mut base, extra) {
        base.extend(extra);
    }
    search(base)
}

fn checked(extra: Value) -> Checked {
    day(extra)
        .check(&Limits::default())
        .expect("the search passes")
}

fn refused(extra: Value) -> String {
    day(extra)
        .check(&Limits::default())
        .expect_err("the search is refused")
        .to_string()
}

fn filter(path: &str, op: &str, value: Value) -> Value {
    json!({ "filters": [{ "path": path, "op": op, "value": value }], "classes": [1007] })
}

#[test]
fn a_search_becomes_milliseconds_classes_and_typed_conditions() {
    let checked = checked(json!({
        "classes": [1007, 1007],
        "filters": [
            { "path": "process.cmd_line", "op": "contains", "value": "curl" },
            { "path": "process.pid", "op": "in", "value": [1, 2] },
            { "path": "process.file.path", "op": "exists" },
        ],
        "limit": 50,
    }));
    assert_eq!(checked.from, 1_790_294_400_000);
    assert_eq!(checked.to - checked.from, 24 * 60 * 60 * 1000);
    assert_eq!(checked.classes, [1007]);
    assert_eq!(checked.limit, 50);
    let [cmd_line, pid, path] = checked.conditions.as_slice() else {
        panic!("{:?}", checked.conditions);
    };
    assert_eq!(cmd_line.kind, Kind::Text);
    assert_eq!(cmd_line.values, [Scalar::Text("curl".to_owned())]);
    assert_eq!(pid.kind, Kind::Integer);
    assert_eq!(pid.op, Op::In);
    assert_eq!(pid.values, [Scalar::Integer(1), Scalar::Integer(2)]);
    assert!(path.values.is_empty());
}

#[test]
fn the_time_range_must_be_valid_and_bounded() {
    let bounds = |from: &str, to: &str| {
        search(json!({ "from": from, "to": to }))
            .check(&Limits::default())
            .map(|checked| checked.limit)
    };
    assert_eq!(
        bounds("2026-09-25T00:00:00Z", "2026-09-25T00:00:01Z"),
        Ok(100)
    );
    assert!(matches!(
        bounds("yesterday", "2026-09-25T00:00:00Z"),
        Err(SearchError::Time { bound: "from", .. })
    ));
    assert_eq!(
        bounds("2026-09-25T00:00:00Z", "2026-09-25T00:00:00Z"),
        Err(SearchError::EmptyRange)
    );
    assert_eq!(
        bounds("2026-01-01T00:00:00Z", "2026-09-25T00:00:00Z"),
        Err(SearchError::SpanTooLong { max_days: 31 })
    );
    assert_eq!(
        refused(json!({ "limit": 1001 })),
        "`limit` must be between 1 and 1000"
    );
    assert_eq!(
        refused(json!({ "limit": 0 })),
        "`limit` must be between 1 and 1000"
    );
}

#[test]
fn paths_are_checked_against_the_classes_searched() {
    assert_eq!(
        refused(filter("process.cmdline", "contains", json!("x"))),
        "`process.cmdline`: object `process` has no attribute `cmdline`"
    );
    assert_eq!(
        refused(json!({ "classes": [9999] })),
        "OCSF 1.5.0 has no class 9999"
    );
    // With no class named, a path of any class is accepted.
    let any = checked(json!({ "filters": [{ "path": "finding_info.title", "op": "exists" }] }));
    assert!(any.classes.is_empty());
    assert_eq!(
        refused(json!({ "filters": [{ "path": "no_such.thing", "op": "exists" }] })),
        "`no_such.thing` is not an attribute of any class"
    );
    // Both classes must have it.
    assert!(
        refused(json!({
            "classes": [1007, 3002],
            "filters": [{ "path": "process.pid", "op": "exists" }],
        }))
        .contains("has no attribute `process`")
    );
}

#[test]
fn lists_cannot_be_searched_yet() {
    assert_eq!(
        refused(json!({
            "classes": [2004],
            "filters": [{ "path": "finding_info.types", "op": "equals", "value": "T1059" }],
        })),
        "`finding_info.types` is inside a list, which searches cannot look into yet"
    );
    assert_eq!(
        refused(json!({
            "classes": [2004],
            "filters": [{ "path": "observables.value", "op": "equals", "value": "x" }],
        })),
        "`observables.value` is inside a list, which searches cannot look into yet"
    );
}

#[test]
fn operators_must_fit_what_the_attribute_holds() {
    assert_eq!(
        refused(filter("process.pid", "contains", json!(1))),
        "`contains` does not apply to `process.pid`, which holds an integer"
    );
    assert_eq!(
        refused(filter("process.cmd_line", "gt", json!("a"))),
        "`gt` does not apply to `process.cmd_line`, which holds text"
    );
    assert_eq!(
        refused(filter("process", "equals", json!("x"))),
        "`equals` does not apply to `process`, which holds an object"
    );
    assert_eq!(
        refused(filter("process.pid", "equals", json!("12"))),
        "`process.pid`: it holds an integer, but the value is text"
    );
    assert_eq!(
        refused(filter("process.cmd_line", "exists", json!("x"))),
        "`process.cmd_line`: `exists` takes no value"
    );
    assert_eq!(
        refused(filter("process.pid", "in", json!(1))),
        "`process.pid`: `in` takes a list of values"
    );
    assert_eq!(
        refused(filter("severity_id", "equals", json!(42))),
        "`severity_id`: 42 is not a defined value"
    );
    checked(filter("severity_id", "in", json!([1, 99])));
}

#[test]
fn times_may_be_written_as_text() {
    let checked = checked(filter("time", "gte", json!("2026-09-25T08:00:00Z")));
    assert_eq!(
        checked.conditions[0].values,
        [Scalar::Integer(1_790_323_200_000)]
    );
}

#[test]
fn unmapped_takes_any_path_and_compares_by_the_value() {
    let checked = checked(json!({
        "classes": [1007],
        "filters": [
            { "path": "unmapped.SYSCALL.a0", "op": "equals", "value": "55d5" },
            { "path": "unmapped.proc.tty", "op": "gt", "value": 0 },
            { "path": "unmapped.anything", "op": "exists" },
        ],
    }));
    assert!(checked.conditions.iter().all(|c| c.kind == Kind::Any));
    assert_eq!(checked.conditions[1].values, [Scalar::Integer(0)]);
    assert_eq!(
        refused(filter("unmapped.x", "contains", json!(1))),
        "`contains` does not apply to `unmapped.x`, which holds an integer"
    );
    assert_eq!(
        refused(filter("unmapped.x", "in", json!(["a", 1]))),
        "`unmapped.x`: the values of `in` must all be of one type"
    );
    for path in [
        "unmapped.a`b",
        "unmapped.a\\b",
        "unmapped.a\u{7}",
        "unmapped..a",
        "unmapped.",
    ] {
        assert!(
            matches!(
                day(filter(path, "exists", Value::Null)).check(&Limits::default()),
                Err(SearchError::Segment { .. })
            ),
            "{path:?}"
        );
    }
}

#[test]
fn a_search_cannot_ask_for_too_much() {
    let limits = Limits {
        max_filters: 2,
        max_values: 3,
        max_text: 4,
        ..Limits::default()
    };
    let three = day(json!({ "filters": [
        { "path": "time", "op": "exists" },
        { "path": "time", "op": "exists" },
        { "path": "time", "op": "exists" },
    ] }));
    assert_eq!(
        three.check(&limits),
        Err(SearchError::TooManyFilters { max: 2 })
    );
    let long = day(filter("process.cmd_line", "equals", json!("12345")));
    assert!(long.check(&limits).is_err());
    let many = day(filter("process.pid", "in", json!([1, 2, 3, 4])));
    assert!(many.check(&limits).is_err());
}

#[test]
fn unknown_members_and_operators_do_not_parse() {
    let parsed = |value: Value| serde_json::from_value::<Search>(value).is_ok();
    let base = json!({ "from": "2026-09-25T00:00:00Z", "to": "2026-09-26T00:00:00Z" });
    assert!(parsed(base.clone()));
    let mut extra = base.clone();
    extra["sql"] = json!("DROP TABLE events");
    assert!(!parsed(extra));
    let mut op = base;
    op["filters"] = json!([{ "path": "time", "op": "like", "value": "x" }]);
    assert!(!parsed(op));
}

#[test]
fn a_page_resumes_after_its_cursor() {
    let cursor: Cursor = format!("1790323200000-{}", "0f".repeat(16))
        .parse()
        .unwrap();
    let checked = checked(json!({ "after": cursor.to_string() }));
    assert_eq!(checked.after, Some(cursor));
    assert!(
        serde_json::from_value::<Search>(json!({
            "from": "2026-09-25T00:00:00Z",
            "to": "2026-09-26T00:00:00Z",
            "after": "page-2",
        }))
        .is_err()
    );
}
