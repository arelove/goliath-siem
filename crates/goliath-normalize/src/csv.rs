//! Rows of comma-separated values, as RFC 4180 writes them and as many
//! tools export their tables.
//!
//! A row has no names of its own: the definition's `columns` gives them, in
//! the row's order. [`decode`] turns a row into one object, each value under
//! its column's name:
//!
//! ```text
//! columns: [SrcIP, DstIp, App]
//! 10.215.173.1,192.0.2.10,"Mail, the app"
//! { "SrcIP": "10.215.173.1", "DstIp": "192.0.2.10", "App": "Mail, the app" }
//! ```
//!
//! Values stay text; a definition converts what it needs. A value that is
//! empty is left out, as a source that had none would leave it out. A row
//! may end before its last columns. A row that is the names themselves, the
//! header a file starts with, is not a record and gives nothing.
//!
//! A row is one line: a quoted value that holds a line's end is not read,
//! since records are framed by lines before they are decoded.

use serde_json::{Map, Value};

/// The row `raw` as an object under the names of `columns`, or `None` for
/// the header.
pub(crate) fn decode(raw: &[u8], columns: &[String]) -> Result<Option<Value>, String> {
    let text = std::str::from_utf8(raw).map_err(|error| error.to_string())?;
    let values = values(text)?;
    if values.len() > columns.len() {
        return Err(format!(
            "the row has {} values and the definition names {} columns",
            values.len(),
            columns.len()
        ));
    }
    if values.len() > 1
        && values
            .iter()
            .zip(columns)
            .all(|(value, column)| value == column)
    {
        return Ok(None);
    }
    let mut record = Map::new();
    for (value, column) in values.into_iter().zip(columns) {
        if !value.is_empty() {
            record.insert(column.clone(), Value::String(value));
        }
    }
    Ok(Some(Value::Object(record)))
}

/// The values of one row.
fn values(row: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut rest = row;
    loop {
        let (value, after) = match rest.strip_prefix('"') {
            Some(quoted) => self::quoted(quoted)?,
            None => match rest.split_once(',') {
                Some((value, after)) => (value.to_owned(), Some(after)),
                None => (rest.to_owned(), None),
            },
        };
        values.push(value);
        match after {
            Some(after) => rest = after,
            None => return Ok(values),
        }
    }
}

/// A value after its opening quote, and what follows its comma, if any. A
/// quote within it is written twice.
fn quoted(text: &str) -> Result<(String, Option<&str>), String> {
    let mut value = String::new();
    let mut rest = text;
    loop {
        let Some((before, after)) = rest.split_once('"') else {
            return Err("a quoted value does not end".to_owned());
        };
        value.push_str(before);
        if let Some(after) = after.strip_prefix('"') {
            value.push('"');
            rest = after;
        } else if after.is_empty() {
            return Ok((value, None));
        } else if let Some(after) = after.strip_prefix(',') {
            return Ok((value, Some(after)));
        } else {
            return Err("text follows a quoted value before the comma".to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn columns() -> Vec<String> {
        ["a", "b", "c"].map(str::to_owned).to_vec()
    }

    #[test]
    fn a_row_is_an_object_under_the_names_of_its_columns() {
        assert_eq!(
            decode(b"1,two,3", &columns()),
            Ok(Some(json!({ "a": "1", "b": "two", "c": "3" })))
        );
    }

    #[test]
    fn a_quoted_value_keeps_its_commas_and_its_quotes() {
        assert_eq!(
            decode(br#""Mail, the app","say ""hi""",x"#, &columns()),
            Ok(Some(
                json!({ "a": "Mail, the app", "b": "say \"hi\"", "c": "x" })
            ))
        );
    }

    #[test]
    fn an_empty_value_is_left_out_and_a_row_may_end_early() {
        assert_eq!(
            decode(b"1,,3", &columns()),
            Ok(Some(json!({ "a": "1", "c": "3" })))
        );
        assert_eq!(
            decode(b"1,2", &columns()),
            Ok(Some(json!({ "a": "1", "b": "2" })))
        );
        assert_eq!(
            decode(b"1,2,", &columns()),
            Ok(Some(json!({ "a": "1", "b": "2" })))
        );
    }

    #[test]
    fn the_header_is_not_a_record() {
        assert_eq!(decode(b"a,b,c", &columns()), Ok(None));
        // A file whose header lacks the last columns is still a header.
        assert_eq!(decode(b"a,b", &columns()), Ok(None));
        // One value that equals the first name is a row, not a header.
        assert_eq!(decode(b"a", &columns()), Ok(Some(json!({ "a": "a" }))));
    }

    #[test]
    fn a_row_that_cannot_be_read_says_why() {
        assert_eq!(
            decode(b"1,2,3,4", &columns()),
            Err("the row has 4 values and the definition names 3 columns".to_owned())
        );
        assert_eq!(
            decode(b"\"1,2", &columns()),
            Err("a quoted value does not end".to_owned())
        );
        assert_eq!(
            decode(b"\"1\"2,3", &columns()),
            Err("text follows a quoted value before the comma".to_owned())
        );
        assert!(decode(&[0xff, b','], &columns()).is_err());
    }
}
