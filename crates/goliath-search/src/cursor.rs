//! Where a page of results ended.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The last event of a page, by `(time, id)`, as a search names it to read
/// the page after. Written as `<milliseconds>-<32 hex digits>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cursor {
    /// The event's time, in milliseconds since the epoch.
    pub time: i64,
    /// The event's identity.
    pub id: [u8; 16],
}

/// Text that is not a cursor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not a cursor from a previous page")]
pub struct CursorError(String);

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-", self.time)?;
        for byte in self.id {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Cursor {
    type Err = CursorError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || CursorError(text.chars().take(64).collect());
        let (time, id) = text.rsplit_once('-').ok_or_else(invalid)?;
        let time = time.parse().map_err(|_| invalid())?;
        if id.len() != 32 || !id.is_ascii() {
            return Err(invalid());
        }
        let mut bytes = [0; 16];
        for (byte, pair) in bytes.iter_mut().zip(id.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self { time, id: bytes })
    }
}

impl Serialize for Cursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cursor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_reads_back_from_its_text() {
        let cursor = Cursor {
            time: 1_727_251_200_123,
            id: [0xab; 16],
        };
        let text = cursor.to_string();
        assert_eq!(text, format!("1727251200123-{}", "ab".repeat(16)));
        assert_eq!(text.parse::<Cursor>(), Ok(cursor));
        // Times before 1970 are negative, and still read back.
        let early = Cursor {
            time: -5,
            id: [0; 16],
        };
        assert_eq!(early.to_string().parse::<Cursor>(), Ok(early));
    }

    #[test]
    fn anything_else_is_refused() {
        for text in [
            "",
            "12",
            "x-00000000000000000000000000000000",
            "1-0000",
            "1-zz000000000000000000000000000000",
            "1-ééééééééééééééééééééééééééééééé",
        ] {
            assert!(text.parse::<Cursor>().is_err(), "{text}");
        }
    }
}
