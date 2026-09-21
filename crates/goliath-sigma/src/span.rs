//! Byte ranges into source text.

use serde::{Deserialize, Serialize};

/// A byte range into the source text a token or error came from.
///
/// Spans exist so that a parse failure can point at the offending characters.
/// Rule authoring is increasingly assisted by tooling and language models, and
/// both correct a mistake far more reliably when told where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// Byte offset of the first character.
    pub start: usize,
    /// Byte offset one past the last character.
    pub end: usize,
}

impl Span {
    /// Builds a span from a half-open byte range.
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Returns an empty span at the given offset, used to point at a position
    /// where something was expected but nothing was found.
    pub const fn empty_at(offset: usize) -> Self {
        Self {
            start: offset,
            end: offset,
        }
    }

    /// Returns the span covering both this span and `other`.
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        let start = if self.start < other.start {
            self.start
        } else {
            other.start
        };
        let end = if self.end > other.end {
            self.end
        } else {
            other.end
        };
        Self { start, end }
    }

    /// Returns the slice of `source` this span covers.
    ///
    /// Returns `None` if the span does not fall on character boundaries of
    /// `source`, which can only happen if the span came from different text.
    pub fn slice(self, source: &str) -> Option<&str> {
        source.get(self.start..self.end)
    }

    /// Returns the length of the span in bytes.
    pub const fn len(self) -> usize {
        self.end - self.start
    }

    /// Reports whether the span covers no characters.
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_the_source_it_came_from() {
        let source = "selection and not filter";
        assert_eq!(Span::new(0, 9).slice(source), Some("selection"));
        assert_eq!(Span::new(18, 24).slice(source), Some("filter"));
    }

    #[test]
    fn merging_covers_both_operands() {
        let merged = Span::new(0, 9).merge(Span::new(18, 24));
        assert_eq!(merged, Span::new(0, 24));

        // Merge is order independent.
        assert_eq!(Span::new(18, 24).merge(Span::new(0, 9)), merged);
    }

    #[test]
    fn empty_span_marks_a_position() {
        let span = Span::empty_at(7);
        assert!(span.is_empty());
        assert_eq!(span.len(), 0);
        assert_eq!(span.slice("selection"), Some(""));
    }

    #[test]
    fn out_of_bounds_span_slices_to_none() {
        assert_eq!(Span::new(0, 99).slice("short"), None);
    }
}
