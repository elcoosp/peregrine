//! Error type shared by every `pgr-format` parser.
//!
//! Design rule (TDD §5): parsers never panic on malformed input — every
//! failure is a typed [`FormatError`] carrying the byte offset that explains
//! *where* the file stopped making sense. Verifiers and fuzz targets depend on
//! that total behavior.

use thiserror::Error;

/// A recoverable, offset-tagged parse failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FormatError {
    /// The input ended before a fixed-size structure or field was complete.
    #[error("unexpected end of input at offset {offset}: need {need} bytes, have {have}")]
    Truncated {
        /// Byte offset where the read started.
        offset: usize,
        /// Bytes the read required.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },
    /// A fixed-size structure or array extended past the end of the input.
    #[error("structure at offset {offset} overruns input by {overrun} bytes")]
    Overrun {
        /// Byte offset where the structure starts.
        offset: usize,
        /// Bytes past the end of the input.
        overrun: usize,
    },
    /// An access violated the alignment the format guarantees for the type.
    #[error("unaligned access at offset {offset}, expected {align}-byte alignment")]
    Unaligned {
        /// Byte offset of the misaligned access.
        offset: usize,
        /// Required alignment in bytes.
        align: usize,
    },
    /// A field carried a value the format forbids.
    #[error("invalid {what} at offset {offset} (value {value:#x})")]
    Invalid {
        /// Byte offset of the offending field.
        offset: usize,
        /// Short description of the field.
        what: &'static str,
        /// Raw field value, for diagnostics.
        value: u64,
    },
    /// A structural violation the bit-field errors cannot express (text
    /// formats such as `.tbd` describe their own failure).
    #[error("malformed input: {what}")]
    Malformed {
        /// What was wrong.
        what: String,
    },
    /// A leading magic number did not identify a supported image.
    #[error("bad magic {magic:#x} at offset {offset}")]
    BadMagic {
        /// Byte offset of the magic field.
        offset: usize,
        /// The magic that was found.
        magic: u32,
    },
}

impl FormatError {
    /// Byte offset the error is anchored at, for verifier diagnostics.
    #[must_use]
    pub const fn offset(&self) -> usize {
        match *self {
            FormatError::Truncated { offset, .. }
            | FormatError::Overrun { offset, .. }
            | FormatError::Unaligned { offset, .. }
            | FormatError::Invalid { offset, .. }
            | FormatError::BadMagic { offset, .. } => offset,
            // Text formats do not track byte offsets; the message is the
            // diagnostic surface.
            FormatError::Malformed { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FormatError;

    #[test]
    fn offsets_are_reported() {
        let e = FormatError::Truncated {
            offset: 8,
            need: 4,
            have: 2,
        };
        assert_eq!(e.offset(), 8);
        assert!(e.to_string().contains("offset 8"));
    }

    #[test]
    fn invalid_carries_value() {
        let e = FormatError::Invalid {
            offset: 16,
            what: "cmdsize",
            value: 0,
        };
        assert_eq!(e.offset(), 16);
        assert!(e.to_string().contains("cmdsize"));
    }
}
