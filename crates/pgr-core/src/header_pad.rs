//! The header-region floor as a nameable decision (M29): the space the
//! header and its load commands occupy stops being the packing loop's
//! natural size alone and gains a named minimum on
//! [`crate::layout::LinkConfig`] — the `-headerpad <n>` flag ld64
//! reserves install-name growth room with (the space
//! `install_name_tool` needs to grow the image's load paths in place,
//! without rewriting every offset behind them). The flag rode the
//! driver surface as an advisory no-op since M1 ("commands never grow
//! after the link"); M29 promotes it to the decision the packing loop
//! reads: the reserved header region grows to at least the named floor
//! before the first `__TEXT` section, and every later byte follows.
//!
//! The decision is *validated, not defaulted* — the grammar refuses
//! with the fix (the house error convention):
//!
//! 1. **Zero names the absence of the knob** (the default decision is
//!    `None`) — a `-headerpad 0` is a typo, drop the flag.
//! 2. **The load-command alignment is 8** — the packing loop rounds
//!    the reserved region to an 8-byte boundary, so an unaligned floor
//!    would silently re-read to a different value; the grammar refuses
//!    instead.
//! 3. **The first-page contract caps the floor at 0x4000** — the
//!    header and its load commands must fit the 16 KiB first page
//!    (TDD §8.1 rule 7), so a floor beyond the page has no home in the
//!    layout at all.
//!
//! The default is `None` — every pre-M29 link plans its natural header
//! region byte-for-byte, and naming a floor at or below the natural
//! size plans the same bytes (a floor is a minimum, never a shrink).
//! The relocatable output refuses the knob outright — its sections are
//! the input's, carried verbatim (`link_reloc`'s re-check backs the
//! driver surface's earlier refusal).

/// The reserved header region an executable, dylib or bundle link
/// plans with: the minimum space the 32-byte header plus its load
/// commands occupy before the first `__TEXT` section. Dylibs and
/// bundles carry the same region (their `LC_ID_DYLIB` install names
/// are exactly the strings `install_name_tool` grows); the relocatable
/// output refuses the knob (the layout's re-check; the driver surface
/// refuses earlier).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderPad {
    floor: u64,
}

impl HeaderPad {
    /// The region ceiling: the 16 KiB arm64 first page (the TDD §8.1
    /// rule 7 contract the packing loop's overflow gate names).
    pub const MAX_BYTES: u64 = 0x4000;

    /// Validates a `-headerpad <n>` decision: non-zero (zero names the
    /// absence of the knob), a multiple of 8 (the load-command
    /// alignment the packing loop rounds the region to), within the
    /// 16 KiB first page.
    ///
    /// # Errors
    /// [`HeaderPadError::Zero`] on a zero floor,
    /// [`HeaderPadError::Unaligned`] off the 8-byte alignment,
    /// [`HeaderPadError::BeyondPage`] beyond the 0x4000 ceiling.
    pub fn from_override(raw: u64) -> Result<Self, HeaderPadError> {
        if raw == 0 {
            return Err(HeaderPadError::Zero);
        }
        if raw % 8 != 0 {
            return Err(HeaderPadError::Unaligned { raw });
        }
        if raw > Self::MAX_BYTES {
            return Err(HeaderPadError::BeyondPage { raw });
        }
        tracing::debug!(floor = raw, "the header seam names its floor");
        Ok(Self { floor: raw })
    }

    /// The named floor in bytes (the minimum the reserved region
    /// occupies before the first `__TEXT` section).
    #[must_use]
    pub const fn floor_bytes(&self) -> u64 {
        self.floor
    }
}

/// A `-headerpad` refusal: the message names the fix (the grammar the
/// flag accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderPadError {
    /// Zero names the absence of the knob, not a decision — the
    /// default *is* the absence, so `-headerpad 0` is a typo; drop the
    /// flag.
    #[error(
        "invalid headerpad 0: zero names the absence of -headerpad — drop the flag \
         or name the floor you meant (e.g. 0x2000)"
    )]
    Zero,
    /// The packing loop rounds the reserved region to an 8-byte
    /// boundary — an unaligned floor would silently re-read to a
    /// different value.
    #[error(
        "invalid headerpad {raw}: the floor must be a multiple of 8 — the load \
         commands align to 8 bytes (e.g. 0x2000)"
    )]
    Unaligned {
        /// The refused floor as written.
        raw: u64,
    },
    /// The header and its load commands must fit the 16 KiB first page
    /// (TDD §8.1 rule 7) — a floor beyond the page has no home in the
    /// layout at all.
    #[error(
        "invalid headerpad {raw}: the floor exceeds the 0x4000 first page — the \
         header and its load commands fit the 16 KiB page the loader maps"
    )]
    BeyondPage {
        /// The refused floor as written.
        raw: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_validate_and_keep_the_shape() {
        let p = HeaderPad::from_override(0x2000).expect("ok");
        assert_eq!(p.floor_bytes(), 0x2000);
        // The ceiling is the first page itself.
        assert_eq!(
            HeaderPad::from_override(0x4000).expect("ok").floor_bytes(),
            0x4000
        );
    }

    #[test]
    fn refusals_name_the_fix() {
        let err = HeaderPad::from_override(0).expect_err("zero refuses");
        assert!(err.to_string().contains("drop the flag"), "{err}");
        let err = HeaderPad::from_override(12).expect_err("unaligned refuses");
        assert!(err.to_string().contains("multiple of 8"), "{err}");
        let err = HeaderPad::from_override(0x8000).expect_err("beyond refuses");
        assert!(err.to_string().contains("0x4000"), "{err}");
    }
}
