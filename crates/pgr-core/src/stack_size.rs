//! The stack reserve as a nameable decision (M18): the executable's
//! `LC_MAIN` stack size stops being the layout's hard-coded zero
//! (`w64(lc + 16, 0)` — dyld falls back to its own main-thread default
//! when the field is zero) and becomes a validated value on
//! [`crate::layout::LinkConfig`] — the seam the header assembly reads
//! when it writes `LC_MAIN` (the reserve rides the load command's
//! `stacksize` field; the command is 24 bytes either way, so nothing
//! else in the plan moves). The driver's `-stack_size` flag names the
//! decision on the command line; the daemon wire (v11) carries it so a
//! resident relink reserves what the client named.
//!
//! The decision is *validated, not defaulted*: an override must be
//! non-zero (the default is the *absence* of the knob, not a zero
//! reserve — a named zero is a typo, not a decision) and a multiple of
//! the 16 KiB arm64 page ([`pgr_format::consts::PAGE_SIZE_16K`]; the
//! kernel maps the stack in pages, and every other reservation in the
//! image already sits on a 16 KiB boundary). No upper bound is invented
//! here — the field is a `u64` and the kernel owns the cap.

use pgr_format::consts::PAGE_SIZE_16K;

/// The `LC_MAIN` stack reserve an executable link plans with: the
/// validated `-stack_size` override. Dylibs, bundles and relocatable
/// outputs carry no `LC_MAIN` (the M3 contract) — the knob refuses
/// there (the layout's re-check; the driver surface refuses earlier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackSize {
    bytes: u64,
}

impl StackSize {
    /// Validates a `-stack_size` override: non-zero, a multiple of the
    /// 16 KiB arm64 page. The refusal names the fix (the house error
    /// convention) — the driver renders it as miette help text, the
    /// wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`StackSizeError::Zero`] on a zero reserve,
    /// [`StackSizeError::Misaligned`] on a non-multiple of 16 KiB.
    pub fn from_override(raw: u64) -> Result<Self, StackSizeError> {
        if raw == 0 {
            return Err(StackSizeError::Zero);
        }
        if raw % PAGE_SIZE_16K != 0 {
            return Err(StackSizeError::Misaligned { raw });
        }
        tracing::debug!(
            raw,
            "the stack reserve names itself: a -stack_size override validates"
        );
        Ok(Self { bytes: raw })
    }

    /// The reserve in bytes (the `LC_MAIN.stacksize` field's value).
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// A `-stack_size` refusal: the message names the fix (the grammar
/// the flag accepts), never just the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StackSizeError {
    /// A zero reserve is the absence of the knob, not a decision — a
    /// named zero is a typo; drop the flag (or pass a real reserve).
    #[error(
        "invalid stack size: a zero reserve is the default (drop -stack_size) — \
         name a non-zero multiple of 16 KiB (e.g. 0x1000000)"
    )]
    Zero,
    /// The kernel maps the stack in pages; a misaligned reserve is a
    /// shape the loader rounds away — name the bytes you meant.
    #[error(
        "invalid stack size {raw:#x}: the reserve must be a multiple of the 16 KiB \
         arm64 page (round up to the next 0x4000 boundary)"
    )]
    Misaligned {
        /// The refused value as written.
        raw: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_validate_nonzero_and_page_alignment() {
        assert_eq!(
            StackSize::from_override(PAGE_SIZE_16K)
                .expect("one page validates")
                .bytes(),
            PAGE_SIZE_16K
        );
        assert_eq!(
            StackSize::from_override(0x100_0000)
                .expect("16 MiB validates")
                .bytes(),
            0x100_0000
        );
    }

    #[test]
    fn refusals_name_the_fix() {
        let err = StackSize::from_override(0).expect_err("zero refuses");
        assert!(err.to_string().contains("non-zero"), "{err}");
        let err = StackSize::from_override(0x3000).expect_err("misaligned refuses");
        assert!(err.to_string().contains("16 KiB"), "{err}");
        assert!(err.to_string().contains("0x3000"), "{err}");
    }
}
