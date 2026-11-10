//! The image base as a nameable decision (M15): the `__PAGEZERO` vmsize
//! stops being the layout's hard-coded 4 GiB constant (TDD §3.6 invariant
//! 1, `pgr_format::consts::PAGEZERO_SIZE_64`) and becomes a validated
//! value on [`crate::layout::LinkConfig`] — the seam the layout's
//! constant-delta contract, the fixup planner (`64_OFFSET` rebase words
//! encode `target − base`), the export trie and the verifier's segment
//! contract all read. The driver's `-pagezero_size` flag names the
//! decision on the command line; the daemon wire (v8) carries it so a
//! resident relink lays out the base the client asked for.
//!
//! The decision is *validated, not defaulted*: an override must be
//! non-zero (a zero `__PAGEZERO` puts `__TEXT` at address 0 — a shape
//! the verifier's canonical-order contract refuses) and a multiple of
//! the 16 KiB arm64 page ([`pgr_format::consts::PAGE_SIZE_16K`]; every
//! other segment already sits on a 16 KiB boundary under the constant
//! delta, so a misaligned base would break `vmaddr ≡ fileoff (mod
//! 16 KiB)` for `__TEXT` itself). Sizes above the 4 GiB default are
//! legal — the base moves `__TEXT` up, and the rebase word carries the
//! target's offset *from* the base, so a larger base does not stress the
//! word's field; the fixup planner's own range gate names an overflow
//! when one happens. No upper bound is invented here.

use crate::layout::OutputType;
use pgr_format::consts::{PAGE_SIZE_16K, PAGEZERO_SIZE_64};

/// The `__PAGEZERO` size an executable link plans with: the Mach-O arm64
/// default (4 GiB, [`Self::default_image`]) or a validated
/// `-pagezero_size` override. Dylibs, bundles and relocatable outputs
/// carry no `__PAGEZERO` (the M3 contract: `__TEXT.vmaddr == fileoff`) —
/// [`PageZero::base_for`] names that too, so the constant-delta base is
/// one decision with no second reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageZero {
    vmsize: u64,
}

impl PageZero {
    /// The Mach-O arm64 default: 4 GiB of unmapped `__PAGEZERO`
    /// (`PAGEZERO_SIZE_64` — the value every pre-M15 link planned with,
    /// bit-for-bit).
    #[must_use]
    pub fn default_image() -> Self {
        Self {
            vmsize: PAGEZERO_SIZE_64,
        }
    }

    /// The `__PAGEZERO` vmsize (the executable's constant-delta base:
    /// `vmaddr = fileoff + vmsize`).
    #[must_use]
    pub const fn vmsize(self) -> u64 {
        self.vmsize
    }

    /// Validates a `-pagezero_size` override: non-zero, a multiple of
    /// the 16 KiB arm64 page. The refusal names the fix (the house
    /// error convention) — the driver renders it as miette help text,
    /// the wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`PageZeroError::Zero`] on a zero size, [`PageZeroError::Misaligned`]
    /// on a non-multiple of 16 KiB.
    pub fn from_override(raw: u64) -> Result<Self, PageZeroError> {
        if raw == 0 {
            return Err(PageZeroError::Zero);
        }
        if raw % PAGE_SIZE_16K != 0 {
            return Err(PageZeroError::Misaligned { raw });
        }
        tracing::debug!(
            raw,
            "the image base names itself: a -pagezero_size override validates"
        );
        Ok(Self { vmsize: raw })
    }

    /// The link's constant-delta base for this output kind: the
    /// `__PAGEZERO` vmsize for executables, `0` for dylibs, bundles and
    /// relocatable outputs (the M3 contract). One function, no second
    /// reader of the kind table.
    #[must_use]
    pub const fn base_for(self, kind: OutputType) -> u64 {
        match kind {
            OutputType::Execute => self.vmsize,
            OutputType::Dylib | OutputType::Bundle | OutputType::Relocatable => 0,
        }
    }
}

impl Default for PageZero {
    fn default() -> Self {
        Self::default_image()
    }
}

/// A `-pagezero_size` refusal: the message names the fix (the grammar
/// the flag accepts), never just the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PageZeroError {
    /// A zero `__PAGEZERO` leaves `__TEXT` at address 0 — a shape the
    /// verifier's canonical-order contract refuses; the default (or any
    /// 16 KiB multiple) is the fix.
    #[error(
        "invalid __PAGEZERO size: a zero size leaves __TEXT at address 0 (use the default \
         0x1_0000_0000 or pick a non-zero multiple of 16 KiB)"
    )]
    Zero,
    /// The constant-delta contract is 16 KiB-congruent (`vmaddr ≡ fileoff
    /// (mod 16 KiB)`); a misaligned base breaks it for `__TEXT` itself.
    #[error(
        "invalid __PAGEZERO size {raw:#x}: the size must be a multiple of the 16 KiB arm64 page \
         (round up to the next 0x4000 boundary)"
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
    fn the_default_is_the_macho_constant() {
        assert_eq!(PageZero::default().vmsize(), PAGEZERO_SIZE_64);
        assert_eq!(PageZero::default_image().vmsize(), 0x1_0000_0000);
    }

    #[test]
    fn overrides_validate() {
        assert_eq!(
            PageZero::from_override(PAGE_SIZE_16K)
                .expect("one page validates")
                .vmsize(),
            PAGE_SIZE_16K
        );
        assert_eq!(
            PageZero::from_override(0x1_0000_0000)
                .expect("the default spelling validates")
                .vmsize(),
            0x1_0000_0000
        );
    }

    #[test]
    fn refusals_name_the_fix() {
        let err = PageZero::from_override(0).expect_err("zero refuses");
        assert!(
            err.to_string().contains("leaves __TEXT at address 0"),
            "{err}"
        );
        let err = PageZero::from_override(0x3000).expect_err("misaligned refuses");
        assert!(err.to_string().contains("16 KiB"), "{err}");
        assert!(err.to_string().contains("0x3000"), "{err}");
    }

    #[test]
    fn the_base_is_zero_off_executables() {
        let pz = PageZero::from_override(0x4000_0000).expect("validates");
        assert_eq!(pz.base_for(OutputType::Execute), 0x4000_0000);
        for kind in [
            OutputType::Dylib,
            OutputType::Bundle,
            OutputType::Relocatable,
        ] {
            assert_eq!(pz.base_for(kind), 0);
        }
    }
}
