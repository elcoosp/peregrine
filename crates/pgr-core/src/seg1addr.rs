//! The first segment's base address as a nameable decision (M124):
//! ld64's `-seg1addr <address>` ("Set the base address of the first
//! segment") stops being the layout's constant-delta floor (the
//! `__PAGEZERO` vmsize for executables — M15; the `-image_base` vmaddr
//! for dylibs — M19) and becomes a validated value on
//! [`crate::layout::LinkConfig`] — the same constant-delta resolver
//! [`crate::image_base::ImageBase::constant_delta`] reads, one override
//! ahead of the kind table. The driver's `-seg1addr` flag names the
//! decision on the command line; the daemon wire (v75) carries it so a
//! resident relink lays out the base the client asked for.
//!
//! The decision is *validated, not defaulted*: an override must be
//! non-zero (a zero first segment puts `__TEXT` at address 0 — a shape
//! the verifier's canonical-order contract refuses) and a multiple of
//! the 16 KiB arm64 page ([`pgr_format::consts::PAGE_SIZE_16K`]; every
//! segment already sits on a 16 KiB boundary under the constant-delta
//! contract, so a misaligned base would break `vmaddr ≡ fileoff
//! (mod 16 KiB)` for `__TEXT` itself). No upper bound is invented here —
//! the field is a `u64` and the rebase word carries `target − base`, so
//! a larger base does not stress the word's field; the fixup planner's
//! own range gate names an overflow when one happens.
//!
//! The knob refuses where it cannot land: a bundle's preferred load
//! address is its loader's job (the host process `dlopen`s the bundle
//! and maps it where it chooses — the M3 contract a bundle rides), and
//! the relocatable output carries no segments at all. The driver
//! surface refuses at parse time; the layout re-checks so no library
//! caller can plan the shape either. One base knob per output kind,
//! never two: `-seg1addr` beside `-pagezero_size` (an executable) or
//! `-image_base` (a dylib) names the same floor twice and the driver
//! surface refuses the pair.

use crate::layout::OutputType;
use pgr_format::consts::PAGE_SIZE_16K;

/// The first segment's base address an executable or dylib link plans
/// with: the validated `-seg1addr` override. Bundles (the loader
/// resolves the base) and the relocatable output (no segments) refuse
/// the knob (the layout's re-check; the driver surface refuses earlier)
/// — a bundle's base is its loader's job, and the relocatable output is
/// blob-relative (M3).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seg1Addr {
    vmaddr: u64,
}

impl Seg1Addr {
    /// Validates a `-seg1addr` override: non-zero, a multiple of the
    /// 16 KiB arm64 page. The refusal names the fix (the house error
    /// convention) — the driver renders it as miette help text, the
    /// wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`Seg1AddrError::Zero`] on a zero base,
    /// [`Seg1AddrError::Misaligned`] on a non-multiple of 16 KiB.
    pub fn from_override(raw: u64) -> Result<Self, Seg1AddrError> {
        if raw == 0 {
            return Err(Seg1AddrError::Zero);
        }
        if raw % PAGE_SIZE_16K != 0 {
            return Err(Seg1AddrError::Misaligned { raw });
        }
        tracing::debug!(
            raw,
            "the first segment's base names itself: a -seg1addr override validates"
        );
        Ok(Self { vmaddr: raw })
    }

    /// The base in bytes (the first segment's vmaddr the image plans
    /// with — `vmaddr = fileoff + base` under the constant-delta
    /// contract; for an executable this is the `__TEXT` vmaddr and the
    /// `__PAGEZERO` vmsize at once, for a dylib the `__TEXT` vmaddr).
    #[must_use]
    pub const fn vmaddr(self) -> u64 {
        self.vmaddr
    }

    /// Whether the named output kind admits the knob: executables and
    /// dylibs carry a first segment whose base the override names;
    /// bundles (the loader resolves the base) and the relocatable
    /// output (no segments) do not. One kind-table reader, shared by
    /// the layout re-check and the driver surface.
    #[must_use]
    pub const fn admits(kind: OutputType) -> bool {
        matches!(kind, OutputType::Execute | OutputType::Dylib)
    }
}

/// A `-seg1addr` refusal: the message names the fix (the grammar the
/// flag accepts), never just the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Seg1AddrError {
    /// A zero first segment leaves `__TEXT` at address 0 — a shape the
    /// verifier's canonical-order contract refuses; the constant-delta
    /// default (or any non-zero 16 KiB multiple) is the fix.
    #[error(
        "invalid first segment base: a zero base leaves __TEXT at address 0 (use the default \
         0x1_0000_0000 or pick a non-zero multiple of 16 KiB)"
    )]
    Zero,
    /// The constant-delta contract is 16 KiB-congruent (`vmaddr ≡ fileoff
    /// (mod 16 KiB)`); a misaligned base breaks it for `__TEXT` itself.
    #[error(
        "invalid first segment base {raw:#x}: the base must be a multiple of the 16 KiB arm64 \
         page (round up to the next 0x4000 boundary)"
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
            Seg1Addr::from_override(PAGE_SIZE_16K)
                .expect("one page validates")
                .vmaddr(),
            PAGE_SIZE_16K
        );
        assert_eq!(
            Seg1Addr::from_override(0x4000_0000)
                .expect("1 GiB validates")
                .vmaddr(),
            0x4000_0000
        );
        assert_eq!(
            Seg1Addr::from_override(0x1_0000_0000)
                .expect("the default spelling validates")
                .vmaddr(),
            0x1_0000_0000
        );
    }

    #[test]
    fn refusals_name_the_fix() {
        let err = Seg1Addr::from_override(0).expect_err("zero refuses");
        assert!(
            err.to_string().contains("leaves __TEXT at address 0"),
            "{err}"
        );
        let err = Seg1Addr::from_override(0x3000).expect_err("misaligned refuses");
        assert!(err.to_string().contains("16 KiB"), "{err}");
        assert!(err.to_string().contains("0x3000"), "{err}");
    }

    #[test]
    fn the_kind_table_admits_executables_and_dylibs_only() {
        assert!(Seg1Addr::admits(OutputType::Execute));
        assert!(Seg1Addr::admits(OutputType::Dylib));
        assert!(!Seg1Addr::admits(OutputType::Bundle));
        assert!(!Seg1Addr::admits(OutputType::Relocatable));
    }
}
