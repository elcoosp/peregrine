//! The dylib/bundle preferred load address as a nameable decision (M19):
//! the `__TEXT` vmaddr a non-executable image plans with stops being the
//! layout's hard-coded zero (the M3 contract `__TEXT.vmaddr == fileoff`)
//! and becomes a validated value on [`crate::layout::LinkConfig`] — the
//! same constant-delta resolver the executable's `__PAGEZERO` vmsize
//! rides (M15; [`crate::pagezero::PageZero::base_for`] is the one kind
//! table, and this decision is its dylib/bundle arm). The driver's
//! `-image_base` flag names the decision on the command line; the daemon
//! wire (v12) carries it so a resident relink lays out the base the
//! client asked for.
//!
//! The decision is *validated, not defaulted*: an override must be
//! non-zero (the default is the *absence* of the knob, not a base of
//! zero — a named zero is a typo, not a decision) and a multiple of the
//! 16 KiB arm64 page ([`pgr_format::consts::PAGE_SIZE_16K`]; every
//! segment already sits on a 16 KiB boundary under the constant-delta
//! contract, so a misaligned base would break `vmaddr ≡ fileoff
//! (mod 16 KiB)` for `__TEXT` itself). No upper bound is invented here —
//! the field is a `u64` and dyld owns the shape.
//!
//! The knob refuses where it cannot land: an executable's
//! constant-delta base is `__PAGEZERO`'s job (`-pagezero_size`, M15 —
//! one base knob per output kind, never two), and the relocatable
//! output carries no segments at all. The driver surface refuses at
//! parse time; the layout re-checks so no library caller can plan the
//! shape either.

use pgr_format::consts::PAGE_SIZE_16K;

/// The preferred load address a dylib or bundle link plans with: the
/// validated `-image_base` override. Executables and relocatable
/// outputs refuse the knob (the layout's re-check; the driver surface
/// refuses earlier) — an executable's base is the `__PAGEZERO` vmsize
/// (M15), and the relocatable output is blob-relative (M3).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageBase {
    vmaddr: u64,
}

impl ImageBase {
    /// Validates an `-image_base` override: non-zero, a multiple of the
    /// 16 KiB arm64 page. The refusal names the fix (the house error
    /// convention) — the driver renders it as miette help text, the
    /// wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`ImageBaseError::Zero`] on a zero base,
    /// [`ImageBaseError::Misaligned`] on a non-multiple of 16 KiB.
    pub fn from_override(raw: u64) -> Result<Self, ImageBaseError> {
        if raw == 0 {
            return Err(ImageBaseError::Zero);
        }
        if raw % PAGE_SIZE_16K != 0 {
            return Err(ImageBaseError::Misaligned { raw });
        }
        tracing::debug!(
            raw,
            "the dylib base names itself: an -image_base override validates"
        );
        Ok(Self { vmaddr: raw })
    }

    /// The base in bytes (the `__TEXT` vmaddr the image plans with —
    /// `vmaddr = fileoff + base` under the constant-delta contract).
    #[must_use]
    pub const fn vmaddr(self) -> u64 {
        self.vmaddr
    }

    /// The constant-delta base this config plans with: the executable's
    /// `__PAGEZERO` vmsize (M15's decision owns the executable base),
    /// the named override for dylibs and bundles (`0` when none — the
    /// M3 default), `0` for the relocatable output. One resolver, one
    /// kind table — the layout's single reader.
    #[must_use]
    pub fn constant_delta(cfg: &crate::layout::LinkConfig) -> u64 {
        cfg.pagezero.base_for(cfg.filetype, cfg.image_base.as_ref())
    }
}

/// An `-image_base` refusal: the message names the fix (the grammar
/// the flag accepts), never just the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImageBaseError {
    /// A zero base is the absence of the knob, not a decision — a named
    /// zero is a typo; drop the flag (or pass a real base).
    #[error(
        "invalid image base: a zero base is the default (drop -image_base) — \
         name a non-zero multiple of 16 KiB (e.g. 0x80000)"
    )]
    Zero,
    /// The constant-delta contract is 16 KiB-congruent (`vmaddr ≡ fileoff
    /// (mod 16 KiB)`); a misaligned base breaks it for `__TEXT` itself.
    #[error(
        "invalid image base {raw:#x}: the base must be a multiple of the 16 KiB \
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
            ImageBase::from_override(PAGE_SIZE_16K)
                .expect("one page validates")
                .vmaddr(),
            PAGE_SIZE_16K
        );
        assert_eq!(
            ImageBase::from_override(0x8000_0000)
                .expect("2 GiB validates")
                .vmaddr(),
            0x8000_0000
        );
    }

    #[test]
    fn refusals_name_the_fix() {
        let err = ImageBase::from_override(0).expect_err("zero refuses");
        assert!(err.to_string().contains("non-zero"), "{err}");
        let err = ImageBase::from_override(0x3000).expect_err("misaligned refuses");
        assert!(err.to_string().contains("16 KiB"), "{err}");
        assert!(err.to_string().contains("0x3000"), "{err}");
    }
}
