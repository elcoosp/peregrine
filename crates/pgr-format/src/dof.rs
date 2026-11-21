//! The `DTrace` `DOF` (`DTrace` Object Format) header contract (M118): the
//! `__dtrace_dof` (`S_DTRACE_DOF`) section carries a DOF payload whose
//! header the producer validates at emit (under `-dtrace`) and the
//! verifier backstops read-side (every `S_DTRACE_DOF` section in the
//! output, regardless of how it was produced). The contract is the
//! identification magic ([`DOF_MAGIC`]) and the bounds ([`DOF_ID_SIZE`])
//! the `DTrace` consumer's first walk gates on — the two gates illumos
//! `<sys/dof.h>`'s `dof_hdr` identification region names, mirrored
//! read-side so a malformed DOF section the producer never saw still
//! reports (the M115 read-side-backstop shape, one section type over).
//!
//! The classification ([`is_dtrace_dof_section`]) is the Pass-1 decision
//! distinct from the generic `S_ATTR_DEBUG` debug class: a `__dtrace_dof`
//! section is a dtrace payload (carried as load-time bytes, validated at
//! emit under the decision), never a debug shape the `-S` strip drops —
//! the M105/M118 distinction the bucketing consults.

use crate::consts::{S_DTRACE_DOF, SECTION_TYPE_MASK};

/// Re-export of the `DOF` identification region's byte width.
pub use crate::consts::DOF_ID_SIZE;
/// Re-export of the `DOF` identification magic (the four bytes `DoFD`)
/// so the [`dof`] module names the whole contract in one place.
pub use crate::consts::DOF_MAGIC;

/// Returns `true` when the section flags name a `DTrace` `DOF` payload
/// (`S_DTRACE_DOF`) — the M118 Pass-1 classification, distinct from the
/// generic `S_ATTR_DEBUG` debug class. The bucketing consults this under
/// `-dtrace` to recognize the payload (the section rides its regular
/// bucket as load-time bytes and the emit validates its DOF header); the
/// verifier consults it read-side on every output section to backstop the
/// producer's gate.
#[must_use]
pub fn is_dtrace_dof_section(flags: u32) -> bool {
    flags & SECTION_TYPE_MASK == S_DTRACE_DOF
}

/// A `DOF` header validation failure (M118): the producer refuses at emit
/// under `-dtrace` with one of these; the verifier reports the same shape
/// read-side (the backstop).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DofError {
    /// The section is too small to carry the `DOF` identification region
    /// (the magic and the version bytes the consumer reads after it).
    #[error(
        "the DOF identification region ({needed} bytes) does not fit in {have} bytes — \
         dyld's consumer gates on the magic at the head of the section"
    )]
    Bounds {
        /// The identification region's byte width (`DOF_ID_SIZE`).
        needed: usize,
        /// The section's actual byte width.
        have: usize,
    },
    /// The leading bytes are not the `DOF` identification magic.
    #[error(
        "the DOF identification magic mismatch (found {found:#?}, expected {expected:#?} — \
         the bytes `DoFD`, illumos <sys/dof.h>'s DOF_ID_MAGIC)"
    )]
    Magic {
        /// The four bytes the section carried.
        found: [u8; 4],
        /// The four bytes the consumer gates on ([`DOF_MAGIC`]).
        expected: [u8; 4],
    },
}

/// Validates the `DOF` header of a `__dtrace_dof` section's bytes: the
/// identification magic ([`DOF_MAGIC`], the four bytes `DoFD`) and the
/// bounds (the identification region [`DOF_ID_SIZE`] fits). The producer
/// calls this at emit under `-dtrace` (the section is emitted with its
/// `DOF` header validated and linked into the output); the verifier calls
/// it read-side on every `S_DTRACE_DOF` section (the backstop — a
/// malformed header the producer never saw still reports).
///
/// # Errors
/// [`DofError::Bounds`] when the section is smaller than the
/// identification region; [`DofError::Magic`] when the leading bytes are
/// not [`DOF_MAGIC`].
pub fn validate_dof_header(bytes: &[u8]) -> Result<(), DofError> {
    if bytes.len() < DOF_ID_SIZE {
        return Err(DofError::Bounds {
            needed: DOF_ID_SIZE,
            have: bytes.len(),
        });
    }
    // The bounds gate guaranteed the identification region fits, so the
    // leading four bytes are present (the magic the consumer gates on);
    // the copy is length-matched by construction (no panic surface).
    let mut found = [0u8; 4];
    found.copy_from_slice(&bytes[..DOF_MAGIC.len()]);
    if found != DOF_MAGIC {
        return Err(DofError::Magic {
            found,
            expected: DOF_MAGIC,
        });
    }
    Ok(())
}
