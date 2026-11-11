//! The initializer-offsets seam (M16): the linker stops treating
//! `S_MOD_INIT_FUNC_POINTERS` sections as pass-through pointer content
//! and can replace them with a `__TEXT,__init_offsets` section of u32
//! offsets — each entry the initializer's distance from the image's load
//! address (the `__TEXT` vmaddr), the shape dyld has walked since the
//! chained-fixups era (`MachOAnalyzer::forEachInitializer` reads
//! `S_INIT_FUNC_OFFSETS` sections beside the pointer sections; the
//! offsets need no rebase, which is the whole point).
//!
//! The decision is the M15 shape ([`crate::pagezero`]): a validated
//! [`InitOffsets`] value on [`crate::layout::LinkConfig`] that the
//! layout's bucketing and the fixup planners (chained *and* classic —
//! the converted pointers simply leave both slot streams) read, and
//! that the driver surface and the daemon wire (v9) carry. ld64 flips
//! the transform on by default for every chained-fixups link;
//! Peregrine keeps the classic pointer form as the default — the
//! pre-M16 bytes stay bit-identical (the §7.2 lock the chain-word
//! family holds) — and names the form on the surface (`-init_offsets`
//! / `-no_init_offsets`) exactly like the chain word family names its
//! encoding. The verifier's own `init_offsets` gate (a hand-broken
//! section is named) is the next rung.
//!
//! The refusals are the M10 rung-4 slice-5 shape (a named form that
//! cannot apply is a refusal, never a silently dropped knob):
//!
//! * below the chained-fixups floor
//!   ([`pgr_format::consts::chained_fixups_floor`] — one table, now four
//!   readers) the target's dyld cannot walk `S_INIT_FUNC_OFFSETS` at
//!   all: the section would silently lose every initializer, so
//!   `-init_offsets` refuses and names the floor;
//! * the relocatable output preserves input sections verbatim (the M10
//!   rung-1 contract), so there is nothing for the transform to own —
//!   it refuses;
//! * an initializer that resolves outside an executable segment (a
//!   bind, or a pointer into `__DATA`) cannot become an offset — dyld's
//!   own load-time check ("initializer does not point within executable
//!   segment") is front-loaded into the link with the fix named.

use pgr_format::consts::S_MOD_INIT_FUNC_POINTERS;

/// Renders a packed `X.Y.Z` version word (`(X << 16) | (Y << 8) | Z`) the
/// way the refusal messages name it (`12.0.0`). `pub(crate)`: the layout's
/// floor refusal and this module's error share one renderer, never two.
pub(crate) fn version_string(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

/// The initializer form a link plans with: the M1-locked classic pointer
/// sections (every pre-M16 link, byte-identical) or the
/// `__TEXT,__init_offsets` u32-offset section.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InitOffsets {
    /// `__mod_init_func` pointer sections pass through and their slots
    /// ride the fixup plan (the M1-locked default).
    #[default]
    Classic,
    /// The pointer sections are replaced by `__TEXT,__init_offsets`
    /// (u32 offsets from the load address, input order, 4-byte aligned).
    Offsets,
}

impl InitOffsets {
    /// Validates the driver's flag pair into the link's decision (the
    /// pagezero `from_override` shape): the flag-less default stays
    /// classic, the explicit off is always valid, and the named form
    /// refuses below the platform's chained-fixups floor — the one table
    /// ([`pgr_format::consts::chained_fixups_floor`]) gating every
    /// reader.
    ///
    /// # Errors
    /// [`InitOffsetsError::BelowFloor`] when the named form rides a
    /// deployment target whose dyld cannot consume the section.
    pub fn from_flag(
        forced: Option<bool>,
        platform: u32,
        minos: u32,
    ) -> Result<Self, InitOffsetsError> {
        match forced {
            None | Some(false) => {
                tracing::debug!(
                    forced = ?forced,
                    "the initializer form stays classic (the default the tree locks)"
                );
                Ok(Self::Classic)
            }
            Some(true) => {
                let floor = pgr_format::consts::chained_fixups_floor(platform);
                if minos < floor {
                    return Err(InitOffsetsError::BelowFloor { minos, floor });
                }
                tracing::debug!(
                    platform,
                    minos,
                    "the initializer offsets form names itself: -init_offsets"
                );
                Ok(Self::Offsets)
            }
        }
    }

    /// True when the layout transforms the pointer sections.
    #[must_use]
    pub const fn is_offsets(self) -> bool {
        matches!(self, Self::Offsets)
    }
}

/// A `-init_offsets` refusal: the floor (and the fix) are named, never
/// just the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InitOffsetsError {
    /// The named form rides a deployment target below the platform's
    /// chained-fixups floor: that dyld does not walk
    /// `S_INIT_FUNC_OFFSETS` sections, so the image would silently lose
    /// every initializer. Raise the deployment target or drop the flag.
    #[error(
        "-init_offsets needs a target at or above the platform's chained-fixups floor {} \
         (the target's dyld cannot consume __init_offsets below it); \
         raise the -platform_version deployment target or use -no_init_offsets",
        version_string(*.floor)
    )]
    BelowFloor {
        /// The refused deployment target (packed `X.Y.Z`).
        minos: u32,
        /// The platform's chained-fixups floor (packed `X.Y.Z`).
        floor: u32,
    },
}

/// A `__mod_init_func` pointer section the transform consumes: the file
/// and its input-section index, in input order (objects in command-line
/// order, sections in order, entries in slot order — the same order lld
/// documents for the form).
pub(crate) struct InitSection {
    pub(crate) file: u32,
    pub(crate) in_sect: usize,
}

/// Collects the input sections the transform replaces, in input order.
/// A section whose size is not a whole pointer count refuses here — the
/// classic path would plan a misaligned slot and error later; the named
/// form refuses with the shape named.
pub(crate) fn collect_sections(
    objects: &[crate::object::InputObject],
) -> Result<Vec<InitSection>, crate::LinkError> {
    let mut specs = Vec::new();
    for (fi, obj) in objects.iter().enumerate() {
        for (si, sect) in obj.sections.iter().enumerate() {
            if sect.flags & pgr_format::consts::SECTION_TYPE_MASK == S_MOD_INIT_FUNC_POINTERS
                && sect.size > 0
            {
                if sect.size % 8 != 0 {
                    return Err(crate::LinkError::Layout {
                        message: format!(
                            "{}:{} is a __mod_init_func section whose size ({:#x}) is not a \
                             whole number of 8-byte pointers; fix the input or use \
                             -no_init_offsets",
                            obj.name, sect.name, sect.size
                        ),
                    });
                }
                specs.push(InitSection {
                    file: fi as u32,
                    in_sect: si,
                });
            }
        }
    }
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_classic() {
        assert_eq!(InitOffsets::default(), InitOffsets::Classic);
        assert!(!InitOffsets::Classic.is_offsets());
    }

    #[test]
    fn the_named_form_validates_at_the_floor() {
        let at_floor =
            InitOffsets::from_flag(Some(true), pgr_format::consts::PLATFORM_MACOS, 0x000C_0000)
                .expect("macOS 12.0 is the floor");
        assert!(at_floor.is_offsets());
        assert_eq!(
            InitOffsets::from_flag(Some(true), pgr_format::consts::PLATFORM_MACOS, 0x000E_0400)
                .expect("above the floor"),
            InitOffsets::Offsets
        );
        // The per-platform table gates every platform (the visionOS floor
        // is 1.0.0, the lowest).
        assert_eq!(
            InitOffsets::from_flag(
                Some(true),
                pgr_format::consts::PLATFORM_VISIONOS,
                0x0001_0000
            )
            .expect("visionOS 1.0 is the floor"),
            InitOffsets::Offsets
        );
    }

    #[test]
    fn refusals_name_the_floor_and_the_fix() {
        let err = InitOffsets::from_flag(Some(true), pgr_format::consts::PLATFORM_IOS, 0x000E_0000)
            .expect_err("iOS 14.0 sits below the 15.0 floor");
        let text = err.to_string();
        assert!(text.contains("15.0.0"), "the floor is named: {text}");
        assert!(
            text.contains("-no_init_offsets"),
            "the fix is named: {text}"
        );
    }

    #[test]
    fn the_explicit_off_and_the_default_never_refuse() {
        for forced in [None, Some(false)] {
            assert_eq!(
                InitOffsets::from_flag(forced, pgr_format::consts::PLATFORM_MACOS, 0)
                    .expect("classic is always valid"),
                InitOffsets::Classic
            );
        }
    }
}
