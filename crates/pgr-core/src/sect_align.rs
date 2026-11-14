//! The section-alignment floors as a nameable decision (M28): the
//! packing loop's per-section alignment stops being the input object's
//! word alone and gains a named floor on [`crate::layout::LinkConfig`]
//! — the `-sectalign <seg> <sect> <align>` flag ld64 names a section's
//! minimum alignment with (ABI contracts, page-tailed payloads, data
//! that must sit on a wider boundary). The decision is a *floor*, not a
//! replacement: the planned alignment is the max of the input's and the
//! named one, so a floor at or below the input's alignment plans the
//! pre-M28 bytes and the default (an empty table) keeps every earlier
//! link byte-identical.
//!
//! The decisions are *validated, not defaulted* — the grammar refuses
//! with the fix (the house error convention):
//!
//! 1. **The segment is one of the packing engine's section-bearing
//!    names** ([`SegName`]): `__TEXT`, `__DATA_CONST`, `__DATA`.
//!    `__LINKEDIT` refuses — the packing engine never plans a section
//!    into it, so a named floor could never land (a silent no-op, the
//!    one shape this seam does not ship).
//! 2. **The section name must survive the `section_64` field**: the
//!    name is a C string in 16 bytes — non-empty, NUL-free, at most 16
//!    bytes.
//! 3. **The value is a power of two in `[1, 0x4000]`**: an alignment
//!    exponent beyond 14 (the 16 KiB arm64 page) has no home in the
//!    verifier's section contract, and a non-power-of-two value is not
//!    an alignment at all.
//!
//! One decision per (segment, section): a second `-sectalign` for the
//! same pair is a refusal, not a last-write-wins surprise. The
//! relocatable output refuses the knob outright — its sections are the
//! input's, carried verbatim (`link_reloc`'s re-check backs the driver
//! surface's earlier refusal).

use crate::segprot::SegName;

/// One named section's alignment floor: the minimum exponent the
/// packing engine aligns the named output section to.
///
/// Constructed through [`SectAlign::from_flag`] (the `-sectalign`
/// grammar) — the wire pays the same validation through
/// [`SectAlignTable::push`], so a foreign frame is malformed, never a
/// silently widened alignment.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectAlign {
    seg: SegName,
    sect: String,
    align_log2: u32,
}

impl SectAlign {
    /// The exponent ceiling: the 16 KiB arm64 page (the `section_64`
    /// align field's contract above it is a verifier finding).
    pub const MAX_EXPONENT: u32 = 14;

    /// Validates a `-sectalign <seg> <sect> <align>` decision: the
    /// segment is one of the section-bearing names, the section name
    /// survives the 16-byte `section_64` field (non-empty, NUL-free),
    /// and the value is a power of two in `[1, 0x4000]`.
    ///
    /// # Errors
    /// [`SectAlignError`] with the fix named — the driver renders it as
    /// miette help text, the wire maps it to a malformed frame.
    pub fn from_flag(seg_raw: &str, sect_raw: &str, value: u64) -> Result<Self, SectAlignError> {
        let seg = SegName::parse(seg_raw).map_err(|e| SectAlignError::UnknownSegment {
            name: seg_raw.to_string(),
            message: e.to_string(),
        })?;
        if seg == SegName::Linkedit {
            return Err(SectAlignError::SegmentWithoutSections {
                name: seg_raw.to_string(),
            });
        }
        if sect_raw.is_empty() {
            return Err(SectAlignError::EmptySection);
        }
        if sect_raw.contains('\0') {
            return Err(SectAlignError::NulSection {
                raw: sect_raw.to_string(),
            });
        }
        if sect_raw.len() > 16 {
            return Err(SectAlignError::LongSection {
                raw: sect_raw.to_string(),
            });
        }
        let align_log2 = Self::exponent_of(value)?;
        tracing::debug!(
            segment = seg.name(),
            section = sect_raw,
            align = align_log2,
            "the sect-align floor names its section"
        );
        Ok(Self {
            seg,
            sect: sect_raw.to_string(),
            align_log2,
        })
    }

    /// The alignment exponent for a named byte value: a power of two in
    /// `[1, 0x4000]`.
    ///
    /// # Errors
    /// [`SectAlignError::NotPowerOfTwo`] off the power-of-two grammar,
    /// [`SectAlignError::BeyondPage`] beyond the 0x4000 ceiling.
    pub fn exponent_of(value: u64) -> Result<u32, SectAlignError> {
        if value == 0 || !value.is_power_of_two() {
            return Err(SectAlignError::NotPowerOfTwo { value });
        }
        let exp = value.trailing_zeros();
        if exp > Self::MAX_EXPONENT {
            return Err(SectAlignError::BeyondPage { value, exp });
        }
        Ok(exp)
    }

    /// Validates the raw exponent form (the wire's door): the segment
    /// is already parsed, the section grammar is the flag's, and the
    /// exponent stays within the ceiling — a caller cannot bypass the
    /// contract through the raw door.
    ///
    /// # Errors
    /// [`SectAlignError::EmptySection`], [`SectAlignError::NulSection`],
    /// [`SectAlignError::LongSection`], [`SectAlignError::BeyondPage`]
    /// — the same contracts the flag pays.
    pub fn from_exponent(
        seg: SegName,
        sect: &str,
        align_log2: u32,
    ) -> Result<Self, SectAlignError> {
        if sect.is_empty() {
            return Err(SectAlignError::EmptySection);
        }
        if sect.contains('\0') {
            return Err(SectAlignError::NulSection {
                raw: sect.to_string(),
            });
        }
        if sect.len() > 16 {
            return Err(SectAlignError::LongSection {
                raw: sect.to_string(),
            });
        }
        if align_log2 > Self::MAX_EXPONENT {
            return Err(SectAlignError::BeyondPage {
                value: 1u64 << align_log2.min(63),
                exp: align_log2,
            });
        }
        Ok(Self {
            seg,
            sect: sect.to_string(),
            align_log2,
        })
    }

    /// The decision's segment.
    #[must_use]
    pub const fn segment(&self) -> SegName {
        self.seg
    }

    /// The decision's section name (the `section_64` field's payload).
    #[must_use]
    pub fn section(&self) -> &str {
        &self.sect
    }

    /// The alignment exponent (`2^n` is the boundary the packing
    /// engine aligns the named section to).
    #[must_use]
    pub const fn align_log2(&self) -> u32 {
        self.align_log2
    }
}

/// A `-sectalign` refusal: the message names the fix (the grammar the
/// flag accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SectAlignError {
    /// The segment is not one of the packing engine's names — the
    /// refusal carries the planned set, so the fix is one line away.
    #[error("invalid -sectalign segment {name:?}: {message}")]
    UnknownSegment {
        /// The refused segment name as written.
        name: String,
        /// The planned set (the seam's refusal).
        message: String,
    },
    /// `__LINKEDIT` carries no sections — the packing engine never
    /// plans one into it, so a named floor could never land.
    #[error(
        "invalid -sectalign segment {name:?}: __LINKEDIT carries no sections — name \
         __TEXT, __DATA_CONST or __DATA (the segments the packing engine plans)"
    )]
    SegmentWithoutSections {
        /// The refused segment name as written.
        name: String,
    },
    /// An empty section name names nothing — the default is the
    /// absence of the knob, so an empty name is a typo.
    #[error(
        "invalid -sectalign: the section name is empty — name the section you mean \
         (e.g. __data)"
    )]
    EmptySection,
    /// The `section_64` name is a C string in 16 bytes: an interior NUL
    /// would silently truncate the name to a different section.
    #[error(
        "invalid -sectalign section {raw:?}: the name must be free of NUL bytes — \
         the section_64 field carries C strings"
    )]
    NulSection {
        /// The refused name as written.
        raw: String,
    },
    /// The `section_64` name field is 16 bytes — a longer name has no
    /// home in the format.
    #[error(
        "invalid -sectalign section {raw:?}: the name exceeds the section_64 field's \
         16 bytes — shorten it"
    )]
    LongSection {
        /// The refused name as written.
        raw: String,
    },
    /// A non-power-of-two value is not an alignment — the packing
    /// engine aligns to `2^n` boundaries only.
    #[error(
        "invalid -sectalign value {value}: the alignment must be a power of two \
         (e.g. 16 or 0x1000)"
    )]
    NotPowerOfTwo {
        /// The refused value as written.
        value: u64,
    },
    /// An exponent beyond 14 (0x4000) has no home in the verifier's
    /// section contract — the 16 KiB arm64 page is the ceiling.
    #[error(
        "invalid -sectalign value {value}: the alignment exceeds the 0x4000 ceiling \
         (exponent {exp} > 14) — the 16 KiB arm64 page is the largest boundary a \
         section can name"
    )]
    BeyondPage {
        /// The refused value as written.
        value: u64,
        /// The exponent the value would carry.
        exp: u32,
    },
    /// The (segment, section) pair is named twice — one decision per
    /// pair, never a last-write-wins surprise.
    #[error(
        "-sectalign names {},{sect} twice: one decision per (segment, section) — \
         drop the second naming or change the pair",
        seg.name()
    )]
    Duplicate {
        /// The repeated segment.
        seg: SegName,
        /// The repeated section.
        sect: String,
    },
}

/// The `-sectalign` decisions on a link: the validated table the
/// packing engine reads when it aligns each output section. The default
/// is empty — every pre-M28 link plans byte-for-byte what it planned
/// before.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectAlignTable {
    decisions: Vec<SectAlign>,
}

impl SectAlignTable {
    /// Adds one decision; a twice-named (segment, section) refuses.
    ///
    /// # Errors
    /// [`SectAlignError::Duplicate`] when the pair already carries a
    /// floor.
    pub fn push(&mut self, decision: SectAlign) -> Result<(), SectAlignError> {
        if self
            .decisions
            .iter()
            .any(|d| d.seg == decision.seg && d.sect == decision.sect)
        {
            return Err(SectAlignError::Duplicate {
                seg: decision.seg,
                sect: decision.sect,
            });
        }
        self.decisions.push(decision);
        Ok(())
    }

    /// The named (segment, section) pair's floor, if one is named. The
    /// packing engine's read: `max(input_align, floor)`.
    #[must_use]
    pub fn floor_for(&self, seg: &str, sect: &str) -> Option<u32> {
        let seg = SegName::ALL.iter().copied().find(|s| s.name() == seg)?;
        self.decisions
            .iter()
            .find(|d| d.seg == seg && d.sect == sect)
            .map(|d| d.align_log2)
    }

    /// True when no floor is named (the default — every pre-M28 link).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// The decisions in flag order (the wire's carriage order).
    pub fn iter(&self) -> impl Iterator<Item = &SectAlign> {
        self.decisions.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_validate_and_keep_the_shape() {
        let d = SectAlign::from_flag("__DATA", "__data", 0x1000).expect("ok");
        assert_eq!(d.segment().name(), "__DATA");
        assert_eq!(d.section(), "__data");
        assert_eq!(d.align_log2(), 12);
        // The ceiling is the 16 KiB page.
        assert_eq!(
            SectAlign::from_flag("__TEXT", "__text", 0x4000)
                .expect("ok")
                .align_log2(),
            14
        );
        // The smallest floor is a 1-byte alignment (exponent 0).
        assert_eq!(
            SectAlign::from_flag("__DATA", "__data", 1)
                .expect("ok")
                .align_log2(),
            0
        );
    }

    #[test]
    fn refusals_name_the_fix() {
        let err = SectAlign::from_flag("__PAGEZERO", "__data", 0x1000).expect_err("refuses");
        assert!(err.to_string().contains("__DATA"), "{err}");
        let err = SectAlign::from_flag("__DATA", "__data", 48).expect_err("refuses");
        assert!(err.to_string().contains("power of two"), "{err}");
        let err = table_dup();
        assert!(err.to_string().contains("twice"), "{err}");
    }

    fn table_dup() -> SectAlignError {
        let mut t = SectAlignTable::default();
        t.push(SectAlign::from_flag("__DATA", "__data", 8).expect("ok"))
            .expect("first lands");
        t.push(SectAlign::from_flag("__DATA", "__data", 16).expect("ok"))
            .expect_err("duplicate refuses")
    }

    #[test]
    fn the_table_reads_floors_by_name() {
        let mut t = SectAlignTable::default();
        t.push(SectAlign::from_flag("__DATA_CONST", "__got", 8).expect("ok"))
            .expect("lands");
        assert_eq!(t.floor_for("__DATA_CONST", "__got"), Some(3));
        assert_eq!(t.floor_for("__DATA", "__got"), None);
        assert_eq!(t.floor_for("__DATA_CONST", "__other"), None);
    }
}
