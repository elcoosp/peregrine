//! The segment protections as a nameable decision (M17): the
//! per-segment `maxprot`/`initprot` pairs stop being the layout's
//! hard-coded table (`__TEXT` RX/RX, `__DATA_CONST`/`__DATA` RW/RW,
//! `__LINKEDIT` R/R — `layout.rs`'s packing match) and become a
//! validated value on [`crate::layout::LinkConfig`] — the seam the
//! segment packing reads when it plans each `LC_SEGMENT_64` (the emit
//! copies the planned pair into the command's `maxprot`/`initprot`
//! fields). The driver's `-segprot <seg> <max> <init>` flag names the
//! decisions on the command line; the daemon wire (v10) carries them so
//! a resident relink protects the segments the client named.
//!
//! The decisions are *validated, not defaulted* — three contracts, each
//! refusal naming the fix (the house error convention):
//!
//! 1. **The grammar**: a protection is a subset of `rwx`, each letter
//!    at most once (ld64's grammar), mapped onto the `VM_PROT_*` bits
//!    ([`pgr_format::consts::VM_PROT_READ`] and friends). Bits outside
//!    the family refuse on the raw constructor too — the wire pays the
//!    same validation the flag does, so a foreign frame is malformed,
//!    never a silently widened mapping.
//! 2. **The kernel rule**: the initial protection never carries bits
//!    the maximum lacks (`initprot ⊆ maxprot` — the kernel maps a page
//!    within its ceiling, never above it).
//! 3. **The W^X contract**: an initial mapping is never writable *and*
//!    executable — arm64 macOS kills the process at exec time. A
//!    writable+executable *ceiling* stays legal (`maxprot` is what
//!    `mprotect` may raise to, not what the kernel maps at load).
//!
//! The names are the layout's planned segments ([`SegName`]):
//! `__TEXT`, `__DATA_CONST`, `__DATA`, `__LINKEDIT`. `__PAGEZERO`
//! refuses — it is the unmapped prefix and carries
//! [`pgr_format::consts::VM_PROT_NONE`] by contract (the verifier's
//! protection half names a fixture that breaks it). One decision per
//! segment: a second `-segprot` for the same name is a refusal, not a
//! last-write-wins surprise. Every segment left unnamed keeps the house
//! pair — the default decision set is empty and every pre-M17 link
//! plans byte-for-byte what it planned before.

use pgr_format::consts::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};

/// A planned output segment: the four names `-segprot` accepts (the
/// layout's packing order; `__PAGEZERO` is not one of them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegName {
    /// The code segment (`__TEXT`).
    Text,
    /// The constant-data segment (`__DATA_CONST`).
    DataConst,
    /// The writable-data segment (`__DATA`).
    Data,
    /// The link-edit segment (`__LINKEDIT`).
    Linkedit,
}

impl SegName {
    /// Every planned segment, in canonical order.
    pub const ALL: [SegName; 4] = [
        SegName::Text,
        SegName::DataConst,
        SegName::Data,
        SegName::Linkedit,
    ];

    /// The Mach-O segment name as the image spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            SegName::Text => "__TEXT",
            SegName::DataConst => "__DATA_CONST",
            SegName::Data => "__DATA",
            SegName::Linkedit => "__LINKEDIT",
        }
    }

    /// Parses a `-segprot` segment name: one of [`Self::ALL`]'s names.
    ///
    /// # Errors
    /// [`SegProtError::UnknownSegment`] on any other name — the refusal
    /// names the planned set, so the fix (not just the verdict) is one
    /// line away.
    pub fn parse(name: &str) -> Result<Self, SegProtError> {
        let parsed = Self::ALL.iter().copied().find(|s| s.name() == name);
        match parsed {
            Some(s) => {
                tracing::debug!(
                    segment = s.name(),
                    "the segment protection names its segment"
                );
                Ok(s)
            }
            None => Err(SegProtError::UnknownSegment {
                name: name.to_string(),
            }),
        }
    }
}

/// One segment's protection pair: the maximum (the `mprotect` ceiling)
/// and the initial mapping (what the kernel loads the segment with).
///
/// Constructed through [`SegProt::parse`] (the `rwx` grammar) or
/// [`SegProt::from_bits`] (the wire's raw form) — both validate the
/// same contracts, so a caller cannot bypass the kernel rule through
/// the raw door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegProt {
    maxprot: u32,
    initprot: u32,
}

impl SegProt {
    /// Validates a raw pair (the wire and the fixture knob's form):
    /// both values carry only `VM_PROT_*` bits, the initial mapping fits
    /// the maximum, and the initial mapping is never writable and
    /// executable.
    ///
    /// # Errors
    /// [`SegProtError::UnknownBits`] outside the `VM_PROT_*` family,
    /// [`SegProtError::InitBeyondMax`] when the initial mapping exceeds
    /// the ceiling, [`SegProtError::WritableExecutable`] on a W+X
    /// initial mapping.
    pub fn from_bits(maxprot: u32, initprot: u32) -> Result<Self, SegProtError> {
        let known = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
        if maxprot & !known != 0 || initprot & !known != 0 {
            return Err(SegProtError::UnknownBits {
                raw: if maxprot & !known != 0 {
                    maxprot
                } else {
                    initprot
                },
            });
        }
        if initprot & !maxprot != 0 {
            return Err(SegProtError::InitBeyondMax { initprot, maxprot });
        }
        if initprot & (VM_PROT_WRITE | VM_PROT_EXECUTE) == (VM_PROT_WRITE | VM_PROT_EXECUTE) {
            return Err(SegProtError::WritableExecutable { initprot });
        }
        Ok(Self { maxprot, initprot })
    }

    /// Parses the `rwx` grammar (ld64's form): a non-empty subset of
    /// `r`, `w`, `x`, each letter at most once.
    ///
    /// # Errors
    /// [`SegProtError::Grammar`] on anything else — the refusal names
    /// the grammar, so the fix (not just the verdict) is one line away.
    pub fn parse(max: &str, init: &str) -> Result<Self, SegProtError> {
        let maxprot = Self::parse_rwx(max)?;
        let initprot = Self::parse_rwx(init)?;
        Self::from_bits(maxprot, initprot)
    }

    /// `rwx` → `VM_PROT_*` bits; empty strings and repeated letters
    /// refuse (the grammar the fix names).
    fn parse_rwx(raw: &str) -> Result<u32, SegProtError> {
        let mut bits = 0u32;
        for ch in raw.chars() {
            let bit = match ch {
                'r' => VM_PROT_READ,
                'w' => VM_PROT_WRITE,
                'x' => VM_PROT_EXECUTE,
                _ => return Err(SegProtError::Grammar { raw: raw.into() }),
            };
            if bits & bit != 0 {
                return Err(SegProtError::Grammar { raw: raw.into() });
            }
            bits |= bit;
        }
        if bits == 0 {
            return Err(SegProtError::Grammar { raw: raw.into() });
        }
        Ok(bits)
    }

    /// The maximum protection (the `mprotect` ceiling).
    #[must_use]
    pub const fn maxprot(self) -> u32 {
        self.maxprot
    }

    /// The initial mapping (what the kernel loads the segment with).
    #[must_use]
    pub const fn initprot(self) -> u32 {
        self.initprot
    }
}

/// The `-segprot` decisions a link plans with: the named segments'
/// protection pairs, every unnamed segment keeping the layout's house
/// pair. Empty is the default — every pre-M17 link plans byte-for-byte
/// what it planned before.
///
/// Constructed entry-by-entry through [`SegProts::insert`] (which pays
/// the full validation and refuses a second decision for one segment);
/// read through [`SegProts::prot_for`] (the layout's one read) or
/// [`SegProts::iter`] (the wire's encode walk).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SegProts {
    entries: Vec<(SegName, SegProt)>,
}

impl SegProts {
    /// Adds a decision. The value is validated here (not at read time),
    /// so a [`SegProts`] in hand is always a legal table.
    ///
    /// # Errors
    /// The [`SegProtError`] the value fails with, plus
    /// [`SegProtError::Duplicate`] when the segment already carries a
    /// decision (one decision per segment — a second `-segprot` is a
    /// refusal, not a last-write-wins surprise).
    pub fn insert(&mut self, seg: SegName, prot: SegProt) -> Result<(), SegProtError> {
        if self.entries.iter().any(|(s, _)| *s == seg) {
            return Err(SegProtError::Duplicate {
                seg: seg.name().to_string(),
            });
        }
        tracing::debug!(
            segment = seg.name(),
            maxprot = prot.maxprot(),
            initprot = prot.initprot(),
            "the segment protection names its pair"
        );
        self.entries.push((seg, prot));
        Ok(())
    }

    /// The named segment's decision, `None` when it keeps the house
    /// pair (the layout's one read).
    #[must_use]
    pub fn prot_for(&self, seg: &str) -> Option<SegProt> {
        self.entries
            .iter()
            .find(|(s, _)| s.name() == seg)
            .map(|(_, p)| *p)
    }

    /// The decisions in insertion order (the wire's encode walk).
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, SegProt)> + '_ {
        self.entries.iter().map(|(s, p)| (s.name(), *p))
    }

    /// How many segments carry a named decision.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no segment is named (the default — the house table
    /// plans every segment).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A `-segprot` refusal: the message names the fix (the grammar, the
/// planned set, the kernel rule, the W^X contract), never just the
/// verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SegProtError {
    /// The protection is not a subset of `rwx` (or a letter repeats).
    #[error(
        "invalid segment protection {raw:?}: the protections are subsets of `rwx` \
         (e.g. `rw` or `rx`), each letter at most once"
    )]
    Grammar {
        /// The refused spelling as written.
        raw: String,
    },
    /// The raw form carries bits outside the `VM_PROT_*` family (the
    /// wire's door; the flag never reaches it).
    #[error(
        "invalid segment protection {raw:#x}: the bits are the `VM_PROT_*` family \
         (read 0x1, write 0x2, execute 0x4)"
    )]
    UnknownBits {
        /// The refused value.
        raw: u32,
    },
    /// The segment is not one of the layout's planned segments.
    #[error(
        "unknown segment {name}: -segprot names one of the planned segments \
         (__TEXT, __DATA_CONST, __DATA, __LINKEDIT)"
    )]
    UnknownSegment {
        /// The refused name as written.
        name: String,
    },
    /// The initial mapping carries bits the ceiling lacks (the kernel
    /// maps a page within its maxprot, never above it).
    #[error(
        "invalid segment protection: the initial mapping {initprot:#x} does not fit \
         the maxprot {maxprot:#x} (the kernel never maps above maxprot); widen the \
         max or shrink the initial protection"
    )]
    InitBeyondMax {
        /// The refused initial mapping.
        initprot: u32,
        /// The named ceiling.
        maxprot: u32,
    },
    /// The initial mapping is writable *and* executable — arm64 macOS
    /// kills the process at exec time; a W+X *ceiling* stays legal.
    #[error(
        "invalid segment protection: the initial mapping {initprot:#x} is writable \
         and executable (arm64 macOS refuses a W+X mapping); drop `w` from the \
         initial protection (the maxprot may stay the wider ceiling)"
    )]
    WritableExecutable {
        /// The refused initial mapping.
        initprot: u32,
    },
    /// The segment is named twice — one decision per segment.
    #[error("{seg} is named twice: one decision per segment (drop the second -segprot)")]
    Duplicate {
        /// The doubly-named segment.
        seg: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grammar_maps_the_bits() {
        let p = SegProt::parse("rwx", "rx").expect("the grammar accepts its subsets");
        assert_eq!(p.maxprot(), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        assert_eq!(p.initprot(), VM_PROT_READ | VM_PROT_EXECUTE);
    }

    #[test]
    fn empty_and_repeated_letters_refuse() {
        assert!(matches!(
            SegProt::parse("", "r"),
            Err(SegProtError::Grammar { .. })
        ));
        assert!(matches!(
            SegProt::parse("rr", "r"),
            Err(SegProtError::Grammar { .. })
        ));
        assert!(matches!(
            SegProt::parse("r", "wq"),
            Err(SegProtError::Grammar { .. })
        ));
    }

    #[test]
    fn the_pagezero_is_not_a_planned_segment() {
        let err = SegName::parse("__PAGEZERO").expect_err("the prefix refuses");
        assert!(err.to_string().contains("__LINKEDIT"), "{err}");
    }

    #[test]
    fn a_w_plus_x_ceiling_is_legal() {
        let p = SegProt::from_bits(
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
            VM_PROT_READ | VM_PROT_EXECUTE,
        )
        .expect("the ceiling shape validates");
        assert_eq!(p.initprot(), VM_PROT_READ | VM_PROT_EXECUTE);
    }

    #[test]
    fn the_table_is_the_house_table_when_empty() {
        let prots = SegProts::default();
        assert!(prots.is_empty());
        for seg in SegName::ALL {
            assert_eq!(
                prots.prot_for(seg.name()),
                None,
                "{} stays house",
                seg.name()
            );
        }
    }
}
