//! The section-rename seam as a nameable decision (M53): ld64's
//! `-rename_section orgSegment orgSection newSegment newSection`
//! ("Renames section orgSegment/orgSection to newSegment/newSection")
//! stops being an unreachable shape and becomes a validated table on
//! [`crate::layout::LinkConfig`] — the rename map the Pass-3
//! classification consults before grouping, so a renamed input section
//! groups with its new name and lands in the new segment (the
//! protections follow the segment the way ld64's reader-level rename
//! does). The default (the empty map) keeps every pre-M53 link
//! byte-identical — the classification pair rides every link it always
//! did.
//!
//! The decision is *validated, not defaulted*: every name is bounded by
//! the Mach-O 16-byte name field (`segment_command_64.segname`,
//! `section_64.sectname` — ld64's own `-rename_section segment name max
//! 16 chars` check), an empty name is the absence of a decision, a
//! source enters the map once (a repeated source is a typo, the
//! `-sub_client` convention), and a target the house synthesizes
//! (`__unwind_info`, `__chain_starts`, `__init_offsets`, `__common`)
//! refuses — a renamed input joining a synthetic bucket would corrupt
//! the section the synthesis speaks for. A source must not collide with
//! a synthetic target either: an input section the house already merges
//! by type or by synthesis is not a rename's to name.
//!
//! The knob refuses where it cannot land: the Pass-3 buckets are the
//! M1 trio (`__TEXT`/`__DATA_CONST`/`__DATA`) — a rename outside the
//! trio refuses at layout with the segment named (the classification's
//! own limit, the driver surfaces it through the link). The relocatable
//! output never reads the map: its section table is the input's,
//! verbatim (the M41/M43/M47 inert-for-relocatable shape).

/// The Mach-O segment/section name field width: a
/// `segment_command_64.segname` / `section_64.sectname` field carries 16
/// bytes — ld64's `-rename_section segment name max 16 chars` validation.
pub const NAME_FIELD_MAX: usize = 16;

/// The house-synthesized section targets a rename must not name: the
/// buckets the linker plans itself (the M34 unwind synthesis, the
/// chained-fixups static mirror, the M16 offsets transform, the
/// zero-fill/commons type merge). A renamed input joining a synthetic
/// bucket would corrupt the section the synthesis speaks for.
const SYNTHETIC_TARGETS: [(&str, &str); 4] = [
    ("__TEXT", "__unwind_info"),
    ("__TEXT", "__chain_starts"),
    ("__TEXT", "__init_offsets"),
    ("__DATA", "__common"),
];

/// One validated rename: the source `(segment, section)` pair an input
/// section carries, the target pair the output carries.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionRename {
    from_seg: String,
    from_sect: String,
    to_seg: String,
    to_sect: String,
}

impl SectionRename {
    /// Validates one `-rename_section` value: every name non-empty and
    /// within the Mach-O 16-byte field width. The refusal names the fix
    /// (the house error convention) — the driver renders it as miette
    /// help text, the wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`RenameError::Empty`] on an empty name,
    /// [`RenameError::TooLong`] on a name over the 16-byte field width.
    pub fn from_flag(
        from_seg: &str,
        from_sect: &str,
        to_seg: &str,
        to_sect: &str,
    ) -> Result<Self, RenameError> {
        for (field, raw) in [
            ("source segment", from_seg),
            ("source section", from_sect),
            ("target segment", to_seg),
            ("target section", to_sect),
        ] {
            validate_name(field, raw)?;
        }
        tracing::debug!(
            from = %format!("{from_seg},{from_sect}"),
            to = %format!("{to_seg},{to_sect}"),
            "the rename seam names a section rename"
        );
        Ok(Self {
            from_seg: from_seg.to_string(),
            from_sect: from_sect.to_string(),
            to_seg: to_seg.to_string(),
            to_sect: to_sect.to_string(),
        })
    }

    /// The source segment name (the input pair the map reads).
    #[must_use]
    pub fn from_seg(&self) -> &str {
        &self.from_seg
    }

    /// The source section name.
    #[must_use]
    pub fn from_sect(&self) -> &str {
        &self.from_sect
    }

    /// The target segment name (the output pair the classification
    /// writes).
    #[must_use]
    pub fn to_seg(&self) -> &str {
        &self.to_seg
    }

    /// The target section name.
    #[must_use]
    pub fn to_sect(&self) -> &str {
        &self.to_sect
    }
}

/// Validates one rename name: non-empty, within the 16-byte field
/// width. The message names which field refused and the rule (the fix).
fn validate_name(field: &'static str, raw: &str) -> Result<(), RenameError> {
    if raw.is_empty() {
        return Err(RenameError::Empty { field });
    }
    if raw.len() > NAME_FIELD_MAX {
        return Err(RenameError::TooLong {
            field,
            raw: raw.to_string(),
        });
    }
    Ok(())
}

/// The rename grammar's refusals: the verdict names the field and the
/// rule; the driver renders the rule as the fix (the house convention —
/// the seam's refusal rides the help, not just the verdict).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenameError {
    /// An empty name is the absence of a section, not a decision.
    #[error(
        "invalid -rename_section name: the {field} must be non-empty — a name is the pair the classification reads"
    )]
    Empty {
        /// Which name refused (the message names it).
        field: &'static str,
    },
    /// The Mach-O name field carries 16 bytes — ld64's own
    /// `-rename_section segment name max 16 chars` check.
    #[error(
        "invalid -rename_section name {raw:?}: the {field} exceeds the 16-byte Mach-O name field (max 16 chars)"
    )]
    TooLong {
        /// Which name refused (the message names it).
        field: &'static str,
        /// The refused name as written.
        raw: String,
    },
    /// The target names a section the house synthesizes — a renamed
    /// input joining the synthetic bucket would corrupt the section the
    /// synthesis speaks for.
    #[error(
        "invalid -rename_section target {seg}/{name}: the section is house-synthesized (or the type-merged __common) — the rename must not name it"
    )]
    SyntheticTarget {
        /// The refused target segment.
        seg: String,
        /// The refused target section.
        name: String,
    },
    /// The source names a section the house already merges by type or
    /// synthesis — a rename's source must be a regular input section.
    #[error(
        "invalid -rename_section source {seg}/{name}: the section is house-synthesized (or the type-merged __common) — the rename must not name it"
    )]
    SyntheticSource {
        /// The refused source segment.
        seg: String,
        /// The refused source section.
        name: String,
    },
    /// The seam names a source once; a repeat is a typo — drop it.
    #[error(
        "duplicate -rename_section source {seg}/{name}: the seam names a source once — drop the repeated entry"
    )]
    DuplicateSource {
        /// The refused source segment.
        seg: String,
        /// The refused source section.
        name: String,
    },
}

/// The rename table: the ordered rename list a link's classification
/// consults (flag order — the first matching entry renames the section,
/// the deterministic order the seam's tests pin). Constructed through
/// [`SectionRenames::new`] so a table in hand is always a legal map
/// (the validated-table convention — the `SubClient` shape).
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectionRenames {
    entries: Vec<SectionRename>,
}

impl SectionRenames {
    /// Validates and assembles the rename table: every entry through
    /// [`SectionRename::from_flag`], no doubled source, no synthetic
    /// source or target. The default is the empty table — every pre-M53
    /// link is byte-identical.
    ///
    /// # Errors
    /// [`RenameError::TooLong`] / [`RenameError::Empty`] on a name
    /// outside the grammar, [`RenameError::SyntheticTarget`] /
    /// [`RenameError::SyntheticSource`] on a synthetic pair,
    /// [`RenameError::DuplicateSource`] on a doubled source.
    pub fn new(entries: Vec<(&str, &str, &str, &str)>) -> Result<Self, RenameError> {
        let mut table = Self {
            entries: Vec::with_capacity(entries.len()),
        };
        for (from_seg, from_sect, to_seg, to_sect) in entries {
            let rename = SectionRename::from_flag(from_seg, from_sect, to_seg, to_sect)?;
            if SYNTHETIC_TARGETS.contains(&(rename.from_seg.as_str(), rename.from_sect.as_str())) {
                return Err(RenameError::SyntheticSource {
                    seg: rename.from_seg.clone(),
                    name: rename.from_sect.clone(),
                });
            }
            if SYNTHETIC_TARGETS.contains(&(rename.to_seg.as_str(), rename.to_sect.as_str())) {
                return Err(RenameError::SyntheticTarget {
                    seg: rename.to_seg.clone(),
                    name: rename.to_sect.clone(),
                });
            }
            if table
                .entries
                .iter()
                .any(|e| e.from_seg == rename.from_seg && e.from_sect == rename.from_sect)
            {
                return Err(RenameError::DuplicateSource {
                    seg: rename.from_seg.clone(),
                    name: rename.from_sect.clone(),
                });
            }
            table.entries.push(rename);
        }
        tracing::debug!(count = table.entries.len(), "the rename seam names its map");
        Ok(table)
    }

    /// Appends one validated rename, re-paying the table's invariants:
    /// no synthetic source or target, no doubled source (the driver's
    /// parse loop builds the table flag-by-flag — the same refusals
    /// [`SectionRenames::new`] pays, one entry at a time).
    ///
    /// # Errors
    /// [`RenameError::SyntheticTarget`] / [`RenameError::SyntheticSource`]
    /// on a synthetic pair, [`RenameError::DuplicateSource`] on a source
    /// the table already names.
    pub fn push(&mut self, rename: SectionRename) -> Result<(), RenameError> {
        if SYNTHETIC_TARGETS.contains(&(rename.from_seg.as_str(), rename.from_sect.as_str())) {
            return Err(RenameError::SyntheticSource {
                seg: rename.from_seg.clone(),
                name: rename.from_sect.clone(),
            });
        }
        if SYNTHETIC_TARGETS.contains(&(rename.to_seg.as_str(), rename.to_sect.as_str())) {
            return Err(RenameError::SyntheticTarget {
                seg: rename.to_seg.clone(),
                name: rename.to_sect.clone(),
            });
        }
        if self
            .entries
            .iter()
            .any(|e| e.from_seg == rename.from_seg && e.from_sect == rename.from_sect)
        {
            return Err(RenameError::DuplicateSource {
                seg: rename.from_seg.clone(),
                name: rename.from_sect.clone(),
            });
        }
        self.entries.push(rename);
        Ok(())
    }

    /// The table's entry count (the driver's surface test reads it).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the map is empty (the default — every pre-M53 shape).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The renames, in flag order (the wire's encode loop reads them).
    pub fn iter(&self) -> impl Iterator<Item = &SectionRename> {
        self.entries.iter()
    }

    /// The classification-time lookup (the Pass-3 seam): the first entry
    /// naming the pair renames it — the renamed pair is the pair every
    /// later classification rule sees (ld64's reader-level rename). A
    /// miss returns `None` (the caller rides the input pair).
    #[must_use]
    pub fn apply(&self, seg: &str, name: &str) -> Option<(&str, &str)> {
        self.entries
            .iter()
            .find(|e| e.from_seg == seg && e.from_sect == name)
            .map(|e| (e.to_seg.as_str(), e.to_sect.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_table_is_the_default() {
        let table = SectionRenames::default();
        assert!(table.is_empty(), "the default carries no renames");
        assert_eq!(
            table.apply("__DATA", "__data"),
            None,
            "an empty map renames nothing"
        );
    }

    #[test]
    fn the_map_renames_the_first_matching_pair() {
        let table = SectionRenames::new(vec![("__DATA", "__mydata", "__DATA_CONST", "__mydata")])
            .expect("the table builds");
        assert_eq!(table.len(), 1, "the table names one rename");
        assert_eq!(
            table.apply("__DATA", "__mydata"),
            Some(("__DATA_CONST", "__mydata")),
            "the source pair renames"
        );
        assert_eq!(
            table.apply("__DATA", "__other"),
            None,
            "an unmatched pair rides unnamed"
        );
    }

    #[test]
    fn the_grammar_refuses_the_shapes_the_docs_name() {
        assert!(
            SectionRenames::new(vec![("__DATA", "", "__DATA", "__x")]).is_err(),
            "an empty name refuses"
        );
        assert!(
            SectionRenames::new(vec![(
                "__DATA",
                "__mydata",
                "__DATA",
                "____________________x"
            )])
            .is_err(),
            "an over-wide name refuses"
        );
        assert!(
            SectionRenames::new(vec![("__TEXT", "__unwind_info", "__DATA", "__x")]).is_err(),
            "a synthetic source refuses"
        );
        assert!(
            SectionRenames::new(vec![("__DATA", "__mydata", "__DATA", "__common")]).is_err(),
            "a synthetic target refuses"
        );
        assert!(
            SectionRenames::new(vec![
                ("__DATA", "__mydata", "__DATA", "__one"),
                ("__DATA", "__mydata", "__DATA", "__two"),
            ])
            .is_err(),
            "a doubled source refuses"
        );
    }
}
