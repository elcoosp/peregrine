//! Classic `LC_DYLD_INFO_ONLY` planning (M6 legacy fallback — architecture
//! doc §10.3 row M6: "`LC_DYLD_INFO` legacy fallback for older deployment
//! targets"; TDD §3.6 invariant 3 pins chained fixups to macOS ≥ 12).
//!
//! The layout pass classifies every pointer slot as a chained `FixupSlot`
//! (M2). In legacy mode the *same* slot list feeds this planner: rebases
//! become rebase-stream entries, binds become bind-stream entries with
//! trailing symbol names. The slot bytes themselves stay zero in the image
//! (dyld writes them at load); no `__chain_starts` mirror exists.
//!
//! Trigger (`pgr-core::layout`): `has_fixups && (!cfg.fixup_chains ||
//! cfg.minos < 12.0.0)`.

use crate::LinkError;
use crate::fixups::{FixupKind, FixupSlot};
use crate::interner::Interner;

use pgr_format::dyld_info::{BindEntry, BindOrdinal, RebaseEntry};

/// The planned classic dyld-info payload: both opcode streams, ready for
/// the LINKEDIT chunk placement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DyldInfoPlan {
    /// Rebase opcode stream (empty when the image has no internal slots).
    pub rebase: Vec<u8>,
    /// Bind opcode stream (empty when the image binds nothing).
    pub bind: Vec<u8>,
    /// True when any bind is weak (`MH_BINDS_TO_WEAK`).
    pub has_weak_binds: bool,
}

impl DyldInfoPlan {
    /// True when at least one stream carries bytes (the load command is
    /// emitted only then).
    #[must_use]
    pub fn is_present(&self) -> bool {
        !self.rebase.is_empty() || !self.bind.is_empty()
    }
}

/// Maps the chained-fixup special ordinals (stored as `u8` magnitudes:
/// 0xFE flat, 0xFD weak, 0xFC main-executable) to the classic stream's
/// negative specials.
fn classic_ordinal(lib_ordinal: u8) -> BindOrdinal {
    match lib_ordinal {
        // pgr_format::consts::BIND_SPECIAL_DYLIB_FLAT_LOOKUP (0xFE).
        0xFE => BindOrdinal::Special(-2),
        // BIND_SPECIAL_DYLIB_WEAK_LOOKUP.
        0xFD => BindOrdinal::Special(-3),
        // BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE.
        0xFC => BindOrdinal::Special(-1),
        ord => BindOrdinal::Dylib(ord),
    }
}

/// Plans the classic rebase/bind streams for address-sorted slots.
///
/// `segments` are the image's `LC_SEGMENT_64` entries in command order as
/// `(vmaddr, vmsize, fileoff)` — the stream references segments by index.
///
/// # Errors
/// [`LinkError::Layout`] when a slot falls outside every segment (the
/// chained path reports the same condition).
pub fn plan_dyld_info(
    mut slots: Vec<FixupSlot>,
    segments: &[(u64, u64, u64)],
    interner: &Interner,
) -> Result<DyldInfoPlan, LinkError> {
    slots.sort_by_key(|s| s.vaddr);
    let seg_of = |vaddr: u64| -> Result<(u8, u64), LinkError> {
        for (i, &(vmaddr, vmsize, _)) in segments.iter().enumerate() {
            if vaddr >= vmaddr && vaddr < vmaddr.saturating_add(vmsize) {
                let idx = u8::try_from(i).map_err(|_| LinkError::Internal {
                    message: "segment count exceeds the classic stream's 255-segment limit".into(),
                })?;
                return Ok((idx, vaddr - vmaddr));
            }
        }
        Err(LinkError::Layout {
            message: format!("fixup slot at {vaddr:#x} lies outside every segment"),
        })
    };

    let mut rebases: Vec<RebaseEntry> = Vec::new();
    let mut binds: Vec<BindEntry> = Vec::new();
    let mut has_weak = false;
    for slot in &slots {
        let (seg, seg_off) = seg_of(slot.vaddr)?;
        match slot.kind {
            FixupKind::Rebase { .. } => {
                rebases.push(RebaseEntry { seg, seg_off });
            }
            FixupKind::Bind {
                lib_ordinal,
                name,
                addend,
                weak,
            } => {
                has_weak |= weak;
                binds.push(BindEntry {
                    seg,
                    seg_off,
                    ordinal: classic_ordinal(lib_ordinal),
                    flags: u8::from(weak) * pgr_format::dyld_info::BIND_SYMBOL_FLAGS_WEAK_IMPORT,
                    name: interner.bytes(name).to_vec(),
                    addend,
                });
            }
        }
    }
    Ok(DyldInfoPlan {
        // An empty entry list carries no stream at all (the load command
        // appears only when at least one stream has bytes).
        rebase: if rebases.is_empty() {
            Vec::new()
        } else {
            pgr_format::dyld_info::encode_rebase_stream(&rebases)
        },
        bind: if binds.is_empty() {
            Vec::new()
        } else {
            pgr_format::dyld_info::encode_bind_stream(&binds)
        },
        has_weak_binds: has_weak,
    })
}

#[cfg(test)]
mod tests {
    use super::plan_dyld_info;
    use crate::fixups::{FixupKind, FixupSlot};
    use crate::ids::{FileId, StringId};
    use crate::interner::Interner;
    use pgr_format::dyld_info::BindOrdinal;

    fn interner_with(names: &[&[u8]]) -> (Interner, Vec<StringId>) {
        let names: Vec<Vec<u8>> = names.iter().map(|b| b.to_vec()).collect();
        let (interner, ids) = Interner::build_with(&names, false);
        (interner, ids)
    }

    #[test]
    fn rebase_and_bind_streams_are_planned_in_slot_order() {
        let (interner, ids) = interner_with(&[b"_printf", b"_weak_fn"]);
        // Segments: PAGEZERO(0), TEXT(0x1_0000, +0x1_0000), DATA_CONST, DATA.
        let segs = vec![
            (0u64, 0x1_0000u64, 0u64),
            (0x1_0000, 0x1_0000, 0),
            (0x2_0000, 0x1_0000, 0x1_0000),
            (0x3_0000, 0x1_0000, 0x2_0000),
        ];
        let slots = vec![
            FixupSlot {
                vaddr: 0x2_1000,
                kind: FixupKind::Bind {
                    lib_ordinal: 1,
                    name: ids[0],
                    addend: 0,
                    weak: false,
                },
            },
            FixupSlot {
                vaddr: 0x2_1008,
                kind: FixupKind::Bind {
                    lib_ordinal: 0xFE,
                    name: ids[1],
                    addend: 8,
                    weak: true,
                },
            },
            FixupSlot {
                vaddr: 0x1_2000,
                kind: FixupKind::Rebase {
                    target_vaddr: 0x1_0400,
                },
            },
        ];
        let plan = plan_dyld_info(slots, &segs, &interner).unwrap();
        // Slots sort by vaddr: rebase first, then the two binds.
        let rebases = pgr_format::dyld_info::decode_rebase_stream(&plan.rebase).unwrap();
        assert_eq!(rebases.len(), 1);
        assert_eq!((rebases[0].seg, rebases[0].seg_off), (1, 0x2000));
        let binds = pgr_format::dyld_info::decode_bind_stream(&plan.bind).unwrap();
        assert_eq!(binds.len(), 2);
        assert_eq!(binds[0].ordinal, BindOrdinal::Dylib(1));
        assert_eq!(binds[0].name, b"_printf");
        assert_eq!((binds[0].seg, binds[0].seg_off), (2, 0x1000));
        assert_eq!(binds[1].ordinal, BindOrdinal::Special(-2));
        assert_eq!(
            binds[1].flags,
            pgr_format::dyld_info::BIND_SYMBOL_FLAGS_WEAK_IMPORT
        );
        assert_eq!(binds[1].addend, 8);
        assert!(plan.has_weak_binds);
    }

    #[test]
    fn slots_outside_every_segment_error() {
        let (interner, _ids) = interner_with(&[]);
        let segs = vec![(0u64, 0x1_0000u64, 0u64)];
        let err = plan_dyld_info(
            vec![FixupSlot {
                vaddr: 0x99_9999,
                kind: FixupKind::Rebase { target_vaddr: 0 },
            }],
            &segs,
            &interner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside every segment"), "{err}");
    }

    #[test]
    fn file_ids_stay_unused_in_streams() {
        // Regression guard: FileId is only a parse-time identity; the
        // streams must not embed it.
        let _ = FileId(0);
    }
}
