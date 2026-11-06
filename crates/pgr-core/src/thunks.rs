//! Branch thunks / veneers (M6 — architecture doc §10.3 row M6: "branch
//! thunks/veneers for `BR26` overflow (> 128 MiB text)").
//!
//! arm64 `B`/`BL` reach is ±128 MiB (`imm26` scaled by 4). When the layout
//! places a branch site and its target further apart, Peregrine inserts a
//! **veneer**: a 3-instruction trampoline
//!
//! ```text
//! adrp x16, target@page   // ±4 GiB reach
//! add  x16, x16, target@pageoff
//! br   x16                // register branch: unbounded
//! ```
//!
//! placed in the same output section immediately after the piece containing
//! the branch site. The site's `B`/`BL` then targets the veneer (always in
//! range: the veneer sits at the site's piece end, and pieces larger than
//! the branch range are rejected — a single atom bigger than 128 MiB cannot
//! host an intervening veneer). The veneer reaches the final target through
//! `adrp`'s ±4 GiB window, so no chaining is ever required.
//!
//! Determinism (TDD §4.3): veneer count and positions are a pure function of
//! the placed addresses — the insertion pass runs inside the existing layout
//! fixed point until no out-of-range `Branch26` patch remains.

use crate::object::{InputObject, RelocTarget};

/// arm64 `B`/`BL` signed reach in bytes (imm26 × 4): ±128 MiB.
pub const BRANCH26_RANGE: i64 = 0x0800_0000;

/// One veneer's size in bytes (`adrp` + `add` + `br`, 4-byte each).
pub const VENEER_SIZE: u64 = 12;

/// The planned veneer for one out-of-range branch site. Pure data: the
/// layout fixed point owns the list, `place` materializes the pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VeneerSpec {
    /// Branch site: input file, input section, section-relative reloc offset.
    pub site: (u32, usize, u32),
    /// What the branch referenced (the veneer's `adrp` target).
    pub target: RelocTarget,
}

/// The veneer's instruction bytes (patches fill the `adrp`/`add` immediates).
pub(crate) fn veneer_bytes() -> Vec<u8> {
    let mut b = Vec::with_capacity(VENEER_SIZE as usize);
    b.extend_from_slice(&0x9000_0010u32.to_le_bytes()); // adrp x16, <patch>
    b.extend_from_slice(&0x9100_0210u32.to_le_bytes()); // add x16, x16, <patch>
    b.extend_from_slice(&0xD61F_0200u32.to_le_bytes()); // br x16
    b
}

/// Materializes one [`VeneerSpec`] per site as a synthetic piece inserted
/// into the site's own bucket immediately after the site's piece. Called by
/// `place` on every fixed-point iteration; the piece list order stays a
/// pure function of the spec list (determinism §4.3).
pub(crate) fn insert_veneer_pieces(
    objects: &[InputObject],
    pieces_of_bucket: &mut [Vec<crate::layout::Piece>],
    veneers: &[VeneerSpec],
) {
    for spec in veneers {
        let Some((bi, piece_idx)) = locate_site(objects, pieces_of_bucket, spec) else {
            // The site's piece is not placed (dead-stripped between
            // iterations cannot happen — liveness is fixed before layout —
            // so this only means the caller scanned a stale plan; skip).
            continue;
        };
        pieces_of_bucket[bi].insert(
            piece_idx + 1,
            crate::layout::Piece {
                file: crate::ids::FileId(spec.site.0),
                in_sect: spec.site.1,
                in_range: 0..0,
                offset: 0,
                size: VENEER_SIZE,
                align_log2: 2,
                zerofill: false,
                common_name: None,
                patches: Vec::new(),
                fixup_slots: Vec::new(),
                synth: Some(crate::layout::SynthPiece {
                    kind: crate::layout::SynthKind::Veneer {
                        site: spec.site,
                        target: spec.target,
                    },
                    bytes: veneer_bytes(),
                }),
            },
        );
    }
}

/// Finds `(bucket, piece index)` of the piece containing a branch site.
fn locate_site(
    objects: &[InputObject],
    pieces_of_bucket: &[Vec<crate::layout::Piece>],
    spec: &VeneerSpec,
) -> Option<(usize, usize)> {
    let obj = objects.get(spec.site.0 as usize)?;
    let data_start = obj.sections.get(spec.site.1)?.data.start;
    let site_file_off = data_start + u64::from(spec.site.2);
    for (bi, pieces) in pieces_of_bucket.iter().enumerate() {
        for (pi, p) in pieces.iter().enumerate() {
            if p.synth.is_some() || p.zerofill {
                continue;
            }
            if p.file.0 == spec.site.0
                && p.in_sect == spec.site.1
                && p.in_range.contains(&site_file_off)
            {
                return Some((bi, pi));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{BRANCH26_RANGE, VENEER_SIZE, veneer_bytes};
    use crate::LinkConfig;
    use crate::link::{LinkInput, link};
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    #[test]
    fn veneer_encoding_is_the_arm64_trampoline() {
        let b = veneer_bytes();
        assert_eq!(b.len() as u64, VENEER_SIZE);
        // adrp x16 (bits 31..24 = 0x90), add x16 (0x91), br x16 (0xd6).
        assert_eq!(&b[0..4], &0x9000_0010u32.to_le_bytes());
        assert_eq!(&b[4..8], &0x9100_0210u32.to_le_bytes());
        assert_eq!(&b[8..12], &0xD61F_0200u32.to_le_bytes());
        assert_eq!(BRANCH26_RANGE, 0x0800_0000);
    }

    // ---- the giant-text corpus ----------------------------------------------
    //
    // a.o: 64 MiB __text, `_main` at 0 branch-rel'ing to `_far` (forward
    //      overflow site), `_far` undefined here.
    // b.o: 66 MiB __text with `_b` (pure distance).
    // c.o: 2 MiB __text with `_far` defined at 0 and a branch back to
    //      `_main` (backward overflow site).
    //
    // Site→target distances land at ~130 MiB both ways: beyond ±128 MiB,
    // fixable with one veneer per site (each site's piece is ≤ 66 MiB, so a
    // veneer right after the piece is always within reach).

    const MIB: usize = 1 << 20;

    fn obj_a() -> ObjectBuilder {
        let mut b = ObjectBuilder::new("a.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0u8; 64 * MIB],
            vec![ObjectReloc::branch26(1).at(0)],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_far".into(),
            weak_ref: false,
        });
        b
    }

    fn obj_b() -> ObjectBuilder {
        let mut b = ObjectBuilder::new("b.o");
        let text = b.add_section(ObjectSection::text("__text", vec![0u8; 66 * MIB], vec![]));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_b".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b
    }

    fn obj_c() -> ObjectBuilder {
        let mut b = ObjectBuilder::new("c.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0u8; 2 * MIB],
            vec![ObjectReloc::branch26(1).at(0)],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_far".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_main".into(),
            weak_ref: false,
        });
        b
    }

    fn giant_inputs() -> Vec<LinkInput> {
        vec![
            LinkInput {
                name: "a.o".into(),
                bytes: obj_a().build().unwrap(),
            },
            LinkInput {
                name: "b.o".into(),
                bytes: obj_b().build().unwrap(),
            },
            LinkInput {
                name: "c.o".into(),
                bytes: obj_c().build().unwrap(),
            },
        ]
    }

    /// M6: the ±128 MiB branch overflow links by inserting one veneer per
    /// overflowing site; every final `Branch26` patch stays in range.
    #[test]
    fn m6_out_of_range_branches_get_veneers() {
        let cfg = LinkConfig {
            ident: "m6-thunks".into(),
            ..LinkConfig::default()
        };
        let result = link(&giant_inputs(), &[], &cfg)
            .unwrap_or_else(|e| panic!("giant-text link must succeed with veneers: {e}"));
        let layout = &result.layout;

        // Two veneers: one per overflowing site.
        let text = layout
            .sections
            .iter()
            .find(|s| s.name == "__text")
            .expect("__text section");
        let veneers: Vec<_> = text
            .pieces
            .iter()
            .enumerate()
            .filter(|(_, p)| matches!(&p.synth, Some(s) if matches!(s.kind, crate::layout::SynthKind::Veneer { .. })))
            .collect();
        assert_eq!(veneers.len(), 2, "one veneer per out-of-range site");

        // Veneers sit right after their site's piece (a.o's text piece and
        // c.o's text piece respectively) and are 12 bytes.
        for (idx, p) in &veneers {
            assert_eq!(p.size, VENEER_SIZE, "veneer size at piece {idx}");
            assert_eq!(p.patches.len(), 2, "adrp + add patches");
        }

        // Every Branch26 patch is within arm64 reach.
        for sect in &layout.sections {
            for p in &sect.pieces {
                for op in &p.patches {
                    if let crate::layout::PatchOp::Branch26 { pc, delta, .. } = op {
                        assert!(
                            delta.abs() <= BRANCH26_RANGE,
                            "branch at {pc:#x} still out of range: {delta}"
                        );
                    }
                }
            }
        }
    }

    /// Determinism (TDD §4.3): two links of the giant corpus (including the
    /// veneer insertion fixed point) produce identical layouts.
    #[test]
    fn m6_veneer_layout_is_deterministic() {
        let cfg = LinkConfig {
            ident: "m6-thunks".into(),
            ..LinkConfig::default()
        };
        let l1 = link(&giant_inputs(), &[], &cfg).unwrap().layout;
        let l2 = link(&giant_inputs(), &[], &cfg).unwrap().layout;
        assert_eq!(l1.file_size, l2.file_size);
        for (s1, s2) in l1.sections.iter().zip(l2.sections.iter()) {
            assert_eq!(s1.name, s2.name);
            assert_eq!(s1.vm_addr, s2.vm_addr);
            assert_eq!(s1.size, s2.size);
            for (p1, p2) in s1.pieces.iter().zip(s2.pieces.iter()) {
                assert_eq!(p1.offset, p2.offset, "piece offsets must match");
                assert_eq!(p1.patches, p2.patches, "patches must match");
            }
        }
    }

    /// In-range corpora keep the M5 layout exactly: no veneer pieces appear
    /// when every branch fits.
    #[test]
    fn m6_in_range_links_gain_no_veneers() {
        let mut a = obj_a();
        // Shrink to 1 MiB of text: the branch to `_far`... unresolved unless
        // c.o is small too — rebuild a compact corpus instead.
        let _ = &mut a;
        let small = |name: &str, syms: &[(&str, bool)]| {
            let mut b = ObjectBuilder::new(name);
            let text = b.add_section(ObjectSection::text(
                "__text",
                vec![
                    0xC0, 0x03, 0x5F, 0xD6, // ret
                    0xC0, 0x03, 0x5F, 0xD6, // ret
                ],
                vec![],
            ));
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            for (i, (n, def)) in syms.iter().enumerate() {
                if *def {
                    b.add_symbol(ObjectSymbol::Defined {
                        name: (*n).into(),
                        section_index: if i == 0 { text } else { data },
                        value: 0,
                        weak: false,
                    });
                }
            }
            b
        };
        let main = small("m.o", &[("_main", true), ("_far", false)])
            .build()
            .unwrap();
        let far = small("f.o", &[("_far", true)]).build().unwrap();
        let cfg = LinkConfig {
            ident: "m6-no-thunks".into(),
            ..LinkConfig::default()
        };
        let layout = link(
            &[
                LinkInput {
                    name: "m.o".into(),
                    bytes: main,
                },
                LinkInput {
                    name: "f.o".into(),
                    bytes: far,
                },
            ],
            &[],
            &cfg,
        )
        .unwrap()
        .layout;
        let text = layout
            .sections
            .iter()
            .find(|s| s.name == "__text")
            .expect("__text section");
        assert!(
            text.pieces
                .iter()
                .all(|p| !matches!(&p.synth, Some(s) if matches!(s.kind, crate::layout::SynthKind::Veneer { .. }))),
            "in-range links must not synthesize veneers"
        );
    }
}
