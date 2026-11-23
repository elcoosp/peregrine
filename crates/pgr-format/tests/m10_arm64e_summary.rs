//! The format summary walk's chain-family seam (the M10 rung 4, slice 1
//! format-layer half): `pgr_format::summarize`'s fixup-slot count reads
//! each segment's declared `pointer_format` instead of hard-coding the
//! 64 family.
//!
//! Plan anchor (TDD §15.4, the arm64e read side): "The slice names the
//! word family in the format layer and teaches the read side to walk
//! it". The codec and the verifier's dyld chain-walk simulation landed
//! with the rung; `summarize`'s own chain walk — the M0
//! parser-throughput unit and a public format face — still decoded every
//! slot as `ChainWord64` (its own doc comment named the gap "a seam for
//! a future slice"). An arm64e word read as a 64 word takes its 12-bit
//! `next` from bits 51..63, where arm64e keeps an 11-bit field and rides
//! bit 62 as the auth flag, and the strides count 8-byte units — a
//! multi-slot chain mis-walked or refused instead of counted.

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec,
    filler,
};
use pgr_format::consts::{
    LC_DYLD_CHAINED_FIXUPS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};

/// A small executable whose `__got` carries `slots` chained fixups —
/// the minimal shape every chain walk can count.
fn got_image(fmt: PointerFormatKind, slots: Vec<SlotKind>) -> Vec<u8> {
    let mut b = ImageBuilder::executable("chain-family-summary");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xBEEF, 64),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    b.add_dylib("/usr/lib/libSystem.B.dylib");
    let undef = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: 1,
        weak: false,
    });
    let owned = slots
        .into_iter()
        .map(|slot| match slot {
            SlotKind::Bind { addend, .. } => SlotKind::Bind {
                sym_index: undef,
                addend,
            },
            other => other,
        })
        .collect();
    b.set_got(owned);
    b.set_entry(0);
    b.set_imports_format(ImportsFormat::Addend64);
    b.set_pointer_format(fmt);
    b.build().expect("fixture image must build").bytes
}

/// The plan-pinning gate: an arm64e chain's slots count exactly — the
/// summary walk reads the segment's declared `pointer_format` (TDD
/// §15.4's "teaches the read side to walk it", the format layer's own
/// named seam). Four bind slots ride one chain; the strides count
/// 8-byte units, so every slot is visited once.
#[test]
fn arm64e_multi_slot_chain_counts_every_slot() {
    let img = got_image(
        PointerFormatKind::Arm64e,
        (0..4)
            .map(|i| SlotKind::Bind {
                sym_index: 0,
                addend: i,
            })
            .collect(),
    );
    let s = pgr_format::summarize(&img).expect("arm64e chains summarize");
    assert!(s.has_chained_fixups);
    assert_eq!(s.fixup_slots, 4, "every chained slot counts once");
}

/// Authenticated words count like plain slots: bit 62 is the auth flag
/// the arm64e reader keeps out of its 11-bit `next` field — the 64
/// reader folded it into the stride count and refused the walk.
#[test]
fn arm64e_auth_words_count_like_plain_slots() {
    let img = got_image(
        PointerFormatKind::Arm64e,
        vec![
            SlotKind::AuthBind {
                sym_index: 0,
                diversity: 0x1234,
                addr_div: true,
                key: 0,
            },
            SlotKind::AuthRebase {
                offset: 0x1000,
                diversity: 0,
                addr_div: false,
                key: 1,
            },
            SlotKind::Bind {
                sym_index: 0,
                addend: 0,
            },
            SlotKind::Rebase { target: 0x2000 },
        ],
    );
    let s = pgr_format::summarize(&img).expect("arm64e auth words summarize");
    assert_eq!(s.fixup_slots, 4, "auth and plain slots count alike");
}

/// A pointer format the read side does not walk refuses with the format
/// named (the verifier's dynamic walk convention — `chain_stride`
/// answers `None`, the summary walk mirrors it): never a silent
/// mis-decode.
#[test]
fn unknown_pointer_format_refuses_with_the_format_named() {
    let img = got_image(
        PointerFormatKind::Offset64,
        vec![
            SlotKind::Bind {
                sym_index: 0,
                addend: 0,
            },
            SlotKind::Bind {
                sym_index: 0,
                addend: 1,
            },
        ],
    );
    // Patch the segment record's `pointer_format` (u16 at record+6) to a
    // value no reader walks — the payload stays otherwise well-formed.
    let hdr = pgr_format::MachHeader64::parse(&img).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(&img, 32, hdr.ncmds, hdr.sizeofcmds).unwrap();
    let mut record_at = None;
    while let Some(cmd) = it.next_command().unwrap() {
        if cmd.kind == pgr_format::LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).unwrap();
            let payload = lc.data(&img).unwrap();
            let fh = pgr_format::fixups::parse_header(payload).unwrap();
            let starts =
                pgr_format::fixups::parse_starts_in_image(payload, fh.starts_offset as usize)
                    .unwrap();
            for &off in &starts.seg_info_offset {
                if off != 0 {
                    record_at =
                        Some(lc.dataoff as usize + fh.starts_offset as usize + off as usize);
                }
            }
        }
    }
    let at = record_at.expect("the payload carries one segment record");
    let mut patched = img.clone();
    patched[at + 6..at + 8].copy_from_slice(&3u16.to_le_bytes());

    let err = pgr_format::summarize(&patched)
        .expect_err("an unknown pointer format refuses the summary walk");
    let rendered = err.to_string();
    assert!(
        rendered.contains("pointer format"),
        "the refusal names the format: {rendered}"
    );
    assert!(
        rendered.contains('3'),
        "the refusal names the value: {rendered}"
    );
}

/// The default families' counts are untouched — the `64_OFFSET` and the
/// format-2 (`DYLD_CHAINED_PTR_64`, the `x86_64` family) shapes decode
/// through the same word reader and stride the M0 walk always used.
#[test]
fn offset64_and_format64_summary_counts_unchanged() {
    for fmt in [PointerFormatKind::Offset64, PointerFormatKind::Format64] {
        let img = got_image(
            fmt,
            (0..4)
                .map(|i| SlotKind::Bind {
                    sym_index: 0,
                    addend: i,
                })
                .collect(),
        );
        let s = pgr_format::summarize(&img).expect("64-family chains summarize");
        assert_eq!(s.fixup_slots, 4, "{fmt:?}: every chained slot counts once");
    }
}
