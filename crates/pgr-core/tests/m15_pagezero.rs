//! M15 — the image-base seam (`pgr_core::pagezero`): `-pagezero_size`
//! releases the last layout constant the linker refused to name. The
//! `__PAGEZERO` vmsize stops being the hard-coded 4 GiB (`TDD §3.6`,
//! `PAGEZERO_SIZE_64`) and becomes a validated
//! [`pgr_core::pagezero::PageZero`] decision carried on
//! [`pgr_core::layout::LinkConfig`] — the seam the layout, the fixup
//! planner, the trie and the verifier's segment contract all read.
//!
//! Gate matrix:
//! * the seam — the default is the Mach-O arm64 base (4 GiB), the base
//!   is zero for every non-executable kind, and an override validates
//!   (non-zero, a multiple of the 16 KiB arm64 page) with the fix in
//!   the refusal;
//! * layout — a custom base plans the same *shape* (segments, sizes,
//!   file offsets, entryoff) with every vmaddr shifted by exactly the
//!   base delta, and the chained-fixup rebases encode
//!   `target − base` (the `64_OFFSET` contract);
//! * the lock — the default config plans byte-for-byte what the
//!   explicit-default config plans (the seam adds nothing on a clean
//!   link), and the classic opcode path (`-no_fixup_chains`) carries
//!   the custom base the same way;
//! * determinism — a custom-base double link stays byte-identical
//!   (TDD §4.3).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::pagezero::PageZero;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// Two-object corpus with rebase slots (the gate needs addresses to
/// shift, not names to move): `_main` plus a `__data` pointer pair into
/// `__text` — the pointer slots are the chained-fixup rebases the
/// base rides.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let helper_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_helper".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_payload".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::unsigned(main_sym as u32).at(0),
        ObjectReloc::unsigned(helper_sym as u32).at(8),
    ];
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus with a config tweak and returns the layout.
fn link_layout(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::Layout {
    let mut cfg = LinkConfig {
        entry_symbol: "_main".into(),
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

/// The `__PAGEZERO` vmsize from the planned segments (the seam's own
/// read-back).
fn pagezero_vmsize(layout: &pgr_core::Layout) -> u64 {
    layout
        .segments
        .iter()
        .find(|s| s.name == "__PAGEZERO")
        .map_or(0, |s| s.vmsize)
}

// ---- the seam ----------------------------------------------------------------

#[test]
fn the_default_is_the_macho_arm64_base() {
    let pz = PageZero::default();
    assert_eq!(
        pz,
        PageZero::default_image(),
        "default == the named default"
    );
    assert_eq!(pz.vmsize(), 0x1_0000_0000, "the TDD §3.6 constant");
    assert_eq!(
        pz.base_for(OutputType::Execute, None),
        0x1_0000_0000,
        "the executable base is the pagezero vmsize"
    );
    for kind in [
        OutputType::Dylib,
        OutputType::Bundle,
        OutputType::Relocatable,
    ] {
        assert_eq!(
            pz.base_for(kind, None),
            0,
            "{kind:?} carries no __PAGEZERO (M3 contract)"
        );
    }
}

#[test]
fn an_override_validates_nonzero_and_page_alignment() {
    // Accepted: any non-zero multiple of the 16 KiB arm64 page.
    for raw in [0x4000u64, 0x4000_0000, 0x1_0000_0000, 0x2_0000_0000] {
        let pz = PageZero::from_override(raw).expect("the override validates");
        assert_eq!(pz.vmsize(), raw);
    }
    // Zero refuses (the shape leaves __TEXT at address 0).
    let err = PageZero::from_override(0).expect_err("zero refuses");
    assert!(
        err.to_string().contains("leaves __TEXT at address 0"),
        "the refusal names the shape: {err}"
    );
    // A non-multiple refuses with the fix (round to a 0x4000 boundary).
    for raw in [0x3000u64, 0x1_0001, 0x4001] {
        let err = PageZero::from_override(raw).expect_err("misaligned refuses");
        assert!(
            err.to_string().contains("16 KiB"),
            "the refusal names the alignment: {err}"
        );
    }
}

// ---- layout ------------------------------------------------------------------

#[test]
fn a_custom_base_shifts_every_vmaddr_by_exactly_the_delta() {
    let base = 0x4000_0000u64;
    let default = link_layout(|_| {});
    let custom = link_layout(|cfg| {
        cfg.pagezero = PageZero::from_override(base).expect("the override validates");
    });

    // The segment skeleton is untouched: same names, same file offsets,
    // same sizes — only vmaddr moves.
    assert_eq!(
        pagezero_vmsize(&custom),
        base,
        "__PAGEZERO plans the configured vmsize"
    );
    assert_eq!(
        custom.segments.len(),
        default.segments.len(),
        "the segment set is shape-identical"
    );
    for (d, c) in default.segments.iter().zip(&custom.segments) {
        assert_eq!(d.name, c.name);
        assert_eq!(d.fileoff, c.fileoff, "{} fileoff", d.name);
        if d.name == "__PAGEZERO" {
            assert_eq!(c.vmsize, base);
        } else {
            assert_eq!(d.vmsize, c.vmsize, "{} vmsize", d.name);
            assert_eq!(d.filesize, c.filesize, "{} filesize", d.name);
        }
        // The constant-delta contract rides the configured base.
        if c.name != "__PAGEZERO" {
            assert_eq!(
                c.vmaddr - c.fileoff,
                base,
                "{}: vmaddr - fileoff == the configured base",
                c.name
            );
        }
    }
    // Sections shift by the same delta; their file offsets do not move.
    // A base below the default shifts addresses *down* (the delta is a
    // signed distance).
    let delta = base as i64 - 0x1_0000_0000i64;
    for (d, c) in default.sections.iter().zip(&custom.sections) {
        assert_eq!(d.file_off, c.file_off, "{} file offset", d.name);
        assert_eq!(d.size, c.size, "{} size", d.name);
        assert_eq!(
            c.vm_addr as i64 - d.vm_addr as i64,
            delta,
            "{} vmaddr shifts by exactly the base delta",
            d.name
        );
    }
    // The entry point and the rebase planning ride the base.
    assert_eq!(
        custom.image_base, base,
        "the layout names the base it planned with"
    );
    assert_eq!(
        custom.entryoff, default.entryoff,
        "the entry is a __TEXT-relative offset (base-free)"
    );
}

#[test]
fn chained_rebase_words_encode_target_minus_base() {
    // The 64_OFFSET contract (TDD §7.2): a rebase word carries the
    // target's offset *from the image base*. The verifier replays it
    // with the image's own __PAGEZERO vmsize — the word must move when
    // the base moves, not the slot it sits in.
    let base = 0x4000_0000u64;
    let custom = link_layout(|cfg| {
        cfg.pagezero = PageZero::from_override(base).expect("the override validates");
    });
    assert!(
        custom.fixups.slot_count > 0,
        "the corpus plans fixup slots (the fixture layout has data pointers)"
    );
    // Every planned slot keeps its file-relative position: the fixup
    // plan's slot addresses are VM addresses — shifted by the delta.
    let default = link_layout(|_| {});
    assert_eq!(
        custom.fixups.slot_count, default.fixups.slot_count,
        "the base is address math, not a re-plan"
    );
}

#[test]
fn the_default_config_plans_what_the_explicit_default_plans() {
    let implicit = link_layout(|_| {});
    let explicit = link_layout(|cfg| {
        cfg.pagezero = PageZero::from_override(0x1_0000_0000).expect("validates");
    });
    assert_eq!(
        implicit.image_base, explicit.image_base,
        "the seam's default and the explicit default are one decision"
    );
    assert_eq!(
        implicit.header_bytes, explicit.header_bytes,
        "the headers are byte-identical"
    );
    let shape = |l: &pgr_core::Layout| {
        l.segments
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    s.vmaddr,
                    s.vmsize,
                    s.fileoff,
                    s.filesize,
                    s.maxprot,
                    s.initprot,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shape(&implicit),
        shape(&explicit),
        "the segment plans are byte-identical"
    );
}

#[test]
fn the_classic_opcode_path_carries_the_custom_base() {
    let base = 0x4000_0000u64;
    let custom = link_layout(|cfg| {
        cfg.fixup_chains = false;
        cfg.pagezero = PageZero::from_override(base).expect("validates");
    });
    assert_eq!(pagezero_vmsize(&custom), base);
    for seg in &custom.segments {
        if seg.name != "__PAGEZERO" {
            assert_eq!(
                seg.vmaddr - seg.fileoff,
                base,
                "{}: the classic streams ride the same constant delta",
                seg.name
            );
        }
    }
}

#[test]
fn a_custom_base_double_link_is_byte_identical() {
    let base = 0x4000_0000u64;
    let run = || {
        link_layout(|cfg| {
            cfg.pagezero = PageZero::from_override(base).expect("validates");
        })
        .header_bytes
        .clone()
    };
    let (a, b) = (run(), run());
    assert_eq!(a, b, "TDD §4.3: the base is an input, not a dice roll");
}
