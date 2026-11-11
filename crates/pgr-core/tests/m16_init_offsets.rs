//! M16 — the initializer-offsets seam (`pgr_core::init_offsets`).
//!
//! `__mod_init_func` stops being the only initializer form: the
//! `-init_offsets` decision replaces the 8-byte pointer sections (each a
//! chained-fixup rebase or a classic rebase opcode) with a
//! `__TEXT,__init_offsets` section of u32 offsets from the image's load
//! address — the shape dyld has walked since the chained-fixups era
//! (`S_INIT_FUNC_OFFSETS`, the section whose presence removes the
//! initializer rebases from every fixup payload). The gates:
//!
//! * the default stays classic — every pre-M16 link is byte-identical
//!   (the §7.2 lock the chain-word family holds);
//! * the named form replaces the pointer section, preserves input order
//!   and drops the converted slots from the fixup plan (chained *and*
//!   classic streams);
//! * the refusals are named: below the chained-fixups floor, on the
//!   relocatable output, at a bind-targeted (non-executable) initializer;
//! * the layout invariants survive the transform: dead-strip roots, a
//!   custom image base (the offsets move with the load address).

use pgr_core::init_offsets::{InitOffsets, InitOffsetsError};
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::UndefinedPolicy;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_INIT_FUNC_OFFSETS, S_MOD_INIT_FUNC_POINTERS, SECTION_TYPE_MASK};

/// A minimal object: `_main` in `__text` plus `count` initializer
/// functions in a second text section, each targeted by one 8-byte
/// pointer in a `__mod_init_func` section (the M5 fixture shape).
fn init_object(name: &str, count: usize, main: bool) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name);
    let n_fns = count + usize::from(main);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
        vec![],
    ));
    for f in 0..n_fns {
        b.add_symbol(ObjectSymbol::Defined {
            name: if main && f == 0 {
                "_main".into()
            } else {
                format!("_init_{}_{}", name.trim_end_matches(".o"), f)
            },
            section_index: text,
            value: (f * 4) as u64,
            weak: false,
        });
    }
    // The initializer pointers: one Unsigned reloc per 8-byte slot, the
    // target being the first non-main function of the section.
    let mut relocs = Vec::new();
    for r in 0..count {
        relocs.push(ObjectReloc::unsigned((usize::from(main) + r) as u32).at((r * 8) as u32));
    }
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; count * 8],
        relocs,
    ));
    b.section_mut(modinit).flags = S_MOD_INIT_FUNC_POINTERS;
    b
}

/// The named `-init_offsets` form (macOS 12.0 — at the chained-fixups
/// floor the section is consumable).
fn offsets_cfg() -> LinkConfig {
    LinkConfig {
        init_offsets: InitOffsets::from_flag(
            Some(true),
            pgr_format::consts::PLATFORM_MACOS,
            0x000C_0000,
        )
        .expect("macos 12.0 is at the floor"),
        ..LinkConfig::default()
    }
}

fn link_sections(cfg: &LinkConfig, inputs: &[LinkInput]) -> pgr_core::layout::Layout {
    link(inputs, &[], cfg).expect("the corpus links").layout
}

fn section<'l>(
    layout: &'l pgr_core::layout::Layout,
    name: &str,
) -> Option<&'l pgr_core::layout::PlacedSection> {
    layout.sections.iter().find(|s| s.name == name)
}

fn u32_entries(layout: &pgr_core::layout::Layout) -> Vec<u32> {
    let sect = section(layout, "__init_offsets").expect("__init_offsets section present");
    let piece = sect.pieces.first().expect("one synthetic piece");
    let bytes = piece
        .synth
        .as_ref()
        .expect("synthetic content")
        .bytes
        .as_slice();
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().expect("4-byte entry")))
        .collect()
}

#[test]
fn the_default_stays_classic() {
    let inputs = vec![LinkInput {
        name: "a.o".into(),
        bytes: init_object("a", 2, true).build().unwrap(),
    }];
    let layout = link_sections(&LinkConfig::default(), &inputs);

    let modinit = section(&layout, "__mod_init_func").expect("classic form keeps the pointers");
    assert_eq!(
        modinit.flags & SECTION_TYPE_MASK,
        S_MOD_INIT_FUNC_POINTERS,
        "the pointer section keeps its type"
    );
    assert!(section(&layout, "__init_offsets").is_none());
    // The two pointers are planned fixup slots (rebases) in the classic form.
    let rebase_slots = layout
        .sections
        .iter()
        .flat_map(|s| &s.pieces)
        .flat_map(|p| &p.fixup_slots)
        .count();
    assert_eq!(
        rebase_slots, 2,
        "the classic form plans one rebase per initializer pointer"
    );
    assert_eq!(LinkConfig::default().init_offsets, InitOffsets::Classic);
}

#[test]
fn the_named_form_replaces_the_pointers() {
    let inputs = vec![LinkInput {
        name: "a.o".into(),
        bytes: init_object("a", 2, true).build().unwrap(),
    }];
    let cfg = offsets_cfg();
    let layout = link_sections(&cfg, &inputs);

    assert!(
        section(&layout, "__mod_init_func").is_none(),
        "the transform replaces the pointer section"
    );
    let sect = section(&layout, "__init_offsets").expect("the offsets section exists");
    assert_eq!(sect.seg_name, "__TEXT");
    assert_eq!(sect.flags & SECTION_TYPE_MASK, S_INIT_FUNC_OFFSETS);
    assert_eq!(sect.align_log2, 2, "4-byte aligned (dyld's contract)");
    assert_eq!(sect.size, 8, "two u32 entries");

    // The entries are offsets from the image's load address (the __TEXT
    // vmaddr): each names the initializer function's __text position.
    let base = layout.image_base;
    let text_vmaddr = layout
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .expect("__TEXT segment")
        .vmaddr;
    assert_eq!(text_vmaddr, base, "the load address is the image base");
    let entries = u32_entries(&layout);
    assert_eq!(entries.len(), 2);
    for (i, off) in entries.iter().enumerate() {
        let target = base + u64::from(*off);
        assert!(
            target >= text_vmaddr && target < text_vmaddr + layout.text_vmsize,
            "entry {i} ({off:#x}) lands inside __TEXT"
        );
    }
    assert_ne!(entries[0], entries[1], "two distinct initializers");

    // The converted slots left the fixup plan: no rebase words on the
    // offsets section, and the payload's slot count shrank by the two
    // converted pointers.
    let slots_on_offsets = sect.pieces.iter().flat_map(|p| &p.fixup_slots).count();
    assert_eq!(slots_on_offsets, 0, "the offsets carry no fixup words");
}

#[test]
fn the_converted_slots_leave_the_fixup_payload() {
    let classic_inputs = vec![LinkInput {
        name: "a.o".into(),
        bytes: init_object("a", 2, true).build().unwrap(),
    }];
    let classic = link_sections(&LinkConfig::default(), &classic_inputs);
    let offsets = link_sections(&offsets_cfg(), &classic_inputs);
    assert_eq!(
        classic.fixups.slot_count - offsets.fixups.slot_count,
        2,
        "the two initializer rebases leave the chained payload"
    );
}

#[test]
fn entries_follow_input_order_across_objects() {
    let inputs = vec![
        LinkInput {
            name: "first.o".into(),
            bytes: init_object("first", 2, true).build().unwrap(),
        },
        LinkInput {
            name: "second.o".into(),
            bytes: init_object("second", 1, false).build().unwrap(),
        },
    ];
    let layout = link_sections(&offsets_cfg(), &inputs);
    let entries = u32_entries(&layout);
    assert_eq!(entries.len(), 3, "2 + 1 initializers, first.o's first");
}

#[test]
fn the_floor_refuses_the_named_form() {
    let err = InitOffsets::from_flag(Some(true), pgr_format::consts::PLATFORM_MACOS, 0x000B_0000)
        .expect_err("macOS 11.0 sits below the chained-fixups floor");
    assert!(
        matches!(err, InitOffsetsError::BelowFloor { .. }),
        "the refusal names the floor: {err}"
    );
    let text = err.to_string();
    assert!(
        text.contains("12.0.0"),
        "the floor version is named: {text}"
    );
    assert!(
        text.contains("-no_init_offsets") || text.contains("deployment target"),
        "the fix is named: {text}"
    );
    // The explicit off is always fine, and the flag-less default never
    // consults the floor (it stays classic).
    assert_eq!(
        InitOffsets::from_flag(Some(false), pgr_format::consts::PLATFORM_MACOS, 0x000B_0000)
            .expect("the explicit off is always valid"),
        InitOffsets::Classic
    );
    assert_eq!(
        InitOffsets::from_flag(None, pgr_format::consts::PLATFORM_MACOS, 0x000B_0000)
            .expect("the default never flips below the floor"),
        InitOffsets::Classic
    );
}

#[test]
fn the_relocatable_output_refuses_the_transform() {
    let inputs = vec![LinkInput {
        name: "a.o".into(),
        bytes: init_object("a", 1, true).build().unwrap(),
    }];
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        ..offsets_cfg()
    };
    let err = link(&inputs, &[], &cfg).expect_err("the relocatable output refuses");
    let text = err.to_string();
    assert!(
        text.contains("-r") || text.contains("relocatable"),
        "the verdict names the output kind: {text}"
    );
}

#[test]
fn a_bind_targeted_initializer_refuses() {
    // One pointer at a defined initializer, one at an undefined external —
    // the second's fixup slot would be a bind, and dyld could not call it
    // as an offset into this image. Both forms run with `-undefined
    // dynamic_lookup`: the classic form links the bind (dyld resolves it
    // at load — the control), the named form refuses with the fix named.
    let mut b = ObjectBuilder::new("bind.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_local_init".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_external_init".into(),
        weak_ref: false,
    });
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 16],
        vec![
            ObjectReloc::unsigned(1).at(0),
            ObjectReloc::unsigned(2).at(8),
        ],
    ));
    b.section_mut(modinit).flags = S_MOD_INIT_FUNC_POINTERS;
    let inputs = vec![LinkInput {
        name: "bind.o".into(),
        bytes: b.build().unwrap(),
    }];
    let dynamic = LinkConfig {
        undefined_policy: UndefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };

    let classic = link_sections(&dynamic, &inputs);
    assert!(
        section(&classic, "__mod_init_func").is_some(),
        "the classic form links the bind-targeted pointer"
    );

    let err = link(
        &inputs,
        &[],
        &LinkConfig {
            undefined_policy: UndefinedPolicy::DynamicLookup,
            ..offsets_cfg()
        },
    )
    .expect_err("the named form refuses");
    let text = err.to_string();
    assert!(
        text.contains("_external_init"),
        "the refusal names the symbol: {text}"
    );
    assert!(
        text.contains("-no_init_offsets"),
        "the fix is named: {text}"
    );
}

#[test]
fn dead_strip_keeps_the_initializer_target_live() {
    let inputs = vec![LinkInput {
        name: "a.o".into(),
        bytes: init_object("a", 2, true).build().unwrap(),
    }];
    let cfg = LinkConfig {
        dead_strip: true,
        ..offsets_cfg()
    };
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let names: Vec<Vec<u8>> = result
        .layout
        .symbols
        .iter()
        .map(|s| result.interner.bytes(s.name).to_vec())
        .collect();
    for name in ["_init_a_1", "_init_a_2"] {
        assert!(
            names.contains(&name.as_bytes().to_vec()),
            "{name} survives the strip under the offsets form: {names:?}"
        );
    }
    assert!(section(&result.layout, "__init_offsets").is_some());
}

#[test]
fn a_custom_base_moves_the_entries_not_the_contract() {
    let inputs = vec![LinkInput {
        name: "a.o".into(),
        bytes: init_object("a", 2, true).build().unwrap(),
    }];
    let cfg = LinkConfig {
        pagezero: pgr_core::PageZero::from_override(0x4000_0000).expect("validates"),
        ..offsets_cfg()
    };
    let layout = link_sections(&cfg, &inputs);
    let base = layout.image_base;
    assert_eq!(base, 0x4000_0000);
    let entries = u32_entries(&layout);
    for (i, off) in entries.iter().enumerate() {
        let target = base + u64::from(*off);
        let text_vmaddr = layout
            .segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .expect("__TEXT segment")
            .vmaddr;
        assert!(
            target >= text_vmaddr && target < text_vmaddr + layout.text_vmsize,
            "entry {i} tracks the custom base"
        );
    }
}

#[test]
fn the_classic_streams_drop_the_converted_rebases() {
    // A second pointer that is NOT an initializer (a plain `__data`
    // pointer at a defined function) keeps the classic rebase stream
    // alive on both sides of the transform — so the assertion is
    // "the two initializer entries left", never "the stream is empty".
    let mut p = ObjectBuilder::new("ptr");
    let text = p.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].to_vec(),
        vec![],
    ));
    p.add_symbol(ObjectSymbol::Defined {
        name: "_fn".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    p.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(0).at(0)],
    ));
    let inputs = vec![
        LinkInput {
            name: "a.o".into(),
            bytes: init_object("a", 2, true).build().unwrap(),
        },
        LinkInput {
            name: "ptr.o".into(),
            bytes: p.build().unwrap(),
        },
    ];
    let cfg = LinkConfig {
        fixup_chains: false,
        ..offsets_cfg()
    };
    let classic = link_sections(
        &LinkConfig {
            fixup_chains: false,
            ..LinkConfig::default()
        },
        &inputs,
    );
    let layout = link_sections(&cfg, &inputs);
    let plan = layout.dyld_info.as_ref().expect("classic streams exist");
    assert!(
        section(&layout, "__mod_init_func").is_none(),
        "the transform runs on the classic path too"
    );
    assert!(section(&layout, "__init_offsets").is_some());
    // The plain pointer's rebase survives; the initializer entries left.
    let classic_plan = classic.dyld_info.as_ref().expect("classic streams exist");
    assert!(
        plan.rebase.len() < classic_plan.rebase.len(),
        "the initializer rebases leave the classic rebase stream \
         ({} -> {})",
        classic_plan.rebase.len(),
        plan.rebase.len()
    );
}
