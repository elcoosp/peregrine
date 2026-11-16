//! M53 — the section-rename decision (`-rename_section`): an input
//! section's `(segment, name)` classification pair stops being a fixed
//! identity and becomes a nameable rename map on
//! [`pgr_core::layout::LinkConfig`] — ld64's
//! `-rename_section orgSegment orgSection newSegment newSection`
//! ("Renames section orgSegment/orgSection to newSegment/newSection"),
//! the reader-level rename ld64 applies before grouping, so a renamed
//! section groups with its new name and lands in the new segment's
//! protections. The default (the empty map) keeps every pre-M53 link
//! byte-identical — the classification pair rides every link it
//! always did.
//!
//! Gate matrix:
//! * the default — the empty map links the input names verbatim (the
//!   pre-M53 shape);
//! * the knob — a rename moves the output section to its new
//!   `(segment, name)` pair: the content bytes, the size and the
//!   pieces are the section's own, the address is the new segment's
//!   packing slot;
//! * the merge — two sections renamed onto the same target bucket
//!   coalesce (the grouping is by name, the rename is a grouping-time
//!   decision);
//! * the type rule — a zero-fill section's `S_ZEROFILL` bucket rule
//!   outranks the rename: the bytes always land in `__common` exactly
//!   as they did;
//! * the refusals — a rename into a house-synthesized section target
//!   (`__unwind_info`, `__chain_starts`, `__init_offsets`, `__common`)
//!   refuses at the map's construction, a name over the Mach-O 16-byte
//!   field width refuses, a duplicate source refuses, and a rename to
//!   a segment outside the M1 trio refuses at layout with the segment
//!   named;
//! * the lock — double-link determinism holds across the decision, and
//!   the relocatable output never reads it (`-r` carries the input's
//!   section table verbatim — the M41/M43/M47 inert-for-relocatable
//!   shape).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_core::rename::SectionRenames;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// One object carrying `__DATA,__mydata` (16 bytes) and `__DATA,__other`
/// (8 bytes), `_main` exported.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__mydata", vec![0x41u8; 16], vec![]));
    let other = b.add_section(ObjectSection::data("__other", vec![0x42u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_mydata_sym".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_other_sym".into(),
        section_index: other,
        value: 0,
        weak: false,
    });
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus with a config tweak and returns the layout.
fn link_layout(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

/// The placed sections as `(segment, name)` pairs, in file order.
fn section_pairs(layout: &pgr_core::layout::Layout) -> Vec<(String, String)> {
    layout
        .sections
        .iter()
        .map(|s| (s.seg_name.clone(), s.name.clone()))
        .collect()
}

// ---- the default --------------------------------------------------------------

#[test]
fn the_empty_map_links_the_input_names_verbatim() {
    let layout = link_layout(|_| {});
    let pairs = section_pairs(&layout);
    assert!(
        pairs.contains(&("__DATA".to_string(), "__mydata".to_string())),
        "the pre-M53 shape: __DATA,__mydata rides unnamed: {pairs:?}"
    );
    assert!(
        pairs.contains(&("__DATA".to_string(), "__other".to_string())),
        "the pre-M53 shape: __DATA,__other rides unnamed: {pairs:?}"
    );
}

// ---- the knob -------------------------------------------------------------------

#[test]
fn the_rename_moves_the_output_section_to_its_new_pair() {
    let renamed = SectionRenames::new(vec![("__DATA", "__mydata", "__DATA_CONST", "__mydata")])
        .expect("the map builds");
    let layout = link_layout(|c| c.renames = renamed);
    let pairs = section_pairs(&layout);
    assert!(
        !pairs.contains(&("__DATA".to_string(), "__mydata".to_string())),
        "the old pair is gone: {pairs:?}"
    );
    assert!(
        pairs.contains(&("__DATA_CONST".to_string(), "__mydata".to_string())),
        "the section carries its new (segment, name): {pairs:?}"
    );
    // The section's own content and size ride: 16 bytes at the new
    // address, the `__DATA_CONST` plan owns it.
    let placed = layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__DATA_CONST" && s.name == "__mydata")
        .expect("the renamed section plans");
    assert_eq!(placed.size, 16, "the content size is the section's own");
    let seg = layout
        .segments
        .iter()
        .find(|s| s.name == "__DATA_CONST")
        .expect("the __DATA_CONST plan exists");
    assert!(
        seg.sections.contains(
            &layout
                .sections
                .iter()
                .position(|s| s.seg_name == "__DATA_CONST" && s.name == "__mydata")
                .expect("the section is in the layout")
        ),
        "the renamed section rides the __DATA_CONST segment plan"
    );
}

#[test]
fn the_header_carries_the_renamed_section_entry() {
    let renamed = SectionRenames::new(vec![("__DATA", "__mydata", "__DATA_CONST", "__mydata")])
        .expect("the map builds");
    let layout = link_layout(|c| c.renames = renamed);
    // The load-command stream names the new pair: the section entry's
    // 16-byte segname/sectname fields carry it (the byte shape dyld
    // reads — NUL-padded to the full field width).
    let header = &layout.header_bytes;
    let seg = b"__DATA_CONST\0\0\0\0";
    let hits = header.windows(16).filter(|w| *w == seg).count();
    assert!(
        hits >= 2,
        "the renamed section's segname rides the header stream ({hits})"
    );
}

// ---- the merge ------------------------------------------------------------------

#[test]
fn two_renamed_sections_coalesce_onto_the_target_bucket() {
    // Two objects, each carrying `__DATA,__mine` — one of them renamed
    // onto the other's pair: one output section, two pieces, the sizes
    // summed (the grouping is by name).
    let mut a = ObjectBuilder::new("a.o").set_subsections_via_symbols(true);
    let at = a.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let ad = a.add_section(ObjectSection::data("__mine", vec![0x11u8; 8], vec![]));
    a.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: at,
        value: 0,
        weak: false,
    });
    a.add_symbol(ObjectSymbol::Defined {
        name: "_a_sym".into(),
        section_index: ad,
        value: 0,
        weak: false,
    });
    let mut b = ObjectBuilder::new("b.o").set_subsections_via_symbols(true);
    let bc = b.add_section(ObjectSection::data("__mine", vec![0x22u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_b_sym".into(),
        section_index: bc,
        value: 0,
        weak: false,
    });
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a.build().expect("the fixture object builds"),
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b.build().expect("the fixture object builds"),
        },
    ];
    let renamed = SectionRenames::new(vec![("__DATA", "__mine", "__DATA", "__mine2")])
        .expect("the map builds");
    let cfg = LinkConfig {
        renames: renamed,
        ..LinkConfig::default()
    };
    let layout = link(&inputs, &[], &cfg).expect("the corpus links").layout;
    let merged = layout
        .sections
        .iter()
        .find(|s| s.name == "__mine2")
        .expect("the target bucket plans");
    assert_eq!(merged.size, 16, "the two members coalesce: sizes sum");
    assert_eq!(merged.pieces.len(), 2, "one piece per input section");
}

// ---- the type rule ---------------------------------------------------------------

#[test]
fn the_zero_fill_type_rule_outranks_the_rename() {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let zero = b.add_section(ObjectSection::zerofill("__mybss", 64, 3));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_zero_sym".into(),
        section_index: zero,
        value: 0,
        weak: false,
    });
    let inputs = vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let renamed = SectionRenames::new(vec![("__DATA", "__mybss", "__DATA_CONST", "__mybss")])
        .expect("the map builds");
    let cfg = LinkConfig {
        renames: renamed,
        dead_strip: false,
        ..LinkConfig::default()
    };
    let layout = link(&inputs, &[], &cfg).expect("the corpus links").layout;
    let pairs = section_pairs(&layout);
    assert!(
        pairs.contains(&("__DATA".to_string(), "__common".to_string())),
        "the zero-fill bytes land in __common exactly as they did: {pairs:?}"
    );
    assert!(
        !pairs.contains(&("__DATA_CONST".to_string(), "__mybss".to_string())),
        "the S_ZEROFILL type rule outranks the rename: {pairs:?}"
    );
}

// ---- the refusals -----------------------------------------------------------------

#[test]
fn a_rename_into_a_synthetic_target_refuses() {
    for (seg, name) in [
        ("__TEXT", "__unwind_info"),
        ("__TEXT", "__chain_starts"),
        ("__TEXT", "__init_offsets"),
        ("__DATA", "__common"),
    ] {
        let err = SectionRenames::new(vec![("__DATA", "__mydata", seg, name)])
            .expect_err("the synthetic target refuses");
        assert!(
            err.to_string().contains(name),
            "the refusal names the synthetic target ({name}): {err}"
        );
    }
}

#[test]
fn a_name_over_the_16_byte_field_width_refuses() {
    let long = "___________seventeen";
    assert_eq!(long.len(), 20, "the fixture name overflows the field");
    let err = SectionRenames::new(vec![("__DATA", "__mydata", "__DATA", long)])
        .expect_err("the over-wide target refuses");
    assert!(
        err.to_string().contains("16"),
        "the refusal names the 16-byte field width: {err}"
    );
    let err = SectionRenames::new(vec![("__DATA", long, "__DATA", "__ok")])
        .expect_err("the over-wide source refuses");
    assert!(
        err.to_string().contains("16"),
        "the refusal names the 16-byte field width: {err}"
    );
}

#[test]
fn a_duplicate_source_refuses() {
    let err = SectionRenames::new(vec![
        ("__DATA", "__mydata", "__DATA_CONST", "__one"),
        ("__DATA", "__mydata", "__DATA_CONST", "__two"),
    ])
    .expect_err("the duplicate source refuses");
    assert!(
        err.to_string().contains("__mydata"),
        "the refusal names the doubled source: {err}"
    );
}

#[test]
fn a_rename_outside_the_m1_trio_refuses_at_layout() {
    let renamed = SectionRenames::new(vec![("__DATA", "__mydata", "__MYSEG", "__mydata")])
        .expect("the map builds");
    let cfg = LinkConfig {
        renames: renamed,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the out-of-trio segment refuses");
    assert!(
        err.to_string().contains("__MYSEG"),
        "the refusal names the renamed segment: {err}"
    );
}

// ---- the lock ---------------------------------------------------------------------

#[test]
fn the_decision_links_deterministically() {
    let mk = || {
        SectionRenames::new(vec![("__DATA", "__mydata", "__DATA_CONST", "__mydata")])
            .expect("the map builds")
    };
    let a = link_layout(|c| c.renames = mk()).header_bytes;
    let b = link_layout(|c| c.renames = mk()).header_bytes;
    assert_eq!(a, b, "the double link is stable");
}

#[test]
fn the_relocatable_output_never_reads_the_decision() {
    // The relocatable link plans separately (`link_reloc`): it stops
    // before Pass 3 and its emit reads the Pass-1 product, whose section
    // tables are the input's, verbatim — the rename decision never reads
    // there (the M41/M43/M47 inert-for-relocatable shape). The input
    // section pairs ride under either decision.
    let renamed = SectionRenames::new(vec![("__DATA", "__mydata", "__DATA_CONST", "__mydata")])
        .expect("the map builds");
    for use_renames in [false, true] {
        let cfg = LinkConfig {
            filetype: OutputType::Relocatable,
            renames: if use_renames {
                renamed.clone()
            } else {
                SectionRenames::new(Vec::new()).expect("the empty map builds")
            },
            ..LinkConfig::default()
        };
        let result = link_reloc(&corpus(), &[], &cfg, Parallelism::Auto)
            .expect("the relocatable link plans under either decision");
        let pairs: Vec<(String, String)> = result
            .objects
            .iter()
            .flat_map(|obj| {
                obj.sections
                    .iter()
                    .map(|s| (s.segment.clone(), s.name.clone()))
            })
            .collect();
        assert!(
            pairs.contains(&("__DATA".to_string(), "__mydata".to_string())),
            "-r carries its input section table verbatim: {pairs:?}"
        );
    }
}
