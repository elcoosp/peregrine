//! M28 — the section-alignment floors (`-sectalign <seg> <sect> <align>`):
//! the packing loop's per-section alignment stops being the input
//! object's word alone and gains a named floor on
//! [`pgr_core::layout::LinkConfig`] — ld64's flag for raising a named
//! section's alignment (ABI contracts, page-tailed data, patching
//! payloads that need a wider boundary). The default table is empty:
//! every pre-M28 link plans byte-for-byte what it planned before.
//!
//! Gate matrix:
//! * the floor — a named floor *raises* the section's alignment (the
//!   max of the input's and the named one): the plan's align exponent
//!   carries the decision and the section's address lands on the raised
//!   boundary;
//! * the max — a floor at or below the input's alignment is a no-op
//!   (the input bytes win; the pre-M28 plan is byte-identical);
//! * the default — an empty table plans the pre-M28 bytes exactly;
//! * the refusals — the grammar refuses with the fix: an unknown
//!   segment, `__LINKEDIT` (it carries no sections), an empty or
//!   oversized or NUL-bearing section name, a non-power-of-two value,
//!   a value beyond the 0x4000 ceiling, a twice-named (segment,
//!   section); the relocatable output refuses the knob outright (its
//!   sections are the input's, verbatim);
//! * the lock — the decision links deterministically.

use pgr_core::layout::{LinkConfig, OutputType, PlacedSection};
use pgr_core::link::{LinkInput, link};
use pgr_core::sect_align::{SectAlign, SectAlignTable};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A corpus whose `__DATA` segment carries two sections — the raised
/// floor must move the *second* one (the first sits on the fresh
/// segment's page boundary either way).
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.add_section(ObjectSection::data("__data", vec![0xAA; 8], vec![]));
    // A second `__DATA` section: tiny, 4-aligned — a floor above 4 moves it.
    b.add_section(ObjectSection::data("__more", vec![0x55; 12], vec![]));
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus and returns the layout plan.
fn plan(tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg).expect("the corpus links").layout
}

/// The plan's sections (segment, section, addr, align exponent).
fn sections_of(layout: &pgr_core::layout::Layout) -> Vec<(&str, &str, u64, u32)> {
    layout
        .sections
        .iter()
        .map(|s: &PlacedSection| {
            (
                s.seg_name.as_str(),
                s.name.as_str(),
                s.vm_addr,
                s.align_log2,
            )
        })
        .collect()
}

/// The identity proxy: header bytes + file size (the header carries the
/// `section_64` entries — an align or offset move shows up there).
fn identity(tweak: impl FnOnce(&mut LinkConfig)) -> (Vec<u8>, u64) {
    let l = plan(tweak);
    (l.header_bytes, l.file_size)
}

// ---- the floor ----------------------------------------------------------------

#[test]
fn the_floor_raises_the_named_section() {
    let mut table = SectAlignTable::default();
    table
        .push(SectAlign::from_flag("__DATA", "__more", 0x4000).expect("the floor validates"))
        .expect("the first decision lands");
    let layout = plan(|c| c.sect_aligns = table);
    let secs = sections_of(&layout);
    let more = secs
        .iter()
        .find(|(seg, name, _, _)| *seg == "__DATA" && *name == "__more")
        .expect("the named section exists");
    assert_eq!(more.3, 14, "the plan carries the raised exponent");
    assert_eq!(
        more.2 % 0x4000,
        0,
        "the address lands on the raised boundary ({:#x})",
        more.2
    );
    // The unnamed section keeps its input alignment.
    let data = secs
        .iter()
        .find(|(seg, name, _, _)| *seg == "__DATA" && *name == "__data")
        .expect("the data section exists");
    assert_eq!(data.3, 3, "the unnamed section keeps its input align");
}

#[test]
fn a_floor_below_the_input_align_is_a_noop() {
    let mut table = SectAlignTable::default();
    table
        .push(SectAlign::from_flag("__DATA", "__more", 2).expect("the floor validates"))
        .expect("the first decision lands");
    assert_eq!(
        identity(|c| c.sect_aligns = table),
        identity(|_| {}),
        "the max semantics keep the input's stronger alignment"
    );
}

#[test]
fn an_empty_table_plans_the_pre_m28_bytes() {
    assert_eq!(
        identity(|_| {}),
        identity(|c| c.sect_aligns = SectAlignTable::default()),
        "the default decision set is empty"
    );
    assert!(SectAlignTable::default().is_empty());
}

// ---- the refusals ---------------------------------------------------------------

#[test]
fn the_grammar_refuses_with_the_fix() {
    // An unknown segment names the planned set.
    let err = SectAlign::from_flag("__FOO", "__data", 0x1000).expect_err("unknown refuses");
    assert!(err.to_string().contains("__DATA"), "{err}");
    // `__LINKEDIT` carries no sections — the knob would never land.
    let err = SectAlign::from_flag("__LINKEDIT", "__symtab", 0x1000).expect_err("refuses");
    assert!(err.to_string().contains("no sections"), "{err}");
    // An empty section name names nothing.
    let err = SectAlign::from_flag("__DATA", "", 0x1000).expect_err("refuses");
    assert!(err.to_string().contains("empty"), "{err}");
    // A NUL-bearing name would truncate in the 16-byte field.
    let err = SectAlign::from_flag("__DATA", "__da\0ta", 0x1000).expect_err("refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
    // The name field is 16 bytes.
    let err =
        SectAlign::from_flag("__DATA", "__averylongsectionname", 0x1000).expect_err("refuses");
    assert!(err.to_string().contains("16 bytes"), "{err}");
    // Non-power-of-two values are not alignments.
    let err = SectAlign::from_flag("__DATA", "__data", 3000).expect_err("refuses");
    assert!(err.to_string().contains("power of two"), "{err}");
    // The exponent ceiling is 14 (0x4000 — the 16 KiB page).
    let err = SectAlign::from_flag("__DATA", "__data", 0x8000).expect_err("refuses");
    assert!(err.to_string().contains("0x4000"), "{err}");
}

#[test]
fn a_twice_named_section_refuses_on_push() {
    let mut table = SectAlignTable::default();
    let first = SectAlign::from_flag("__DATA", "__data", 0x1000).expect("validates");
    table.push(first).expect("the first lands");
    let second = SectAlign::from_flag("__DATA", "__data", 0x2000).expect("validates");
    let err = table.push(second).expect_err("the duplicate refuses");
    assert!(err.to_string().contains("__data"), "{err}");
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let mut table = SectAlignTable::default();
    table
        .push(SectAlign::from_flag("__DATA", "__data", 0x1000).expect("validates"))
        .expect("lands");
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        sect_aligns: table,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the relocatable output refuses");
    assert!(
        err.to_string().contains("sectalign"),
        "the refusal names the knob: {err}"
    );
}

// ---- the lock -----------------------------------------------------------------

#[test]
fn the_decision_links_deterministically() {
    let table = |v: u64| {
        let mut t = SectAlignTable::default();
        t.push(SectAlign::from_flag("__DATA", "__more", v).expect("validates"))
            .expect("lands");
        t
    };
    let a = identity(|c| c.sect_aligns = table(0x4000));
    let b = identity(|c| c.sect_aligns = table(0x4000));
    assert_eq!(a, b, "the double link is stable");
}
