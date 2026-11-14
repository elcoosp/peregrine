//! M29 — the header-region floor (`-headerpad`): the flag the driver
//! surface accepted as an advisory no-op since M1 becomes a real
//! decision on [`pgr_core::layout::LinkConfig`] — the minimum space the
//! header and its load commands occupy before the first `__TEXT`
//! section, the region `install_name_tool` grows install names in. The
//! default (`None`) keeps every pre-M29 link byte-identical; naming a
//! floor at or below the natural size plans the same bytes (a floor is
//! a minimum, never a shrink).
//!
//! Gate matrix:
//! * the floor — a named pad grows the reserved region: the first
//!   `__TEXT` section moves to the raised boundary and every later
//!   byte follows it (the plan's shapes carry the decision);
//! * the max — a floor at or below the natural header size plans the
//!   pre-M29 bytes;
//! * the default — an unnamed pad plans the pre-M29 bytes exactly;
//! * the refusals — the grammar refuses with the fix (zero names the
//!   absence of the knob, an unaligned value breaks the load-command
//!   alignment, a value beyond the 16 KiB page has no home in the
//!   first-page contract); the relocatable output refuses the knob
//!   outright (its sections are the input's, carried verbatim);
//! * the lock — the decision links deterministically and on the
//!   classic opcode path (the pad is a packing decision, not a
//!   fixup-level one).

use pgr_core::header_pad::HeaderPad;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A single-object corpus (`_main` exported) linkable as any kind.
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

/// The first `__TEXT` section's placement (file and VM cursor).
fn first_text(layout: &pgr_core::layout::Layout) -> (u64, u64) {
    let s = layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT")
        .expect("the text section exists");
    (s.file_off, s.vm_addr)
}

/// The identity proxy: header bytes + file size (a pad move shifts the
/// first section's `section_64` offset — the header shows it).
fn identity(tweak: impl FnOnce(&mut LinkConfig)) -> (Vec<u8>, u64) {
    let l = plan(tweak);
    (l.header_bytes, l.file_size)
}

// ---- the floor ----------------------------------------------------------------

#[test]
fn the_floor_grows_the_reserved_region() {
    let layout = plan(|c| c.header_pad = Some(HeaderPad::from_override(0x2000).expect("ok")));
    let (file_off, vm_addr) = first_text(&layout);
    assert_eq!(
        file_off, 0x2000,
        "the first section sits past the named floor"
    );
    assert_eq!(
        vm_addr - layout.image_base,
        0x2000,
        "the VM cursor rides the file cursor (the constant-delta base)"
    );
    // The natural (pre-M29) size sits far below the floor.
    let natural = plan(|_| {});
    let (natural_off, _) = first_text(&natural);
    assert!(
        natural_off < 0x2000,
        "the pre-M29 header region is smaller ({natural_off})"
    );
}

#[test]
fn a_floor_below_the_natural_size_is_a_noop() {
    let natural = identity(|_| {});
    // The natural region on this corpus is well under 0x400 — the
    // smaller floor plans the same bytes.
    let small = identity(|c| c.header_pad = Some(HeaderPad::from_override(0x100).expect("ok")));
    assert_eq!(
        natural, small,
        "the max semantics keep the natural header size"
    );
}

#[test]
fn an_unnamed_pad_plans_the_pre_m29_bytes() {
    let natural = identity(|_| {});
    let none = identity(|c| c.header_pad = None);
    assert_eq!(natural, none, "the default decision is the absence");
    assert_eq!(LinkConfig::default().header_pad, None);
}

// ---- the refusals ---------------------------------------------------------------

#[test]
fn the_grammar_refuses_with_the_fix() {
    // Zero names the absence of the knob, not a decision.
    let err = HeaderPad::from_override(0).expect_err("zero refuses");
    assert!(err.to_string().contains("drop the flag"), "{err}");
    // The load-command alignment is 8 — an unaligned floor would
    // misplace the first section.
    let err = HeaderPad::from_override(0x2001).expect_err("unaligned refuses");
    assert!(err.to_string().contains("multiple of 8"), "{err}");
    // The first-page contract caps the region at the 16 KiB page.
    let err = HeaderPad::from_override(0x8000).expect_err("beyond the page refuses");
    assert!(err.to_string().contains("0x4000"), "{err}");
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        header_pad: Some(HeaderPad::from_override(0x2000).expect("ok")),
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the relocatable output refuses");
    assert!(
        err.to_string().contains("headerpad"),
        "the refusal names the knob: {err}"
    );
}

// ---- the lock -----------------------------------------------------------------

#[test]
fn the_decision_links_deterministically_and_on_the_classic_path() {
    let pad =
        |c: &mut LinkConfig| c.header_pad = Some(HeaderPad::from_override(0x2000).expect("ok"));
    let a = identity(pad);
    let b = identity(pad);
    assert_eq!(a, b, "the double link is stable");
    // The pad is a packing decision — the classic opcode path plans the
    // same region.
    let classic = plan(|c| {
        pad(c);
        c.fixup_chains = false;
    });
    let (file_off, _) = first_text(&classic);
    assert_eq!(file_off, 0x2000, "the classic path carries the named floor");
}
