//! M36 — the compact-unwind suppression: `-no_compact_unwind` drops
//! the output `__TEXT,__unwind_info` section (the pre-M34 bytes — no
//! section at all), the default keeps every pre-M36 link
//! byte-identical, and the suppression is a Pass-3 decision — never a
//! parse blindfold: a table the parse refuses still refuses with the
//! knob set (the shape the input cannot vouch for is a shape no
//! output should carry, suppressed or not).
//!
//! Gate matrix:
//! * the suppression — an entry-carrying corpus linked under the
//!   named decision plans no section (the pre-M34 shape; the driver's
//!   e2e gates the byte-identity against the entry-free link);
//! * the default — the same corpus under the default decision links
//!   into the M35 compressed shape (the knob names the absence);
//! * the parse contract — a table whose range leaves the object's
//!   `__text` refuses at parse with the knob set;
//! * the wire — the daemon wire v25 carries the decision the resident
//!   relink asked for (the daemon's own round-trip gate).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::CompactUnwindEntry;
use pgr_format::consts::UNWIND_ARM64_MODE_FRAME;

/// A canonical arm64 frame encoding.
const FRAME_ENCODING: u32 = UNWIND_ARM64_MODE_FRAME;

/// One `__text` of `n` RET functions with symbols at every function
/// start (`_main` for the first — only one input may own it).
fn ret_corpus(name: &str, n_fns: usize) -> ObjectBuilder {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
        vec![],
    ));
    let stem = name.trim_end_matches(".o");
    for f in 0..n_fns {
        b.add_symbol(ObjectSymbol::Defined {
            name: if f == 0 {
                "_main".into()
            } else {
                format!("_{stem}_fn_{f}")
            },
            section_index: text,
            value: (f * 4) as u64,
            weak: false,
        });
    }
    b
}

/// An `n`-function object carrying a compact-unwind entry per
/// function.
fn obj_with_unwind(name: &str, n_fns: usize, entries: bool) -> Vec<u8> {
    let mut b = ret_corpus(name, n_fns);
    if entries {
        let table: Vec<CompactUnwindEntry> = (0..n_fns)
            .map(|f| CompactUnwindEntry {
                range_start: (f * 4) as u64,
                range_length: 4,
                encoding: FRAME_ENCODING,
                personality: 0,
                lsda: 0,
            })
            .collect();
        b.add_section(ObjectSection::compact_unwind(&table));
    }
    b.build().expect("the fixture object builds")
}

fn corpus(bytes: Vec<u8>) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes,
    }]
}

/// Links the corpus under `tweak`; returns the full Pass 1–3 result.
fn plan(bytes: Vec<u8>, tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::link::LinkResult {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(bytes), &[], &cfg).expect("the corpus links")
}

/// Whether the layout carries the `__TEXT,__unwind_info` section.
fn carries_unwind_info(layout: &pgr_core::layout::Layout) -> bool {
    layout
        .sections
        .iter()
        .any(|s| s.seg_name == "__TEXT" && s.name == "__unwind_info")
}

// ---- the suppression ----------------------------------------------------------

#[test]
fn the_suppressed_link_plans_no_section() {
    let result = plan(obj_with_unwind("main.o", 3, true), |c| {
        c.compact_unwind = false;
    });
    assert!(
        !carries_unwind_info(&result.layout),
        "the suppression drops the section (the pre-M34 bytes)"
    );
}

#[test]
fn the_default_keeps_the_section() {
    let result = plan(obj_with_unwind("main.o", 3, true), |_| ());
    assert!(
        carries_unwind_info(&result.layout),
        "the default keeps every pre-M36 link byte-identical"
    );
}

// ---- the parse contract --------------------------------------------------------

#[test]
fn the_parse_still_validates_the_table_under_the_suppression() {
    let mut b = ret_corpus("main.o", 2);
    let entries = vec![CompactUnwindEntry {
        range_start: 16, // the two 4-byte functions end at 8
        range_length: 4,
        encoding: FRAME_ENCODING,
        personality: 0,
        lsda: 0,
    }];
    b.add_section(ObjectSection::compact_unwind(&entries));
    let mut cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    cfg.compact_unwind = false;
    let err = link(&corpus(b.build().expect("builds")), &[], &cfg)
        .expect_err("the beyond-__text range refuses even suppressed");
    assert!(
        err.to_string().contains("__LD,__compact_unwind"),
        "the refusal names the table: {err}"
    );
}

// ---- the relocatable output keeps its contract ----------------------------------

#[test]
fn the_relocatable_output_never_engages_the_carriage() {
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        ..LinkConfig::default()
    };
    let reloc = pgr_core::link_reloc(
        &corpus(obj_with_unwind("main.o", 2, true)),
        &[],
        &cfg,
        pgr_core::link::Parallelism::Auto,
    )
    .expect("the object output links");
    assert_eq!(reloc.objects.len(), 1);
    assert_eq!(
        reloc.objects[0].compact_unwind.len(),
        2,
        "the parse carries the table (the suppression is an output decision)"
    );
}
