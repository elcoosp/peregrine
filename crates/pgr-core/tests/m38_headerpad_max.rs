//! M38 — the header-pad auto-floor: `-headerpad_max_install_names` —
//! the M29 row's named later item — is the decision the packing loop
//! reads: the reserved header region grows past its natural size by the
//! room every load-dylib command needs to grow its install name to the
//! longest install name in the image (+1 NUL, 8-byte aligned), the room
//! `install_name_tool` needs to rewrite any install name in place. The
//! flag composes with `-headerpad` (the effective floor is the max of
//! the two — both are minimums); a corpus whose install names are all
//! the same length plans zero growth (the pre-M38 bytes); the
//! relocatable output refuses the knob (its sections are the input's,
//! verbatim).
//!
//! Gate matrix:
//! * the floor — two dylibs of different install-name lengths plan a
//!   header region of natural + Σ growth; the no-flag link plans the
//!   natural region;
//! * the minimum — a single-dylib corpus plans zero growth (the
//!   pre-M38 bytes), and the effective floor is the max of the two
//!   knobs when both are named;
//! * the refusals — the relocatable output refuses the knob;
//! * the wire — the daemon wire v26 carries the decision (the daemon's
//!   own round-trip gate).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::Dylib;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// `_main` (RET) plus a local `_fn_a` definition — the corpus the
/// dylib-less gates link (nothing unresolved, no install names).
fn self_contained_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_fn_a".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// `_main` (RET) with one external reference (`_fn_a`) so the dylibs
/// resolve; the corpus is the same for every gate.
fn main_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_fn_a".into(),
        weak_ref: false,
    });
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// One stub dylib exporting `_fn_a` (the corpus's one external) with the
/// named install name.
fn dylib(install_name: &str) -> Dylib {
    Dylib {
        install_name: install_name.to_string(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_fn_a".to_vec()],
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    }
}

/// Links the corpus (single input) under `tweak`.
fn plan(bytes: &[LinkInput], tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::layout::Layout {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(bytes, &[], &cfg).expect("the corpus links").layout
}

/// The reserved header region: the first `__TEXT` section's file offset
/// (the region the header and its load commands occupy).
fn region_size(layout: &pgr_core::layout::Layout) -> u64 {
    layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT")
        .map_or(layout.header_bytes.len() as u64, |s| s.file_off)
}

fn dylibs(names: &[&str]) -> Vec<Dylib> {
    names.iter().map(|n| dylib(n)).collect()
}

// ---- the floor -------------------------------------------------------------

#[test]
fn the_floor_covers_the_longest_install_name() {
    // Two dylibs: `@rpath/lib_with_a_long_install_name.dylib` (41 chars)
    // and `@rpath/lib_a.dylib` (18). The growth is the difference the
    // longer name needs, per command.
    let bytes = main_corpus();
    let long = "@rpath/lib_with_a_long_install_name.dylib";
    let short = "@rpath/lib_a.dylib";
    let names = [long, short];
    let aligned = |n: &str| (n.len() as u64 + 1 + 7) & !7;
    // Per-command room (the `install_names_growth` semantics): every
    // command gets the room to hold the longest name — the long name is
    // already the longest (its room is 0), the short one grows by the
    // aligned difference.
    let growth = (aligned(long) - aligned(short)) + (aligned(long) - aligned(long));
    let natural = region_size(&plan(&bytes, |c| {
        c.dylibs = dylibs(&names);
    }));
    let padded = region_size(&plan(&bytes, |c| {
        c.dylibs = dylibs(&names);
        c.header_pad_max_install_names = true;
    }));
    assert_eq!(
        padded,
        natural + growth,
        "the reserved region grows by every command's room to the longest name"
    );
    // The natural link (no flag) plans the pre-M38 region.
    assert!(
        padded > natural,
        "the longer install name needs room: {padded} > {natural}"
    );
}

#[test]
fn a_single_dylib_plans_zero_growth() {
    let bytes = main_corpus();
    let name = "@rpath/lib_a.dylib";
    let natural = region_size(&plan(&bytes, |c| {
        c.dylibs = dylibs(&[name]);
    }));
    let padded = region_size(&plan(&bytes, |c| {
        c.dylibs = dylibs(&[name]);
        c.header_pad_max_install_names = true;
    }));
    assert_eq!(
        padded, natural,
        "one install name already is the longest — the pre-M38 bytes"
    );
}

#[test]
fn the_effective_floor_is_the_max_of_the_two_knobs() {
    let bytes = main_corpus();
    let long = "@rpath/lib_with_a_long_install_name.dylib";
    let short = "@rpath/lib_a.dylib";
    let names = [long, short];
    let aligned = |n: &str| (n.len() as u64 + 1 + 7) & !7;
    let growth = (aligned(long) - aligned(short)) * 2;
    // The named floor (0x2000) dwarfs the growth floor; the effective
    // region is the max.
    let padded = region_size(&plan(&bytes, |c| {
        c.dylibs = dylibs(&names);
        c.header_pad = Some(pgr_core::header_pad::HeaderPad::from_override(0x2000).expect("ok"));
        c.header_pad_max_install_names = true;
    }));
    let natural = region_size(&plan(&bytes, |c| {
        c.dylibs = dylibs(&names);
    }));
    assert_eq!(
        padded,
        natural.max(0x2000),
        "the max-of-two-floors semantics — the bigger region wins"
    );
    assert!(growth > 0, "the two names differ — the growth is real");
}

// ---- the refusals ----------------------------------------------------------

#[test]
fn the_relocatable_output_refuses_the_knob() {
    // The `-r` pipeline is `link_reloc` (the driver's `-r` path) — the
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either.
    let bytes = main_corpus();
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        header_pad_max_install_names: true,
        ..LinkConfig::default()
    };
    let err = pgr_core::link::link_reloc(&bytes, &[], &cfg, pgr_core::Parallelism::Serial)
        .expect_err("the relocatable output refuses the knob");
    let msg = err.to_string();
    assert!(
        msg.contains("headerpad"),
        "the refusal names the knob: {msg}"
    );
}

// ---- the cache-independent default ----------------------------------------

#[test]
fn a_corpus_without_dylibs_plans_the_natural_region() {
    // No install names: nothing to grow, the pre-M38 bytes verbatim.
    let bytes = self_contained_corpus();
    let natural = region_size(&plan(&bytes, |c| {
        c.header_pad_max_install_names = true;
    }));
    let plain = region_size(&plan(&bytes, |_| {}));
    assert_eq!(natural, plain, "no install names — nothing to grow");
}
