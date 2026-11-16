//! M52 — the dead-strip init/term roots (`-no_dead_strip_inits_and_terms`):
//! ld64's flag ("The linker never dead strips initialization and
//! termination routines") is the Pass-2 decision the dead-strip root set
//! reads — the termination-pointer sections
//! (`S_MOD_TERM_FUNC_POINTERS`) join the initialization-pointer
//! sections' whole-section root treatment, so a term routine nothing
//! references survives `-dead_strip`. The default (`false`) keeps every
//! pre-M52 link byte-identical: the init half has been the house default
//! since M5 (the `__mod_init_func` sections are roots), and an
//! unreferenced term routine strips exactly as it did.
//!
//! Gate matrix:
//! * the default — an unreferenced term routine strips under
//!   `-dead_strip` (the pre-M52 shape); the init routine beside it
//!   survives (the M5 root the flag never changes);
//! * the knob — the term routine survives: the termination-pointer
//!   section is a root like the initialization-pointer one;
//! * the inert shapes — without `-dead_strip` the decision never fires
//!   (nothing strips either way), and the relocatable output strips
//!   nothing (its symbol table is the input's, verbatim — the
//!   M41/M43/M47 inert-for-relocatable shape);
//! * the lock — double-link determinism holds across the decision.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_with};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// main.o: the entry the executable root needs.
fn main_object() -> ObjectBuilder {
    let mut main = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = main.add_section(ObjectSection::text(
        "__text",
        [0xD65F_03C0u32.to_le_bytes()].concat(),
        vec![],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    main
}

/// routines.o: one unreferenced initializer and one unreferenced
/// terminator, each with its pointer-section slot.
fn routines_object() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("routines.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let init_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_init_fn".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let term_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_term_fn".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(init_sym as u32).at(0)],
    ));
    b.section_mut(modinit).flags = pgr_format::consts::S_MOD_INIT_FUNC_POINTERS;
    let modterm = b.add_section(ObjectSection::data(
        "__mod_term_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(term_sym as u32).at(0)],
    ));
    b.section_mut(modterm).flags = pgr_format::consts::S_MOD_TERM_FUNC_POINTERS;
    b
}

/// Links the corpus and returns the output symtab names.
fn link_names(tweak: impl FnOnce(&mut LinkConfig)) -> Vec<Vec<u8>> {
    let cfg_link = |cfg: &LinkConfig| {
        link_with(
            &[
                LinkInput {
                    name: "main.o".to_string(),
                    bytes: main_object().build().expect("the fixture object builds"),
                },
                LinkInput {
                    name: "routines.o".to_string(),
                    bytes: routines_object()
                        .build()
                        .expect("the fixture object builds"),
                },
            ],
            &[],
            cfg,
            Parallelism::Auto,
        )
        .expect("the corpus links")
    };
    let mut cfg = LinkConfig {
        ident: "initsterms".into(),
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    let result = cfg_link(&cfg);
    result
        .layout
        .symbols
        .iter()
        .map(|s| result.interner.bytes(s.name).to_vec())
        .collect()
}

#[test]
fn the_default_strips_an_unreferenced_term_routine_and_keeps_the_init() {
    let names = link_names(|c| c.dead_strip = true);
    assert!(
        !names.contains(&b"_term_fn".to_vec()),
        "the pre-M52 shape: an unreferenced terminator strips: {names:?}"
    );
    assert!(
        names.contains(&b"_init_fn".to_vec()),
        "the M5 root: an unreferenced initializer survives either way: {names:?}"
    );
}

#[test]
fn the_knob_roots_the_term_routines() {
    let names = link_names(|c| {
        c.dead_strip = true;
        c.no_dead_strip_inits_and_terms = true;
    });
    assert!(
        names.contains(&b"_term_fn".to_vec()),
        "the named decision: the terminator never strips: {names:?}"
    );
    assert!(
        names.contains(&b"_init_fn".to_vec()),
        "the init half rides unchanged under the knob: {names:?}"
    );
}

#[test]
fn without_dead_strip_the_decision_never_fires() {
    let plain = link_names(|_| {});
    let knobbed = link_names(|c| c.no_dead_strip_inits_and_terms = true);
    assert!(
        plain.contains(&b"_term_fn".to_vec()) && knobbed.contains(&b"_term_fn".to_vec()),
        "nothing strips without -dead_strip, either decision"
    );
    assert_eq!(plain, knobbed, "the decision is inert off the strip");
}

#[test]
fn the_relocatable_output_never_reads_the_decision() {
    for keep in [false, true] {
        let cfg = LinkConfig {
            filetype: OutputType::Relocatable,
            no_dead_strip_inits_and_terms: keep,
            ..LinkConfig::default()
        };
        let result = link_with(
            &[LinkInput {
                name: "routines.o".to_string(),
                bytes: routines_object()
                    .build()
                    .expect("the fixture object builds"),
            }],
            &[],
            &cfg,
            Parallelism::Auto,
        )
        .expect("the relocatable link plans under either decision");
        let names: Vec<Vec<u8>> = result
            .layout
            .symbols
            .iter()
            .map(|s| result.interner.bytes(s.name).to_vec())
            .collect();
        assert!(
            names.contains(&b"_term_fn".to_vec()),
            "-r carries its input symbol table verbatim: {names:?}"
        );
    }
}

#[test]
fn the_decision_links_deterministically() {
    let a = link_names(|c| {
        c.dead_strip = true;
        c.no_dead_strip_inits_and_terms = true;
    });
    let b = link_names(|c| {
        c.dead_strip = true;
        c.no_dead_strip_inits_and_terms = true;
    });
    assert_eq!(a, b, "the double link is stable");
}
