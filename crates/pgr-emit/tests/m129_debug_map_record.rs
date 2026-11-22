//! M129 — the incremental record treats a stab-set change as a digest
//! change: the record feeds `symtab_bytes(layout)` (which carries the
//! debug-map stabs) into the page hashes (the whole image, including
//! the symtab in `__LINKEDIT`) and the symtab byte stream. A flip in
//! the stab set (stab-free → stab-carrying over the same atoms) must
//! produce a different record — so every fallback rung lands a correct
//! image (the relink re-records the new stab set, never silently
//! reuses the old one).
//!
//! The gate is the record's own `page_hashes` and the encoded record
//! bytes: two links over the same atoms, one stab-free and one
//! stab-carrying, produce two records whose page hashes and encoded
//! bytes differ (the stab set rides the symtab, the symtab rides the
//! image, the image is hashed page-by-page).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_emit::build_image_fused;
use pgr_emit::incremental::LinkRecord;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectStab, ObjectSymbol};

/// A stab-free corpus: `_main` over a small `__text`.
fn plain_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture builds"),
    }]
}

/// A stab-carrying corpus: the same `_main` over the same `__text`, plus
/// the debug-map stabs (`N_SO`, `N_OSO`, `N_FUN` begin/end, `N_GSYM`).
/// The atoms are identical to the plain corpus — only the stab set
/// differs.
fn stab_corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_stab(ObjectStab::So {
        path: "main.c".into(),
    });
    b.add_stab(ObjectStab::Oso {
        path: "main.o".into(),
    });
    b.add_stab(ObjectStab::Fun {
        name: "_main".into(),
        section_index: text,
        value: 0,
    });
    b.add_stab(ObjectStab::FunEnd { size: 8 });
    b.add_stab(ObjectStab::Gsym {
        name: "_main".into(),
    });
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture builds"),
    }]
}

/// Links a corpus as an executable and records the link record.
fn link_and_record(corpus: &[LinkInput]) -> (LinkRecord, Vec<u8>) {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let result = link_cached(corpus, &[], &cfg, Parallelism::Auto, None).expect("the link runs");
    let image = build_image_fused(&result.layout, &result.objects).expect("the image emits");
    let record = LinkRecord::record(&result.layout, &result.objects, &image, None)
        .expect("the record builds");
    (record, image)
}

#[test]
fn a_stab_set_change_produces_a_different_record() {
    let (plain_record, plain_image) = link_and_record(&plain_corpus());
    let (stab_record, stab_image) = link_and_record(&stab_corpus());

    // The images differ (the stab-carrying image carries the debug-map
    // rows the stab-free image does not).
    assert_ne!(
        plain_image, stab_image,
        "the stab-carrying image differs from the stab-free image"
    );

    // The records' page hashes differ — the stab set rides the symtab,
    // the symtab rides the image, the image is hashed page-by-page.
    assert_ne!(
        plain_record.page_hashes, stab_record.page_hashes,
        "the stab-set change is a page-hash change (the digest captures the stab set)"
    );

    // The encoded records differ (the record is the persistent form the
    // next relink reads — a stab-set change re-records, never silently
    // reuses the old record).
    assert_ne!(
        plain_record.encode(),
        stab_record.encode(),
        "the encoded records differ (the stab-set change re-records)"
    );
}

#[test]
fn the_same_stab_corpus_records_identically() {
    // The determinism contract: the same stab-carrying corpus records
    // byte-identically (the fixed mtime is the determinism anchor).
    let (a, _) = link_and_record(&stab_corpus());
    let (b, _) = link_and_record(&stab_corpus());
    assert_eq!(
        a.encode(),
        b.encode(),
        "the same stab corpus records identically"
    );
}
