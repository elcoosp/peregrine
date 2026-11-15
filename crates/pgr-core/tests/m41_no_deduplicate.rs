//! M41 — the dedup toggle: `-no_deduplicate` turns the D4 `__cstring`
//! merge off — every input literal rides the output verbatim (the
//! pre-D4 shape), the default (`true`) keeps every pre-M41 link
//! byte-identical, and the knob is a Pass-3 decision — never a parse
//! blindfold: the parse still splits cstring sections into atoms
//! (the liveness and the POI cache are flag-independent), and
//! dead-strip still drops dead literals under either decision.
//!
//! Gate matrix:
//! * the default — two identical literals across two inputs merge into
//!   one output copy and the duplicate's symbol remaps to the
//!   canonical address (the D4 contract, unchanged since M5);
//! * the suppression — the same corpus keeps both copies and every
//!   symbol lands on its own instance (the verbatim pass-through);
//! * the polarity — `LinkConfig::default()` carries `deduplicate:
//!   true` and the explicitly-spelled default links byte-identical;
//! * the liveness contract — dead literals strip under both decisions
//!   (the knob widens the merge off, never the strip);
//! * the relocatable output — `-r` carries the input sections
//!   verbatim under both decisions (the merge is a segmented-output
//!   decision).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// One `__text` of `n` RET functions with symbols at every function
/// start (`_main` for the first — only one input may own it).
fn ret_object(name: &str, strings: &[&str], string_syms: &[&str]) -> Vec<u8> {
    assert_eq!(
        strings.len(),
        string_syms.len(),
        "one named symbol per literal"
    );
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if name == "a.o" {
            "_main".into()
        } else {
            format!("_{}", name.trim_end_matches(".o"))
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    let cstr = b.add_section(ObjectSection::cstring(&strings.join("\0")));
    for (i, sym) in string_syms.iter().enumerate() {
        // The offset of the i-th literal inside the joined, NUL-terminated
        // section data (each literal but the last ends one NUL earlier than
        // `strings[i].len()` because the join inserted a separator NUL).
        let offset: u64 = strings[..i].iter().map(|s| s.len() as u64 + 1).sum();
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: cstr,
            value: offset,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// The output `__TEXT,__cstring` section.
fn cstring_section(layout: &pgr_core::layout::Layout) -> &pgr_core::layout::PlacedSection {
    layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__cstring")
        .expect("the corpus carries a cstring bucket")
}

/// The input symbol index of the object's one cstring-section symbol
/// (each fixture object defines exactly one named literal).
fn cstring_sym_index(obj: &pgr_core::object::InputObject) -> usize {
    let cstring_sect = obj
        .sections
        .iter()
        .position(|s| {
            s.flags & pgr_format::consts::SECTION_TYPE_MASK
                == pgr_format::consts::S_CSTRING_LITERALS
        })
        .expect("the fixture carries a cstring section");
    obj.symbols
        .iter()
        .position(|s| s.section == Some(cstring_sect))
        .expect("the fixture symbol names the literal")
}

// ---- the default (the D4 contract, unchanged) ---------------------------------

#[test]
fn the_default_merges_the_duplicates() {
    let a = ret_object("a.o", &["shared literal"], &["_s1"]);
    let b_bytes = ret_object("b.o", &["shared literal"], &["_s2"]);
    let cfg = LinkConfig {
        load_symbols: vec![b"_s1".to_vec(), b"_s2".to_vec()],
        ..LinkConfig::default()
    };
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a,
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b_bytes,
        },
    ];
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let sect = cstring_section(&result.layout);
    assert_eq!(
        sect.size,
        ("shared literal\0".len()) as u64,
        "the default carries one output copy"
    );
    assert_eq!(sect.pieces.len(), 1, "one canonical piece");
    // The duplicate's symbol remaps to the canonical address (the D4
    // remap — the M5 contract the default keeps byte-identical).
    let i1 = cstring_sym_index(&result.objects[0]);
    let i2 = cstring_sym_index(&result.objects[1]);
    let v1 = result.layout.resolved[0].syms[i1];
    let v2 = result.layout.resolved[1].syms[i2];
    assert_eq!(v1, v2, "the duplicate resolves to the canonical copy");
}

// ---- the suppression ----------------------------------------------------------

#[test]
fn the_suppression_keeps_every_copy() {
    let a = ret_object("a.o", &["shared literal"], &["_s1"]);
    let b_bytes = ret_object("b.o", &["shared literal"], &["_s2"]);
    let cfg = LinkConfig {
        deduplicate: false,
        load_symbols: vec![b"_s1".to_vec(), b"_s2".to_vec()],
        ..LinkConfig::default()
    };
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a,
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b_bytes,
        },
    ];
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let sect = cstring_section(&result.layout);
    assert_eq!(
        sect.size,
        2 * ("shared literal\0".len()) as u64,
        "the suppression keeps both input copies"
    );
    // Every symbol lands on its own instance: the values differ by the
    // first copy's stride (the verbatim pass-through — no remap).
    let i1 = cstring_sym_index(&result.objects[0]);
    let i2 = cstring_sym_index(&result.objects[1]);
    let v1 = result.layout.resolved[0].syms[i1];
    let v2 = result.layout.resolved[1].syms[i2];
    assert_ne!(v1, v2, "the copies stay distinct");
    assert_eq!(
        v2 - v1,
        ("shared literal\0".len()) as u64,
        "the second instance sits at its own stride"
    );
}

#[test]
fn the_suppressed_shape_is_the_whole_section_pass_through() {
    // The suppressed link carries one whole-section piece per input;
    // the default carries one canonical piece per unique string.
    let a = ret_object("a.o", &["shared literal"], &["_s1"]);
    let b_bytes = ret_object("b.o", &["shared literal"], &["_s2"]);
    let cfg = LinkConfig {
        deduplicate: false,
        ..LinkConfig::default()
    };
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a,
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b_bytes,
        },
    ];
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let sect = cstring_section(&result.layout);
    assert_eq!(sect.pieces.len(), 2, "one whole-section piece per input");
    assert_eq!(
        sect.flags & pgr_format::consts::SECTION_TYPE_MASK,
        pgr_format::consts::S_CSTRING_LITERALS,
        "the output section keeps its type"
    );
}

// ---- the polarity -------------------------------------------------------------

#[test]
fn the_default_polarity_and_the_explicit_spelling_agree() {
    let a = ret_object("a.o", &["shared literal"], &["_s1"]);
    let b_bytes = ret_object("b.o", &["shared literal"], &["_s2"]);
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a,
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b_bytes,
        },
    ];
    assert!(
        LinkConfig::default().deduplicate,
        "the default keeps every pre-M41 link byte-identical"
    );
    let cfg = LinkConfig {
        deduplicate: true,
        ..LinkConfig::default()
    };
    let implicit = link(&inputs, &[], &LinkConfig::default()).expect("links");
    let explicit = link(&inputs, &[], &cfg).expect("links");
    assert_eq!(
        implicit.layout.file_size, explicit.layout.file_size,
        "the spelled default is the default"
    );
    assert_eq!(implicit.layout.header_bytes, explicit.layout.header_bytes);
}

// ---- the liveness contract ------------------------------------------------------

#[test]
fn dead_literals_strip_under_both_decisions() {
    // Each object roots its first literal (`-u`-style load symbol) and
    // carries a second, symbol-less literal nothing references.
    let mut a = ObjectBuilder::new("a.o").set_subsections_via_symbols(true);
    let text = a.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    a.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let keep = "keep me";
    let dead = "dead literal";
    let cstr_a = a.add_section(ObjectSection::cstring(&format!("{keep}\0{dead}")));
    a.add_symbol(ObjectSymbol::Defined {
        name: "_s1".into(),
        section_index: cstr_a,
        value: 0,
        weak: false,
    });
    let mut b = ObjectBuilder::new("b.o").set_subsections_via_symbols(true);
    let text_b = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_b".into(),
        section_index: text_b,
        value: 0,
        weak: false,
    });
    let cstr_b = b.add_section(ObjectSection::cstring(&format!("{keep}\0{dead}")));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_s2".into(),
        section_index: cstr_b,
        value: 0,
        weak: false,
    });
    let inputs = vec![
        LinkInput {
            name: "a.o".to_string(),
            bytes: a.build().expect("builds"),
        },
        LinkInput {
            name: "b.o".to_string(),
            bytes: b.build().expect("builds"),
        },
    ];
    let keep_len = keep.len() as u64 + 1;
    for dedup in [true, false] {
        let cfg = LinkConfig {
            dead_strip: true,
            deduplicate: dedup,
            load_symbols: vec![b"_s1".to_vec(), b"_s2".to_vec()],
            ..LinkConfig::default()
        };
        let result = link(&inputs, &[], &cfg).expect("links");
        let sect = cstring_section(&result.layout);
        let expected = if dedup { keep_len } else { 2 * keep_len };
        assert_eq!(
            sect.size, expected,
            "dead literals strip; the merge follows the decision (dedup={dedup})"
        );
    }
}

// ---- the relocatable output -----------------------------------------------------

#[test]
fn the_relocatable_output_never_dedups() {
    let a = ret_object("a.o", &["shared literal"], &["_s1"]);
    let b_bytes = ret_object("b.o", &["shared literal"], &["_s2"]);
    for dedup in [true, false] {
        let cfg = LinkConfig {
            filetype: OutputType::Relocatable,
            deduplicate: dedup,
            ..LinkConfig::default()
        };
        let inputs = vec![
            LinkInput {
                name: "a.o".to_string(),
                bytes: a.clone(),
            },
            LinkInput {
                name: "b.o".to_string(),
                bytes: b_bytes.clone(),
            },
        ];
        let reloc =
            link_reloc(&inputs, &[], &cfg, Parallelism::Auto).expect("the object output links");
        for obj in &reloc.objects {
            let cstrings: Vec<_> = obj
                .sections
                .iter()
                .filter(|s| {
                    s.flags & pgr_format::consts::SECTION_TYPE_MASK
                        == pgr_format::consts::S_CSTRING_LITERALS
                })
                .collect();
            assert_eq!(
                cstrings.len(),
                1,
                "the input cstring section rides verbatim (dedup={dedup})"
            );
            assert_eq!(
                cstrings[0].data.end - cstrings[0].data.start,
                ("shared literal\0".len()) as u64,
                "the object's bytes are untouched (dedup={dedup})"
            );
        }
    }
}
