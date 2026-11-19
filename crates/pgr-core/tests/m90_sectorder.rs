//! M90 — the `-sectorder` rank-append face: ld64's per-section order
//! flag (`-sectorder <seg> <sect> <file>`) rides the M11 rank seam. The
//! classification mirrors ld64's `parseSectionOrderFile` walk exactly:
//! an ordinary section's file appends its entries to the *one* global
//! rank table (ld64: "ignore section information and append all symbol
//! names to global order file"), `__TEXT,__cstring` names the literal
//! face, and a `__TEXT,__literal*` section is the warned no-op. The
//! composition is command-line order — `-order_file`'s entries first
//! when it parses first, every `-sectorder`'s entries as its flag
//! appears — and a name two sources rank is a contradiction (one rank
//! per symbol, both sources named).
//!
//! Gate matrix:
//! * the classification — the three faces, named per (segment, section);
//! * the composition — source order, file order within a source, the
//!   duplicate refusal with both sources, the composed table equal to
//!   the single merged file's table;
//! * the link parity — a composed table lays the image the merged file
//!   lays (the rank sort is a pure function of the table);
//! * the advisory — composed entries that rank nothing ride
//!   `order_unmatched` in entry order, the M11 face.

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::order::{
    OrderComposeError, OrderEntry, OrderFile, OrderSource, SectionOrderClass, SymbolOrder,
    classify_section_order,
};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

// ---- the ld64 classification -------------------------------------------

#[test]
fn the_classification_names_the_three_faces() {
    // An ordinary section: the rank-append face (the section names are
    // inert — ld64 ignores them for anything but __cstring/__literal).
    assert_eq!(
        classify_section_order("__TEXT", "__text"),
        SectionOrderClass::RankAppend
    );
    assert_eq!(
        classify_section_order("__DATA", "__data"),
        SectionOrderClass::RankAppend
    );
    assert_eq!(
        classify_section_order("__TEXT", "__const"),
        SectionOrderClass::RankAppend
    );
    // The cstring face: exactly `__TEXT,__cstring` (ld64's strcmp pair).
    assert_eq!(
        classify_section_order("__TEXT", "__cstring"),
        SectionOrderClass::CstringLiteral
    );
    assert_eq!(
        classify_section_order("__DATA", "__cstring"),
        SectionOrderClass::RankAppend,
        "the face is the __TEXT pair only — __DATA,__cstring is an ordinary section"
    );
    // The literal no-op face: every `__TEXT,__literal*` section (ld64's
    // 9-char prefix match: __literal4, __literal8, __literal16).
    for sect in ["__literal4", "__literal8", "__literal16", "__literally"] {
        assert_eq!(
            classify_section_order("__TEXT", sect),
            SectionOrderClass::LiteralNotSupported,
            "{sect} rides the warned no-op face"
        );
    }
}

// ---- the composition ----------------------------------------------------

#[test]
fn compose_appends_entries_in_source_order() {
    let a = OrderFile::parse("_a_tail\n_a_second\n").expect("parses");
    let b = OrderFile::parse("b.o:_b_main\n_b_third\n").expect("parses");
    let sources = [
        OrderSource {
            name: "first.txt",
            file: &a,
        },
        OrderSource {
            name: "sectorder __TEXT __text",
            file: &b,
        },
    ];
    let table = SymbolOrder::compose(&sources).expect("the sources compose");
    // The rank order is the source order, the file order within each.
    let names: Vec<&str> = table.entries().iter().map(|e| e.symbol.as_str()).collect();
    assert_eq!(
        names,
        ["_a_tail", "_a_second", "_b_main", "_b_third"],
        "the appended ranks read in command-line order: {names:?}"
    );
    // The scoped entry rides its file's scope; the lookup answers what
    // the per-file tables answered.
    assert_eq!(table.rank_of("b.o", b"_b_main"), Some(2));
    assert_eq!(
        table.rank_of("other.o", b"_b_main"),
        None,
        "the scoped entry answers for its object only (the M11 precedence)"
    );
    assert_eq!(table.rank_of("a.o", b"_a_tail"), Some(0));
}

#[test]
fn compose_refuses_a_name_two_sources_rank() {
    let a = OrderFile::parse("_shared\n_a_only\n").expect("parses");
    let b = OrderFile::parse("_b_only\n_shared\n").expect("parses");
    let sources = [
        OrderSource {
            name: "first.txt",
            file: &a,
        },
        OrderSource {
            name: "second.txt",
            file: &b,
        },
    ];
    let err = SymbolOrder::compose(&sources).unwrap_err();
    assert_eq!(
        err,
        OrderComposeError::Duplicate {
            symbol: "_shared".into(),
            first_source: "first.txt".into(),
            first_line: 1,
            second_source: "second.txt".into(),
            second_line: 2,
        },
        "the refusal names both sources and both lines: {err}"
    );
}

#[test]
fn compose_of_no_sources_refuses() {
    assert_eq!(
        SymbolOrder::compose(&[]),
        Err(OrderComposeError::Empty),
        "an empty composition cannot rank anything (the parse's own Empty)"
    );
}

#[test]
fn compose_of_a_single_source_builds_the_same_table() {
    // One source composes to exactly what `SymbolOrder::build` builds
    // (the M11 shape is the one-source composition).
    let file = OrderFile::parse("_shared\nfirst.o:_shared\n").expect("parses");
    let built = SymbolOrder::build(&file);
    let composed = SymbolOrder::compose(&[OrderSource {
        name: "only.txt",
        file: &file,
    }])
    .expect("the single source composes");
    assert_eq!(built, composed, "one source, one table — the same rows");
}

#[test]
fn compose_matches_the_merged_file() {
    // The composition of two files and the parse of the merged text
    // carry the same rows — the entries with their scopes, in order.
    let a = OrderFile::parse("_a_second\na.o:_a_tail\n").expect("parses");
    let b = OrderFile::parse("_b_third\n").expect("parses");
    let composed = SymbolOrder::compose(&[
        OrderSource {
            name: "a.txt",
            file: &a,
        },
        OrderSource {
            name: "sectorder __TEXT __text",
            file: &b,
        },
    ])
    .expect("composes");
    let merged = OrderFile::parse("_a_second\na.o:_a_tail\n_b_third\n").expect("parses");
    let built = SymbolOrder::build(&merged);
    fn strip_line(entries: &[OrderEntry]) -> Vec<(Option<String>, String)> {
        entries
            .iter()
            .map(|e| (e.object.clone(), e.symbol.clone()))
            .collect()
    }
    assert_eq!(
        strip_line(composed.entries()),
        strip_line(built.entries()),
        "the composed rows equal the merged file's rows"
    );
}

// ---- the link parity -----------------------------------------------------

/// An object with `MH_SUBSECTIONS_VIA_SYMBOLS` whose `__text` carries
/// five 4-byte functions (one ret each, one symbol per atom) and a
/// `__data` definition (the m11 corpus shape).
fn five_fns(name: &str, prefix: &str, uses: &str, defines: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let ext_sym = 5u32;
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(5),
        vec![
            ObjectReloc::got_page21(ext_sym).at(16),
            ObjectReloc::got_pageoff12(ext_sym).at(20),
        ],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    for (i, atom) in ["_main", "_second", "_third", "_tail", "_use"]
        .iter()
        .enumerate()
    {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_{prefix}{atom}"),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.add_symbol(ObjectSymbol::Undefined {
        name: uses.into(),
        weak_ref: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: defines.into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn corpus() -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "a.o".into(),
            bytes: five_fns("a.o", "a", "_ext_a", "_ext_b"),
        },
        LinkInput {
            name: "b.o".into(),
            bytes: five_fns("b.o", "b", "_ext_b", "_ext_a"),
        },
    ]
}

/// The placed `__text` rows as `(object, atom index)` pairs in output
/// order (the m11 helper's shape — the atom index derives from the
/// object's own section table, never from the placed order).
fn text_order(cfg_order: impl FnOnce(&mut LinkConfig)) -> Vec<(&'static str, u64)> {
    let mut cfg = LinkConfig {
        entry_symbol: "_a_main".into(),
        ..LinkConfig::default()
    };
    cfg_order(&mut cfg);
    let inputs = corpus();
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let text = result
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__text")
        .expect("the text section places");
    let text_data_start: std::collections::HashMap<u32, u64> = result
        .objects
        .iter()
        .map(|o| {
            let sect = o
                .sections
                .iter()
                .find(|s| s.name == "__text")
                .expect("the corpus __text");
            (o.file.0, sect.data.start)
        })
        .collect();
    text.pieces
        .iter()
        .map(|p| {
            let name = result.objects[p.file.0 as usize].name.clone();
            let atom = (p.in_range.start - text_data_start[&p.file.0]) / 4;
            (
                match name.as_str() {
                    "a.o" => "a.o",
                    "b.o" => "b.o",
                    other => panic!("unexpected object {other}"),
                },
                atom,
            )
        })
        .collect()
}

#[test]
fn a_sectorder_rank_lays_the_rows_the_merged_file_lays() {
    // The composition (order_file then sectorder) ranks a.o's atom 3
    // then b.o's atom 1 ahead of everything else — the same rows the
    // single merged file ranks.
    let composed = text_order(|cfg| {
        let a = OrderFile::parse("_a_tail\n").expect("parses");
        let b = OrderFile::parse("_b_second\n").expect("parses");
        let table = SymbolOrder::compose(&[
            OrderSource {
                name: "order.txt",
                file: &a,
            },
            OrderSource {
                name: "sectorder __TEXT __text",
                file: &b,
            },
        ])
        .expect("composes");
        cfg.symbol_order = Some(table);
    });
    let merged = text_order(|cfg| {
        let file = OrderFile::parse("_a_tail\n_b_second\n").expect("parses");
        cfg.symbol_order = Some(SymbolOrder::build(&file));
    });
    assert_eq!(
        composed[..2],
        [("a.o", 3), ("b.o", 1)],
        "the composed ranks lead in source order: {composed:?}"
    );
    assert_eq!(
        composed, merged,
        "one table, one layout — the composed ranks lay the merged file's rows"
    );
}

#[test]
fn composed_entries_that_rank_nothing_ride_the_advisory() {
    let a = OrderFile::parse("_nowhere\n_a_tail\n").expect("parses");
    let b = OrderFile::parse("_b_second\n_also_nowhere\n").expect("parses");
    let table = SymbolOrder::compose(&[
        OrderSource {
            name: "order.txt",
            file: &a,
        },
        OrderSource {
            name: "sectorder __TEXT __text",
            file: &b,
        },
    ])
    .expect("composes");
    let cfg = LinkConfig {
        entry_symbol: "_a_main".into(),
        symbol_order: Some(table),
        ..LinkConfig::default()
    };
    let inputs = corpus();
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    assert_eq!(
        result.layout.order_unmatched,
        vec![b"_nowhere".to_vec(), b"_also_nowhere".to_vec()],
        "the unmatched composed entries report in rank order (the M11 face)"
    );
}
