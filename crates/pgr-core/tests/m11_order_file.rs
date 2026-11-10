//! M11 rung 1 — the `-order_file` rank seam: the parsed order file's
//! ranks ride the layout as a stable sort (TDD §8.4), ordered buckets go
//! atom-granular so a named symbol's piece can carry its rank, and the
//! contract-coupled buckets (`__got`/`__stubs`/`__common`/`__cstring`)
//! keep their own order. Every gate here pins one half of that contract;
//! the clean-link path (no order file) is the M1–M10 byte shape and is
//! gated by every other suite.

use pgr_core::layout::{LinkConfig, SynthKind};
use pgr_core::link::{LinkInput, link};
use pgr_core::order::{OrderFile, SymbolOrder};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// An object with `MH_SUBSECTIONS_VIA_SYMBOLS` whose `__text` carries
/// five 4-byte functions (one ret each, one symbol per atom): `_main`,
/// `_second`, `_third`, `_tail` and a `_use` atom whose adrp/ldr pair
/// reaches the object's extern (the GOT-synthesis shape).
fn five_fns(name: &str, prefix: &str, uses: &str, defines: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    // Five rets; `_use` (atom 4) carries the GOT-load pair.
    // The GOT-load pair targets the object's extern — symtab index 5
    // (five defined symbols precede it in the table).
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
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{prefix}_main"),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{prefix}_second"),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{prefix}_third"),
        section_index: text,
        value: 8,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{prefix}_tail"),
        section_index: text,
        value: 12,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{prefix}_use"),
        section_index: text,
        value: 16,
        weak: false,
    });
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

/// The two-object corpus: a.o reaches `_ext_a` (defined in b.o), b.o
/// reaches `_ext_b` (defined in a.o) — first-use GOT order is
/// `[_ext_a, _ext_b]`.
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

/// Links the corpus with the given order-file text (raw bytes = rank
/// table) and returns the placed `__text` pieces as `(file, atom index)`
/// pairs in output order (the atom index is the piece's position among
/// the object's `__text` atoms — the file-absolute `in_range` offset
/// normalized by the section's data start).
fn text_order(order_text: Option<&str>) -> Vec<(&'static str, u64)> {
    let mut cfg = LinkConfig {
        entry_symbol: "_a_main".into(),
        ..LinkConfig::default()
    };
    if let Some(text) = order_text {
        let file = OrderFile::parse(text).expect("the rank text parses");
        cfg.symbol_order = Some(SymbolOrder::build(&file));
    }
    let inputs = corpus();
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    let text = result
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__text")
        .expect("the text section places");
    // Atom index = (absolute in_range start − the object's `__text`
    // data start) / 4 — derived from the *object's* section table, never
    // from the placed piece order (the ranks move the first piece).
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
fn an_order_file_ranks_the_named_pieces_first() {
    // The canonical order is a.o's atoms then b.o's (file order within
    // the section). The ranks pull `_a_tail` (atom 3) and `_b_second`
    // (atom 1) to the head in entry order.
    let ranked = text_order(Some("_a_tail\n_b_second\n"));
    assert_eq!(
        ranked[..2],
        [("a.o", 3), ("b.o", 1)],
        "the ranked pieces lead in entry order: {ranked:?}"
    );
}

#[test]
fn unranked_pieces_keep_the_canonical_order_behind() {
    // Same corpus, one rank: everything unranked follows the canonical
    // file/atom order it had before (the stable half of §8.4) — the
    // atom sequence a.o 0..=4 then b.o 0..=4, minus the ranked piece.
    let ranked = text_order(Some("_b_third\n"));
    assert_eq!(ranked[0], ("b.o", 2), "the ranked piece leads: {ranked:?}");
    let canonical_without_ranked: Vec<(&str, u64)> = [
        ("a.o", 0),
        ("a.o", 1),
        ("a.o", 2),
        ("a.o", 3),
        ("a.o", 4),
        ("b.o", 0),
        ("b.o", 1),
        ("b.o", 3),
        ("b.o", 4),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        ranked[1..],
        canonical_without_ranked,
        "the unranked tail keeps the canonical order: {ranked:?}"
    );
}

#[test]
fn a_scoped_rank_names_its_object_only() {
    // `a.o:_a_second` ranks a.o's atom 1; the same-offset b.o atom is
    // unranked and keeps its place.
    let ranked = text_order(Some("a.o:_a_second\n"));
    assert_eq!(ranked[0], ("a.o", 1), "the scoped rank leads: {ranked:?}");
    assert_eq!(ranked[1], ("a.o", 0), "a.o's unranked _main follows");
}

#[test]
fn entries_that_rank_nothing_ride_the_advisory() {
    let file = OrderFile::parse("_nowhere\n_a_tail\n").expect("parses");
    let cfg = LinkConfig {
        entry_symbol: "_a_main".into(),
        symbol_order: Some(SymbolOrder::build(&file)),
        ..LinkConfig::default()
    };
    let inputs = corpus();
    let result = link(&inputs, &[], &cfg).expect("the corpus links");
    assert_eq!(
        result.layout.order_unmatched,
        vec![b"_nowhere".to_vec()],
        "the unmatched entry is reported in entry order"
    );
}

#[test]
fn contract_buckets_keep_their_own_order() {
    // The order file names the two externs in the reverse of their
    // first-use order; the `__got` bucket mirrors the import table's
    // first-use ordinals — its placed order must equal the order-free
    // link's, whatever the ranks say.
    let got_order = |order_text: Option<&str>| {
        let mut cfg = LinkConfig {
            entry_symbol: "_a_main".into(),
            ..LinkConfig::default()
        };
        if let Some(text) = order_text {
            let file = OrderFile::parse(text).expect("parses");
            cfg.symbol_order = Some(SymbolOrder::build(&file));
        }
        let inputs = corpus();
        let result = link(&inputs, &[], &cfg).expect("the corpus links");
        let got = result
            .layout
            .sections
            .iter()
            .find(|s| s.seg_name == "__DATA_CONST" && s.name == "__got")
            .expect("the got section places");
        got.pieces
            .iter()
            .map(|p| match &p.synth {
                Some(synth) => match &synth.kind {
                    SynthKind::GotSlot { name } => result.interner.name(*name),
                    other => panic!("unexpected got piece {other:?}"),
                },
                None => panic!("the got bucket carries synthetic slots only"),
            })
            .collect::<Vec<_>>()
    };
    let plain = got_order(None);
    let ranked = got_order(Some("_b_tail\n_ext_b\n_ext_a\n"));
    assert_eq!(plain.len(), 2, "both externs synthesize a slot: {plain:?}");
    assert_eq!(
        ranked, plain,
        "the got slots keep the first-use order under ranks: {ranked:?}"
    );
}

#[test]
fn the_rank_table_is_a_pure_function_of_the_parse() {
    // Two builds of the same order file produce equal rank tables (the
    // driver rebuilds per link; equality is the determinism gate).
    let a = SymbolOrder::build(&OrderFile::parse("_x\ny.o:_x\n").unwrap());
    let b = SymbolOrder::build(&OrderFile::parse("_x\ny.o:_x\n").unwrap());
    assert_eq!(a, b);
}
