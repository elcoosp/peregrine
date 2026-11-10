//! M11 rung 2 — the `-map` link-map seam: the map is a pure function of
//! the plan (the same layout the fused emit writes), its render is
//! deterministic, and its symbol rows agree with the placed addresses
//! (a symbol's map value is the address its `__text` bytes sit at).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::map::build_link_map;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A subsection-split object: three functions, one atom each.
fn object(name: &str, stem: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    for (i, fn_name) in ["main", "second", "third"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_{stem}_{fn_name}"),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

fn link_corpus() -> pgr_core::LinkResult {
    let cfg = LinkConfig {
        entry_symbol: "_a_main".into(),
        ident: "map-corpus".into(),
        ..LinkConfig::default()
    };
    let inputs = vec![
        LinkInput {
            name: "a.o".into(),
            bytes: object("a.o", "a"),
        },
        LinkInput {
            name: "b.o".into(),
            bytes: object("b.o", "b"),
        },
    ];
    link(&inputs, &[], &cfg).expect("the corpus links")
}

#[test]
fn the_map_reports_every_placed_segment_and_section() {
    let result = link_corpus();
    let map = build_link_map(&result.layout, &result.interner);
    assert_eq!(map.ident, "map-corpus");
    let seg_names: Vec<&str> = map.segments.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        seg_names,
        [
            "__PAGEZERO",
            "__TEXT",
            "__DATA_CONST",
            "__DATA",
            "__LINKEDIT"
        ]
    );
    let text = map
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .and_then(|s| s.sections.iter().find(|c| c.name == "__text"))
        .expect("the text section rows");
    // The two objects' three functions each, plus the image's own
    // header symbol (the symtab's n_sect rows it under __text).
    assert_eq!(text.symbols.len(), 7, "every defined extern rows: {text:?}");
}

#[test]
fn the_map_values_agree_with_the_layout_addresses() {
    let result = link_corpus();
    let map = build_link_map(&result.layout, &result.interner);
    let text = map
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .and_then(|s| s.sections.iter().find(|c| c.name == "__text"))
        .expect("the text rows");
    // Every symbol row sits inside its section's placed range — except
    // the header symbol, whose `n_sect` is `__text` by the symtab's own
    // convention while its value is the image base (the file's first
    // byte; ld64's maps row it the same way).
    for sym in &text.symbols {
        if sym.name == "__mh_execute_header" {
            continue;
        }
        assert!(
            sym.value >= text.vm_addr && sym.value < text.vm_addr + text.size,
            "{sym:?} outside the section it rows under"
        );
    }
    // The rows are sorted by address (the render's determinism input).
    let values: Vec<u64> = text.symbols.iter().map(|s| s.value).collect();
    let mut sorted = values.clone();
    sorted.sort_unstable();
    assert_eq!(values, sorted);
}

#[test]
fn the_render_is_stable_across_builds() {
    let result = link_corpus();
    let a = build_link_map(&result.layout, &result.interner).render();
    let b = build_link_map(&result.layout, &result.interner).render();
    assert_eq!(a, b, "the same plan renders byte-identical maps");
    assert!(a.starts_with("# Peregrine link map"));
    assert!(a.contains("segment __TEXT"));
    assert!(a.contains("_a_main"));
}
