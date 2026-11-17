//! The M55 link-map JSON interchange's consumer cycle, runnable: a
//! two-object link whose plan renders as the structured map, the map
//! rendered as the deterministic compact JSON (the machine face ld64's
//! `-map` never had) and parsed back — the reader restores the writer's
//! data exactly, so a build system can ship the interchange to any JSON
//! tooling (jq, a size dashboard, a diff gate) without a custom parser.
//! The text render stays the human face: both come from the same
//! structured map, so the report and the bytes cannot disagree.
//!
//! ```sh
//! cargo run -p pgr-core --example map_json
//! ```

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::map::{build_link_map, parse_link_map_json};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// One object: a two-instruction `__text`, a `__data` word, one definition.
fn object(name: &str, stem: &str, main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
    let symbol = if main {
        "_main".to_string()
    } else {
        format!("_{stem}")
    };
    b.add_symbol(ObjectSymbol::Defined {
        name: symbol,
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn main() {
    let inputs = vec![
        LinkInput {
            name: "main.o".to_string(),
            bytes: object("main.o", "main", true),
        },
        LinkInput {
            name: "aux.o".to_string(),
            bytes: object("aux.o", "aux_fn", false),
        },
    ];
    let result = link(&inputs, &[], &LinkConfig::default()).expect("the corpus links");
    let map = build_link_map(&result.layout, &result.interner);

    // The human face (the `-map` text) and the machine face (the JSON
    // interchange) come from the same structured map.
    let text = map.render();
    let json = map.render_json();
    println!("--- text (the -map face) ---");
    println!("{text}");
    println!("--- json (the interchange face, {} bytes) ---", json.len());
    println!("{json}");

    // The strict reader restores the writer's data exactly — the
    // round-trip is a gate (tests/m55_map_json.rs), not a promise.
    let parsed = parse_link_map_json(&json).expect("the interchange parses back");
    assert_eq!(parsed, map, "the reader restores the writer's data");
    assert_eq!(
        parsed.render_json(),
        json,
        "the re-render is byte-identical"
    );
    println!(
        "--- parsed back: {} segments, {} symbols (identical) ---",
        parsed.segments.len(),
        parsed
            .segments
            .iter()
            .map(|s| s.sections.iter().map(|c| c.symbols.len()).sum::<usize>())
            .sum::<usize>(),
    );
}
