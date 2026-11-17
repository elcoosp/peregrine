//! M55 — the link-map JSON interchange (`pgr_core::map`): the placed
//! image's map — already the build-system-facing report ld64's `-map`
//! serves, already a pure function of the plan (the report and the bytes
//! cannot disagree) — gains a machine face. [`LinkMap::render_json`] is
//! the deterministic compact rendering (fixed key order, one line, the
//! report-JSON escape rules), [`parse_link_map_json`] the strict reader:
//! a rigid schema (unknown or duplicate keys refuse), byte-positioned
//! typed errors, and the structural gate the data model carries
//! (a section's `seg_name` must name the segment it rode in on).
//!
//! Gate matrix:
//! * the round trip — a linked plan's map renders, parses back and
//!   re-renders byte-identically (the reader restores the writer's data,
//!   the `to_json`/`parse_report_json` convention);
//! * the shape — the JSON names the map's own fields (a build system
//!   reads segments, sections, sizes and symbols without a custom
//!   parser);
//! * the determinism — two renders of the same map are byte-identical
//!   (no hash iteration order, the §4.3 policy).

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
    let data = b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
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
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{stem}_data"),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// A two-object linked plan rendered as a map — the shape the `-map`
/// flag writes and the JSON interchange carries.
fn linked_map() -> pgr_core::map::LinkMap {
    let inputs = vec![
        LinkInput {
            name: "main.o".to_string(),
            bytes: object("main.o", "main", true),
        },
        LinkInput {
            name: "aux.o".to_string(),
            bytes: object("aux.o", "aux", false),
        },
    ];
    let result = link(&inputs, &[], &LinkConfig::default()).expect("the corpus links");
    build_link_map(&result.layout, &result.interner)
}

#[test]
fn the_json_round_trips_a_linked_plan() {
    let map = linked_map();
    let json = map.render_json();
    let parsed = parse_link_map_json(&json).expect("the linked plan's map parses");
    assert_eq!(parsed, map, "the reader restores the writer's data");
    assert_eq!(
        parsed.render_json(),
        json,
        "the re-render is byte-identical"
    );
}

#[test]
fn the_json_names_the_maps_own_fields() {
    let json = linked_map().render_json();
    assert!(json.contains("\"ident\":\""), "the identity rides");
    assert!(
        json.contains("\"name\":\"__TEXT\""),
        "segments carry the plan's names (the executable's map leads with __PAGEZERO, __TEXT follows)"
    );
    assert!(json.contains("\"name\":\"__text\""), "sections carry names");
    assert!(json.contains("\"name\":\"_main\""), "symbols carry names");
    assert!(json.contains("\"file_size\":"), "the total rides");
    assert!(json.contains("\"zerofill\":"), "the zero-fill bit rides");
}

#[test]
fn the_json_render_is_deterministic() {
    let a = linked_map().render_json();
    let b = linked_map().render_json();
    assert_eq!(a, b, "two renders of the same plan are byte-identical");
    assert!(!a.contains('\n'), "the interchange is one compact line");
}
