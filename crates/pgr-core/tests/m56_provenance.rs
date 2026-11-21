//! M56 — the symbol-reference provenance query (`pgr_core::provenance`,
//! the `-why_export` seam): the reverse reference index the M8
//! propagation planner keeps private becomes a nameable, typed answer —
//! *why is this symbol exported?* A query names the definition the
//! resolution installed (the input file and section, the dylib export
//! that serves it, the loader's dynamic lookup) and every reference site
//! the link saw (`(file, section, offset)`, the index's own total
//! order), rendered as text and as the deterministic JSON interchange
//! (the M55 house writer rules).
//!
//! Gate matrix:
//! * the answer — an in-image definition reports its file, section,
//!   rank and weak mark, and every site that references it, in the
//!   index's ascending order; a dylib export names its provider's
//!   install name; a dynamic-lookup reference names the loader;
//! * the refusals — a name nothing interned (defined or referenced)
//!   refuses with the misspelling named (the `-U`/`-alias` vacuous
//!   convention: the C-underscore hint is the fix);
//! * the interchange — `render_json` is one line, fixed key order, the
//!   report-JSON escape rules over hostile names;
//! * the read-only contract — a queried link plans the identical layout
//!   (the parity gate is the seam's own contract, the M54 shape);
//! * the duplicates — one relocation site record per
//!   `(file, section, offset)` (the index's own dedup, surfaced).

use pgr_core::ids::FileId;
use pgr_core::layout::LinkConfig;
use pgr_core::link::{Parallelism, link_from_objects};
use pgr_core::map::build_link_map;
use pgr_core::object::InputObject;
use pgr_core::provenance::{DefinitionSource, ProvenanceError, RefSiteReport, explain_export};
use pgr_core::resolve::{Dylib, UndefinedPolicy};
use pgr_core::revindex::ReverseIndex;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `main.o`: `_main` defined over a small `__text`, two 8-byte data
/// pointers at `__data` offsets 0 and 8 — both targeting `_greet`.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let main = 0usize; // builder index of `_main`
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let data = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 16],
        vec![
            ObjectReloc::unsigned(greet as u32).at(0),
            ObjectReloc::unsigned(greet as u32).at(8),
        ],
    ));
    let _ = (main, data);
    b.build().expect("the fixture object builds")
}

/// `greet.o`: `_greet` defined over a small `__text` — the body the
/// pointers above target.
fn greet_object(name: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Parses the two fixture objects into the Pass-1 arena (`FileId`s in
/// command-line order).
fn arena() -> Vec<InputObject> {
    vec![
        InputObject::parse(FileId(0), "main.o", main_object()).expect("main.o parses"),
        InputObject::parse(FileId(1), "greet.o", greet_object("greet.o")).expect("greet.o parses"),
    ]
}

/// Runs the segmented link over the arena (a plain executable).
fn link_arena() -> pgr_core::LinkResult {
    let cfg = LinkConfig {
        filetype: pgr_core::layout::OutputType::Execute,
        ..LinkConfig::default()
    };
    link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links")
}

// ---- the answer ---------------------------------------------------------------

#[test]
fn the_query_names_the_definition_and_its_sites() {
    let result = link_arena();
    let index = ReverseIndex::build_all(&result.objects);
    let x = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name resolves");
    assert_eq!(x.name, "_greet");
    let DefinitionSource::Input {
        file,
        section,
        rank,
        weak,
        ..
    } = &x.definition
    else {
        panic!("expected an in-image definition, got {:?}", x.definition);
    };
    assert_eq!(file, "greet.o");
    assert_eq!(
        section.as_ref().map(|(s, n)| (s.as_str(), n.as_str())),
        Some(("__TEXT", "__text"))
    );
    assert!(matches!(rank, pgr_core::resolve::Rank::Strong));
    assert!(!*weak);
    // The two pointers, in the index's ascending order.
    assert_eq!(
        x.sites,
        vec![
            RefSiteReport {
                file: "main.o".into(),
                section: ("__DATA".into(), "__data".into()),
                offset: 0,
            },
            RefSiteReport {
                file: "main.o".into(),
                section: ("__DATA".into(), "__data".into()),
                offset: 8,
            },
        ]
    );
}

#[test]
fn an_unreferenced_definition_reports_an_empty_site_list() {
    let result = link_arena();
    let index = ReverseIndex::build_all(&result.objects);
    let x = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_main",
    )
    .expect("the name resolves");
    let DefinitionSource::Input { file, .. } = &x.definition else {
        panic!("expected an in-image definition, got {:?}", x.definition);
    };
    assert_eq!(file, "main.o");
    assert!(x.sites.is_empty(), "nothing references the entry point");
}

#[test]
fn a_dylib_export_names_its_provider() {
    // main.o alone: `_greet` is an undefined external — the two-level
    // bind resolves against the dylib (no in-image definition outranks
    // the export).
    let arena =
        vec![InputObject::parse(FileId(0), "main.o", main_object()).expect("main.o parses")];
    let mut cfg = LinkConfig {
        filetype: pgr_core::layout::OutputType::Execute,
        ..LinkConfig::default()
    };
    cfg.dylibs.push(Dylib {
        install_name: "@rpath/libgreet.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_greet".to_vec()],
        weak: false,
        reexport: false,
        needed: false,
        lazy: false,
        upward: false,
    });
    let result =
        link_from_objects(arena, &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    let index = ReverseIndex::build_all(&result.objects);
    let x = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name resolves");
    let DefinitionSource::Dylib { install_name, weak } = &x.definition else {
        panic!("expected a dylib export, got {:?}", x.definition);
    };
    assert_eq!(install_name, "@rpath/libgreet.dylib");
    assert!(!*weak);
    // The reference sites are still the input's relocations.
    assert_eq!(x.sites.len(), 2);
}

#[test]
fn a_dynamic_lookup_names_the_loader() {
    // main.o alone: `_greet` stays open — the loader resolves it at launch.
    let arena =
        vec![InputObject::parse(FileId(0), "main.o", main_object()).expect("main.o parses")];
    let cfg = LinkConfig {
        filetype: pgr_core::layout::OutputType::Execute,
        undefined_policy: UndefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };
    let result =
        link_from_objects(arena, &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    let index = ReverseIndex::build_all(&result.objects);
    let x = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name resolves");
    assert_eq!(x.definition, DefinitionSource::DynamicLookup);
    assert_eq!(x.sites.len(), 2);
}

// ---- the refusals -------------------------------------------------------------

#[test]
fn an_unknown_name_refuses_with_the_fix() {
    let result = link_arena();
    let index = ReverseIndex::build_all(&result.objects);
    let err = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_grete",
    )
    .expect_err("the misspelling refuses");
    assert!(matches!(err, ProvenanceError::UnknownSymbol { .. }));
    let rendered = err.to_string();
    assert!(
        rendered.contains("_grete"),
        "the misspelling is named: {rendered}"
    );
    assert!(
        rendered.contains("underscore"),
        "the C-underscore hint is the fix: {rendered}"
    );
}

// ---- the duplicates -----------------------------------------------------------

#[test]
fn one_site_record_per_file_section_offset() {
    // Two relocations at the same offset: one site record (the index's
    // own dedup, surfaced verbatim).
    let mut b = ObjectBuilder::new("dup.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![
            ObjectReloc::unsigned(greet as u32).at(0),
            ObjectReloc::unsigned(greet as u32).at(0),
        ],
    ));
    let dup =
        InputObject::parse(FileId(0), "dup.o", b.build().expect("builds")).expect("dup.o parses");
    let greet_obj =
        InputObject::parse(FileId(1), "greet.o", greet_object("greet.o")).expect("greet.o parses");
    let result = link_from_objects(
        vec![dup, greet_obj],
        &[],
        &LinkConfig::default(),
        Parallelism::Serial,
        None,
    )
    .expect("the corpus links");
    let index = ReverseIndex::build_all(&result.objects);
    let x = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name resolves");
    assert_eq!(x.sites.len(), 1, "one record per (file, section, offset)");
}

// ---- the interchange ----------------------------------------------------------

#[test]
fn the_json_face_is_the_deterministic_interchange() {
    let mut b = ObjectBuilder::new("we\"ird\t.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(greet as u32).at(0)],
    ));
    let odd = InputObject::parse(FileId(0), "we\"ird\t.o", b.build().expect("builds"))
        .expect("the hostile name parses");
    let greet_obj =
        InputObject::parse(FileId(1), "greet.o", greet_object("greet.o")).expect("greet.o parses");
    let result = link_from_objects(
        vec![odd, greet_obj],
        &[],
        &LinkConfig::default(),
        Parallelism::Serial,
        None,
    )
    .expect("the corpus links");
    let index = ReverseIndex::build_all(&result.objects);
    let x = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name resolves");
    let json = x.render_json();
    // One line, fixed key order, the escape rules over the hostile name.
    assert!(!json.contains('\n'), "one line: {json}");
    assert!(
        json.starts_with("{\"name\":\"_greet\""),
        "fixed key order: {json}"
    );
    assert!(json.contains("we\\\"ird\\t.o"), "the escapes ride: {json}");
    // The same answer renders twice identically (the determinism gate).
    assert_eq!(json, x.render_json());
}

#[test]
fn the_text_face_names_every_field() {
    let result = link_arena();
    let index = ReverseIndex::build_all(&result.objects);
    let x = explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name resolves");
    let text = x.render();
    assert!(text.contains("_greet"));
    assert!(text.contains("greet.o"));
    assert!(text.contains("main.o"));
    assert!(text.contains("__data"));
}

// ---- the read-only contract ---------------------------------------------------

#[test]
fn a_queried_link_plans_the_identical_layout() {
    let queried = link_arena();
    let index = ReverseIndex::build_all(&queried.objects);
    let _ = explain_export(
        &index,
        &queried.objects,
        &queried.resolution,
        &queried.interner,
        "_greet",
    )
    .expect("the name resolves");
    let _ = explain_export(
        &index,
        &queried.objects,
        &queried.resolution,
        &queried.interner,
        "_main",
    )
    .expect("the name resolves");
    let fresh = link_arena();
    let a = build_link_map(&queried.layout, &queried.interner).render();
    let b = build_link_map(&fresh.layout, &fresh.interner).render();
    assert_eq!(a, b, "the query never touches the plan");
}
