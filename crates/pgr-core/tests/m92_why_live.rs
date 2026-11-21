//! M92 — the liveness-provenance query (`pgr_core::why_live`, the
//! `-why_live <symbol>` seam): ld64's flag — previously unknown on the
//! surface — is the M5 mark-sweep's own decision made nameable, the
//! third provenance face beside `-why_export` (M56) and `-why_load`
//! (M57). The mark phase records, from data it already had, *why* each
//! atom went live — the root that named it (the entry point, the export
//! surface, `-u`, an alias, `__mod_init_func`, …) or the first
//! reference that reached it (the referrer atom, the referenced name,
//! the relocation site) — and the query walks that record back from the
//! queried definition to its root: *why is this symbol still live
//! under `-dead_strip`?*
//!
//! Gate matrix:
//! * the chain — a two-hop corpus (`_main` calls `_a` calls `_b`) names
//!   the keepers in the walk's own order: `_b` kept by `_a`, `_a` kept
//!   by `_main`, `_main` rooted at the entry point; a one-hop query
//!   names one keeper;
//! * the verdicts — an unreferenced definition answers `Dead` (the
//!   strip drops it; the honest answer is the verdict, not an error);
//!   a root definition answers `Live` with an empty chain;
//! * the refusals — a name nothing interned refuses with the
//!   misspelling named (the C-underscore hint, the M56 convention); a
//!   name that binds against a dylib export has no link-time
//!   definition to walk; a link that never carried `-dead_strip` has
//!   no strip to explain (the seam refuses the premise — a vacuous
//!   answer is never silently empty);
//! * the read-only contract — the record rides the mark phase's own
//!   stores (`LinkResult::liveness`, `Some` exactly when the strip ran)
//!   and never changes the plan: a link that records plans the
//!   identical layout, and the record is deterministic across the
//!   scheduling policies;
//! * the interchange — `render_json` is one line, fixed key order, the
//!   report-JSON escape rules over hostile names; `render` is the
//!   diffable text face.

use pgr_core::ids::FileId;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{Parallelism, link_from_objects};
use pgr_core::object::InputObject;
use pgr_core::resolve::{Dylib, UndefinedPolicy};
use pgr_core::why_live::{LiveRootKind, LiveVerdict, WhyLiveError, explain_live};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `main.o`: `_main` (the entry root) calls `callee` through a
/// `branch26` at offset 0 — the entry atom carries the edge.
fn main_object(callee: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    b.add_section(ObjectSection::text(
        "__text",
        [0x9400_0000u32.to_le_bytes(), 0xD65F_03C0u32.to_le_bytes()].concat(),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    // Builder declaration index 1 (the callee) — the branch's target.
    let _ = b.add_symbol(ObjectSymbol::Undefined {
        name: callee.into(),
        weak_ref: false,
    });
    b.section_mut(0).relocs.push(ObjectReloc::branch26(1).at(0));
    b.build().expect("the fixture object builds")
}

/// A middle caller: `name` defined over an 8-byte `__text` (one atom —
/// the definition and the call are the same atom, so the strip's edge
/// and the chain's hop agree), calling `callee` through a `branch26`.
fn caller_object(name: &str, callee: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new("caller.o").set_subsections_via_symbols(true);
    b.add_section(ObjectSection::text(
        "__text",
        [0x9400_0000u32.to_le_bytes(), 0xD65F_03C0u32.to_le_bytes()].concat(),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: name.into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    let _ = b.add_symbol(ObjectSymbol::Undefined {
        name: callee.into(),
        weak_ref: false,
    });
    b.section_mut(0).relocs.push(ObjectReloc::branch26(1).at(0));
    b.build().expect("the fixture object builds")
}

/// `leaf.o`: `leaf_name` defined over a plain `ret` — the chain's tail.
fn leaf_object(leaf_name: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new("leaf.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: leaf_name.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The two-hop corpus: `_main` → `_a` → `_b`, plus `_dead` — a defined,
/// unreferenced body the strip drops. The arena is atomized (the
/// `link_from_objects` contract: parsed, atomized, command-line ids).
fn arena() -> Vec<InputObject> {
    let mut main =
        InputObject::parse(FileId(0), "main.o", main_object("_a")).expect("main.o parses");
    let mut a =
        InputObject::parse(FileId(1), "a.o", caller_object("_a", "_b")).expect("a.o parses");
    let mut b = InputObject::parse(FileId(2), "b.o", leaf_object("_b")).expect("b.o parses");
    let mut dead =
        InputObject::parse(FileId(3), "dead.o", leaf_object("_dead")).expect("dead.o parses");
    for obj in [&mut main, &mut a, &mut b, &mut dead] {
        obj.compute_atoms(true);
    }
    vec![main, a, b, dead]
}

/// Links the corpus with `-dead_strip` (the query's premise).
fn strip_link() -> pgr_core::LinkResult {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        dead_strip: true,
        ..LinkConfig::default()
    };
    link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links")
}

// ---- the record ---------------------------------------------------------------

#[test]
fn the_record_rides_the_result_exactly_when_the_strip_runs() {
    let on = strip_link();
    let live = on
        .liveness
        .as_ref()
        .expect("the strip ran: the record rides");
    assert!(live.is_active());

    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let off =
        link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    assert!(off.liveness.is_none(), "no strip: nothing to explain");
}

// ---- the chain ----------------------------------------------------------------

#[test]
fn the_chain_names_the_keepers_root_first() {
    let result = strip_link();
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_b",
    )
    .expect("the name stays live");
    assert_eq!(x.name, "_b");
    let LiveVerdict::Live { chain, root } = &x.verdict else {
        panic!("expected a live verdict, got {:?}", x.verdict);
    };
    // The walk's own order: the queried atom's keeper first, the entry
    // root last. `_b` is kept by `_a`'s call; `_a` is kept by `_main`'s
    // call; `_main` is the entry point.
    assert_eq!(chain.len(), 2, "two hops to the root: {chain:?}");
    assert_eq!(chain[0].referrer_symbol.as_deref(), Some("_a"));
    assert_eq!(chain[0].via.as_deref(), Some("_b"));
    assert_eq!(chain[0].file, "a.o");
    assert_eq!(
        chain[0].section,
        ("__TEXT".to_string(), "__text".to_string())
    );
    assert_eq!(chain[0].offset, 0);
    assert_eq!(chain[1].referrer_symbol.as_deref(), Some("_main"));
    assert_eq!(chain[1].via.as_deref(), Some("_a"));
    assert_eq!(chain[1].file, "main.o");
    assert!(
        matches!(root, LiveRootKind::Entry),
        "the entry root: {root:?}"
    );
}

#[test]
fn a_one_hop_query_names_one_keeper() {
    let result = strip_link();
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_a",
    )
    .expect("the name stays live");
    let LiveVerdict::Live { chain, root } = &x.verdict else {
        panic!("expected a live verdict, got {:?}", x.verdict);
    };
    assert_eq!(chain.len(), 1, "one hop: {chain:?}");
    assert_eq!(chain[0].referrer_symbol.as_deref(), Some("_main"));
    assert!(matches!(root, LiveRootKind::Entry));
}

#[test]
fn a_root_definition_answers_an_empty_chain() {
    let result = strip_link();
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_main",
    )
    .expect("the name stays live");
    let LiveVerdict::Live { chain, root } = &x.verdict else {
        panic!("expected a live verdict, got {:?}", x.verdict);
    };
    assert!(chain.is_empty(), "the entry point is the root: {chain:?}");
    assert!(matches!(root, LiveRootKind::Entry));
}

// ---- the verdicts and refusals --------------------------------------------------

#[test]
fn an_unreferenced_definition_answers_dead() {
    let result = strip_link();
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_dead",
    )
    .expect("the name resolves; the verdict is the answer");
    assert!(
        matches!(x.verdict, LiveVerdict::Dead),
        "the strip drops it: {:?}",
        x.verdict
    );
}

#[test]
fn a_u_symbol_roots_the_chain() {
    // `-u _dead` roots `_dead` beside the strip (the load-symbol root) —
    // the chain is empty and the root kind names the flag.
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        dead_strip: true,
        load_symbols: vec![b"_dead".to_vec()],
        ..LinkConfig::default()
    };
    let result =
        link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_dead",
    )
    .expect("the -u mark keeps it");
    let LiveVerdict::Live { chain, root } = &x.verdict else {
        panic!("expected a live verdict, got {:?}", x.verdict);
    };
    assert_eq!(chain.len(), 0);
    assert!(matches!(root, LiveRootKind::LoadSymbol), "{root:?}");
}

#[test]
fn a_dylib_surface_roots_its_definitions() {
    // A dylib's export surface roots every definition (the M5 shape) —
    // the queried body answers `Live` with an empty chain and the
    // surface root.
    let cfg = LinkConfig {
        filetype: OutputType::Dylib,
        dead_strip: true,
        ..LinkConfig::default()
    };
    let result =
        link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_b",
    )
    .expect("the surface roots it");
    let LiveVerdict::Live { chain, root } = &x.verdict else {
        panic!("expected a live verdict, got {:?}", x.verdict);
    };
    assert!(chain.is_empty(), "the surface is the root: {chain:?}");
    assert!(matches!(root, LiveRootKind::ExportedSurface), "{root:?}");
}

#[test]
fn an_unknown_name_refuses_with_the_fix() {
    let result = strip_link();
    let live = result.liveness.as_ref().expect("the record rides");
    let err = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_grete",
    )
    .expect_err("the misspelling refuses");
    assert!(matches!(err, WhyLiveError::UnknownSymbol { .. }));
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

#[test]
fn a_dylib_bound_name_refuses_the_walk() {
    // The name resolves against a dylib export — no link-time
    // definition, no atom to walk (the strip never kept or dropped it).
    let mut arena = vec![
        InputObject::parse(FileId(0), "main.o", main_object("_greet")).expect("main.o parses"),
    ];
    for obj in &mut arena {
        obj.compute_atoms(true);
    }
    let mut cfg = LinkConfig {
        filetype: OutputType::Execute,
        dead_strip: true,
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
    let live = result.liveness.as_ref().expect("the record rides");
    let err = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect_err("no in-image definition walks");
    assert!(matches!(err, WhyLiveError::NotDefinedHere { .. }));
    assert!(
        err.to_string().contains("dylib"),
        "the provider is named: {err}"
    );
}

#[test]
fn a_link_without_the_strip_has_no_record() {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        undefined_policy: UndefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };
    let result =
        link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    assert!(result.liveness.is_none());
}

// ---- the read-only contract -----------------------------------------------------

#[test]
fn the_record_never_changes_the_plan() {
    let recorded = strip_link();
    // The record rides the mark phase's own stores — the same run plans
    // the layout. A fresh link (the same inputs, the same config) plans
    // the identical one.
    let fresh = strip_link();
    let a = pgr_core::map::build_link_map(&recorded.layout, &recorded.interner).render();
    let b = pgr_core::map::build_link_map(&fresh.layout, &fresh.interner).render();
    assert_eq!(a, b, "the record never touches the plan");
    // The dead body is absent from the recorded run's plan too (the
    // record and the strip agree).
    assert!(a.contains("_b"), "the live body ships: {a}");
    assert!(!a.contains("_dead"), "the dead body strips: {a}");
}

#[test]
fn the_record_is_schedule_independent() {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        dead_strip: true,
        ..LinkConfig::default()
    };
    let serial =
        link_from_objects(arena(), &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    let auto =
        link_from_objects(arena(), &[], &cfg, Parallelism::Auto, None).expect("the corpus links");
    let render = |r: &pgr_core::LinkResult| {
        let live = r.liveness.as_ref().expect("the record rides");
        explain_live(live, &r.objects, &r.resolution, &r.interner, "_b")
            .expect("the name stays live")
            .render()
    };
    assert_eq!(render(&serial), render(&auto), "the walk is deterministic");
}

// ---- the interchange ------------------------------------------------------------

#[test]
fn the_json_face_is_the_deterministic_interchange() {
    let result = strip_link();
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_b",
    )
    .expect("the name stays live");
    let json = x.render_json();
    assert!(!json.contains('\n'), "one line: {json}");
    assert!(
        json.starts_with("{\"name\":\"_b\""),
        "fixed key order: {json}"
    );
    assert!(
        json.contains("\"kind\":\"live\""),
        "the verdict rides: {json}"
    );
    assert!(json.contains("\"root\":{\"kind\":\"entry\""), "{json}");
    assert_eq!(json, x.render_json(), "the render is deterministic");
}

#[test]
fn the_text_face_names_every_field() {
    let result = strip_link();
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_b",
    )
    .expect("the name stays live");
    let text = x.render();
    assert!(text.contains("_b"));
    assert!(text.contains("_a"));
    assert!(text.contains("_main"));
    assert!(text.contains("a.o"));
    assert!(text.contains("0x0"), "the site rides: {text}");
}

#[test]
fn the_json_face_escapes_hostile_names() {
    // The referrer's file name carries JSON-hostile bytes — the escape
    // rules ride the interchange (the M55 house writer).
    let mut main = ObjectBuilder::new("we\"ird\t.o").set_subsections_via_symbols(true);
    main.add_section(ObjectSection::text(
        "__text",
        [0x9400_0000u32.to_le_bytes(), 0xD65F_03C0u32.to_le_bytes()].concat(),
        vec![],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    let _ = main.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    main.section_mut(0)
        .relocs
        .push(ObjectReloc::branch26(1).at(0));
    let main_obj = InputObject::parse(FileId(0), "we\"ird\t.o", main.build().expect("builds"))
        .expect("the hostile name parses");
    let mut main_obj = main_obj;
    main_obj.compute_atoms(true);
    let mut greet =
        InputObject::parse(FileId(1), "greet.o", leaf_object("_greet")).expect("greet.o parses");
    greet.compute_atoms(true);
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        dead_strip: true,
        ..LinkConfig::default()
    };
    let result = link_from_objects(vec![main_obj, greet], &[], &cfg, Parallelism::Serial, None)
        .expect("the corpus links");
    let live = result.liveness.as_ref().expect("the record rides");
    let x = explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name stays live");
    let json = x.render_json();
    assert!(json.contains("we\\\"ird\\t.o"), "the escapes ride: {json}");
    assert_eq!(json, x.render_json());
}
