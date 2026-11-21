//! M57 — the load-side provenance (`pgr_core::provenance::LoadReport`,
//! the `-why_load` seam): the S7 archive pull's per-member decision —
//! the reference whose fixpoint round reached it, the `-all_load`/
//! `-force_load` eager family, the `-ObjC` metadata pull — and, under
//! `-dead_strip_dylibs`, every input dylib's carriage, recorded by the
//! pull itself and carried on the link result.
//!
//! Gate matrix:
//! * the lazy fixpoint's seed — a member pulled for `_greet` names the
//!   triggering reference, its definitions and the undefineds its pull
//!   opened; a member nothing reached is absent (the "why not" half of
//!   the question);
//! * the fixpoint's chain — a member whose pull opens `_b` pulls the
//!   member defining it in the next round, seeded by `_b`;
//! * the eager families — `-all_load` names every member, `-ObjC`
//!   names the metadata family;
//! * the read-only contract — the record never changes the plan (the
//!   M54 parity shape, the seam's own contract);
//! * the M42 half — under `-dead_strip_dylibs` every input dylib
//!   carries its carriage (kept binds, dropped doesn't); without the
//!   knob the dylib rows ride empty;
//! * the interchange — `render_json` is one line, fixed key order, the
//!   escape rules over a hostile member name.

use pgr_core::ids::FileId;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkArchive, LinkArchiveMember, LinkInput, Parallelism, link_from_objects};
use pgr_core::map::build_link_map;
use pgr_core::object::InputObject;
use pgr_core::provenance::LoadDecision;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `main.o`: `_main` + a data pointer at `_greet`, one at `_spare`
/// (the name no archive member defines — the "why not" probe).
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
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let spare = b.add_symbol(ObjectSymbol::Undefined {
        name: "_spare".into(),
        weak_ref: false,
    });
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 16],
        vec![
            ObjectReloc::unsigned(greet as u32).at(0),
            ObjectReloc::unsigned(spare as u32).at(8),
        ],
    ));
    b.build().expect("the fixture object builds")
}

/// `greet.o`: defines `_greet`, opens `_next` (the fixpoint's chain
/// probe — a second member defines it).
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
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_next".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// `next.o`: defines `_next` — the chain's second hop.
fn next_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("next.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_next".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// `unused.o`: defines `_unused` — nothing references it.
fn unused_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("unused.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_unused".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// `libgreet.a`: greet.o, next.o, unused.o — the ranlib index naming
/// the three definitions.
fn greet_archive() -> LinkArchive {
    let mut bytes = Vec::new();
    for obj in [greet_object("greet.o"), next_object(), unused_object()] {
        bytes.extend_from_slice(&obj);
    }
    // The members slice the concatenated bytes by the builders' output
    // lengths; the index names the member each symbol defines.
    let (greet_len, next_len) = {
        let g = greet_object("greet.o");
        let n = next_object();
        (g.len(), n.len())
    };
    LinkArchive {
        name: "libgreet.a".into(),
        index: vec![
            (b"_greet".to_vec(), 0),
            (b"_next".to_vec(), 1),
            (b"_unused".to_vec(), 2),
        ],
        members: vec![
            LinkArchiveMember {
                name: "greet.o".into(),
                offset: 0,
                size: greet_len as u64,
            },
            LinkArchiveMember {
                name: "next.o".into(),
                offset: greet_len as u64,
                size: next_len as u64,
            },
            LinkArchiveMember {
                name: "unused.o".into(),
                offset: (greet_len + next_len) as u64,
                size: (bytes.len() - greet_len - next_len) as u64,
            },
        ],
        bytes,
        all_load: false,
    }
}

/// Links `main.o` against the archive; returns the link result. The
/// `_spare` probe (a name no member defines) rides the dynamic lookup —
/// the pull fixpoint is policy-independent, the spare must only link.
fn link_with(archive: LinkArchive, tweak: impl FnOnce(&mut LinkConfig)) -> pgr_core::LinkResult {
    let mut cfg = LinkConfig {
        filetype: OutputType::Execute,
        undefined_policy: pgr_core::resolve::UndefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    let objects =
        vec![InputObject::parse(FileId(0), "main.o", main_object()).expect("main.o parses")];
    link_from_objects(objects, &[archive], &cfg, Parallelism::Serial, None)
        .expect("the corpus links")
}

// ---- the lazy fixpoint --------------------------------------------------------

#[test]
fn a_member_pulled_for_a_reference_names_the_seed() {
    let result = link_with(greet_archive(), |_| {});
    let loads = &result.loads.members;
    // greet.o rides for _greet; the chain pulls next.o for _next —
    // and unused.o stays out (nothing reached it).
    let members: Vec<&str> = loads.iter().map(|m| m.member.as_str()).collect();
    assert_eq!(
        members,
        vec!["greet.o", "next.o"],
        "the pull order, unused.o out"
    );
    let greet = &loads[0];
    assert_eq!(greet.archive, "libgreet.a");
    let LoadDecision::Reference { seed } = &greet.decision else {
        panic!("expected the lazy fixpoint, got {:?}", greet.decision);
    };
    assert_eq!(seed, "_greet");
    assert_eq!(greet.definitions, vec!["_greet".to_string()]);
    assert_eq!(greet.opened, vec!["_next".to_string()]);
    // The chain's second hop is seeded by the first hop's own open.
    let LoadDecision::Reference { seed } = &loads[1].decision else {
        panic!("expected the lazy fixpoint, got {:?}", loads[1].decision);
    };
    assert_eq!(seed, "_next");
    assert_eq!(loads[1].definitions, vec!["_next".to_string()]);
    assert!(loads[1].opened.is_empty(), "next.o opens nothing");
}

// ---- the eager families -------------------------------------------------------

#[test]
fn all_load_names_every_member() {
    let mut archive = greet_archive();
    archive.all_load = true;
    let result = link_with(archive, |_| {});
    let loads = &result.loads.members;
    assert_eq!(loads.len(), 3, "every member rides the eager pull");
    assert!(
        loads.iter().all(|m| m.decision == LoadDecision::AllLoad),
        "the decision is the eager family"
    );
}

#[test]
fn the_objc_metadata_pull_names_itself() {
    // A member defining `_OBJC_CLASS_$_Greet` rides under `-ObjC`
    // without a reference.
    let mut b = ObjectBuilder::new("cls.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_OBJC_CLASS_$_Greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let cls_bytes = b.build().expect("cls.o builds");
    let archive = LinkArchive {
        name: "libcls.a".into(),
        index: vec![(b"_OBJC_CLASS_$_Greet".to_vec(), 0)],
        members: vec![LinkArchiveMember {
            name: "cls.o".into(),
            offset: 0,
            size: cls_bytes.len() as u64,
        }],
        bytes: cls_bytes,
        all_load: false,
    };
    let result = link_with(archive, |cfg| cfg.objc = true);
    let loads = &result.loads.members;
    assert_eq!(
        loads.len(),
        1,
        "the metadata member rides without a reference"
    );
    assert_eq!(loads[0].decision, LoadDecision::ObjcMetadata);
    assert_eq!(
        loads[0].definitions,
        vec!["_OBJC_CLASS_$_Greet".to_string()]
    );
}

// ---- the read-only contract ---------------------------------------------------

#[test]
fn the_record_never_changes_the_plan() {
    let recorded = link_with(greet_archive(), |_| {});
    let fresh = link_with(greet_archive(), |_| {});
    let a = build_link_map(&recorded.layout, &recorded.interner).render();
    let b = build_link_map(&fresh.layout, &fresh.interner).render();
    assert_eq!(a, b, "the provenance record never touches the plan");
    assert_eq!(
        recorded.loads, fresh.loads,
        "the record is a pure function of the pull"
    );
}

// ---- the M42 half -------------------------------------------------------------

#[test]
fn dead_strip_dylibs_names_the_carriage() {
    // Two dylibs: the first serves `_greet` (kept), the second serves
    // nothing (dropped). main.o's `_spare` rides the dynamic lookup so
    // the corpus links.
    let mut cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    cfg.dead_strip_dylibs = true;
    cfg.undefined_policy = pgr_core::resolve::UndefinedPolicy::DynamicLookup;
    cfg.dylibs.push(pgr_core::resolve::Dylib {
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
    cfg.dylibs.push(pgr_core::resolve::Dylib {
        install_name: "@rpath/libspare.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_nothing".to_vec()],
        weak: false,
        reexport: false,
        needed: false,
        lazy: false,
        upward: false,
    });
    let objects =
        vec![InputObject::parse(FileId(0), "main.o", main_object()).expect("main.o parses")];
    let result =
        link_from_objects(objects, &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    let dylibs = &result.loads.dylibs;
    assert_eq!(dylibs.len(), 2, "one row per input dylib under the knob");
    assert!(dylibs[0].kept, "the bind keeps its provider");
    assert_eq!(dylibs[0].install_name, "@rpath/libgreet.dylib");
    assert!(!dylibs[1].kept, "nothing binds against the second");
    assert!(result.loads.members.is_empty(), "no archive rode");
}

#[test]
fn the_dylib_rows_ride_empty_without_the_knob() {
    let result = link_with(greet_archive(), |_| {});
    assert!(
        result.loads.dylibs.is_empty(),
        "the default rides every dylib"
    );
}

// ---- the interchange ----------------------------------------------------------

#[test]
fn the_json_face_is_the_deterministic_interchange() {
    let result = link_with(greet_archive(), |_| {});
    let json = result.loads.render_json();
    assert!(!json.contains('\n'), "one line: {json}");
    assert!(
        json.starts_with("{\"members\":[{"),
        "fixed key order: {json}"
    );
    assert!(
        json.contains("\"kind\":\"reference\",\"seed\":\"_greet\""),
        "the seed rides the decision: {json}"
    );
    assert!(json.contains("\"dylibs\":[]"), "the empty carriage: {json}");
    assert_eq!(
        json,
        result.loads.render_json(),
        "the render is deterministic"
    );
}

#[test]
fn a_hostile_member_name_escapes() {
    let mut archive = greet_archive();
    archive.members[0].name = "we\"ird\t.o".into();
    let result = link_with(archive, |_| {});
    let json = result.loads.render_json();
    assert!(
        json.contains("we\\\"ird\\t.o"),
        "the escape rules ride: {json}"
    );
}

// ---- the LinkInput path (the driver's own shape) ------------------------------

#[test]
fn the_link_input_path_carries_the_report() {
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
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(greet as u32).at(0)],
    ));
    let inputs = vec![LinkInput {
        name: "main.o".into(),
        bytes: b.build().expect("main.o builds"),
    }];
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let result = pgr_core::link(&inputs, &[greet_archive()], &cfg).expect("the corpus links");
    let members: Vec<&str> = result
        .loads
        .members
        .iter()
        .map(|m| m.member.as_str())
        .collect();
    assert_eq!(members, vec!["greet.o", "next.o"]);
}
