//! M10 rung 1 — the `-r` relocatable output rung (roadmap §10.4 row M10):
//! Passes 1–2 stop short of the segment layout. A relocatable link keeps
//! undefined externals open (the output is itself a link *input*), still
//! rejects duplicate strong definitions, and records the winners the emit
//! side re-points the relocation entries at.
//!
//! The segment-shaped Pass 3 never runs on this path — the object layout
//! and its byte rules live in `pgr-emit` (`build_object_image`); this file
//! gates the resolve-shaped half the object emit consumes.

use pgr_core::{LinkConfig, LinkError, LinkInput, OutputType, Parallelism, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

fn hello_main() -> (String, Vec<u8>) {
    let mut b = ObjectBuilder::new("hello_main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x90, 0x00, 0x00, 0x00, // adrp x0, _msg@page
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #_msg@pageoff
            0x94, 0x00, 0x00, 0x00, // bl _greet
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    (String::from("hello_main.o"), b.build().unwrap())
}

fn greet() -> (String, Vec<u8>) {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    (String::from("greet.o"), b.build().unwrap())
}

fn open_extern() -> (String, Vec<u8>) {
    let mut b = ObjectBuilder::new("open.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x94, 0x00, 0x00, 0x00], // bl _never
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_open_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_never".into(),
        weak_ref: false,
    });
    (String::from("open.o"), b.build().unwrap())
}

fn inputs(parts: &[(String, Vec<u8>)]) -> Vec<LinkInput> {
    parts
        .iter()
        .map(|(name, bytes)| LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect()
}

#[test]
fn relocatable_output_type_maps_to_mh_object() {
    assert_eq!(
        OutputType::Relocatable.filetype(),
        pgr_format::consts::MH_OBJECT
    );
    assert_eq!(
        pgr_core::pagezero::PageZero::default().base_for(OutputType::Relocatable, None),
        0,
    );
    assert!(!OutputType::Relocatable.is_executable());
}

#[test]
fn link_reloc_keeps_undefineds_open() {
    // The whole point of `-r`: the output is a link input, so an
    // unresolved external is not an error — the *next* link resolves it.
    let corpus = vec![greet(), open_extern()];
    let cfg = LinkConfig::default();
    let out = link_reloc(&inputs(&corpus), &[], &cfg, Parallelism::Auto).unwrap();
    // The winner side still records definitions the emit re-points at.
    let interner = &out.interner;
    let greet_id = interner.lookup(b"_greet").unwrap();
    let def = out.resolution.def(greet_id).expect("_greet is defined");
    assert_eq!(def.file.0, 0, "greet.o is the first input");
    assert_eq!(def.section, Some(0));
    // `_never` has no winner — and no error was raised.
    let never_id = interner.lookup(b"_never").unwrap();
    assert!(out.resolution.def(never_id).is_none());
}

#[test]
fn link_reloc_still_rejects_duplicate_strongs() {
    let corpus = vec![greet(), greet()];
    let cfg = LinkConfig::default();
    let err = link_reloc(&inputs(&corpus), &[], &cfg, Parallelism::Serial).unwrap_err();
    assert!(matches!(err, LinkError::Symbol { .. }), "{err:?}");
}

#[test]
fn link_reloc_records_the_section_relative_values_the_emit_maps() {
    // The object emit rebuilds `n_value`s as output-blob offsets:
    // `Def.value` is input-section-relative, so the emit needs the
    // defining input section's own `addr` base alongside the winner.
    let corpus = vec![hello_main()];
    let cfg = LinkConfig::default();
    let out = link_reloc(&inputs(&corpus), &[], &cfg, Parallelism::Auto).unwrap();
    let msg_id = out.interner.lookup(b"_msg").unwrap();
    let def = out.resolution.def(msg_id).expect("_msg is defined");
    assert_eq!(def.section, Some(1), "_msg lives in __cstring");
    // The parse normalizes `n_value`s to *section-relative* (object.rs):
    // `Def.value` is the intra-section offset the emit adds to the
    // contribution base — here the very start of __cstring.
    assert_eq!(def.value, 0, "_msg sits at the __cstring base");
    // The input section's blob-relative `addr` (16) is the other half of
    // the mapping the emit does NOT need — pinned so a parse change here
    // surfaces as this test, not as silently shifted object bytes.
    assert_eq!(out.objects[0].sections[1].addr, 16);
}
