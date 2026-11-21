//! M99 — the named output UUID released: `-uuid <uuid>` — the other
//! half of M32's `-no_uuid`: ld64's named-UUID face is the emit
//! decision the two-pass UUID patch reads (`LinkConfig::named_uuid`):
//! the named value replaces the content-derived derivation, riding the
//! `LC_UUID` field the header already plans. The parse validates the
//! 8-4-4-4-12 hex form (36 chars, hyphens at 8/13/18/23,
//! case-insensitive — malformed refuses with the fix); `-no_uuid` ×
//! `-uuid` refuse each other (a suppression and a named value are two
//! answers to one question), and `-r` refuses (the relocatable output
//! carries no `LC_UUID` at all). The default (`None`) keeps every
//! pre-M99 link byte-identical — the derivation stays content-derived.

use pgr_core::layout::{LinkConfig, OutputType, UuidSource};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// `7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7f80` as raw bytes (big-endian over
/// the hex groups — the wire form the command carries).
const NAMED: [u8; 16] = [
    0x7d, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d, 0x6e, 0x7f, 0x80,
];

/// lib.o: `_my_init` and `_api`, both `ret` bodies in one `__text`.
fn lib_object(tag: u8) -> Vec<u8> {
    let mut b = ObjectBuilder::new("lib.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, tag], // ret; <tag>
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_my_init".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_api".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn lib_inputs(tag: u8) -> Vec<LinkInput> {
    vec![LinkInput {
        name: "lib.o".into(),
        bytes: lib_object(tag),
    }]
}

fn dylib_cfg(uuid_source: UuidSource, named: Option<[u8; 16]>) -> LinkConfig {
    LinkConfig {
        ident: "lib".into(),
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/lib.dylib".into()),
        uuid_source,
        named_uuid: named,
        ..LinkConfig::default()
    }
}

#[test]
fn the_default_echoes_no_named_uuid() {
    // Pre-M99 shape: without the knob the decision is the config's own
    // absence — the derivation stays content-derived.
    let layout = link(
        &lib_inputs(0xA0),
        &[],
        &dylib_cfg(UuidSource::Content, None),
    )
    .expect("the default dylib plans")
    .layout;
    assert!(
        layout.named_uuid.is_none(),
        "the default echoes no named value"
    );
}

#[test]
fn a_named_uuid_rides_the_layout() {
    // The named decision echoes onto the plan the emit two-pass patch
    // reads: the patch writes the named 16 bytes instead of deriving
    // them.
    let layout = link(
        &lib_inputs(0xA0),
        &[],
        &dylib_cfg(UuidSource::Content, Some(NAMED)),
    )
    .expect("the named dylib plans")
    .layout;
    assert_eq!(
        layout.named_uuid,
        Some(NAMED),
        "the plan carries the named identity verbatim"
    );
}

#[test]
fn a_named_uuid_refuses_beside_the_uuid_suppression() {
    // M32's suppression and M99's name are two answers to one question
    // — a link asking both refuses naming both flags (the layout's
    // re-check backs the driver surface's refusal).
    let cfg = dylib_cfg(UuidSource::None, Some(NAMED));
    let err =
        link(&lib_inputs(0xA0), &[], &cfg).expect_err("the suppressed-plus-named config refuses");
    let message = err.to_string();
    assert!(
        message.contains("-no_uuid"),
        "the refusal names the suppression: {message}"
    );
    assert!(
        message.contains("-uuid"),
        "the refusal names the knob: {message}"
    );
}

#[test]
fn a_named_uuid_refuses_on_the_relocatable_output() {
    // The relocatable output carries no LC_UUID at all (the M32 shape —
    // the object's header has no uuid field), so a named value has no
    // field to land on: `-r` refuses (the link_reloc re-check backs the
    // driver surface's refusal).
    let cfg = LinkConfig {
        ident: "reloc".into(),
        filetype: OutputType::Relocatable,
        named_uuid: Some(NAMED),
        ..LinkConfig::default()
    };
    let err = link_reloc(&lib_inputs(0xA0), &[], &cfg, Parallelism::Auto)
        .expect_err("the relocatable output refuses the knob");
    let message = err.to_string();
    assert!(
        message.contains("-uuid"),
        "the relocatable refusal names the knob: {message}"
    );
    assert!(
        message.contains("LC_UUID") || message.contains("load commands"),
        "the relocatable refusal names the premise: {message}"
    );
}
