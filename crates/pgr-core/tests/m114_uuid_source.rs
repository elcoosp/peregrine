//! M114 — the UUID source released: `-random_uuid` — ld64's random-UUID
//! face, the typed alphabet the M32/M99 pair hid: `UuidSource` rides
//! `LinkConfig` with three values — `content` (the default: the
//! content-derived derivation from the page hashes, the M32 pattern),
//! `random` (a fresh identity generated at emit time, ld64's
//! `-random_uuid`), `none` (the `-no_uuid` suppression, the M32
//! decision — no `LC_UUID` command at all). The plan echoes the source
//! the emit two-pass patch reads. The conflicts: `-random_uuid` ×
//! `-uuid` refuse each other (two answers to the identity question —
//! the M99 shape), `-random_uuid` × `-no_uuid` likewise, and `-r`
//! refuses `random` (the object carries no `LC_UUID` command — the
//! M99 relocatable refusal mirrored exactly). The default keeps every
//! pre-M114 link byte-identical — the derivation stays content-derived.

use pgr_core::layout::{LinkConfig, OutputType, UuidSource};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// lib.o: `_my_init` and `_api`, both `ret` bodies in one `__text` (the
/// corpus the M32/M99 uuid tests share).
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
    // The executable/bundle kinds resolve the entry (`_main`) — the
    // same body, one more definition.
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
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

fn dylib_cfg(source: UuidSource, named: Option<[u8; 16]>) -> LinkConfig {
    LinkConfig {
        ident: "lib".into(),
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/lib.dylib".into()),
        uuid_source: source,
        named_uuid: named,
        ..LinkConfig::default()
    }
}

/// Scans the plan's header bytes for an `LC_UUID` command
/// (the M32 test's `carries_uuid` helper).
fn carries_uuid(header: &[u8]) -> bool {
    let parsed = pgr_format::MachHeader64::parse(header).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        header,
        pgr_format::MachHeader64::SIZE,
        parsed.ncmds,
        parsed.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if matches!(cmd.kind, pgr_format::LoadCommandKind::Uuid) {
            return true;
        }
    }
    false
}

#[test]
fn the_default_is_the_content_source() {
    // Pre-M114 shape: without the knob the source is the content-derived
    // derivation — every pre-M114 link byte-identical.
    let layout = link(
        &lib_inputs(0xA0),
        &[],
        &dylib_cfg(UuidSource::Content, None),
    )
    .expect("the default dylib plans")
    .layout;
    assert_eq!(
        layout.uuid_source,
        UuidSource::Content,
        "the plan echoes the content source"
    );
    assert!(
        carries_uuid(&layout.header_bytes),
        "the content source carries the LC_UUID command (the pre-M114 shape)"
    );
    assert!(
        layout.linkedit.uuid_at != 0,
        "the uuid field's offset names the carried command"
    );
}

#[test]
fn the_wire_alphabet_is_the_three_value_order() {
    // The v65 alphabet: content, random, none — the wire byte and the
    // from_wire decode mirror it; anything else refuses (an old server
    // reading a new client's alphabet refuses the request as malformed,
    // the M107 reversed-admits shape).
    assert_eq!(UuidSource::Content.wire(), 0);
    assert_eq!(UuidSource::Random.wire(), 1);
    assert_eq!(UuidSource::None.wire(), 2);
    for (b, want) in [
        (0u8, Some(UuidSource::Content)),
        (1, Some(UuidSource::Random)),
        (2, Some(UuidSource::None)),
    ] {
        assert_eq!(UuidSource::from_wire(b), want, "byte {b} decodes");
    }
    assert_eq!(
        UuidSource::from_wire(3),
        None,
        "the alphabet carries three values; anything else is malformed"
    );
    assert_eq!(
        UuidSource::default(),
        UuidSource::Content,
        "content is the default"
    );
}

#[test]
fn a_random_source_rides_the_layout() {
    // ld64's `-random_uuid`: the identity is the emit's own draw. The
    // plan-level contract: the command still rides (the field is there
    // for the emit to patch) and the plan echoes the source.
    let layout = link(&lib_inputs(0xA1), &[], &dylib_cfg(UuidSource::Random, None))
        .expect("the random dylib plans")
        .layout;
    assert_eq!(
        layout.uuid_source,
        UuidSource::Random,
        "the plan echoes the source"
    );
    assert!(
        carries_uuid(&layout.header_bytes),
        "the random source carries the LC_UUID command"
    );
    assert!(layout.linkedit.uuid_at != 0, "the field is there to patch");
}

#[test]
fn the_suppression_face_is_the_none_source() {
    // The M32 decision rides the alphabet's third value: no command, no
    // field, the absent sentinel.
    let layout = link(&lib_inputs(0xA2), &[], &dylib_cfg(UuidSource::None, None))
        .expect("the suppressed dylib plans")
        .layout;
    assert_eq!(
        layout.uuid_source,
        UuidSource::None,
        "the plan echoes the source"
    );
    assert!(
        !carries_uuid(&layout.header_bytes),
        "the none source drops the LC_UUID command (the M32 shape)"
    );
    assert_eq!(
        layout.linkedit.uuid_at, 0,
        "the absent sentinel names the dropped field"
    );
}

#[test]
fn the_suppression_is_exactly_one_command_narrower() {
    // The M32 sizing contract rides the new field unchanged: the none
    // face plans one command less (24 bytes).
    let carried = link(
        &lib_inputs(0xA3),
        &[],
        &dylib_cfg(UuidSource::Content, None),
    )
    .expect("the carried dylib plans")
    .layout;
    let dropped = link(&lib_inputs(0xA3), &[], &dylib_cfg(UuidSource::None, None))
        .expect("the suppressed dylib plans")
        .layout;
    assert_eq!(
        carried.header_bytes.len() - dropped.header_bytes.len(),
        24,
        "the suppression is exactly the LC_UUID command's 24 bytes"
    );
}

#[test]
fn a_random_source_refuses_beside_a_named_value() {
    // ld64's two identity flags answer one question: a random draw and
    // a named value cannot coexist (the M99 conflict shape).
    let err = link(
        &lib_inputs(0xA4),
        &[],
        &dylib_cfg(
            UuidSource::Random,
            Some([
                0x7d, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d, 0x6e,
                0x7f, 0x80,
            ]),
        ),
    )
    .expect_err("random and named refuse each other");
    let message = err.to_string();
    assert!(
        message.contains("-random_uuid") && message.contains("-uuid"),
        "the refusal names both flags: {message}"
    );
}

#[test]
fn a_named_value_refuses_beside_the_none_source() {
    // The M99 conflict rides the alphabet: a suppression and a named
    // value are two answers to one question.
    let err = link(
        &lib_inputs(0xA5),
        &[],
        &dylib_cfg(
            UuidSource::None,
            Some([
                0x7d, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d, 0x6e,
                0x7f, 0x80,
            ]),
        ),
    )
    .expect_err("the suppression and a named value refuse each other");
    let message = err.to_string();
    assert!(
        message.contains("-no_uuid") && message.contains("-uuid"),
        "the refusal names both flags: {message}"
    );
}

#[test]
fn a_random_source_refuses_on_the_relocatable_output() {
    // `-r` keeps its refusal: the object carries no LC_UUID command at
    // all — a random draw has no field to land on (the M99 relocatable
    // refusal mirrored exactly).
    let err = link_reloc(
        &[LinkInput {
            name: "lib.o".into(),
            bytes: lib_object(0xA6),
        }],
        &[],
        &LinkConfig {
            uuid_source: UuidSource::Random,
            ..LinkConfig::default()
        },
        Parallelism::Auto,
    )
    .expect_err("the object refuses the random source");
    let message = err.to_string();
    assert!(
        message.contains("-random_uuid") && message.contains("LC_UUID"),
        "the refusal names the flag and the missing command: {message}"
    );
}

#[test]
fn the_content_source_stays_deterministic_across_plans() {
    // The content face keeps the reproducible-builds contract: the same
    // corpus plans byte-identical headers (the emit's derivation hashes
    // the same pages).
    let a = link(
        &lib_inputs(0x42),
        &[],
        &dylib_cfg(UuidSource::Content, None),
    )
    .expect("the first plans")
    .layout
    .header_bytes;
    let b = link(
        &lib_inputs(0x42),
        &[],
        &dylib_cfg(UuidSource::Content, None),
    )
    .expect("the second plans")
    .layout
    .header_bytes;
    assert_eq!(a, b, "the content face is deterministic");
}

#[test]
fn every_output_kind_carries_the_source() {
    // The M32/M99 shape: every segmented output kind carries the
    // decision (executables, dylibs, bundles); the relocatable output
    // carries no command for any random/named face.
    for kind in [OutputType::Execute, OutputType::Dylib, OutputType::Bundle] {
        let layout = link(
            &lib_inputs(0x77),
            &[],
            &LinkConfig {
                ident: "lib".into(),
                filetype: kind,
                install_name: (kind == OutputType::Dylib).then(|| "@rpath/lib.dylib".to_string()),
                uuid_source: UuidSource::Random,
                ..LinkConfig::default()
            },
        )
        .expect("the segmented kind plans");
        assert!(
            carries_uuid(&layout.layout.header_bytes),
            "the random source carries the command on {kind:?}"
        );
    }
}
