//! M125 — the CPU subtype override (`-force_cpusubtype_ALL`): ld64's
//! flag ("Force the cpusubtype to be CPU_SUBTYPE_ARM64_ALL") forces the
//! output's `mach_header_64.cpusubtype` word to `CPU_SUBTYPE_ARM64_ALL`
//! regardless of the input objects' subtypes. The default keeps the
//! pre-M125 bytes (every image already carries ALL — the segmented path
//! writes `CPU_SUBTYPE_ARM64_ALL`); the named decision carries the same
//! ALL (byte-identity, the M122 `-pie` pattern over the cpusubtype
//! word). Executable, dylib and bundle outputs accept the knob (the
//! header word is the producer's to name); the relocatable output
//! refuses it (the object's header is the input's, verbatim — the
//! M104/M105/M117 refusal shape, mirrored exactly so every caller pays
//! it).
//!
//! Gate matrix:
//! * the default — an executable carries `CPU_SUBTYPE_ARM64_ALL` (the
//!   pre-M125 shape), every pre-knob link byte-identical;
//! * the knob — a named `-force_cpusubtype_ALL` carries the same ALL
//!   (byte-identity — the M122 `-pie` pattern);
//! * the byte-identity lock — the named face plans byte-identical
//!   bytes to the pre-knob link;
//! * the admissions — executable, dylib and bundle outputs accept the
//!   knob (the cpusubtype word is ALL on each);
//! * the refusal — the relocatable output refuses the knob (the
//!   object's header is the input's, verbatim);
//! * the lock — double-link determinism holds across the decision.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A single-object corpus (`_main` exported) linkable as any kind.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    for (i, sym) in ["_main", "_lib_fn"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    vec![LinkInput {
        name: "main.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus with a config tweak and returns the header bytes.
fn link_header(tweak: impl FnOnce(&mut LinkConfig)) -> Vec<u8> {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg)
        .expect("the corpus links")
        .layout
        .header_bytes
}

/// The header's cpusubtype word (byte 8..12 of the 32-byte header).
fn cpusubtype(header: &[u8]) -> u32 {
    u32::from_le_bytes(header[8..12].try_into().expect("cpusubtype word"))
}

#[test]
fn the_default_executable_carries_all() {
    let header = link_header(|_| {});
    assert_eq!(
        cpusubtype(&header),
        pgr_format::consts::CPU_SUBTYPE_ARM64_ALL,
        "the pre-M125 shape: every executable carries CPU_SUBTYPE_ARM64_ALL"
    );
}

#[test]
fn the_named_override_carries_the_same_all() {
    let header = link_header(|c| c.force_cpusubtype_all = true);
    assert_eq!(
        cpusubtype(&header),
        pgr_format::consts::CPU_SUBTYPE_ARM64_ALL,
        "the named decision carries CPU_SUBTYPE_ARM64_ALL"
    );
}

#[test]
fn the_named_face_plans_byte_identical_bytes() {
    // The knob is byte-identity — the cpusubtype word is ALL either way
    // (the M122 `-pie` pattern over the cpusubtype word), so the named
    // face plans byte-identical bytes to the pre-knob link.
    let default = link_header(|_| {});
    let forced = link_header(|c| c.force_cpusubtype_all = true);
    assert_eq!(forced, default, "the named face is the pre-knob shape");
}

#[test]
fn executable_dylib_and_bundle_accept_the_knob() {
    // The header word is the producer's to name on every segmented
    // output — the knob links on an executable, a dylib and a bundle,
    // and the cpusubtype word is ALL on each.
    for (kind, install_name) in [
        (OutputType::Execute, None),
        (OutputType::Dylib, Some("@rpath/libm125.dylib".into())),
        (OutputType::Bundle, None),
    ] {
        let cfg = LinkConfig {
            filetype: kind,
            install_name,
            force_cpusubtype_all: true,
            ..LinkConfig::default()
        };
        let layout = link(&corpus(), &[], &cfg).expect("the segmented output accepts the knob");
        assert_eq!(
            cpusubtype(&layout.layout.header_bytes),
            pgr_format::consts::CPU_SUBTYPE_ARM64_ALL,
            "the {kind:?} output carries CPU_SUBTYPE_ARM64_ALL"
        );
    }
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        force_cpusubtype_all: true,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the relocatable output refuses");
    assert!(
        err.to_string().contains("relocatable"),
        "the refusal names the relocatable output: {err}"
    );
}

#[test]
fn the_decision_links_deterministically() {
    // Double-link determinism across the decision.
    let a = link_header(|c| c.force_cpusubtype_all = true);
    let b = link_header(|c| c.force_cpusubtype_all = true);
    assert_eq!(a, b, "the double link is stable");
}
