//! M126 — the output image's atomization decision
//! (`-allow_subsections_via_symbols`/`-no_allow_subsections_via_symbols`):
//! ld64's flags ("Turn on/off the `MH_SUBSECTIONS_VIA_SYMBOLS` bit in
//! the output mach-O header"). The decision is a bool on
//! [`pgr_core::layout::LinkConfig`] (`subsections_via_symbols`) that
//! the segmented path's `build_header` reads — `true` ORs
//! `MH_SUBSECTIONS_VIA_SYMBOLS` into the output's `mach_header_64.flags`
//! word (the atomization the dead-strip and ICF passes already read from
//! *input* objects since M5; the output decision names whether the
//! *producer* marks its own image atomizable). The default (`false`)
//! keeps every pre-M126 link byte-identical — the segmented path never
//! set the bit, so the named `false` face is the pre-knob shape; the
//! named `true` face adds exactly the one bit.
//!
//! Gate matrix:
//! * the default — an executable plans no `MH_SUBSECTIONS_VIA_SYMBOLS`
//!   bit (the pre-M126 shape), every pre-knob link byte-identical;
//! * the knob — a named `-allow_subsections_via_symbols` ORs the bit
//!   into the flags word, `-no_allow_subsections_via_symbols` holds it
//!   off (last-wins the pair, the M102 `-bind_at_load`/`-no_bind_at_load`
//!   shape: the emit reads `cfg.subsections_via_symbols`);
//! * the byte-identity lock — a `-no_allow_subsections_via_symbols`
//!   naming the default plans byte-identical bytes to the pre-knob link;
//! * the refusals — a named knob on the relocatable output is a layout
//!   error (the object's header is the input's, verbatim — the
//!   M104/M105/M117 refusal shape, mirrored exactly so every caller
//!   pays it);
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

/// The image header's flags word (byte 24..28 of the 32-byte header).
fn flags_word(header: &[u8]) -> u32 {
    u32::from_le_bytes(header[24..28].try_into().expect("the flags word"))
}

#[test]
fn the_default_executable_plans_no_subsections_bit() {
    let header = link_header(|_| {});
    assert_eq!(
        flags_word(&header) & pgr_format::consts::MH_SUBSECTIONS_VIA_SYMBOLS,
        0,
        "the pre-M126 shape: the default carries no MH_SUBSECTIONS_VIA_SYMBOLS bit"
    );
}

#[test]
fn a_named_decision_sets_the_bit() {
    // The named `-allow_subsections_via_symbols` ORs exactly the one bit
    // into the flags word — the dead-strip and ICF passes already read
    // the bit from inputs; the producer now names its own atomization.
    let default = link_header(|_| {});
    let knobbed = link_header(|c| {
        c.subsections_via_symbols = true;
    });
    let bit = pgr_format::consts::MH_SUBSECTIONS_VIA_SYMBOLS;
    // The flags word is at bytes 24..28 (LE); OR exactly the one bit.
    let mut expected = default.clone();
    let flags = u32::from_le_bytes(expected[24..28].try_into().expect("the flags word"));
    expected[24..28].copy_from_slice(&(flags | bit).to_le_bytes());
    assert_eq!(knobbed, expected, "the named face adds exactly the one bit");
    assert_ne!(
        flags_word(&knobbed) & pgr_format::consts::MH_SUBSECTIONS_VIA_SYMBOLS,
        0,
        "the named face carries the bit"
    );
}

#[test]
fn a_no_subsections_face_is_byte_identical_to_the_default() {
    // The named `-no_allow_subsections_via_symbols` face names the
    // default (the bit is off either way) — the byte-identity lock the
    // M122 `-pie` pattern rides (the named off is the pre-knob shape,
    // never a layout product the bytes move on).
    let default = link_header(|_| {});
    let off = link_header(|c| {
        c.subsections_via_symbols = false;
    });
    assert_eq!(off, default, "the named-off face is the pre-knob shape");
}

#[test]
fn the_dylib_face_carries_the_bit_too() {
    // The bit is header-level, not executable-level: a dylib's
    // `mach_header_64.flags` word carries it the same way (the loader
    // consults `MH_SUBSECTIONS_VIA_SYMBOLS` regardless of filetype).
    let mut cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libm126.dylib".into()),
        subsections_via_symbols: true,
        ..LinkConfig::default()
    };
    let _ = &mut cfg;
    let layout = link(&corpus(), &[], &cfg).expect("the dylib links");
    assert_ne!(
        flags_word(&layout.layout.header_bytes) & pgr_format::consts::MH_SUBSECTIONS_VIA_SYMBOLS,
        0,
        "the dylib carries the bit"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    // The relocatable output's header is the input's, verbatim (the M10
    // rung-1 contract — the object is itself a link input, its flags
    // word rides untouched). A named knob that cannot apply is a
    // refusal, never a silently dropped one.
    let cfg = LinkConfig {
        subsections_via_symbols: true,
        filetype: OutputType::Relocatable,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
    assert!(
        err.to_string().contains("relocatable"),
        "the refusal names the relocatable output: {err}"
    );
}

#[test]
fn the_decision_links_deterministically() {
    // Double-link determinism across the decision.
    let a = link_header(|c| {
        c.subsections_via_symbols = true;
    });
    let b = link_header(|c| {
        c.subsections_via_symbols = true;
    });
    assert_eq!(a, b, "the double link is stable");
}
