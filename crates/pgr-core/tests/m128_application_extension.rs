//! M128 — the app-extension-safe decision (`-application_extension`):
//! ld64's flag marks the image as app-extension-safe — the loader
//! consults `MH_APP_EXTENSION_SAFE` on the image's
//! `mach_header_64.flags` word for the App Store's sandbox
//! compatibility contract (the app-extension gate the system enforces
//! on a `.appex`'s loaded images). The decision is a bool on
//! [`pgr_core::layout::LinkConfig`] (`application_extension`) that the
//! segmented path's `build_header` reads — `true` ORs the bit into the
//! flags word. The default (`false`) keeps every pre-M128 link
//! byte-identical — the segmented path never set the bit, so the named
//! `false` face is the pre-knob shape (byte-identity, the M122 `-pie`
//! pattern over the flags word). The relocatable output refuses the
//! knob (the object's header is the input's, verbatim — the M104/M105/
//! M117 pattern, `link_reloc` and the layout's re-check backing the
//! driver surface's `ApplicationExtensionConflict`).
//!
//! Gate matrix:
//! * the default — an executable plans no `MH_APP_EXTENSION_SAFE` bit
//!   (the pre-M128 shape), every pre-knob link byte-identical;
//! * the knob — a named `-application_extension` ORs the bit into the
//!   flags word;
//! * the byte-identity lock — a `-application_extension` naming the
//!   default (off) plans byte-identical bytes;
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
fn the_default_executable_plans_no_app_extension_bit() {
    let header = link_header(|_| {});
    assert_eq!(
        flags_word(&header) & pgr_format::consts::MH_APP_EXTENSION_SAFE,
        0,
        "the pre-M128 shape: the default carries no MH_APP_EXTENSION_SAFE bit"
    );
}

#[test]
fn a_named_decision_sets_the_bit() {
    // The named `-application_extension` ORs exactly the one bit into
    // the flags word — the App Store's sandbox-compatibility contract.
    let default = link_header(|_| {});
    let knobbed = link_header(|c| {
        c.application_extension = true;
    });
    let flags = flags_word(&default);
    let mut expected = default.clone();
    expected[24..28]
        .copy_from_slice(&(flags | pgr_format::consts::MH_APP_EXTENSION_SAFE).to_le_bytes());
    assert_eq!(knobbed, expected, "the named face adds exactly the one bit");
    assert_ne!(
        flags_word(&knobbed) & pgr_format::consts::MH_APP_EXTENSION_SAFE,
        0,
        "the named face carries the bit"
    );
}

#[test]
fn the_off_face_is_byte_identical_to_the_default() {
    // The named `false` face names the default (the bit is off either
    // way) — the byte-identity lock.
    let default = link_header(|_| {});
    let off = link_header(|c| {
        c.application_extension = false;
    });
    assert_eq!(off, default, "the named-off face is the pre-knob shape");
}

#[test]
fn the_dylib_face_carries_the_bit_too() {
    // The bit is header-level, not executable-level: a dylib's
    // `mach_header_64.flags` word carries it the same way.
    let mut cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libm128.dylib".into()),
        application_extension: true,
        ..LinkConfig::default()
    };
    let _ = &mut cfg;
    let layout = link(&corpus(), &[], &cfg).expect("the dylib links");
    assert_ne!(
        flags_word(&layout.layout.header_bytes) & pgr_format::consts::MH_APP_EXTENSION_SAFE,
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
        application_extension: true,
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
        c.application_extension = true;
    });
    let b = link_header(|c| {
        c.application_extension = true;
    });
    assert_eq!(a, b, "the double link is stable");
}
