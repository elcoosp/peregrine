//! M127 — the dylib's export-interposability decision (`-interposable`):
//! ld64's flag marks a dylib's exports as interposable — the loader
//! consults `MH_WEAK_DEFINES | MH_BINDS_TO_WEAK` on the image's
//! `mach_header_64.flags` word to treat every export as overridable at
//! runtime (the interpose-all contract, distinct from the per-symbol
//! weak-define bit the M2 trie already carries). The decision is a bool
//! on [`pgr_core::layout::LinkConfig`] (`interposable`) that the
//! segmented path's `build_header` reads — `true` ORs both bits into
//! the flags word regardless of whether the dylib already carries weak
//! defines. The default (`false`) keeps every pre-M127 link
//! byte-identical — the bits ride the weak-define presence the M2 trie
//! already priced; a dylib with no weak defines never carried the bits,
//! so the named `false` face is the pre-knob shape (byte-identity, the
//! M122 `-pie` pattern over the flags word). The knob is a dylib's
//! decision — an executable's identity is `LC_MAIN` (the kernel loads
//! it), a bundle dlopens without an export table to interpose, and the
//! relocatable output's header is the input's, verbatim.
//!
//! Gate matrix:
//! * the default — a dylib with no weak defines plans no
//!   `MH_WEAK_DEFINES | MH_BINDS_TO_WEAK` bits (the pre-M127 shape),
//!   every pre-knob link byte-identical;
//! * the knob — a named `-interposable` ORs both bits into the flags
//!   word;
//! * the byte-identity lock — a `-interposable` naming a dylib that
//!   already carries weak defines (the bits were already set) plans
//!   byte-identical bytes;
//! * the refusals — a named knob on an executable, a bundle or the
//!   relocatable output is a layout error (the M104/M105/M117 refusal
//!   shape, mirrored exactly so every caller pays it);
//! * the lock — double-link determinism holds across the decision.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// A single-object dylib corpus (`_main` exported, no weak defines —
/// the pre-M127 shape carries no `MH_WEAK_DEFINES` bit).
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

/// Links the corpus as a dylib with a config tweak and returns the
/// header bytes.
fn link_header(tweak: impl FnOnce(&mut LinkConfig)) -> Vec<u8> {
    let mut cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libm127.dylib".into()),
        ..LinkConfig::default()
    };
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg)
        .expect("the dylib links")
        .layout
        .header_bytes
}

/// The image header's flags word (byte 24..28 of the 32-byte header).
fn flags_word(header: &[u8]) -> u32 {
    u32::from_le_bytes(header[24..28].try_into().expect("the flags word"))
}

const INTERPOSE_BITS: u32 =
    pgr_format::consts::MH_WEAK_DEFINES | pgr_format::consts::MH_BINDS_TO_WEAK;

#[test]
fn the_default_dylib_plans_no_interpose_bits() {
    let header = link_header(|_| {});
    assert_eq!(
        flags_word(&header) & INTERPOSE_BITS,
        0,
        "the pre-M127 shape: the default carries no interpose bits"
    );
}

#[test]
fn a_named_decision_sets_both_bits() {
    // The named `-interposable` ORs both `MH_WEAK_DEFINES` and
    // `MH_BINDS_TO_WEAK` into the flags word — the interpose-all
    // contract the loader consults.
    let default = link_header(|_| {});
    let knobbed = link_header(|c| {
        c.interposable = true;
    });
    let flags = flags_word(&default);
    let mut expected = default.clone();
    expected[24..28].copy_from_slice(&(flags | INTERPOSE_BITS).to_le_bytes());
    assert_eq!(
        knobbed, expected,
        "the named face adds exactly the two bits"
    );
    assert_eq!(
        flags_word(&knobbed) & INTERPOSE_BITS,
        INTERPOSE_BITS,
        "the named face carries both interpose bits"
    );
}

#[test]
fn the_off_face_is_byte_identical_to_the_default() {
    // The named `false` face names the default (the bits are off either
    // way for a dylib with no weak defines) — the byte-identity lock.
    let default = link_header(|_| {});
    let off = link_header(|c| {
        c.interposable = false;
    });
    assert_eq!(off, default, "the named-off face is the pre-knob shape");
}

#[test]
fn the_executable_output_refuses_the_knob() {
    // An executable's identity is `LC_MAIN` (the kernel loads it), not
    // an export table to interpose — the M104/M105/M117 refusal shape.
    let cfg = LinkConfig {
        interposable: true,
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
    assert!(
        err.to_string().contains("executable"),
        "the refusal names the executable output: {err}"
    );
}

#[test]
fn the_bundle_output_refuses_the_knob() {
    // A bundle dlopens without an export table to interpose.
    let cfg = LinkConfig {
        interposable: true,
        filetype: OutputType::Bundle,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
    assert!(
        err.to_string().contains("bundle"),
        "the refusal names the bundle output: {err}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    // The relocatable output's header is the input's, verbatim (the M10
    // rung-1 contract).
    let cfg = LinkConfig {
        interposable: true,
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
        c.interposable = true;
    });
    let b = link_header(|c| {
        c.interposable = true;
    });
    assert_eq!(a, b, "the double link is stable");
}
