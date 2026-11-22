//! M122 — the PIE positive-form twin (`-pie`): ld64's flag ("Force the
//! creation of an `MH_PIE` file") is the explicit-decision mirror of the
//! M27 `-no_pie` knob — the M120 `-executable` pattern over the PIE bit.
//! The default keeps the pre-M122 bytes (every executable already
//! carries `MH_PIE`); the named decision holds the bit ON even when a
//! `-no_pie` arrived earlier on the command line (last-wins, the M102
//! `-bind_at_load`/`-no_bind_at_load` pair shape). The bit is
//! loader-level, not fixup-level, so the classic opcode path plans the
//! same flag word. Non-executable outputs refuse the knob (`MH_PIE` is
//! an executable-only bit — the M27 refusal shape, mirrored exactly).
//!
//! Gate matrix:
//! * the default — an executable carries `MH_PIE` (the pre-M122 shape),
//!   every pre-knob link byte-identical;
//! * the knob — `-pie` re-sets the bit a `-no_pie` cleared (the
//!   last-wins contract the M102 pair names);
//! * the refusals — a named `-pie` on a dylib, a bundle or the
//!   relocatable output is a layout error (the M27 refusal shape,
//!   mirrored exactly so every caller pays it);
//! * the lock — double-link determinism holds across the decision, and
//!   the classic opcode path (no chained fixups) plans the same flag
//!   word.

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

/// The header's flags word (byte 24..28 of the 32-byte header).
fn flags(header: &[u8]) -> u32 {
    u32::from_le_bytes(header[24..28].try_into().expect("flags word"))
}

#[test]
fn the_default_executable_carries_mh_pie() {
    let header = link_header(|_| {});
    assert_eq!(
        flags(&header) & pgr_format::consts::MH_PIE,
        pgr_format::consts::MH_PIE,
        "the pre-M122 shape: every executable is PIE"
    );
}

#[test]
fn pie_re_sets_the_bit_a_no_pie_cleared() {
    // The last-wins contract: `-pie` arriving after `-no_pie` holds the
    // bit ON (the M102 pair shape — the bool carries whichever came
    // last). The bit is the whole diff against the default (no other
    // byte moves).
    let default = link_header(|_| {});
    let knobbed = link_header(|c| {
        c.no_pie = true;
        c.pie = true;
    });
    assert_eq!(
        flags(&knobbed) & pgr_format::consts::MH_PIE,
        pgr_format::consts::MH_PIE,
        "the named decision re-sets MH_PIE"
    );
    // The named decision plans the same bytes as the default (the bit
    // is the default's own — `-pie` is the explicit-decision mirror,
    // never a layout product; the M109 pattern's face).
    assert_eq!(knobbed, default, "the named face plans the default bytes");
}

#[test]
fn pie_alone_plans_the_default_bytes() {
    // `-pie` on its own (no preceding `-no_pie`) names the default
    // explicitly — every byte identical to the pre-knob link.
    let default = link_header(|_| {});
    let knobbed = link_header(|c| c.pie = true);
    assert_eq!(knobbed, default, "the named face is the default shape");
}

#[test]
fn non_executable_outputs_refuse_the_knob() {
    for (kind, label) in [
        (OutputType::Dylib, "dylib"),
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let cfg = LinkConfig {
            pie: true,
            filetype: kind,
            ..LinkConfig::default()
        };
        let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
        assert!(
            err.to_string().contains(label),
            "the refusal names the output kind ({label}): {err}"
        );
    }
}

#[test]
fn the_decision_links_deterministically_and_on_the_classic_path() {
    // Double-link determinism across the decision.
    let a = link_header(|c| c.pie = true);
    let b = link_header(|c| c.pie = true);
    assert_eq!(a, b, "the double link is stable");
    // The classic opcode path (no chained fixups) plans the same flag
    // word: the bit is loader-level, not fixup-level.
    let classic = link_header(|c| {
        c.pie = true;
        c.fixup_chains = false;
    });
    assert_eq!(
        flags(&classic) & pgr_format::consts::MH_PIE,
        pgr_format::consts::MH_PIE,
        "the classic path carries the named decision too"
    );
}
