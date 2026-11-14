//! M27 — the PIE decision (`-no_pie`): the executable header's
//! `MH_PIE` flag stops being hard-coded and becomes a named decision on
//! [`pgr_core::layout::LinkConfig`] — ld64's `-no_pie` drops the flag
//! so the kernel (or a bootloader) loads the image at its fixed
//! addresses instead of handing it a slid base. The default keeps the
//! pre-M27 bytes: every executable carries `MH_PIE` exactly as before.
//!
//! Gate matrix:
//! * the default — an executable carries `MH_PIE` (the pre-M27 shape),
//!   and the flag word rides every output kind it always did (a dylib
//!   or a bundle never carries it — the M3 contract the verifier's
//!   structural contract names);
//! * the knob — `-no_pie` clears exactly the `MH_PIE` bit: the header
//!   flags differ from the default link by that bit alone (nothing
//!   else in the plan moves — the flag is one bit in one word);
//! * the refusals — a named `-no_pie` on a dylib, a bundle or the
//!   relocatable output is a layout error: `MH_PIE` is an
//!   executable-only bit (the driver surface refuses earlier; the
//!   layout re-checks so no library caller can plan the shape either);
//! * the lock — double-link determinism holds across the decision, and
//!   the classic opcode path (no chained fixups) plans the same flag
//!   word (the bit is loader-level, not fixup-level).

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
        "the pre-M27 shape: every executable is PIE"
    );
}

#[test]
fn no_pie_clears_exactly_the_pie_bit() {
    let default = link_header(|_| {});
    let knobbed = link_header(|c| c.no_pie = true);
    assert_eq!(
        flags(&knobbed) & pgr_format::consts::MH_PIE,
        0,
        "the named decision drops MH_PIE"
    );
    // The bit is the whole diff: clearing the flag does not move any
    // other byte of the header (the command stream, the segment
    // layout, the entry — all untouched).
    let pie_bit = pgr_format::consts::MH_PIE;
    let mut expect = default.clone();
    let word = u32::from_le_bytes(expect[24..28].try_into().expect("flags"));
    expect[24..28].copy_from_slice(&(word & !pie_bit).to_le_bytes());
    assert_eq!(knobbed, expect, "MH_PIE is the only byte that moves");
}

#[test]
fn non_executable_outputs_refuse_the_knob() {
    for (kind, label) in [
        (OutputType::Dylib, "dylib"),
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let cfg = LinkConfig {
            no_pie: true,
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
    let a = link_header(|c| c.no_pie = true);
    let b = link_header(|c| c.no_pie = true);
    assert_eq!(a, b, "the double link is stable");
    // The classic opcode path (no chained fixups) plans the same flag
    // word: the bit is loader-level, not fixup-level.
    let classic = link_header(|c| {
        c.no_pie = true;
        c.fixup_chains = false;
    });
    assert_eq!(
        flags(&classic) & pgr_format::consts::MH_PIE,
        0,
        "the classic path carries the named decision too"
    );
}
