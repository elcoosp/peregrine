//! M102 — the bind-at-load decision (`-bind_at_load`/`-no_bind_at_load`):
//! ld64's `MH_BINDATLOAD` flag word stops being unnamed and becomes a
//! named decision on [`pgr_core::layout::LinkConfig`] — the bit tells
//! dyld to bind every undefined symbol at load time, before `main`
//! runs (the `dlopen(RTLD_NOW)` contract the executable promises its
//! host). The default stays bitless: every pre-M102 link is
//! byte-identical (ld64's own default — the flag is off unless named).
//!
//! Gate matrix:
//! * the default — an executable carries no `MH_BINDATLOAD` (the
//!   pre-M102 shape), and the decision rides every output kind it
//!   never named (the flag word is one bit in one word);
//! * the knob — `-bind_at_load` sets exactly the `MH_BINDATLOAD` bit:
//!   the header flags differ from the default link by that bit alone
//!   (nothing else in the plan moves — the bit is loader-level, not
//!   fixup-level, so the classic opcode path plans the same word);
//! * the pair — `-no_bind_at_load` drops the bit the positive face
//!   set (the last flag wins at the parse; the core decision is the
//!   bool, so a dropped bit plans the default bytes);
//! * the refusals — a named `-bind_at_load` on a dylib, a bundle or
//!   the relocatable output is a layout error: `MH_BINDATLOAD` is an
//!   executable-only bit (the driver surface refuses earlier; the
//!   layout re-check and [`pgr_core::link::link_reloc`] back the
//!   refusal so no library caller can plan the shape either);
//! * the verifier — `MH_BINDATLOAD` is a dyld-consumed flag, never a
//!   format defect: an executable carrying the bit verifies strict,
//!   and a foreign image that carries it where dyld never reads it
//!   (a dylib, a bundle) draws the warning face, never a refusal (the
//!   `-no_adhoc` carve-out pattern);
//! * the lock — double-link determinism holds across the decision.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ImageBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

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

/// Links the corpus with a config tweak and returns the image bytes.
fn link_image(tweak: impl FnOnce(&mut LinkConfig)) -> Vec<u8> {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    link(&corpus(), &[], &cfg)
        .expect("the corpus links")
        .layout
        .header_bytes
}

/// The header's flags word (byte 24..28 of the 32-byte header).
fn header_flags(image: &[u8]) -> u32 {
    u32::from_le_bytes(image[24..28].try_into().expect("flags word"))
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

// ---- the decision -------------------------------------------------------------

#[test]
fn the_default_stays_bitless() {
    let cfg = LinkConfig::default();
    assert!(
        !cfg.bind_at_load,
        "the pre-M102 shape: no default executable binds at load"
    );
    assert_eq!(
        header_flags(&link_image(|_| ())) & pgr_format::consts::MH_BINDATLOAD,
        0,
        "the default link carries no MH_BINDATLOAD"
    );
}

#[test]
fn the_knob_sets_exactly_the_bit() {
    let default = link_image(|_| ());
    let knobbed = link_image(|c| c.bind_at_load = true);
    assert_eq!(
        header_flags(&knobbed) & pgr_format::consts::MH_BINDATLOAD,
        pgr_format::consts::MH_BINDATLOAD,
        "the named decision sets MH_BINDATLOAD"
    );
    assert_eq!(
        header_flags(&default) ^ header_flags(&knobbed),
        pgr_format::consts::MH_BINDATLOAD,
        "the flag word differs by the MH_BINDATLOAD bit alone"
    );
}

#[test]
fn the_pair_drops_the_bit() {
    let dropped = link_image(|c| {
        c.bind_at_load = true;
        c.bind_at_load = false;
    });
    assert_eq!(
        header_flags(&dropped) & pgr_format::consts::MH_BINDATLOAD,
        0,
        "-no_bind_at_load plans the default bytes"
    );
    assert_eq!(
        link_image(|_| ()),
        dropped,
        "a dropped bit is byte-identical to the pre-knob link"
    );
}

#[test]
fn the_classic_opcode_path_plans_the_same_word() {
    let knobbed = link_image(|c| {
        c.bind_at_load = true;
        c.fixup_chains = false;
    });
    assert_eq!(
        header_flags(&knobbed) & pgr_format::consts::MH_BINDATLOAD,
        pgr_format::consts::MH_BINDATLOAD,
        "the bit is header-level, not fixup-level: the classic path carries it"
    );
}

// ---- the refusals -------------------------------------------------------------

#[test]
fn the_non_executable_outputs_refuse_the_knob() {
    for (kind, label) in [
        (OutputType::Dylib, "dylib"),
        (OutputType::Bundle, "bundle"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let cfg = LinkConfig {
            filetype: kind,
            bind_at_load: true,
            ..LinkConfig::default()
        };
        let err = link(&corpus(), &[], &cfg).expect_err("the knob refuses off an executable");
        let message = err.to_string();
        assert!(
            message.contains("MH_BINDATLOAD"),
            "the refusal names the flag word ({label}): {message}"
        );
        assert!(
            message.contains("executable-only") || message.contains("executable"),
            "the refusal names the fix ({label}): {message}"
        );
    }
}

#[test]
fn the_relocatable_path_refuses_the_knob() {
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        bind_at_load: true,
        ..LinkConfig::default()
    };
    let err = link_reloc(&corpus(), &[], &cfg, Parallelism::Auto)
        .expect_err("the -r path refuses the knob");
    assert!(
        err.to_string().contains("MH_BINDATLOAD"),
        "the relocatable re-check names the flag word: {err}",
    );
}

// ---- the verifier faces --------------------------------------------------------

#[test]
fn the_knobbed_executable_plans_the_strict_contract() {
    // The strict verifier's own face lives in the driver's end-to-end
    // gate; the core-side contract is the header word: the bit rides an
    // executable whose every other flag byte matches the default link.
    let default = link_image(|_| ());
    let knobbed = link_image(|c| c.bind_at_load = true);
    assert_ne!(default, knobbed, "the bit moves the header word");
    assert_eq!(
        header_flags(&default) | pgr_format::consts::MH_BINDATLOAD,
        header_flags(&knobbed),
        "MH_BINDATLOAD is the only flag byte the decision moves"
    );
}

#[test]
fn a_foreign_image_carrying_the_bit_draws_the_warning_face() {
    // A dylib whose header carries MH_BINDATLOAD is a foreign shape
    // (the producer refuses to plan it) — the verifier warns, never
    // refuses: the flag is dyld's to consume, not a format defect.
    let mut b = ImageBuilder::dylib("@rpath/libf.dylib", "libf");
    b.add_segment(pgr_fixtures::SegmentSpec {
        name: "__TEXT".into(),
        maxprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        initprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        sections: [pgr_fixtures::SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
            data: [0xC0u8, 0x03, 0x5F, 0xD6].repeat(24),
            relocs: Vec::new(),
        }]
        .to_vec(),
    });
    b.add_symbol(pgr_fixtures::SymbolSpec::Defined {
        name: "_libf_fn".into(),
        section_index: 0,
    });
    b.set_mh_flags(pgr_format::consts::MH_BINDATLOAD);
    let bytes = b.build().expect("the fixture dylib builds").bytes;
    let report = verify(&bytes, &strict());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("MH_BINDATLOAD")),
        "the warning face names the bit: {:?}",
        report.issues
    );
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.severity != pgr_verify::Severity::Error),
        "the bit never refuses: {:?}",
        report.issues
    );
}

// ---- the lock ------------------------------------------------------------------

#[test]
fn double_link_is_byte_identical_across_the_decision() {
    let a = link_image(|c| c.bind_at_load = true);
    let b = link_image(|c| c.bind_at_load = true);
    assert_eq!(a, b, "the decision is deterministic");
}
