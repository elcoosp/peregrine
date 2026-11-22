//! M125 — the verifier's CPU-subtype backstop: the read-side
//! `check_header` gate accepts the `CPU_SUBTYPE_ARM64_ALL` shape
//! without warning (the knob forces ALL, the value every pre-M125
//! image carried — the default and the named override are
//! byte-identical), and a non-ALL cpusubtype word is named as a
//! warning (the read-side backstop that accepts the ALL shape the
//! `-force_cpusubtype_ALL` knob plans).

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal executable fixture (one `__TEXT` with `__text`). The
/// builder writes `CPU_SUBTYPE_ARM64_ALL` (0) at byte 8 — the shape
/// `-force_cpusubtype_ALL` plans (the default carries the same ALL, so
/// the knob is byte-identity).
fn builder() -> ImageBuilder {
    let mut b = ImageBuilder::executable("m125");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, 96),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_m125_main".into(),
        section_index: 0,
    });
    b
}

// ---- the invariant ------------------------------------------------------------

#[test]
fn the_all_cpusubtype_verifies_strict() {
    // The ALL shape the `-force_cpusubtype_ALL` knob plans (and the
    // default already carries) verifies strict — the read-side backstop
    // accepts `CPU_SUBTYPE_ARM64_ALL` without warning.
    let img = builder().build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the ALL cpusubtype verifies strict: {:?}",
        report.issues
    );
    // The cpusubtype word is CPU_SUBTYPE_ARM64_ALL (0).
    let cpusubtype = u32::from_le_bytes(img.bytes[8..12].try_into().expect("cpusubtype word"));
    assert_eq!(
        cpusubtype,
        pgr_format::consts::CPU_SUBTYPE_ARM64_ALL,
        "the builder writes CPU_SUBTYPE_ARM64_ALL"
    );
}

#[test]
fn a_non_all_cpusubtype_is_named() {
    // The hostile fixture: patch the cpusubtype word to a non-ALL
    // value — the read-side backstop names it (a warning, not an error,
    // mirroring ld64's own tolerance of vendor subtypes; the
    // `-force_cpusubtype_ALL` knob exists to keep the word at ALL
    // regardless of input objects' subtypes).
    let mut img = builder().build().expect("the fixture builds");
    // A non-ALL subtype the gate names (the low 24 bits != 0).
    img.bytes[8..12].copy_from_slice(&0x42u32.to_le_bytes());
    // The signature page hashes no longer match the patched bytes —
    // skip the hash recompute so the cpusubtype finding is the one the
    // gate names (the signature gate is its own contract).
    let no_hash = Options {
        skip_hash_recompute: true,
        ..opts()
    };
    let report = verify(&img.bytes, &no_hash);
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("cpusubtype")),
        "the finding names the non-ALL cpusubtype: {:?}",
        report.issues
    );
}
