//! M126 — the verifier's atomization backstop: the read-side
//! `check_header` gate accepts the `MH_SUBSECTIONS_VIA_SYMBOLS`-bearing
//! shape without warning (the bit is loader-advisory, not a contract
//! the strict verifier gates on — the gate warns on a wrong cputype or
//! an unusual filetype, never on the atomization bit). The producer's
//! `-allow_subsections_via_symbols` image verifies strict exactly like
//! the default one.

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
/// builder writes the default flags word (no `MH_SUBSECTIONS_VIA_SYMBOLS`
/// bit) — the shape the producer's `-no_allow_subsections_via_symbols`
/// face plans (the default carries the same shape, so the knob is
/// byte-identity on the off face).
fn builder() -> ImageBuilder {
    let mut b = ImageBuilder::executable("m126");
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
        name: "_m126_main".into(),
        section_index: 0,
    });
    b
}

/// The byte offset of the flags word inside the 32-byte header (byte 24).
const FLAGS_AT: usize = 24;

// ---- the invariant ------------------------------------------------------------

#[test]
fn the_default_flags_word_verifies_strict() {
    // The pre-M126 shape (no `MH_SUBSECTIONS_VIA_SYMBOLS` bit) verifies
    // strict — the read-side backstop accepts the flags word without
    // warning.
    let img = builder().build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the default flags word verifies strict: {:?}",
        report.issues
    );
    let flags = u32::from_le_bytes(img.bytes[FLAGS_AT..FLAGS_AT + 4].try_into().expect("flags"));
    assert_eq!(
        flags & pgr_format::consts::MH_SUBSECTIONS_VIA_SYMBOLS,
        0,
        "the builder writes no MH_SUBSECTIONS_VIA_SYMBOLS bit"
    );
}

#[test]
fn the_atomized_flags_word_verifies_strict() {
    // The hostile-but-valid fixture: OR the
    // `MH_SUBSECTIONS_VIA_SYMBOLS` bit into the flags word — the
    // shape the producer's `-allow_subsections_via_symbols` knob
    // plans. The read-side backstop accepts it (the bit is
    // loader-advisory, the gate never warns on it), so the
    // atomized image verifies strict exactly like the default.
    let mut img = builder().build().expect("the fixture builds");
    let flags = u32::from_le_bytes(img.bytes[FLAGS_AT..FLAGS_AT + 4].try_into().expect("flags"));
    img.bytes[FLAGS_AT..FLAGS_AT + 4]
        .copy_from_slice(&(flags | pgr_format::consts::MH_SUBSECTIONS_VIA_SYMBOLS).to_le_bytes());
    // The signature page hashes no longer match the patched bytes —
    // skip the hash recompute so the flags-word finding is the one the
    // gate names (the signature gate is its own contract).
    let no_hash = Options {
        skip_hash_recompute: true,
        ..opts()
    };
    let report = verify(&img.bytes, &no_hash);
    assert!(
        report.is_ok(&no_hash),
        "the atomized flags word verifies strict (the bit is loader-advisory): {:?}",
        report.issues
    );
    // And no warning names the atomization bit — the gate does not gate
    // on `MH_SUBSECTIONS_VIA_SYMBOLS`.
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.message.contains("SUBSECTIONS")),
        "no finding names the atomization bit: {:?}",
        report.issues
    );
}
