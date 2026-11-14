//! M27 — the verifier reads the PIE decision: a non-PIE executable
//! verifies strict exactly like the PIE default (the flag is a named
//! `-no_pie` decision, not a defect), and the pre-existing structural
//! contract keeps naming the genuinely broken shape — `MH_PIE` on a
//! non-executable image (the fixture control).

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable fixture with the PIE bit on or off.
fn exec_builder(pie: bool) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m27exec");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x5AA5, 96),
            relocs: Vec::new(),
        }],
    });
    b.set_entry(0);
    b.set_pie(pie);
    b
}

/// A minimal legal dylib fixture (the shape `MH_PIE` must never ride).
fn dylib_builder() -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm27.dylib", "m27");
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
        name: "_m27_init".into(),
        section_index: 0,
    });
    b
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn a_non_pie_executable_verifies_strict() {
    let img = exec_builder(false).build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the -no_pie decision verifies like the default: {:?}",
        report.issues
    );
}

#[test]
fn the_pie_default_verifies_strict() {
    let img = exec_builder(true).build().expect("builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the PIE default verifies strict: {:?}",
        report.issues
    );
}

// ---- the broken shape (the pre-existing contract, as a control) --------------

#[test]
fn mh_pie_on_a_non_executable_is_still_named() {
    // The knob cannot produce this shape (the layout refuses it) — the
    // hand-built fixture is the hostile third-party image the
    // structural contract exists to name.
    let img = dylib_builder().build().expect("the dylib fixture builds");
    // Flip the flag word's MH_PIE bit on the dylib.
    let mut bytes = img.bytes.clone();
    let word = u32::from_le_bytes(bytes[24..28].try_into().expect("flags"));
    bytes[24..28].copy_from_slice(&(word | pgr_format::consts::MH_PIE).to_le_bytes());
    let report = verify(&bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i
            .message
            .contains("MH_PIE is only meaningful for executables")),
        "the misplaced PIE bit is named: {:?}",
        report.issues
    );
    assert!(!report.is_ok(&opts()), "strict fails on the misplaced bit");
}
