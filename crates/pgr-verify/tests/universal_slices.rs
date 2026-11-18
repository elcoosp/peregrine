//! M71 — the verifier's universal-container face: the driver links a
//! universal container through its arm64 slice (M70), so the verifier
//! owes the same container a *read-side* story — every slice the table
//! declares gets the strict pass over its own window, and the table's
//! row must agree with the slice's own header about the arch it names
//! (the driver links by the table's row; a lying table is the shape
//! the seam can break). The container's decode is the format reader's
//! gate — a malformed table refuses to the caller, the way
//! `parse_universal` refuses the driver.
//!
//! Gate matrix:
//! * the clean pass — a container carrying one real arm64 slice
//!   verifies clean end to end (`is_ok`, zero issues);
//! * the lying table — a row that names a cputype the window's own
//!   header does not carry rides a `Code::Structure` issue anchored at
//!   the slice's offset, while the slice's other checks still run;
//! * the corrupt twin — a byte flipped inside a slice's `__text` rides
//!   an error-severity issue on that slice's verdict (the container's
//!   other slices are unaffected);
//! * the refusal — a truncated container refuses (`FormatError`), the
//!   format reader's offset-tagged error verbatim.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{Code, Options, Severity, verify_universal};

/// The `x86_64` cputype (the lie the table tells in the mismatch gate).
const CPU_TYPE_X86_64: u32 = 0x0100_0007;

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A small arm64 dylib fixture (an export surface over a `__text` body).
fn dylib_slice(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libm71.dylib", "m71-universal");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(seed, 128),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

#[test]
fn clean_container_verifies_ok() {
    let slice = dylib_slice(0x71);
    let container = universal_image(&[(&slice, CPU_TYPE_ARM64)]).expect("the container wraps");
    let report = verify_universal(&container, &opts()).expect("the container decodes");
    assert_eq!(report.slices.len(), 1, "one verdict per table row");
    let verdict = &report.slices[0];
    assert_eq!(verdict.arch.cputype, CPU_TYPE_ARM64);
    assert!(
        verdict.report.is_ok(&opts()),
        "the clean slice verifies: {:#?}",
        verdict.report.issues
    );
    assert!(report.is_ok(&opts()), "the container verifies clean");
}

#[test]
fn a_lying_table_row_rides_a_structure_issue() {
    let slice = dylib_slice(0x72);
    // The table names x86_64 for an arm64 window — the row and the
    // image disagree (the driver would link the wrong arch's bytes).
    let container = universal_image(&[(&slice, CPU_TYPE_X86_64)]).expect("the container wraps");
    let report = verify_universal(&container, &opts()).expect("the container decodes");
    let verdict = &report.slices[0];
    let mismatch = verdict
        .report
        .issues
        .iter()
        .find(|i| i.code == Code::HeaderInvalid && i.message.contains("cputype"));
    assert!(
        mismatch.is_some(),
        "the disagreement rides a structure issue: {:#?}",
        verdict.report.issues
    );
    let issue = mismatch.expect("the mismatch issue rides");
    assert_eq!(issue.offset, Some(verdict.arch.offset));
    assert_eq!(issue.severity, Severity::Error);
}

#[test]
fn a_corrupt_slice_rides_its_own_verdict() {
    let slice = dylib_slice(0x73);
    let foreign = vec![0u8; 64]; // not a Mach-O window — its own verdict
    // Flip one byte of the arm64 slice's __text (past the headers, in
    // the page the signature hashes).
    let mut corrupt = slice.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xFF;
    let container = universal_image(&[(&corrupt, CPU_TYPE_ARM64), (&foreign, CPU_TYPE_X86_64)])
        .expect("the container wraps");
    let report = verify_universal(&container, &opts()).expect("the container decodes");
    assert_eq!(report.slices.len(), 2, "one verdict per table row");
    let arm64 = &report.slices[0];
    assert!(
        !arm64.report.is_ok(&opts()),
        "the corrupt slice refuses: {:#?}",
        arm64.report.issues
    );
    assert!(
        arm64
            .report
            .issues
            .iter()
            .any(|i| i.severity == Severity::Error),
        "the corruption rides an error issue"
    );
    assert!(
        !report.is_ok(&opts()),
        "the container's verdict is its slices'"
    );
}

#[test]
fn a_truncated_container_refuses() {
    let slice = dylib_slice(0x74);
    let container = universal_image(&[(&slice, CPU_TYPE_ARM64)]).expect("the container wraps");
    // The header cut: the count's own field cannot read.
    let err = verify_universal(&container[..6], &opts()).expect_err("the header refuses");
    assert!(
        err.to_string().contains("offset 4"),
        "the refusal is the format reader's: {err}"
    );
    // The window cut: the table reads, the slice's bytes do not ride.
    let err = verify_universal(&container[..40], &opts()).expect_err("the window refuses");
    assert!(
        err.to_string().contains("overruns"),
        "the refusal is the format reader's: {err}"
    );
}
