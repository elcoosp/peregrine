//! M30 — the verifier's data-in-code contract: the entries the output
//! `LC_DATA_IN_CODE` payload names must stay inside `__TEXT` (the M0
//! shape check), arrive **sorted** by offset and **non-overlapping**
//! (the LINKEDIT stream the debugger walks — an unsorted or overlapping
//! stream re-reads as garbage ranges). An honest image (the fixture
//! emits sorted, disjoint, in-bounds entries) verifies strict; the
//! broken shapes are the fixture controls the contract names.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::DataInCodeEntry;
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Code, Options, Severity, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable (`__text` of 96 filler bytes) with the
/// named data-in-code entries (`__TEXT`-relative offsets).
fn exec_builder(entries: Vec<DataInCodeEntry>) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m30exec");
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
    b.add_data_in_code(entries);
    b
}

fn entries<const N: usize>(at: [u32; N]) -> Vec<DataInCodeEntry> {
    at.iter()
        .map(|&offset| DataInCodeEntry {
            offset,
            length: 4,
            kind: 1,
        })
        .collect()
}

// ---- the honest shape ----------------------------------------------------------

#[test]
fn a_sorted_in_bounds_stream_verifies_strict() {
    let img = exec_builder(entries([0, 8, 16]))
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the honest stream verifies strict: {:?}",
        report.issues
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.code == Code::LinkeditPayload),
        "no linkedit-payload findings ride the honest shape: {:?}",
        report.issues
    );
}

// ---- the broken shapes (the fixture controls) ------------------------------------

#[test]
fn an_unsorted_stream_is_an_error() {
    let img = exec_builder(entries([16, 8, 0]))
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::LinkeditPayload
            && i.severity == Severity::Error
            && i.message.contains("sorted")),
        "the unsorted stream names the sort contract: {:?}",
        report.issues
    );
}

#[test]
fn an_overlapping_stream_is_an_error() {
    // Sorted, but the second range starts inside the first one's bytes.
    let img = exec_builder(vec![
        DataInCodeEntry {
            offset: 8,
            length: 8,
            kind: 1,
        },
        DataInCodeEntry {
            offset: 12,
            length: 4,
            kind: 2,
        },
    ])
    .build()
    .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::LinkeditPayload
            && i.severity == Severity::Error
            && i.message.contains("overlap")),
        "the overlapping stream names the disjointness contract: {:?}",
        report.issues
    );
}

#[test]
fn an_entry_beyond_text_warns() {
    // The M0 shape check stays: an entry past `__TEXT` is a warning
    // (strict warnings fail the gate).
    let img = exec_builder(entries([96]))
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.code == Code::LinkeditPayload
            && i.severity == Severity::Warning
            && i.message.contains("beyond __TEXT")),
        "the beyond-__TEXT entry keeps its M0 warning: {:?}",
        report.issues
    );
    assert!(
        !report.is_ok(&opts()),
        "strict warnings fail the gate on the warning"
    );
}
