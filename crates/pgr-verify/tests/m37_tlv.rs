//! M37 — the verifier's TLV contract: an image carrying thread-local
//! sections declares the load-time contract dyld keys on —
//! `MH_HAS_TLV_DESCRIPTORS` rides the header flags exactly when the
//! image carries `S_THREAD_LOCAL_*` sections, the `__thread_vars`
//! descriptors are whole 16-byte thunk/initializer pairs, and the
//! descriptors' initializers have thread-local data to point at. The
//! shapes here are built by hand — the verifier gates shapes built
//! independently of the producer (the §11 different-code-path rule;
//! the carriage is gated in pgr-core's own tests).
//!
//! Gate matrix:
//! * the honest shape (the flag, the descriptors, the data) verifies
//!   strict;
//! * the flag/section parity gates — the flag without any TLV section,
//!   TLV sections without the flag;
//! * the descriptor geometry — a descriptor section off the 16-byte
//!   stride, descriptors with no thread-local data section;
//! * the family joins the `--checks` registry and gates the broken
//!   shapes when selected alone.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_verify::{Check, CheckSet, Code, Options, Severity, verify, verify_with_checks};

use pgr_format::consts::{
    MH_HAS_TLV_DESCRIPTORS, S_THREAD_LOCAL_REGULAR, S_THREAD_LOCAL_VARIABLES,
};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// An executable carrying the named TLV sections: `data` the
/// `__thread_data` initializer bytes (present ⇒ `S_THREAD_LOCAL_REGULAR`),
/// `descriptors` the `__thread_vars` descriptor bytes (present ⇒
/// `S_THREAD_LOCAL_VARIABLES`), `flag` whether the header declares
/// `MH_HAS_TLV_DESCRIPTORS`.
fn exec_with_tlv(data: Option<Vec<u8>>, descriptors: Option<Vec<u8>>, flag: bool) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m37exec");
    let mut data_sects = vec![SectionSpec {
        name: "__text".into(),
        align_log2: 2,
        flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
        data: filler(0x37B7, 64),
        relocs: Vec::new(),
    }];
    if let Some(d) = data {
        data_sects.push(SectionSpec {
            name: "__thread_data".into(),
            align_log2: 3,
            flags: S_THREAD_LOCAL_REGULAR,
            data: d,
            relocs: Vec::new(),
        });
    }
    if let Some(v) = descriptors {
        data_sects.push(SectionSpec {
            name: "__thread_vars".into(),
            align_log2: 3,
            flags: S_THREAD_LOCAL_VARIABLES,
            data: v,
            relocs: Vec::new(),
        });
    }
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        initprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        sections: data_sects,
    });
    if flag {
        b.set_mh_flags(MH_HAS_TLV_DESCRIPTORS);
    }
    b.set_entry(0);
    b
}

fn report_of(
    data: Option<Vec<u8>>,
    descriptors: Option<Vec<u8>>,
    flag: bool,
) -> pgr_verify::Report {
    let img = exec_with_tlv(data, descriptors, flag)
        .build()
        .expect("the fixture builds");
    verify(&img.bytes, &opts())
}

fn tlv_errors(report: &pgr_verify::Report, needle: &str) -> bool {
    report
        .issues
        .iter()
        .any(|i| i.code == Code::Tlv && i.severity == Severity::Error && i.message.contains(needle))
}

// ---- the honest shapes -----------------------------------------------------

#[test]
fn an_honest_tlv_image_verifies_strict() {
    let descriptors = vec![0u8; 16];
    let data = 42u64.to_le_bytes().to_vec();
    let report = report_of(Some(data), Some(descriptors), true);
    assert!(
        report.is_ok(&opts()),
        "the honest TLV shape verifies strict: {:?}",
        report.issues
    );
    assert!(
        !report.issues.iter().any(|i| i.code == Code::Tlv),
        "no TLV findings ride the honest shape: {:?}",
        report.issues
    );
}

#[test]
fn an_image_without_tlv_verifies_strict() {
    // The flag is a TLV marker, not a defect marker: an image with no
    // thread-local surface and no flag verifies strict silently.
    let report = report_of(None, None, false);
    assert!(
        report.is_ok(&opts()),
        "the TLV-free image verifies strict: {:?}",
        report.issues
    );
}

// ---- the flag/section parity ----------------------------------------------

#[test]
fn the_flag_without_any_tlv_section_refuses() {
    let report = report_of(None, None, true);
    assert!(
        tlv_errors(&report, "declares"),
        "the flag without sections names the declaration: {:?}",
        report.issues
    );
}

#[test]
fn tlv_sections_without_the_flag_refuse() {
    let descriptors = vec![0u8; 16];
    let data = 42u64.to_le_bytes().to_vec();
    let report = report_of(Some(data), Some(descriptors), false);
    assert!(
        tlv_errors(&report, "MH_HAS_TLV_DESCRIPTORS"),
        "the missing flag names the marker: {:?}",
        report.issues
    );
}

#[test]
fn tlv_data_without_the_flag_refuses() {
    let data = 42u64.to_le_bytes().to_vec();
    let report = report_of(Some(data), None, false);
    assert!(
        tlv_errors(&report, "MH_HAS_TLV_DESCRIPTORS"),
        "data without the flag names the marker: {:?}",
        report.issues
    );
}

// ---- the descriptor geometry ----------------------------------------------

#[test]
fn a_descriptor_section_off_the_stride_refuses() {
    // 24 bytes: one whole descriptor and eight orphan bytes.
    let report = report_of(None, Some(vec![0u8; 24]), true);
    assert!(
        tlv_errors(&report, "16"),
        "the broken stride names the 16-byte descriptor: {:?}",
        report.issues
    );
}

#[test]
fn descriptors_without_thread_local_data_refuse() {
    let report = report_of(None, Some(vec![0u8; 16]), true);
    assert!(
        tlv_errors(&report, "initializer"),
        "the orphan descriptors name the missing data: {:?}",
        report.issues
    );
}

// ---- the registry ----------------------------------------------------------

#[test]
fn the_tlv_family_joins_the_registry() {
    assert_eq!(Check::Tlv.as_str(), "tlv", "the family's --checks token");
    assert_eq!(Code::Tlv.as_str(), "tlv", "the issue code");
    assert!(
        Check::ALL.contains(&Check::Tlv),
        "the family rides Check::ALL"
    );
    let set = CheckSet::parse("tlv").expect("the token parses");
    assert!(set.contains(Check::Tlv), "the token selects the family");
}

#[test]
fn the_selected_family_gates_the_broken_shape() {
    // Flag without sections, the family selected alone: the finding
    // rides the selection, and the honest shape passes it.
    let broken = exec_with_tlv(None, None, true)
        .build()
        .expect("the fixture builds");
    let set = CheckSet::parse("tlv").expect("the token parses");
    let report = verify_with_checks(&broken.bytes, &opts(), &set);
    assert!(
        tlv_errors(&report, "declares"),
        "the selected family gates the broken shape: {:?}",
        report.issues
    );
    let honest = exec_with_tlv(
        Some(42u64.to_le_bytes().to_vec()),
        Some(vec![0u8; 16]),
        true,
    )
    .build()
    .expect("the fixture builds");
    let honest_report = verify_with_checks(&honest.bytes, &opts(), &set);
    assert!(
        honest_report.is_ok(&opts()),
        "the honest shape passes the selected family: {:?}",
        honest_report.issues
    );
}

#[test]
fn the_unselected_family_stays_silent() {
    // A broken shape with the family deselected: the other checks ride,
    // no TLV finding lands (the selection contract, the M12 shape).
    let broken = exec_with_tlv(None, None, true)
        .build()
        .expect("the fixture builds");
    let set = CheckSet::parse("segments").expect("the token parses");
    let report = verify_with_checks(&broken.bytes, &opts(), &set);
    assert!(
        !report.issues.iter().any(|i| i.code == Code::Tlv),
        "the deselected family contributes nothing: {:?}",
        report.issues
    );
}
