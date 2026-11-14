//! M32 — the verifier's UUID contract reads the decision, not a
//! constant: the M0 absence warning ("no LC_UUID") named Peregrine's
//! always-carried default, which the M32 suppression unnames — an
//! image without `LC_UUID` is a *decision* (the `-no_uuid` link), not
//! a defect, so it verifies strict. The carried command's payload is
//! opaque either way (the derived bytes are the emit's business), so
//! both shapes — the carrying default and the named suppression — are
//! clean.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Code, Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable (`__text` of 96 filler bytes), built
/// with or without the `LC_UUID` command.
fn exec_builder(no_uuid: bool) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m32exec");
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
    if no_uuid {
        b.set_no_uuid();
    }
    b
}

// ---- the two honest shapes ------------------------------------------------------

#[test]
fn the_carried_uuid_verifies_strict() {
    let img = exec_builder(false).build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the carrying image verifies strict: {:?}",
        report.issues
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.code == Code::LinkeditPayload),
        "no linkedit-payload findings ride the carried command: {:?}",
        report.issues
    );
}

#[test]
fn the_suppressed_uuid_verifies_strict() {
    // Pre-M32 this image raised the absence warning (an always-carried
    // default was named); M32 names the absence — the suppression
    // decision — and the image verifies strict like any other.
    let img = exec_builder(true).build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the suppressed image verifies strict: {:?}",
        report.issues
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.code == Code::LinkeditPayload),
        "no linkedit-payload findings ride the suppression decision: {:?}",
        report.issues
    );
}
