//! M17 — the verifier's protection contract: the segment
//! `maxprot`/`initprot` checks keep verifying the *invariants* — init
//! within max, no writable+executable initial mapping, and a
//! protection-free `__PAGEZERO` — so a `-segprot` image verifies strict
//! exactly like the default one, and a hand-broken protection table is
//! named (the read-side half of the seam; the fixture knob writes the
//! protections during assembly, so the signature rides the final
//! bytes).

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_NONE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal executable fixture (one `__TEXT` with `__text`, plus an
/// empty `__DATA_CONST` so the house table has a second row to name).
fn builder() -> ImageBuilder {
    let mut b = ImageBuilder::executable("m17");
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
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    b
}

#[test]
fn the_default_image_verifies_clean() {
    let img = builder().build().expect("the default fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the pre-seam contract holds: {:?}",
        report.issues
    );
}

#[test]
fn a_custom_protection_image_verifies_clean() {
    // The M17 shape: `__DATA_CONST` rides read-only after fixups (the
    // classic post-rebase decision) under a writable ceiling.
    let mut b = builder();
    b.set_segment_prot("__DATA_CONST", VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ);
    let img = b.build().expect("the custom fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the named protections verify: {:?}",
        report.issues
    );
}

#[test]
fn init_beyond_max_is_named() {
    let mut b = builder();
    b.set_segment_prot("__DATA_CONST", VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE);
    let img = b.build().expect("the broken fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "the broken table refuses");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("initprot has bits outside maxprot")),
        "the finding names the kernel rule: {:?}",
        report.issues
    );
}

#[test]
fn a_writable_executable_mapping_is_named() {
    let mut b = builder();
    b.set_segment_prot(
        "__TEXT",
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
    );
    let img = b.build().expect("the broken fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "the W+X mapping refuses");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.to_lowercase().contains("writable")
                && i.message.to_lowercase().contains("executable")),
        "the finding names the W^X contract: {:?}",
        report.issues
    );
}

#[test]
fn a_protected_pagezero_is_named() {
    // `__PAGEZERO` is the unmapped prefix: it carries no protections by
    // contract (the M15 base contract checks the addresses; this is the
    // protection half).
    let mut b = builder();
    b.set_segment_prot("__PAGEZERO", VM_PROT_READ, VM_PROT_READ);
    let img = b.build().expect("the broken fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "the protected __PAGEZERO refuses");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("__PAGEZERO") && i.message.contains("protection")),
        "the finding names the unmapped-prefix rule: {:?}",
        report.issues
    );
}

#[test]
fn vm_prot_none_stays_the_pagezero_default() {
    // The knob is an override, not a requirement: without it the
    // builder writes the house `VM_PROT_NONE` pair on `__PAGEZERO`.
    let img = builder().build().expect("the default fixture builds");
    let header = pgr_format::MachHeader64::parse(&img.bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &img.bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Ok(Some(cmd)) = it.next_command().map_err(|e| panic!("{e}")) {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the command parses");
            if seg.name().expect("utf8") == "__PAGEZERO" {
                assert_eq!(seg.maxprot, VM_PROT_NONE);
                assert_eq!(seg.initprot, VM_PROT_NONE);
                return;
            }
        }
    }
    panic!("__PAGEZERO is in the image");
}
