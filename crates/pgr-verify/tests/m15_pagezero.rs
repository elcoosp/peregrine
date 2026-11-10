//! M15 — the verifier's generalized image-base contract: the
//! executable's `__PAGEZERO` checks stop pinning the 4 GiB constant and
//! verify the *invariant* the layout plans — vmaddr 0, no file bytes, a
//! non-zero multiple of the 16 KiB arm64 page, and `__TEXT.vmaddr` equal
//! to the pagezero's vmsize (the constant-delta base) — so a
//! `-pagezero_size` image verifies strict exactly like the default one,
//! and a hand-broken pagezero is named.
//!
//! Gate matrix:
//! * the default image verifies clean (the pre-seam contract holds
//!   bit-for-bit);
//! * a fixture-built 1 GiB-base image verifies clean (the new shape);
//! * a misaligned `__PAGEZERO` vmsize refuses with the alignment rule
//!   in the finding;
//! * a `__TEXT.vmaddr` that does not sit on the pagezero's vmsize
//!   refuses (the constant-delta gate names both sides);
//! * a zero vmsize refuses (the shape leaves `__TEXT` at address 0).

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal executable fixture (one `__TEXT` with `__text`, the
/// builder's defaults for everything else) at the given pagezero
/// (`None` = the builder default).
fn builder(pagezero: Option<u64>) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m15");
    if let Some(vmsize) = pagezero {
        b.set_pagezero(vmsize);
    }
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
    b
}

#[test]
fn the_default_image_verifies_clean() {
    let img = builder(None).build().expect("the default fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the pre-seam contract holds: {:?}",
        report.issues
    );
}

#[test]
fn a_custom_base_image_verifies_clean() {
    let img = builder(Some(0x4000_0000))
        .build()
        .expect("the custom-base fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the configured base verifies: {:?}",
        report.issues
    );
    // The map's __text sits on the base (the builder rode the knob).
    let text = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .expect("__text");
    assert_eq!(text.addr, 0x4000_0000 + text.fileoff, "the delta rides");
}

#[test]
fn a_misaligned_pagezero_is_named() {
    let img = builder(Some(0x4000_0800))
        .build()
        .expect("the misaligned fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "the broken pagezero refuses");
    assert!(
        report.issues.iter().any(|i| i.message.contains("16 KiB")),
        "the finding names the alignment rule: {:?}",
        report.issues
    );
}

#[test]
fn a_text_off_the_base_is_named() {
    // Build the custom-base image, then repatch `__TEXT.vmaddr` back to
    // the 4 GiB constant (the shape the old contract would have
    // accepted): the invariant check names both sides.
    let mut img = builder(Some(0x4000_0000))
        .build()
        .expect("the custom-base fixture builds");
    // Walk to the __TEXT LC and patch its vmaddr (at +24 in the
    // segment command) — the same site the builder writes.
    let text_vmaddr_at = {
        let header = pgr_format::MachHeader64::parse(&img.bytes).expect("the header parses");
        let mut it = pgr_format::LoadCommandIter::new(
            &img.bytes,
            pgr_format::MachHeader64::SIZE,
            header.ncmds,
            header.sizeofcmds,
        )
        .expect("the load commands walk");
        let mut found = None;
        while let Ok(Some(cmd)) = it.next_command() {
            if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
                let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the LC parses");
                if seg.name() == Ok("__TEXT") {
                    found = Some(cmd.offset + 24);
                }
            }
        }
        found.expect("__TEXT command found")
    };
    img.bytes[text_vmaddr_at..text_vmaddr_at + 8].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
    // The signature page hashes no longer match the patched bytes —
    // skip the hash recompute so the base finding is the one the gate
    // names (the signature gate is its own contract).
    let no_hash = Options {
        skip_hash_recompute: true,
        ..opts()
    };
    let report = verify(&img.bytes, &no_hash);
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("__TEXT") && i.message.contains("__PAGEZERO")),
        "the finding names both sides: {:?}",
        report.issues
    );
}

#[test]
fn a_zero_pagezero_is_named() {
    let img = builder(Some(0)).build().expect("the zero fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "the zero pagezero refuses");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("__PAGEZERO")),
        "the finding names the segment: {:?}",
        report.issues
    );
}
