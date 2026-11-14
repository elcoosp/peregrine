//! M29 — the verifier's header-region contract: a segment-bearing
//! image's sections start *after* the header and its load commands
//! (offset ≥ 32 + `sizeofcmds` — both readable from the image bytes),
//! the invariant a padded `-headerpad` reservation grows honestly and a
//! hand-built image can break. An honest padded image (the fixture
//! reserves the named floor before the first section) verifies strict;
//! the overlapping shape is the fixture control the contract names.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable with the named header-region floor (the
/// fixture's packing reserves the floor before the first section — the
/// same decision the layout plans).
fn exec_builder(header_pad: Option<u64>) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m29exec");
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
    b.set_header_pad(header_pad);
    b
}

// ---- the invariant -------------------------------------------------------------

#[test]
fn a_padded_image_verifies_strict() {
    let img = exec_builder(Some(0x2000))
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the padded reservation verifies like the natural one: {:?}",
        report.issues
    );
}

#[test]
fn the_natural_image_verifies_strict() {
    let img = exec_builder(None).build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the pre-M29 shape verifies strict: {:?}",
        report.issues
    );
}

// ---- the broken shape (the fixture control) --------------------------------------

#[test]
fn a_section_inside_the_header_region_is_named() {
    let img = exec_builder(None).build().expect("the fixture builds");
    let bytes = img.bytes.as_slice();
    let header = pgr_format::MachHeader64::parse(bytes).expect("the image parses");
    // Corrupt the recorded file offset of `__TEXT,__text` to land inside
    // the header region (36 — inside the load commands): the shape a
    // hand-built image can carry.
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut broken = img.bytes.clone();
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if cmd.kind != pgr_format::LoadCommandKind::Segment64 {
            continue;
        }
        let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("parses");
        if seg.name() != Ok("__TEXT") {
            continue;
        }
        let base = cmd.offset + pgr_format::SegmentCommand64::SIZE;
        for i in 0..seg.nsects as usize {
            let at = base + i * 80;
            let name = &broken[at..at + 16];
            let trimmed = &name[..name.iter().position(|&b| b == 0).unwrap_or(16)];
            if trimmed == b"__text" {
                broken[at + 48..at + 52].copy_from_slice(&36u32.to_le_bytes());
            }
        }
    }
    let report = verify(&broken, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("header region")),
        "the overlapping section is named: {:?}",
        report.issues
    );
    assert!(!report.is_ok(&opts()), "strict fails on the broken shape");
}
