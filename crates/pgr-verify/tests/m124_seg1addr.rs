//! M124 — the verifier's first-segment-base contract: the segment
//! congruence gate validates the *shifted shape* the `-seg1addr` knob
//! plans. For an executable the override names the `__PAGEZERO` vmsize
//! *and* the `__TEXT` vmaddr at once (the constant-delta contract
//! `vmaddr = fileoff + base` — the same base resolver `-pagezero_size`
//! reads, one knob over), so a `-seg1addr` image verifies strict
//! exactly like the default one, and a hand-broken base (the two words
//! disagreeing) is named.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal executable fixture (one `__TEXT` with `__text`) with the
/// given named first-segment base. The builder's `set_pagezero` writes
/// the `__PAGEZERO` vmsize and the `__TEXT` vmaddr at once — the shape
/// `-seg1addr` plans for an executable (the constant-delta resolver
/// reads either knob the same way).
fn builder(first_segment_base: Option<u64>) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m124");
    if let Some(bytes) = first_segment_base {
        b.set_pagezero(bytes);
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
    b.add_symbol(SymbolSpec::Defined {
        name: "_m124_main".into(),
        section_index: 0,
    });
    b
}

/// The byte offset of a named segment's `vmaddr` field inside the file.
fn segment_vmaddr_at(image: &[u8], seg_name: &str) -> usize {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut found = None;
    while let Ok(Some(cmd)) = it.next_command().map_err(|e| panic!("{e}")) {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the LC parses");
            if seg.name() == Ok(seg_name) {
                found = Some(cmd.offset + 24);
            }
        }
    }
    found.unwrap_or_else(|| panic!("{seg_name} command found"))
}

// ---- the invariant ------------------------------------------------------------

#[test]
fn a_named_base_executable_verifies_strict() {
    // The shifted shape: `__PAGEZERO.vmsize` and `__TEXT.vmaddr` both
    // at the named 1 GiB floor — the constant-delta contract holds, so
    // the strict verifier accepts the shape `-seg1addr` plans.
    let img = builder(Some(0x4000_0000))
        .build()
        .expect("the named-base fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the named-base executable verifies like the default: {:?}",
        report.issues
    );
}

#[test]
fn the_default_floor_verifies_strict() {
    let img = builder(None).build().expect("the default fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the pre-M124 4 GiB floor holds: {:?}",
        report.issues
    );
}

#[test]
fn a_text_vmaddr_drifted_off_the_pagezero_floor_is_named() {
    // The hostile fixture: build the shifted shape, then patch
    // `__TEXT.vmaddr` to a different floor — `__PAGEZERO.vmsize` and
    // `__TEXT.vmaddr` disagree, the constant-delta contract breaks,
    // and the segment congruence gate names the drift (the read-side
    // backstop that validates the shifted shape `-seg1addr` plans).
    let mut shifted = builder(Some(0x4000_0000))
        .build()
        .expect(" the shifted fixture builds");
    let at = segment_vmaddr_at(&shifted.bytes, "__TEXT");
    // __TEXT.vmaddr was 0x4000_0000 (the named floor); drift it to
    // 0x8000_0000 — congruent (a 16 KiB multiple), but off the
    // `__PAGEZERO` vmsize the constant-delta contract ties it to.
    let drifted = 0x8000_0000u64;
    shifted.bytes[at..at + 8].copy_from_slice(&drifted.to_le_bytes());
    // The signature page hashes no longer match the patched bytes —
    // skip the hash recompute so the segment finding is the one the
    // gate names (the signature gate is its own contract).
    let no_hash = Options {
        skip_hash_recompute: true,
        ..opts()
    };
    let report = verify(&shifted.bytes, &no_hash);
    assert!(!report.is_ok(&no_hash), "the drifted __TEXT.vmaddr refuses");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("__TEXT") && i.message.contains("__PAGEZERO")),
        "the finding names the drifted segment and the floor it broke: {:?}",
        report.issues
    );
}
