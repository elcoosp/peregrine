//! M19 — the verifier's image-base contract: the dylib/bundle
//! `__TEXT.vmaddr` check verifies the *invariant* the layout plans —
//! the constant-delta base is a multiple of the 16 KiB arm64 page and
//! every segment shares it (the M3 zero default being the base-free
//! shape) — so a `-image_base` image verifies strict exactly like the
//! default one, and a hand-broken base is named.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal non-executable fixture (one `__TEXT` with `__text`) with
/// the given named image base.
fn builder(image_base: Option<u64>) -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm19.dylib", "m19");
    if let Some(bytes) = image_base {
        b.set_image_base(bytes);
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
        name: "_m19_init".into(),
        section_index: 0,
    });
    b
}

/// The byte offset of a named segment's `vmaddr` field inside the file
/// (the same site the builder writes).
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
fn a_named_base_dylib_verifies_strict() {
    let img = builder(Some(0x80000))
        .build()
        .expect("the named-base fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the named base verifies like the default: {:?}",
        report.issues
    );
    // The named base is the __TEXT vmaddr (the constant-delta contract);
    // the builder's own assembly gates carried it.
}

#[test]
fn the_zero_default_verifies_strict() {
    let img = builder(None).build().expect("the default fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the M3 base-free contract holds: {:?}",
        report.issues
    );
}

#[test]
fn a_misaligned_base_is_named() {
    let img = builder(Some(0x80008))
        .build()
        .expect("the misaligned fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "the broken base refuses");
    assert!(
        report.issues.iter().any(|i| i.message.contains("16 KiB")),
        "the finding names the alignment rule: {:?}",
        report.issues
    );
}

#[test]
fn a_segment_off_the_shared_base_is_named() {
    // Build the named-base image with two mapped segments, then shift
    // one segment's vmaddr by a whole page: congruence holds per
    // segment, but the shared constant delta is broken — the
    // delta-consistency gate names the drifted side (the segment and the
    // base it drifted from).
    let mut b = ImageBuilder::dylib("@rpath/libm19.dylib", "m19-two");
    b.set_image_base(0x80000);
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
        name: "__DATA".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![SectionSpec {
            name: "__data".into(),
            align_log2: 2,
            flags: S_REGULAR,
            data: filler(0x5A5A, 32),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_m19_init".into(),
        section_index: 0,
    });
    let mut two = b.build().expect("the two-segment fixture builds");
    let at = segment_vmaddr_at(&two.bytes, "__DATA");
    // __DATA plans at fileoff + the named base (0x4000 + 0x80000); the
    // drift is one whole page past that — congruent, not shared.
    let drifted = 0x4000u64 + 0x80000 + 0x4000;
    two.bytes[at..at + 8].copy_from_slice(&drifted.to_le_bytes());
    // The signature page hashes no longer match the patched bytes —
    // skip the hash recompute so the base finding is the one the gate
    // names (the signature gate is its own contract).
    let no_hash = Options {
        skip_hash_recompute: true,
        ..opts()
    };
    let report = verify(&two.bytes, &no_hash);
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("__DATA") && i.message.contains("constant-delta")),
        "the finding names the drifted segment: {:?}",
        report.issues
    );
}
