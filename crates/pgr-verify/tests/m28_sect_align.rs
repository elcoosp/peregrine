//! M28 — the verifier's section-congruence contract: a section's
//! address is congruent to its own declared alignment (`addr % (1 <<
//! align) == 0`) — the invariant a `-sectalign` floor raises the bar
//! for, and the shape a hand-built or corrupted image can break. An
//! honest raised-alignment image (the fixture places the section on the
//! raised boundary) verifies strict; the misplaced shape is the fixture
//! control the contract names.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable whose `__DATA,__data` carries the named
/// alignment exponent (the packing math keeps every section congruent
/// to its own exponent — the invariant the verifier gates).
fn exec_builder(data_align: u32) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m28exec");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR,
            data: filler(0x5AA5, 96),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![SectionSpec {
            name: "__data".into(),
            align_log2: data_align,
            flags: S_REGULAR,
            data: filler(0xA5A5, 8),
            relocs: Vec::new(),
        }],
    });
    b.set_entry(0);
    b
}

// ---- the invariant -------------------------------------------------------------

#[test]
fn a_raised_alignment_verifies_strict() {
    let img = exec_builder(14).build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the raised floor stays congruent: {:?}",
        report.issues
    );
}

#[test]
fn the_default_alignment_verifies_strict() {
    let img = exec_builder(3).build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the pre-M28 shape verifies strict: {:?}",
        report.issues
    );
}

// ---- the broken shape (the fixture control) --------------------------------------

#[test]
fn a_misaligned_section_is_named() {
    let img = exec_builder(3).build().expect("the fixture builds");
    // Corrupt the recorded address of `__DATA,__data` (+1 byte): the
    // address stops being congruent to the section's own 8-byte
    // alignment — the shape a hand-built image can carry.
    let bytes = img.bytes.as_slice();
    let header = pgr_format::MachHeader64::parse(bytes).expect("the image parses");
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
        if seg.name() != Ok("__DATA") {
            continue;
        }
        let base = cmd.offset + pgr_format::SegmentCommand64::SIZE;
        for i in 0..seg.nsects as usize {
            let at = base + i * 80;
            let name = &broken[at..at + 16];
            let trimmed = &name[..name.iter().position(|&b| b == 0).unwrap_or(16)];
            if trimmed == b"__data" {
                let addr_at = at + 32;
                let addr =
                    u64::from_le_bytes(broken[addr_at..addr_at + 8].try_into().expect("addr"));
                broken[addr_at..addr_at + 8].copy_from_slice(&(addr + 1).to_le_bytes());
            }
        }
    }
    let report = verify(&broken, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("__data") && i.message.contains("not congruent")),
        "the misplaced section is named: {:?}",
        report.issues
    );
    assert!(!report.is_ok(&opts()), "strict fails on the broken shape");
}
