//! M18 — the verifier's stack-reserve contract: the `LC_MAIN.stacksize`
//! check verifies the *invariant* the layout plans — a reserve is a
//! multiple of the 16 KiB arm64 page (the kernel maps the stack in
//! pages; the zero default means "dyld's own default") — so a
//! `-stack_size` image verifies strict exactly like the default one,
//! and a hand-broken reserve is named.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal executable fixture (one `__TEXT` with `__text`; the
/// builder's defaults for everything else) with the given stack
/// reserve.
fn builder(stack_size: Option<u64>) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m18");
    if let Some(bytes) = stack_size {
        b.set_stack_size(bytes);
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
fn a_named_reserve_image_verifies_clean() {
    let img = builder(Some(0x100_0000))
        .build()
        .expect("the reserved fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the named reserve verifies: {:?}",
        report.issues
    );
    // The reserve rides the image's LC_MAIN (the builder's knob wrote
    // it during assembly).
    let header = pgr_format::MachHeader64::parse(&img.bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        &img.bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Ok(Some(cmd)) = it.next_command().map_err(|e| panic!("{e}")) {
        if cmd.kind == pgr_format::LoadCommandKind::Main {
            let ep = pgr_format::EntryPointCommand::parse(cmd.bytes).expect("the command parses");
            assert_eq!(ep.stacksize, 0x100_0000, "the reserve landed");
            return;
        }
    }
    panic!("an executable carries LC_MAIN");
}

#[test]
fn a_misaligned_reserve_is_named() {
    let img = builder(Some(0x3000))
        .build()
        .expect("the broken fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "the broken reserve refuses");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("16 KiB") && i.message.contains("stacksize")),
        "the finding names the page rule: {:?}",
        report.issues
    );
}
