//! M20 — the verifier's umbrella-region contract: the
//! `LC_SUB_UMBRELLA` / `LC_SUB_LIBRARY` commands are a dylib's identity
//! block, so an umbrella dylib verifies strict exactly like a plain
//! one, and the hand-broken shapes are named — a sub command off a
//! dylib, an empty or missing name, a duplicate member, a stray `lc_str`
//! offset, an undersized command.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{
    LC_SUB_LIBRARY, LC_SUB_UMBRELLA, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE,
    VM_PROT_READ,
};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal dylib fixture with the named sub members.
fn builder(members: &[(&str, &str)]) -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm20.dylib", "m20");
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
        name: "_m20_init".into(),
        section_index: 0,
    });
    for (kind, name) in members {
        if *kind == "sub-umbrella" {
            b.add_sub_umbrella(name);
        } else {
            b.add_sub_library(name);
        }
    }
    b
}

/// An executable fixture (the shape that must refuse the region).
fn exec_builder(members: &[(&str, &str)]) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m20exec");
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
    for (kind, name) in members {
        if *kind == "sub-umbrella" {
            b.add_sub_umbrella(name);
        } else {
            b.add_sub_library(name);
        }
    }
    b
}

/// Overwrites one region command's `lc_str` offset and `cmdsize` in place
/// (the broken shapes the byte-level gates build).
fn rewire(image: &mut [u8], opcode: u32, new_offset: u32, new_cmdsize: u32) {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut at = None;
    while let Some(cmd) = it.next_command().expect("the chain walks") {
        if cmd.hdr().0 == opcode {
            at = Some(cmd.offset);
        }
    }
    let at = at.unwrap_or_else(|| panic!("opcode {opcode:#x} present"));
    image[at + 4..at + 8].copy_from_slice(&new_cmdsize.to_le_bytes());
    image[at + 8..at + 12].copy_from_slice(&new_offset.to_le_bytes());
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn an_umbrella_dylib_verifies_strict() {
    let img = builder(&[
        ("sub-umbrella", "libsub.dylib"),
        ("sub-library", "liblegacy.dylib"),
    ])
    .build()
    .expect("the umbrella fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the region verifies like the default: {:?}",
        report.issues
    );
}

// ---- the broken shapes -------------------------------------------------------

#[test]
fn a_sub_command_off_a_dylib_is_named() {
    let img = exec_builder(&[("sub-umbrella", "libsub.dylib")])
        .build()
        .expect("the fixture builds (the verifier names the shape)");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "the region off a dylib is an error");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("LC_SUB_UMBRELLA") && i.message.contains("dylib")),
        "the finding names the command and the shape that cannot carry it: {:?}",
        report.issues
    );
}

#[test]
fn an_empty_member_name_is_named() {
    let mut b = builder(&[("sub-umbrella", "libsub.dylib")]);
    b.add_sub_umbrella("");
    let img = b.build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "an empty name is an error");
    assert!(
        report.issues.iter().any(|i| i.message.contains("is empty")),
        "the finding names the fix: {:?}",
        report.issues
    );
}

#[test]
fn a_duplicate_member_is_named() {
    let img = builder(&[
        ("sub-umbrella", "libsub.dylib"),
        ("sub-library", "libsub.dylib"),
    ])
    .build()
    .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "a duplicate member is an error");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("libsub.dylib")),
        "the finding names the member: {:?}",
        report.issues
    );
}

#[test]
fn a_stray_lc_str_offset_is_malformed() {
    let mut img = builder(&[("sub-umbrella", "libsub.dylib")])
        .build()
        .expect("the fixture builds");
    // The name's lc_str offset moves off the command's fixed part (12).
    rewire(&mut img.bytes, LC_SUB_UMBRELLA, 13, 24);
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "a stray offset is an error");
}

#[test]
fn an_undersized_command_is_malformed() {
    let mut img = builder(&[("sub-library", "liblegacy.dylib")])
        .build()
        .expect("the fixture builds");
    // cmdsize shrinks under the 12-byte fixed part (the header rides 8).
    rewire(&mut img.bytes, LC_SUB_LIBRARY, 12, 8);
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "an undersized command is an error");
}
