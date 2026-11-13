//! M21 — the verifier's client contract: `LC_SUB_CLIENT` rides the
//! same identity block the M20 region commands do, so a
//! client-restricted dylib verifies strict exactly like a plain one,
//! and the hand-broken shapes are named — a client command off a dylib,
//! an empty or missing name, a duplicate client, a stray `lc_str`
//! offset, an undersized command.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{
    LC_SUB_CLIENT, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal dylib fixture with the named clients.
fn builder(clients: &[&str]) -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm21.dylib", "m21");
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
        name: "_m21_init".into(),
        section_index: 0,
    });
    for name in clients {
        b.add_sub_client(name);
    }
    b
}

/// An executable fixture (the shape that must refuse the clients).
fn exec_builder(clients: &[&str]) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m21exec");
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
    for name in clients {
        b.add_sub_client(name);
    }
    b
}

/// Overwrites one client command's `lc_str` offset and `cmdsize` in
/// place (the broken shapes the byte-level gates build).
fn rewire(image: &mut [u8], new_offset: u32, new_cmdsize: u32) {
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
        if cmd.hdr().0 == LC_SUB_CLIENT {
            at = Some(cmd.offset);
        }
    }
    let at = at.expect("LC_SUB_CLIENT present");
    image[at + 4..at + 8].copy_from_slice(&new_cmdsize.to_le_bytes());
    image[at + 8..at + 12].copy_from_slice(&new_offset.to_le_bytes());
}

/// Un-terminates the first client command's name: every byte from the
/// name's terminator to the command's end becomes non-NUL, so the name
/// no longer ends inside the command (the zero pad bytes would
/// otherwise still terminate it).
fn strip_terminator(image: &mut [u8]) {
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
        if cmd.hdr().0 == LC_SUB_CLIENT {
            at = Some(cmd.offset);
        }
    }
    let at = at.expect("LC_SUB_CLIENT present");
    let cmdsize = u32::from_le_bytes(image[at + 4..at + 8].try_into().expect("cmdsize"));
    let tail = &mut image[at + 12..at + cmdsize as usize];
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .expect("the name terminates");
    for b in &mut tail[end..] {
        *b = b'X';
    }
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn a_client_restricted_dylib_verifies_strict() {
    let img = builder(&["client.app", "/usr/bin/tool"])
        .build()
        .expect("the client fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the clients verify like the default: {:?}",
        report.issues
    );
}

// ---- the broken shapes -------------------------------------------------------

#[test]
fn a_client_command_off_a_dylib_is_named() {
    let img = exec_builder(&["client.app"])
        .build()
        .expect("the fixture builds (the verifier names the shape)");
    let report = verify(&img.bytes, &opts());
    assert!(
        !report.is_ok(&opts()),
        "the clients off a dylib are an error"
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("LC_SUB_CLIENT") && i.message.contains("dylib")),
        "the finding names the command and the shape that cannot carry it: {:?}",
        report.issues
    );
}

#[test]
fn an_empty_client_name_is_named() {
    let mut b = builder(&["client.app"]);
    b.add_sub_client("");
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
fn a_duplicate_client_is_named() {
    let img = builder(&["client.app", "client.app"])
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "a duplicate client is an error");
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("client.app")),
        "the finding names the client: {:?}",
        report.issues
    );
}

#[test]
fn a_stray_lc_str_offset_is_malformed() {
    let mut img = builder(&["client.app"])
        .build()
        .expect("the fixture builds");
    // The name's lc_str offset moves off the command's fixed part (12).
    rewire(&mut img.bytes, 13, 24);
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "a stray offset is an error");
}

#[test]
fn an_undersized_command_is_malformed() {
    let mut img = builder(&["client.app"])
        .build()
        .expect("the fixture builds");
    // cmdsize shrinks under the 12-byte fixed part (the header rides 8).
    rewire(&mut img.bytes, 12, 8);
    let report = verify(&img.bytes, &opts());
    assert!(!report.is_ok(&opts()), "an undersized command is an error");
}

#[test]
fn an_unterminated_client_name_is_malformed() {
    let mut img = builder(&["client.app"])
        .build()
        .expect("the fixture builds");
    strip_terminator(&mut img.bytes);
    let report = verify(&img.bytes, &opts());
    assert!(
        !report.is_ok(&opts()),
        "a name with no terminator inside the command is an error"
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("NUL-terminated")),
        "the finding names the shape: {:?}",
        report.issues
    );
}
