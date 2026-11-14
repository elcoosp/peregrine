//! M26 — the verifier's loader-path contract: `LC_LOAD_DYLINKER` is
//! the command the kernel execs as the image's dynamic loader, so a
//! configured executable verifies strict exactly like the
//! `/usr/lib/dyld` default, and the hand-broken shapes are named — a
//! command off an executable (an object: an error; a dylib or a
//! bundle: inert, a warning), a second loader command (the kernel
//! execs one loader), an empty name, a relative path, a stray `lc_str`
//! offset, an undersized command, an unterminated name.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable fixture with the named loader path.
fn exec_builder(loader: Option<&str>) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m26exec");
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
    if let Some(path) = loader {
        b.set_loader_path(path);
    }
    b
}

/// A minimal legal dylib fixture (the shape the command is inert on).
fn dylib_builder() -> ImageBuilder {
    use pgr_fixtures::SymbolSpec;
    let mut b = ImageBuilder::dylib("@rpath/libm26.dylib", "m26");
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
        name: "_m26_init".into(),
        section_index: 0,
    });
    b
}

/// The first `LC_LOAD_DYLINKER` command's offset in the image.
fn loader_offset(image: &[u8]) -> usize {
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
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylinker {
            at = Some(cmd.offset);
        }
    }
    at.expect("LC_LOAD_DYLINKER present")
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn a_configured_executable_verifies_strict() {
    let img = exec_builder(Some("/usr/local/bin/mydyld"))
        .build()
        .expect("the loader fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the named loader verifies like the default: {:?}",
        report.issues
    );
}

#[test]
fn the_default_executable_verifies_strict() {
    let img = exec_builder(None).build().expect("builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the /usr/lib/dyld default verifies strict: {:?}",
        report.issues
    );
}

// ---- the broken shapes -------------------------------------------------------

#[test]
fn a_loader_command_off_an_executable_is_named() {
    // The control: a dylib carries no LC_LOAD_DYLINKER and verifies
    // strict (the M3 contract).
    let img = dylib_builder().build().expect("the dylib fixture builds");
    assert!(
        verify(&img.bytes, &opts()).is_ok(&opts()),
        "the dylib control verifies strict"
    );
    // The broken shape: a spliced-in loader command rides a
    // non-executable image — the kernel loads a dylib itself, so the
    // command is inert there (a warning; strict fails on it).
    let header = pgr_format::MachHeader64::parse(&img.bytes).expect("the header parses");
    let sizeofcmds = header.sizeofcmds as usize;
    let hdr_size = pgr_format::MachHeader64::SIZE;
    let mut grown = Vec::with_capacity(img.bytes.len() + 32);
    grown.extend_from_slice(&img.bytes[..hdr_size + sizeofcmds]);
    grown.extend_from_slice(&[
        0x0e, 0x00, 0x00, 0x00, // LC_LOAD_DYLINKER
        16, 0, 0, 0, // cmdsize
        12, 0, 0, 0, // lc_str offset
        b'/', 0, 0, 0, // "/\0" + padding
    ]);
    grown.extend_from_slice(&img.bytes[hdr_size + sizeofcmds..]);
    let ncmds = header.ncmds + 1;
    grown[16..20].copy_from_slice(&ncmds.to_le_bytes());
    grown[20..24].copy_from_slice(&(sizeofcmds as u32 + 16).to_le_bytes());
    let report = verify(&grown, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("LC_LOAD_DYLINKER")),
        "the inert placement is named: {:?}",
        report.issues
    );
    assert!(
        !report.is_ok(&opts()),
        "strict fails on the inert placement"
    );
}

#[test]
fn an_empty_loader_name_is_named() {
    let mut img = exec_builder(Some("/usr/local/bin/mydyld"))
        .build()
        .expect("builds");
    let at = loader_offset(&img.bytes);
    // Overwrite the name's first byte with the terminator: an empty
    // name inside an otherwise well-formed command.
    img.bytes[at + 12] = 0;
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("names no loader")),
        "the empty name is named: {:?}",
        report.issues
    );
    assert!(!report.is_ok(&opts()), "strict fails on the empty name");
}

#[test]
fn a_relative_loader_path_is_named() {
    let img = exec_builder(Some("bin/dyld")).build().expect("builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("not absolute") && i.message.contains("bin/dyld")),
        "the relative path is named: {:?}",
        report.issues
    );
    assert!(!report.is_ok(&opts()), "strict fails on the relative path");
}

#[test]
fn a_second_loader_command_is_named() {
    let mut img = exec_builder(Some("/usr/local/bin/mydyld"))
        .build()
        .expect("builds");
    // Splice a second, minimal loader command ("/\0", 16 bytes) right
    // before the LC_MAIN command that follows the first loader.
    let first = loader_offset(&img.bytes);
    let first_size =
        u32::from_le_bytes(img.bytes[first + 4..first + 8].try_into().expect("cmdsize"));
    let insert_at = first + first_size as usize;
    let mut grown = Vec::with_capacity(img.bytes.len() + 16);
    grown.extend_from_slice(&img.bytes[..insert_at]);
    grown.extend_from_slice(&[
        0x0e, 0x00, 0x00, 0x00, // LC_LOAD_DYLINKER
        16, 0, 0, 0, // cmdsize
        12, 0, 0, 0, // lc_str offset
        b'/', 0, 0, 0, // "/\0" + padding
    ]);
    grown.extend_from_slice(&img.bytes[insert_at..]);
    // Fix the header's ncmds and sizeofcmds for the grown command.
    let ncmds = u32::from_le_bytes(grown[16..20].try_into().expect("ncmds")) + 1;
    grown[16..20].copy_from_slice(&ncmds.to_le_bytes());
    let sizeofcmds = u32::from_le_bytes(grown[20..24].try_into().expect("sizeofcmds")) + 16;
    grown[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    img.bytes = grown;
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("duplicate LC_LOAD_DYLINKER")),
        "the second loader is named: {:?}",
        report.issues
    );
    assert!(!report.is_ok(&opts()), "strict fails on the duplicate");
}

#[test]
fn a_stray_lc_str_offset_is_named() {
    let mut img = exec_builder(Some("/usr/local/bin/mydyld"))
        .build()
        .expect("builds");
    let at = loader_offset(&img.bytes);
    img.bytes[at + 8..at + 12].copy_from_slice(&13u32.to_le_bytes());
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.message.contains("lc_str")),
        "the stray offset is named: {:?}",
        report.issues
    );
}

#[test]
fn an_undersized_command_is_named() {
    let mut img = exec_builder(Some("/usr/local/bin/mydyld"))
        .build()
        .expect("builds");
    let at = loader_offset(&img.bytes);
    img.bytes[at + 4..at + 8].copy_from_slice(&10u32.to_le_bytes());
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.message.contains("cmdsize")),
        "the undersized command is named: {:?}",
        report.issues
    );
}

#[test]
fn an_unterminated_name_is_named() {
    let mut img = exec_builder(Some("/usr/local/bin/mydyld"))
        .build()
        .expect("builds");
    let at = loader_offset(&img.bytes);
    let cmdsize =
        u32::from_le_bytes(img.bytes[at + 4..at + 8].try_into().expect("cmdsize")) as usize;
    // Fill the name region's final NUL: the string runs to the command
    // edge with no terminator (the alignment padding is zeros, so
    // overwrite the whole tail including the padding).
    img.bytes[at + 12..at + cmdsize].fill(b'x');
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("NUL-terminated")),
        "the unterminated name is named: {:?}",
        report.issues
    );
}
