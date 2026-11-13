//! M22 — the verifier's environment contract: `LC_DYLD_ENVIRONMENT` is
//! the loader-configuration command dyld reads from the main
//! executable, so a configured executable verifies strict exactly like
//! a plain one, and the hand-broken shapes are named — an environment
//! command off an executable (inert there: a warning), a variable dyld
//! would ignore (not `DYLD_`-prefixed), an empty variable, a pair
//! missing its `=`, a duplicate variable, a stray `lc_str` offset, an
//! undersized command, an unterminated pair.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{
    LC_DYLD_ENVIRONMENT, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable fixture with the named env pairs.
fn exec_builder(envs: &[&str]) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m22exec");
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
    for pair in envs {
        b.add_dyld_env(pair);
    }
    b
}

/// A minimal legal dylib fixture (the shape the command is inert on).
fn dylib_builder(envs: &[&str]) -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm22.dylib", "m22");
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
        name: "_m22_init".into(),
        section_index: 0,
    });
    for pair in envs {
        b.add_dyld_env(pair);
    }
    b
}

/// The first environment command's offset in the image.
fn env_offset(image: &[u8]) -> usize {
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
        if cmd.hdr().0 == LC_DYLD_ENVIRONMENT {
            at = Some(cmd.offset);
        }
    }
    at.expect("LC_DYLD_ENVIRONMENT present")
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn a_configured_executable_verifies_strict() {
    let img = exec_builder(&["DYLD_PRINT_LIBRARIES=1", "DYLD_PRINT_RPATHS=1"])
        .build()
        .expect("the env fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the environment commands verify like the default: {:?}",
        report.issues
    );
}

// ---- the broken shapes -------------------------------------------------------

#[test]
fn an_env_command_off_an_executable_is_named() {
    // dyld reads the command from the main executable only — on a dylib
    // it is inert, so the finding is a warning (strict fails on it).
    let img = dylib_builder(&["DYLD_PRINT_LIBRARIES=1"])
        .build()
        .expect("the dylib fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("LC_DYLD_ENVIRONMENT")),
        "the placement finding names the command: {:?}",
        report.issues
    );
    assert!(
        !report.is_ok(&opts()),
        "strict fails on the inert placement"
    );
}

#[test]
fn a_variable_dyld_would_ignore_is_named() {
    // Anything not `DYLD_`-prefixed is ignored by the loader — the
    // command would be a silently dropped knob.
    let img = exec_builder(&["PATH=/bin"]).build().expect("builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("DYLD_")
                && matches!(i.severity, pgr_verify::Severity::Error)),
        "the non-DYLD_ variable is an error: {:?}",
        report.issues
    );
}

#[test]
fn an_empty_variable_and_a_missing_separator_are_named() {
    for (pair, needle) in [("DYLD_=x", "variable"), ("DYLD_PRINT_LIBRARIES", "=")] {
        let img = exec_builder(&[pair]).build().expect("builds");
        let report = verify(&img.bytes, &opts());
        assert!(
            report.issues.iter().any(|i| i.message.contains(needle)),
            "the broken pair {pair:?} is named (needle {needle:?}): {:?}",
            report.issues
        );
    }
}

#[test]
fn a_duplicate_variable_is_named() {
    let img = exec_builder(&["DYLD_PRINT_LIBRARIES=1", "DYLD_PRINT_LIBRARIES=0"])
        .build()
        .expect("builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("duplicate")),
        "the duplicate variable is named: {:?}",
        report.issues
    );
}

#[test]
fn a_stray_lc_str_offset_is_named() {
    let mut img = exec_builder(&["DYLD_PRINT_LIBRARIES=1"])
        .build()
        .expect("builds");
    let at = env_offset(&img.bytes);
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
    let mut img = exec_builder(&["DYLD_PRINT_LIBRARIES=1"])
        .build()
        .expect("builds");
    let at = env_offset(&img.bytes);
    img.bytes[at + 4..at + 8].copy_from_slice(&8u32.to_le_bytes());
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| i.message.contains("cmdsize")),
        "the undersized command is named: {:?}",
        report.issues
    );
}

#[test]
fn an_unterminated_pair_is_named() {
    let mut img = exec_builder(&["DYLD_PRINT_LIBRARIES=1"])
        .build()
        .expect("builds");
    let at = env_offset(&img.bytes);
    let cmdsize = u32::from_le_bytes(img.bytes[at + 4..at + 8].try_into().expect("cmdsize"));
    let tail = &mut img.bytes[at + 12..at + cmdsize as usize];
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .expect("the pair terminates");
    for b in &mut tail[end..] {
        *b = b'X';
    }
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.message.contains("NUL-terminated")),
        "the unterminated pair is named: {:?}",
        report.issues
    );
}
