//! M120 — the verifier's executable contract read-side: an executable's
//! identity is `LC_MAIN`, never `LC_ID_DYLIB`. The producer never writes
//! `LC_ID_DYLIB` for a non-dylib (the `-executable` override forces
//! `MH_EXECUTE`), and the `check_dylib_contract` `MH_EXECUTE` arm mirrors
//! the contract read-side on every `MH_EXECUTE` so a malformed image the
//! producer never saw still reports (the M115 read-side-backstop shape,
//! the `MH_BUNDLE` arm's twin).
//!
//! Gate matrix:
//! * an `MH_EXECUTE` carrying an `LC_ID_DYLIB` reports
//!   `Code::LoadCommandMalformed` (the gap the M120 arm closes — a dylib
//!   image whose filetype byte was patched to `MH_EXECUTE` carries the
//!   install-name command the executable contract forbids).

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    MH_DYLIB, MH_EXECUTE, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{Code, Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A dylib fixture (carries `LC_ID_DYLIB`) with its filetype byte patched
/// to `MH_EXECUTE` — the malformed shape the read-side gate catches.
fn executable_with_an_id_dylib() -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libpgr.dylib", "m120");
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
        name: "_greet".into(),
        section_index: 0,
    });
    b.set_imports_format(ImportsFormat::Plain);
    b.set_got(Vec::<SlotKind>::new());
    let img = b.build().expect("the dylib fixture builds");
    let mut bytes = img.bytes;
    // mach_header_64: magic(0), cputype(4), cpusubtype(8), filetype(12).
    assert_eq!(
        u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        MH_DYLIB,
        "the fixture is a dylib before the patch"
    );
    bytes[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
    bytes
}

#[test]
fn an_executable_carrying_an_id_dylib_reports() {
    // The `MH_EXECUTE` arm of `check_dylib_contract` refuses an
    // `LC_ID_DYLIB` on an executable (the M120 read-side backstop — the
    // `MH_BUNDLE` arm's twin, the layout's `-install_name` re-check
    // mirrored read-side).
    let bytes = executable_with_an_id_dylib();
    let report = verify(&bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == Code::LoadCommandMalformed
                && i.message.contains("LC_ID_DYLIB")
                && i.message.contains("LC_MAIN")),
        "the read-side gate reports the LC_ID_DYLIB on the MH_EXECUTE: {:?}",
        report.issues
    );
}
