//! M10 rung 3, slice 2 — the verifier reads the encoding floor: an
//! image that carries `LC_DYLD_CHAINED_FIXUPS` while its declared
//! deployment target sits below the platform's chained-fixups floor
//! cannot load on that target's dyld, so the build-version gate names
//! it (`fixups_floor`, the fix riding the message). Above the floor the
//! chained words are contract-clean, and an image *without* chained
//! fixups is silent at any target — classic streams below the floor
//! are the contract, not a violation. The fixtures are born at their
//! build versions through the builder's platform knob (no post-build
//! repatching), so the ad-hoc signature hashes stay live and the
//! strict gate runs with the recompute on.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler};
use pgr_format::consts::{
    PLATFORM_IOS, PLATFORM_MACOS, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{Code, Options, Severity, verify};

fn strict() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

fn text_segment(bytes_len: usize) -> SegmentSpec {
    SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, bytes_len),
            relocs: Vec::new(),
        }],
    }
}

fn data_const_segment() -> SegmentSpec {
    SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    }
}

/// A chained-fixup executable born at `(platform, minos, sdk)`: one
/// `LC_LOAD_DYLIB` + a `__got` bind slot, so the image carries
/// `LC_DYLD_CHAINED_FIXUPS` by construction.
fn chained_exec(platform: u32, minos: u32, sdk: u32) -> Vec<u8> {
    let mut b = ImageBuilder::executable("floor-gate");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 0,
    }]);
    b.set_entry(0x40);
    b.set_build_version(platform, minos, sdk);
    b.build().expect("the floor-gate fixture builds").bytes
}

/// An executable with no fixups at all (no dylibs, no `__got`): no
/// `LC_DYLD_CHAINED_FIXUPS` by construction.
fn plain_exec(platform: u32, minos: u32, sdk: u32) -> Vec<u8> {
    let mut b = ImageBuilder::executable("no-fixups");
    b.add_segment(text_segment(96));
    b.set_entry(0x40);
    b.set_build_version(platform, minos, sdk);
    b.build().expect("the no-fixups fixture builds").bytes
}

#[test]
fn below_floor_chained_fixups_are_a_named_error() {
    // iOS 14.0 sits under the 15.0 floor; the image carries chained words.
    let bytes = chained_exec(PLATFORM_IOS, 0x000E_0000, 0x0010_0000);
    let opts = strict();
    let report = verify(&bytes, &opts);
    assert!(
        !report.is_ok(&opts),
        "below-floor chained fixups must fail strict: {:#?}",
        report.issues
    );
    let floor_issue = report
        .issues
        .iter()
        .find(|i| i.code == Code::FixupsFloor)
        .expect("the gate names itself fixups_floor");
    assert_eq!(floor_issue.severity, Severity::Error);
    assert!(
        floor_issue.message.contains("14.0.0") && floor_issue.message.contains("15.0.0"),
        "the message names the target and the floor: {}",
        floor_issue.message
    );
    assert!(
        floor_issue.message.contains("-no_fixup_chains"),
        "the message carries the fix, not just the verdict: {}",
        floor_issue.message
    );
}

#[test]
fn at_floor_chained_fixups_verify_strict() {
    // iOS 15.0 / SDK 17.0 — the rung-2 matrix row, born (not repatched).
    let bytes = chained_exec(PLATFORM_IOS, 0x000F_0000, 0x0011_0000);
    let opts = strict();
    let report = verify(&bytes, &opts);
    assert!(
        report.is_ok(&opts) && report.issues.is_empty(),
        "at-floor chained fixups verify clean: {:#?}",
        report.issues
    );
}

#[test]
fn macos_control_verifies_strict_with_live_hashes() {
    // The builder's historical default row (macOS 12.0 / 14.4), pinned
    // through the knob — with the hashes computed over the final bytes,
    // the strict gate runs with the recompute ON (the rung-2 repatch
    // path had to skip it).
    let bytes = chained_exec(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    let opts = strict();
    let report = verify(&bytes, &opts);
    assert!(
        report.is_ok(&opts) && report.issues.is_empty(),
        "macos control must verify strict with live hashes: {:#?}",
        report.issues
    );
}

#[test]
fn no_chained_fixups_no_floor_gate() {
    // A below-floor image without `LC_DYLD_CHAINED_FIXUPS` is exactly
    // what the classic streams produce — the gate stays silent. (The
    // no-dylinker warning may fire; the gate must not.)
    let bytes = plain_exec(PLATFORM_IOS, 0x000E_0000, 0x0010_0000);
    let opts = strict();
    let report = verify(&bytes, &opts);
    assert!(
        report.issues.iter().all(|i| i.code != Code::FixupsFloor),
        "the gate only speaks when chained words are present: {:#?}",
        report.issues
    );
}
