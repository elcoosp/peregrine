//! M10 rung 2 — the verifier's platform gate (roadmap §10.4 row M10):
//! `LC_BUILD_VERSION` is checked against the platform the linker links —
//! a known platform (macos, ios, tvos, watchos, visionos) is clean, an
//! unknown platform constant is a contract error, and an SDK older than
//! the deployment target is refused. Before the rung the verifier warned
//! on *every* non-macos image, so a legitimately-plumbed iOS image could
//! not pass `--strict`.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler};
use pgr_format::consts::{LC_BUILD_VERSION, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use pgr_verify::{Code, Options, Severity, verify};

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

fn exec_builder() -> ImageBuilder {
    let mut b = ImageBuilder::executable("platform-gate");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
        SlotKind::Rebase { target: 0x40 },
    ]);
    b.set_entry(0x40);
    b
}

/// Rewrites the `LC_BUILD_VERSION` payload (platform, minos, sdk) in an
/// already-built image — the fixture builder pins macOS, the gate must
/// see the platforms the linker now emits. The patch lands after the
/// signature was computed, so these runs skip the hash recompute.
fn repatch_build_version(bytes: &[u8], platform: u32, minos: u32, sdk: u32) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let ncmds = u32::from_le_bytes(out[16..20].try_into().unwrap());
    let mut off = 32usize;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(out[off..off + 4].try_into().unwrap());
        let size = u32::from_le_bytes(out[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == LC_BUILD_VERSION {
            out[off + 8..off + 12].copy_from_slice(&platform.to_le_bytes());
            out[off + 12..off + 16].copy_from_slice(&minos.to_le_bytes());
            out[off + 16..off + 20].copy_from_slice(&sdk.to_le_bytes());
            return out;
        }
        off += size;
    }
    panic!("fixture carries no LC_BUILD_VERSION to repatch");
}

fn strict_skip_hash() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: true,
    }
}

fn errors_of(report: &pgr_verify::Report) -> Vec<String> {
    report
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| i.message.clone())
        .collect()
}

#[test]
fn the_control_repatch_still_verifies_strict() {
    let img = exec_builder().build().unwrap();
    let bytes = repatch_build_version(&img.bytes, 1, 0x000C_0000, 0x000E_0000);
    let report = verify(&bytes, &strict_skip_hash());
    assert!(
        report.is_ok(&strict_skip_hash()),
        "macos control must verify strict: {:#?}",
        report.issues
    );
}

#[test]
fn every_linked_platform_verifies_strict() {
    // (platform, minos, sdk) at each platform's chained-fixups floor.
    let cases: [(u32, u32, u32); 4] = [
        (2, 0x000F_0000, 0x0011_0000),  // ios 15.0 / 17.0
        (3, 0x000F_0000, 0x0011_0000),  // tvos 15.0 / 17.0
        (4, 0x0008_0000, 0x000A_0000),  // watchos 8.0 / 10.0
        (11, 0x0001_0000, 0x0001_0000), // visionos 1.0 / 1.0
    ];
    let img = exec_builder().build().unwrap();
    for (platform, minos, sdk) in cases {
        let bytes = repatch_build_version(&img.bytes, platform, minos, sdk);
        let report = verify(&bytes, &strict_skip_hash());
        assert!(
            report.is_ok(&strict_skip_hash()),
            "platform {platform} must verify strict: {:#?}",
            report.issues
        );
        assert!(
            report.issues.is_empty(),
            "platform {platform} must not even warn: {:#?}",
            report.issues
        );
    }
}

#[test]
fn an_unknown_platform_constant_is_an_error() {
    let img = exec_builder().build().unwrap();
    let bytes = repatch_build_version(&img.bytes, 42, 0x000C_0000, 0x000E_0000);
    let report = verify(&bytes, &strict_skip_hash());
    let errs = errors_of(&report);
    assert!(
        errs.iter()
            .any(|m| m.contains("not a known Mach-O platform")),
        "unknown platform must be a named error: {errs:?}"
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == Code::LinkeditPayload && i.severity == Severity::Error),
        "the gate rides the LinkeditPayload code"
    );
}

#[test]
fn an_sdk_older_than_the_deployment_target_is_an_error() {
    let img = exec_builder().build().unwrap();
    let bytes = repatch_build_version(&img.bytes, 1, 0x000E_0000, 0x000C_0000);
    let report = verify(&bytes, &strict_skip_hash());
    let errs = errors_of(&report);
    assert!(
        errs.iter()
            .any(|m| m.contains("older than the deployment target")),
        "sdk < minos must be a named error: {errs:?}"
    );
}

#[test]
fn a_zero_deployment_target_still_warns() {
    let img = exec_builder().build().unwrap();
    let bytes = repatch_build_version(&img.bytes, 1, 0, 0x000E_0000);
    let report = verify(&bytes, &strict_skip_hash());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.severity == Severity::Warning
                && i.message.contains("minimum OS version is 0")),
        "the M0 zero-minos warning must survive the rung: {:#?}",
        report.issues
    );
}

/// The non-strict surface stays non-strict: warnings alone do not fail
/// `is_ok` when `strict_warnings` is off (the M0 policy, unchanged).
#[test]
fn warnings_stay_advisory_when_not_strict() {
    let img = exec_builder().build().unwrap();
    let bytes = repatch_build_version(&img.bytes, 1, 0, 0x000E_0000);
    let relaxed = Options {
        strict_warnings: false,
        skip_hash_recompute: true,
    };
    let report = verify(&bytes, &relaxed);
    assert!(
        report.is_ok(&relaxed),
        "warnings are advisory: {:#?}",
        report.issues
    );
}
