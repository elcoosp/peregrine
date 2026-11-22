//! M94 — the verifier's `init_offsets` gate: the `__TEXT,__init_offsets`
//! section dyld's initializer walk consumes must name targets the image
//! actually maps — each u32 entry is the initializer's distance from the
//! load address, and dyld's load-time check ("initializer does not point
//! within executable segment") is the contract the gate replays read-side
//! on shapes built independently of the producer (the §11
//! different-code-path rule; the transform itself is gated in pgr-core's
//! own M16 tests). The classic pointer form rides the same walk (its
//! slots are fixup words, so the raw bytes stay unread — the stride is
//! the shape the gate can honestly check), and the floor rule rides it
//! too: below the platform's chained-fixups floor no dyld consumes the
//! section, so the initializers would silently never run.
//!
//! Gate matrix:
//! * the honest shapes (the u32-offset section at the floor, the classic
//!   pointer section, no initializer surface at all) verify strict;
//! * the geometry — an offsets section off the 4-byte stride, a pointer
//!   section off the 8-byte stride;
//! * the targets — an entry outside every segment, an entry inside a
//!   segment that never gains execute;
//! * the floor — the offsets form below the platform's chained-fixups
//!   floor names the floor (the producer refuses the same premise);
//! * the family joins the `--checks` registry (`Check::ALL` in canonical
//!   order, the selection gates the broken shapes alone) and the code
//!   rides the report-JSON interchange.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_verify::{Check, CheckSet, Code, Options, Severity, verify, verify_with_checks};

use pgr_format::consts::{PLATFORM_MACOS, S_MOD_INIT_FUNC_POINTERS};

/// The executable's load address: the 4 GiB `__PAGEZERO` the arm64
/// contract fixes (TDD §3.6), where the `__TEXT` — and the mach header —
/// maps.
const LOAD_ADDR: u64 = 0x1_0000_0000;

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// Packed `LC_BUILD_VERSION` words (`X << 16 | Y << 8 | Z`).
const MINOS_AT_FLOOR: u32 = 12 << 16; // (12, 0, 0) — the macOS fixups floor
const MINOS_BELOW_FLOOR: u32 = 11 << 16; // (11, 0, 0)
const SDK_14: u32 = 14 << 16; // (14, 0, 0)

/// Builds an executable whose `__text` (64 filler bytes inside an
/// executable `__TEXT`) carries the honest code the initializer targets
/// point at, plus the named initializer surface: `offsets` rides
/// `__TEXT,__init_offsets` (`S_INIT_FUNC_OFFSETS`), `mod_init` rides the
/// classic `__DATA_CONST,__mod_init_func` (`S_MOD_INIT_FUNC_POINTERS`),
/// and `data_seg` adds an RW segment whose `__data` carries the bytes a
/// non-executable target would name. `minos` pins the deployment target
/// (the floor gate's premise).
fn exec_builder(
    offsets: Option<Vec<u8>>,
    mod_init: Option<Vec<u8>>,
    data_seg: bool,
    minos: u32,
) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m94exec");
    let mut text_sects = vec![SectionSpec {
        name: "__text".into(),
        align_log2: 2,
        flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
        data: filler(0x9401, 64),
        relocs: Vec::new(),
    }];
    if let Some(bytes) = offsets {
        text_sects.push(SectionSpec {
            name: "__init_offsets".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_INIT_FUNC_OFFSETS,
            data: bytes,
            relocs: Vec::new(),
        });
    }
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        initprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        sections: text_sects,
    });
    let mut data_sects = Vec::new();
    if let Some(bytes) = mod_init {
        data_sects.push(SectionSpec {
            name: "__mod_init_func".into(),
            align_log2: 3,
            flags: S_MOD_INIT_FUNC_POINTERS,
            data: bytes,
            relocs: Vec::new(),
        });
    }
    if data_seg {
        data_sects.push(SectionSpec {
            name: "__data".into(),
            align_log2: 3,
            flags: pgr_format::consts::S_REGULAR,
            data: filler(0x9402, 32),
            relocs: Vec::new(),
        });
    }
    if !data_sects.is_empty() {
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_WRITE,
            initprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_WRITE,
            sections: data_sects,
        });
    }
    b.set_build_version(PLATFORM_MACOS, minos, SDK_14);
    b.set_entry(0);
    b
}

/// The `__text` address the honest entries need, probed the only way a
/// fixture can know it: one build of the same layout without the offsets
/// section (the probe's `__text` precedes anything the offsets section
/// shifts, so its address is the final build's), as the load-address
/// distance the u32 form carries.
fn text_entry_offset() -> u64 {
    section_entry_offset("__text", false)
}

/// The `__data` address, for the non-executable target case.
fn data_entry_offset() -> u64 {
    section_entry_offset("__data", true)
}

/// One section's load-address distance from the probe build.
fn section_entry_offset(name: &str, data_seg: bool) -> u64 {
    let probe = exec_builder(None, None, data_seg, MINOS_AT_FLOOR)
        .build()
        .expect("the probe builds");
    let sect = probe
        .map
        .sections
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("the probe carries {name}"));
    sect.addr - LOAD_ADDR
}

/// The probe's addresses as the u32 LE entries the offsets form carries.
fn offsets_bytes(entries: &[u64]) -> Vec<u8> {
    entries
        .iter()
        .flat_map(|e| {
            u32::try_from(*e)
                .expect("fixture offsets fit u32")
                .to_le_bytes()
        })
        .collect()
}

fn verify_of(b: &ImageBuilder) -> pgr_verify::Report {
    let img = b.build().expect("the fixture builds");
    verify(&img.bytes, &opts())
}

fn issues_with_code<'a>(report: &'a pgr_verify::Report, code: &Code) -> Vec<&'a pgr_verify::Issue> {
    report.issues.iter().filter(|i| i.code == *code).collect()
}

// --------------------------------------------------------------- honest

#[test]
fn the_honest_offsets_section_verifies_strict() {
    let entry = text_entry_offset();
    let report = verify_of(&exec_builder(
        Some(offsets_bytes(&[entry, entry + 16])),
        None,
        false,
        MINOS_AT_FLOOR,
    ));
    assert!(
        report.issues.is_empty(),
        "the honest offsets section stays clean: {:?}",
        report.issues
    );
    assert!(report.is_ok(&opts()));
}

#[test]
fn the_honest_pointer_form_verifies_strict() {
    let report = verify_of(&exec_builder(
        None,
        Some(vec![0u8; 16]),
        false,
        MINOS_AT_FLOOR,
    ));
    assert!(
        report.issues.is_empty(),
        "the classic pointer form stays clean: {:?}",
        report.issues
    );
}

#[test]
fn the_absence_stays_clean() {
    let report = verify_of(&exec_builder(None, None, false, MINOS_AT_FLOOR));
    assert!(
        report.issues.is_empty(),
        "a no-initializer image is the default, never a finding: {:?}",
        report.issues
    );
}

// ------------------------------------------------------------- geometry

#[test]
fn an_offsets_section_off_the_u32_stride_refuses() {
    let entry = text_entry_offset();
    let mut bytes = offsets_bytes(&[entry]);
    bytes.push(0u8); // the 4-byte stride broken by one trailing byte
    let report = verify_of(&exec_builder(Some(bytes), None, false, MINOS_AT_FLOOR));
    let hits = issues_with_code(&report, &Code::InitOffsets);
    assert_eq!(hits.len(), 1, "one stride finding: {:?}", report.issues);
    assert_eq!(hits[0].severity, Severity::Error);
    assert!(
        hits[0].message.contains("4-byte"),
        "the stride names itself: {}",
        hits[0].message
    );
}

#[test]
fn a_pointer_section_off_the_8_byte_stride_refuses() {
    let report = verify_of(&exec_builder(
        None,
        Some(vec![0u8; 12]),
        false,
        MINOS_AT_FLOOR,
    ));
    let hits = issues_with_code(&report, &Code::InitOffsets);
    assert_eq!(hits.len(), 1, "one stride finding: {:?}", report.issues);
    assert!(
        hits[0].message.contains("8-byte"),
        "the pointer stride names itself: {}",
        hits[0].message
    );
}

// -------------------------------------------------------------- targets

#[test]
fn an_entry_outside_every_segment_refuses() {
    let report = verify_of(&exec_builder(
        Some(offsets_bytes(&[0x7fff_f000u64])),
        None,
        false,
        MINOS_AT_FLOOR,
    ));
    let hits = issues_with_code(&report, &Code::InitOffsets);
    assert_eq!(hits.len(), 1, "one target finding: {:?}", report.issues);
    assert!(
        hits[0].message.contains("no segment"),
        "the unmapped target names itself: {}",
        hits[0].message
    );
}

#[test]
fn an_entry_in_a_non_executable_segment_refuses() {
    let data_off = data_entry_offset();
    let report = verify_of(&exec_builder(
        Some(offsets_bytes(&[data_off])),
        None,
        true,
        MINOS_AT_FLOOR,
    ));
    let hits = issues_with_code(&report, &Code::InitOffsets);
    assert_eq!(hits.len(), 1, "one target finding: {:?}", report.issues);
    assert!(
        hits[0].message.contains("executable"),
        "the dyld check's own words name the fix: {}",
        hits[0].message
    );
}

// ---------------------------------------------------------------- floor

#[test]
fn the_offsets_form_below_the_fixups_floor_refuses() {
    let entry = text_entry_offset();
    let report = verify_of(&exec_builder(
        Some(offsets_bytes(&[entry])),
        None,
        false,
        MINOS_BELOW_FLOOR,
    ));
    let hits = issues_with_code(&report, &Code::InitOffsets);
    assert_eq!(hits.len(), 1, "one floor finding: {:?}", report.issues);
    assert!(
        hits[0].message.contains("12.0.0"),
        "the floor names itself the producer refusal's way: {}",
        hits[0].message
    );
    assert!(
        hits[0].message.contains("__init_offsets"),
        "the section the floor silences is named: {}",
        hits[0].message
    );
}

// ------------------------------------------------------------ registry

#[test]
fn the_family_joins_the_registry_in_canonical_order() {
    let names: Vec<&'static str> = Check::ALL.iter().map(|c| c.as_str()).collect();
    let pos = names
        .iter()
        .position(|n| *n == "init_offsets")
        .expect("the family joins ALL");
    // M115's `objc` family joined between `tlv` and `init_offsets` (the
    // registry order rides the surface milestones).
    assert_eq!(
        names.get(pos - 1),
        Some(&"objc"),
        "canonical order rides the surface: M115 joins before the M94 family"
    );
    assert_eq!(
        names.get(pos - 2),
        Some(&"tlv"),
        "canonical order rides the M37 surface"
    );
    assert_eq!(
        Check::ALL.len(),
        17,
        "one family per rung — the sixteen M0–M129 families plus the M131 \
         literal family (the registry grew under M118/M119/M129 and M131)"
    );
    let set = CheckSet::parse("init_offsets").expect("the token parses");
    assert_eq!(set.to_string(), "init_offsets");
    for unit in pgr_verify::image_checks() {
        if unit.name() == "init_offsets" {
            assert!(
                unit.codes().contains(&Code::InitOffsets),
                "the family declares its code"
            );
            return;
        }
    }
    panic!("the registry carries the family");
}

#[test]
fn the_selection_alone_gates_the_broken_shapes() {
    let mut bytes = offsets_bytes(&[text_entry_offset()]);
    bytes.push(0u8);
    let img = exec_builder(Some(bytes), None, false, MINOS_AT_FLOOR)
        .build()
        .expect("the fixture builds");
    let set = CheckSet::parse("init_offsets").expect("the token parses");
    let report = verify_with_checks(&img.bytes, &opts(), &set);
    let hits = issues_with_code(&report, &Code::InitOffsets);
    assert_eq!(
        hits.len(),
        1,
        "the selected family runs alone: {:?}",
        report.issues
    );
}

#[test]
fn the_code_rides_the_json_interchange() {
    assert!(Code::ALL.iter().any(|c| c.as_str() == "init_offsets"));
    let entry = text_entry_offset();
    let img = exec_builder(
        Some(offsets_bytes(&[0x7fff_f000u64, entry])),
        None,
        false,
        MINOS_AT_FLOOR,
    )
    .build()
    .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    let json = pgr_verify::to_json(&report);
    let back = pgr_verify::parse_report_json(&json).expect("the document re-reads");
    assert_eq!(back, report, "the new code round-trips the interchange");
}
