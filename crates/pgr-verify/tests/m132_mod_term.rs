//! M132 — the verifier's `mod_term` gate: the `__DATA_CONST,__mod_term_func`
//! section dyld's *exit-time* terminator walk consumes
//! (`MachOAnalyzer::forEachTerminator`, the mirror of the initializer walk
//! the M94 family gates) must ride a whole 8-byte pointer stride — every
//! entry is a fixup word the walk reads as a whole slot, so a section whose
//! size is not a multiple of 8 is the malformed shape dyld's walk would
//! misread (the same stride contract the M94 pointer form carries, one
//! section type over — `S_MOD_TERM_FUNC_POINTERS` 0xa beside
//! `S_MOD_INIT_FUNC_POINTERS` 0x9). The producer emits the section
//! (`pgr_core::layout` sizes `__mod_term_func` beside `__mod_init_func`,
//! and `dead_strip` keeps it whole under `-no_dead_strip_inits`); the
//! family is the read-side backstop the producer's emit-side stride
//! assumes, regardless of how the section was produced (the M115/M131
//! read-side-backstop shape — a malformed pool the producer never wrote
//! still reports).
//!
//! The slots are fixup words (chained rebase encodings under
//! `LC_DYLD_CHAINED_FIXUPS`, opcode-driven rebases under the legacy
//! streams), so the raw bytes stay unread — the *stride* is the shape this
//! gate can honestly check (the M94 pointer-form precedent). Terminators
//! are pointer-form only (Mach-O carries no `S_TERM_FUNC_OFFSETS`), so the
//! family carries no offsets-form target walk and no chained-fixups floor
//! rule (the M94 offsets-form concerns stay the initializer family's own).
//!
//! Gate matrix:
//! * the honest shapes (a whole-stride `__mod_term_func`, no terminator
//!   surface at all) verify strict;
//! * the geometry — a `__mod_term_func` section off the 8-byte stride;
//! * the family joins the `--checks` registry (`Check::ALL` in canonical
//!   order, appended after the M131 `literal` family — the registry grew
//!   under M131 and M132; the selection gates the broken shape alone) and
//!   the code rides the report-JSON interchange.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, filler};
use pgr_verify::{Check, CheckSet, Code, Options, Severity, verify, verify_with_checks};

use pgr_format::consts::{PLATFORM_MACOS, S_MOD_TERM_FUNC_POINTERS};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// Packed `LC_BUILD_VERSION` words (`X << 16 | Y << 8 | Z`).
const MINOS_AT_FLOOR: u32 = 12 << 16; // (12, 0, 0) — the macOS fixups floor
const SDK_14: u32 = 14 << 16; // (14, 0, 0)

/// Builds an executable whose `__text` (64 filler bytes inside an
/// executable `__TEXT`) carries the honest code, plus the named terminator
/// surface: `mod_term` rides the classic `__DATA_CONST,__mod_term_func`
/// (`S_MOD_TERM_FUNC_POINTERS`). The deployment target pins at the
/// chained-fixups floor so the whole-image pass stays clean beside the
/// family's own stride gate.
fn exec_builder(mod_term: Option<Vec<u8>>) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m132exec");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        initprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_REGULAR | pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x9401, 64),
            relocs: Vec::new(),
        }],
    });
    if let Some(bytes) = mod_term {
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_WRITE,
            initprot: pgr_format::consts::VM_PROT_READ | pgr_format::consts::VM_PROT_WRITE,
            sections: vec![SectionSpec {
                name: "__mod_term_func".into(),
                align_log2: 3,
                flags: S_MOD_TERM_FUNC_POINTERS,
                data: bytes,
                relocs: Vec::new(),
            }],
        });
    }
    b.set_build_version(PLATFORM_MACOS, MINOS_AT_FLOOR, SDK_14);
    b.set_entry(0);
    b
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
fn the_honest_pointer_form_verifies_strict() {
    let report = verify_of(&exec_builder(Some(vec![0u8; 16])));
    assert!(
        report.issues.is_empty(),
        "the honest terminator pointer form stays clean: {:?}",
        report.issues
    );
    assert!(report.is_ok(&opts()));
}

#[test]
fn the_absence_stays_clean() {
    let report = verify_of(&exec_builder(None));
    assert!(
        report.issues.is_empty(),
        "a no-terminator image is the default, never a finding: {:?}",
        report.issues
    );
}

// ------------------------------------------------------------- geometry

#[test]
fn a_pointer_section_off_the_8_byte_stride_refuses() {
    let report = verify_of(&exec_builder(Some(vec![0u8; 12])));
    let hits = issues_with_code(&report, &Code::ModTerm);
    assert_eq!(hits.len(), 1, "one stride finding: {:?}", report.issues);
    assert_eq!(hits[0].severity, Severity::Error);
    assert!(
        hits[0].message.contains("8-byte"),
        "the pointer stride names itself: {}",
        hits[0].message
    );
    assert!(
        hits[0].message.contains("__mod_term_func"),
        "the section the stride gates is named: {}",
        hits[0].message
    );
}

// ------------------------------------------------------------ registry

#[test]
fn the_family_joins_the_registry_in_canonical_order() {
    let names: Vec<&'static str> = Check::ALL.iter().map(|c| c.as_str()).collect();
    let pos = names
        .iter()
        .position(|n| *n == "mod_term")
        .expect("the family joins ALL");
    // M132 appends after the M130 `objc_stubs` family (wired alongside
    // the M132 repair) and the M131 `literal` family — the registry grew
    // under M131 and M132, and the M130 family the M131 compile breakage
    // had masked rides the registry now its constants ride the format
    // table again.
    assert_eq!(
        names.get(pos - 1),
        Some(&"objc_stubs"),
        "canonical order rides the surface: M132 joins after the M130 objc_stubs family"
    );
    assert_eq!(
        names.get(pos + 1),
        None,
        "the M132 family is the registry's tail"
    );
    assert_eq!(
        Check::ALL.len(),
        19,
        "one family per rung — the sixteen M0–M129 families plus the M131 \
         literal family, the M130 objc_stubs family (wired) and the M132 \
         mod_term family (the registry grew under M118/M119/M129, M131 and M132)"
    );
    let set = CheckSet::parse("mod_term").expect("the token parses");
    assert_eq!(set.to_string(), "mod_term");
    for unit in pgr_verify::image_checks() {
        if unit.name() == "mod_term" {
            assert!(
                unit.codes().contains(&Code::ModTerm),
                "the family declares its code"
            );
            return;
        }
    }
    panic!("the registry carries the family");
}

#[test]
fn the_selection_alone_gates_the_broken_shape() {
    let img = exec_builder(Some(vec![0u8; 12]))
        .build()
        .expect("the fixture builds");
    let set = CheckSet::parse("mod_term").expect("the token parses");
    let report = verify_with_checks(&img.bytes, &opts(), &set);
    let hits = issues_with_code(&report, &Code::ModTerm);
    assert_eq!(
        hits.len(),
        1,
        "the selected family runs alone: {:?}",
        report.issues
    );
}

#[test]
fn the_code_rides_the_json_interchange() {
    assert!(Code::ALL.iter().any(|c| c.as_str() == "mod_term"));
    let img = exec_builder(Some(vec![0u8; 12]))
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    let json = pgr_verify::to_json(&report);
    let back = pgr_verify::parse_report_json(&json).expect("the document re-reads");
    assert_eq!(back, report, "the new code round-trips the interchange");
}
