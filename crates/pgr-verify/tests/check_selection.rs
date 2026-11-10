//! The M12 selective-verification surface: named check families, the
//! `CheckSet` selector and the `ImageCheck` registry seam.
//!
//! The executable specification, in order:
//!
//! * parity — `CheckSet::all()` through `verify_with_checks` is exactly
//!   today's `verify` (issues and stats),
//! * selection — a corrupted image's finding is contained by its own
//!   family and absent from the complement (both directions, per family),
//! * parsing — canonical names round-trip; unknown/empty/mixed-case
//!   tokens name the failure and the valid surface,
//! * registry honesty — a single-family run never reports a code outside
//!   that family's declared `codes()`.

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{Check, CheckSet, Code, Options, Severity, verify, verify_with_checks};

fn opts() -> Options {
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
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
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

/// A small chained-fixup executable: one bind + one rebase slot, an entry
/// point, a build version at the macOS floor.
fn exec_builder() -> ImageBuilder {
    let mut b = ImageBuilder::executable("select-checks-test");
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
    b.set_imports_format(ImportsFormat::Plain);
    b
}

/// A small dylib: defines `_greet` in `__text`, no entry point.
fn dylib_bytes() -> Vec<u8> {
    let mut b = ImageBuilder::dylib("/usr/lib/libgreet.1.dylib", "greet-test");
    b.add_segment(text_segment(64));
    b.add_segment(data_const_segment());
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.set_imports_format(ImportsFormat::Plain);
    b.build().expect("the dylib fixture builds").bytes
}

fn codes_of(report: &pgr_verify::Report) -> Vec<Code> {
    report.issues.iter().map(|i| i.code).collect()
}

// ---------------------------------------------------------------- parity

/// `CheckSet::all()` through the selective surface is exactly `verify`:
/// same issues, same stats, on both an executable and a dylib.
#[test]
fn all_matches_verify_parity() {
    let exec = exec_builder().build().unwrap().bytes;
    let dylib = dylib_bytes();
    let all = CheckSet::all();
    for (name, bytes) in [("executable", &exec), ("dylib", &dylib)] {
        let full = verify(bytes, &opts());
        let selected = verify_with_checks(bytes, &opts(), &all);
        assert_eq!(
            full, selected,
            "{name}: all() must reproduce verify() issue-for-issue"
        );
    }
}

/// The empty set runs the parse pre-pass only: no issues on a clean
/// image, but the aggregate counters from the parse still land.
#[test]
fn empty_set_is_parse_only() {
    let bytes = exec_builder().build().unwrap().bytes;
    let report = verify_with_checks(bytes.as_slice(), &opts(), &CheckSet::empty());
    assert!(
        report.issues.is_empty(),
        "clean image must not gather issues under the empty set: {:#?}",
        report.issues
    );
    assert!(report.stats.segments >= 2, "parse still counts segments");
    assert!(report.stats.sections >= 1, "parse still counts sections");
    assert!(report.stats.symbols >= 1, "parse still counts symbols");
}

// ---------------------------------------------------------------- parsing

/// Canonical names round-trip through `parse` and `Display`; duplicates
/// collapse into the same set.
#[test]
fn parse_roundtrip_dedup_and_display() {
    let set = CheckSet::parse("segments, fixups ,segments").expect("duplicate names collapse");
    assert!(set.contains(Check::Segments) && set.contains(Check::Fixups));
    assert_eq!(set.names().count(), 2, "dedup to the two families");
    let reparsed = CheckSet::parse(&set.to_string()).expect("Display output re-parses");
    assert_eq!(set, reparsed, "parse ∘ display is the identity");
    assert_eq!(
        CheckSet::all(),
        CheckSet::parse(
            &Check::ALL
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )
        .expect("every canonical name parses"),
        "the joined canonical names are exactly all()"
    );
}

/// Unknown, empty and mixed-case tokens fail while naming the offender
/// and the valid surface.
#[test]
fn parse_rejects_unknown_empty_and_case() {
    let err = CheckSet::parse("segments,nope").expect_err("unknown token refused");
    assert!(err.invalid.contains("nope"), "error names the token");
    assert!(
        err.valid.contains(&"segments"),
        "error carries the valid names"
    );
    assert!(
        CheckSet::parse("segments,").is_err(),
        "trailing empty token refused"
    );
    assert!(CheckSet::parse("").is_err(), "empty input refused");
    assert!(
        CheckSet::parse("Segments").is_err(),
        "selectors are exact lowercase names"
    );
}

// ------------------------------------------------------------- isolation

/// Flipping any `__text` byte breaks exactly the signature page hash.
fn corrupt_signature() -> Vec<u8> {
    let img = exec_builder().build().unwrap();
    let mut corrupt = img.bytes;
    let text_off = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .expect("the fixture carries __text")
        .fileoff as usize;
    corrupt[text_off + 7] ^= 0xff;
    corrupt
}

/// Bumping `__DATA_CONST`'s vmaddr breaks the 16 KiB congruence.
fn corrupt_congruence() -> Vec<u8> {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes;
    let hdr = pgr_format::MachHeader64::parse(&bytes).expect("fixture header parses");
    let vmaddr_at = {
        let mut it = pgr_format::LoadCommandIter::new(&bytes, 32, hdr.ncmds, hdr.sizeofcmds)
            .expect("fixture load commands parse");
        let mut found = None;
        while let Some(cmd) = it.next_command().expect("fixture iterates") {
            if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
                let seg =
                    pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("fixture segment");
                if seg.name() == Ok("__DATA_CONST") {
                    found = Some(cmd.offset + 24);
                }
            }
        }
        found.expect("the fixture carries __DATA_CONST")
    };
    let vm = u64::from_le_bytes(bytes[vmaddr_at..vmaddr_at + 8].try_into().unwrap());
    bytes[vmaddr_at..vmaddr_at + 8].copy_from_slice(&(vm + 0x1000).to_le_bytes());
    bytes
}

/// A chain stride that jumps past the page end breaks the walk.
fn corrupt_chain_stride() -> Vec<u8> {
    let img = exec_builder().build().unwrap();
    let mut bytes = img.bytes;
    let got_at = img
        .map
        .sections
        .iter()
        .find(|s| s.name == "__got")
        .expect("the fixture carries __got")
        .fileoff as usize;
    let w = pgr_format::fixups::ChainWord64::new(u64::from_le_bytes(
        bytes[got_at..got_at + 8].try_into().unwrap(),
    ));
    let mut raw = w.raw;
    raw &= !(0xfffu64 << 51);
    raw |= 0xfffu64 << 51; // next = 0xfff strides: the slot leaves the page
    bytes[got_at..got_at + 8].copy_from_slice(&raw.to_le_bytes());
    bytes
}

/// Each corruption surfaces in full verify, is contained by its own
/// family, and is absent from the complement — both directions.
#[test]
fn corruption_isolated_to_its_family() {
    let cases: &[(&str, Vec<u8>, Code, Check)] = &[
        (
            "page hash",
            corrupt_signature(),
            Code::SignatureHashMismatch,
            Check::Signature,
        ),
        (
            "congruence",
            corrupt_congruence(),
            Code::SegmentContract,
            Check::Segments,
        ),
        (
            "chain stride",
            corrupt_chain_stride(),
            Code::FixupsChain,
            Check::Fixups,
        ),
    ];
    for (label, bytes, code, family) in cases {
        let full = verify(bytes, &opts());
        assert!(
            codes_of(&full).contains(code),
            "{label}: full verify names {code:?}, got {:?}",
            codes_of(&full)
        );
        let alone = CheckSet::parse(family.as_str()).expect("family name parses");
        let only = verify_with_checks(bytes, &opts(), &alone);
        assert!(
            codes_of(&only).contains(code),
            "{}: the {} family alone must surface {code:?}, got {:?}",
            label,
            family.as_str(),
            codes_of(&only)
        );
        let complement = CheckSet::parse(
            &Check::ALL
                .iter()
                .filter(|c| *c != family)
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
        .expect("the complement parses");
        let others = verify_with_checks(bytes, &opts(), &complement);
        assert!(
            !codes_of(&others).contains(code),
            "{label}: the complement must not surface {code:?}, got {:?}",
            codes_of(&others)
        );
    }
}

/// A single-family run only ever reports codes that family declares —
/// the registry's `codes()` metadata is honest.
#[test]
fn single_check_never_reports_foreign_codes() {
    let exec = exec_builder().build().unwrap().bytes;
    let corrupt_sig = corrupt_signature();
    let corpus = [
        exec,
        corrupt_sig,
        corrupt_congruence(),
        corrupt_chain_stride(),
        dylib_bytes(),
    ];
    for check in Check::ALL {
        let set = CheckSet::parse(check.as_str()).expect("family name parses");
        for bytes in &corpus {
            let report = verify_with_checks(bytes, &opts(), &set);
            for issue in &report.issues {
                let family = image_family(check);
                assert!(
                    family.contains(&issue.code),
                    "{} declared {family:?} but reported {:?} ({})",
                    check.as_str(),
                    issue.code,
                    issue.message
                );
            }
        }
    }
}

use pgr_verify::image_checks;

/// The trait registry's view of a check's codes (the test-side lookup).
fn image_family(check: Check) -> &'static [Code] {
    let unit = image_checks()
        .iter()
        .find(|unit| unit.name() == check.as_str())
        .unwrap_or_else(|| panic!("every Check has a registry unit: {}", check.as_str()));
    unit.codes()
}

/// The registry is canonical: unique names, every `Check` present, and
/// the registry order matches the canonical `Check::ALL` order.
#[test]
fn registry_names_are_canonical() {
    let registry = image_checks();
    let mut names: Vec<_> = registry.iter().map(|u| u.name()).collect();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count, "registry names are unique");
    assert_eq!(count, Check::ALL.len(), "one unit per Check");
    for (unit, check) in registry.iter().zip(Check::ALL) {
        assert_eq!(unit.name(), check.as_str(), "registry order is canonical");
        assert!(!unit.summary().is_empty(), "every unit summarizes itself");
    }
}

/// `Severity` ordering stays defined (the report sort leans on it).
#[test]
fn severity_ordering_is_defined() {
    assert_ne!(Severity::Error as u8, Severity::Warning as u8);
}
