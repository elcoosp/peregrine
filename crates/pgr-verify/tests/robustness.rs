//! Property-based robustness: the verifier and parser must never panic on
//! mutated or truncated images — every path returns a report or a typed
//! error (M0 gate: "fuzz targets for the parsers", stable-CI edition).
//! The report readers ride the same gate: the M96 container-baseline
//! reader accepts or rejects arbitrary (mutated, truncated, garbage)
//! documents with a typed result, never a panic.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler};
use pgr_format::consts::{CPU_TYPE_ARM64, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use pgr_format::universal::FatArch;
use pgr_verify::{
    Options, SliceWindow, parse_container_baseline, slice_label, to_json_with_file, verify,
};
use proptest::prelude::*;

/// Builds the canonical clean exec fixture bytes.
fn good_exec() -> Vec<u8> {
    let mut b = ImageBuilder::executable("robustness");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: pgr_format::consts::S_REGULAR,
            data: filler(7, 128),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
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
    b.build().unwrap().bytes
}

/// The canonical container slice window the document props ride (the
/// rows the record face labels — the window's triple is the reader's
/// identity check, so a real-shaped one keeps the round trip honest).
fn slice_arch() -> FatArch {
    FatArch {
        cputype: CPU_TYPE_ARM64,
        cpusubtype: 0,
        offset: 0x1000,
        size: 0x4000,
        align_log2: 12,
    }
}

/// One synthetic slice report: `n` error issues at descending anchors.
fn slice_report(n: u64) -> pgr_verify::Report {
    let issues = (0..n)
        .map(|i| {
            pgr_verify::Issue::error(
                pgr_verify::Code::SignatureHashMismatch,
                format!("probe {i}"),
                Some(0x100 + i),
            )
        })
        .collect();
    pgr_verify::Report {
        issues,
        stats: pgr_verify::Stats::default(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Any byte mutation set must produce a report, never a panic.
    #[test]
    fn mutated_images_never_panic(
        seed in 0u64..1_000_000,
        flips in 1usize..=8,
    ) {
        let mut bytes = good_exec();
        let len = bytes.len();
        let mut state = seed | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % len as u64) as usize
        };
        let flips_at: Vec<usize> = (0..flips).map(|_| next()).collect();
        for at in flips_at {
            bytes[at] ^= 0xff;
        }
        let opts = Options::default();
        let report = verify(&bytes, &opts);
        prop_assert!(report.issues.len() <= 64, "issue explosion");
    }

    /// Arbitrary truncations must produce a report, never a panic.
    #[test]
    fn truncated_images_never_panic(cut in 0usize..=40_000usize) {
        let bytes = good_exec();
        let end = cut.min(bytes.len());
        let opts = Options::default();
        let _ = verify(&bytes[..end], &opts);
    }

    /// The structural parser must accept or reject arbitrary byte strings
    /// with a typed result, never panic.
    #[test]
    fn arbitrary_bytes_never_panic(
        seed in 0u64..1_000_000,
        len in 0usize..4096usize,
    ) {
        let bytes = filler(seed, len);
        let _ = pgr_format::summarize(&bytes);
        let opts = Options::default();
        let _ = verify(&bytes, &opts);
    }

    /// The M96 container-baseline reader must accept or reject arbitrary
    /// documents with a typed result, never panic — the reader faces the
    /// same hostile surface the image parsers do (any text a gate's
    /// output file may hold, garbage included).
    #[test]
    fn arbitrary_container_baseline_documents_never_panic(
        seed in 0u64..1_000_000,
        len in 0usize..4096usize,
    ) {
        let text = String::from_utf8_lossy(&filler(seed, len)).into_owned();
        let _ = parse_container_baseline(&text);
    }

    /// The record face's own output round-trips: one labeled line per
    /// declared slice, and the reader restores every label, every window
    /// and every issue the writer wrote (the gate's document is only as
    /// good as its reader's fidelity).
    #[test]
    fn the_container_document_round_trips(
        slices in 1usize..=4usize,
        issues in 0u64..=16u64,
    ) {
        let arch = slice_arch();
        let lines: Vec<String> = (0..slices)
            .map(|i| to_json_with_file(&slice_label("fat.dylib", i, &arch), &slice_report(issues)))
            .collect();
        let document = lines.join("\n");
        let baseline = parse_container_baseline(&document)
            .expect("the record face's own output parses");
        prop_assert_eq!(baseline.entries.len(), slices, "one entry per line");
        for (i, entry) in baseline.entries.iter().enumerate() {
            prop_assert_eq!(&entry.label, &slice_label("fat.dylib", i, &arch));
            prop_assert_eq!(
                entry.window,
                SliceWindow {
                    cputype: arch.cputype,
                    offset: arch.offset,
                    size: arch.size,
                }
            );
            prop_assert_eq!(entry.report.issues.len(), issues as usize);
            prop_assert_eq!(&entry.report.issues, &slice_report(issues).issues);
        }
    }

    /// Any byte mutation of a valid document must parse or refuse with a
    /// typed error, never panic — the mutation gate the images ride.
    #[test]
    fn mutated_container_baseline_documents_never_panic(
        seed in 0u64..1_000_000,
        flips in 1usize..=8,
    ) {
        let arch = slice_arch();
        let mut document = to_json_with_file(
            &slice_label("fat.dylib", 0, &arch),
            &slice_report(8),
        )
        .into_bytes();
        let len = document.len();
        let mut state = seed | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % len as u64) as usize
        };
        for _ in 0..flips {
            document[next()] ^= 0xff;
        }
        let text = String::from_utf8_lossy(&document).into_owned();
        let _ = parse_container_baseline(&text);
    }
}
