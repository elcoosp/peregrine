//! Property-based robustness: the verifier and parser must never panic on
//! mutated or truncated images — every path returns a report or a typed
//! error (M0 gate: "fuzz targets for the parsers", stable-CI edition).

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler};
use pgr_format::consts::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use pgr_verify::{Options, verify};
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
}
