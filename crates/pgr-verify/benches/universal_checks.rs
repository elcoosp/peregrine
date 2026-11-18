//! The M74 selected container face's price: `verify_universal_with_checks`
//! beside the full pass it wraps — the selection narrows the per-slice
//! pass's check families (the signature-only lane skips the segment,
//! fixup and structural walks), so the honest expectation is a lane under
//! the full pass, both linear in the slices (the M12 `checks` bench's
//! shape, composed over the M71 container face).

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion};
use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{CheckSet, Options, verify_universal, verify_universal_with_checks};

/// One small arm64 dylib slice (the export surface the strict pass
/// walks — segments, symtab, chained fixups, the signature recompute).
fn dylib_slice(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libbench.dylib", "m74-bench");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(seed, 128),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_bench_symbol".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// A container of `slices` real arm64 slices (every window verifies
/// clean — the bench prices the work, not the refusals).
fn container(slices: usize) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = (0..slices)
        .map(|i| dylib_slice(0x80 + u64::try_from(i).expect("few slices")))
        .collect();
    let refs: Vec<(&[u8], u32)> = entries
        .iter()
        .map(|b| (b.as_slice(), CPU_TYPE_ARM64))
        .collect();
    universal_image(&refs).expect("the container wraps")
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    let opts = Options::default();
    let signature = CheckSet::parse("signature").expect("the family parses");
    let mut group = criterion.benchmark_group("universal_checks");

    // The full pass (the M71 face, the lane the selection narrows).
    for slices in [2usize, 4] {
        let bytes = container(slices);
        group.bench_with_input(BenchmarkId::new("full", slices), &bytes, |b, bytes| {
            b.iter(|| verify_universal(black_box(bytes), &opts).expect("the container decodes"));
        });
        // The signature-only lane: the page-hash recompute without the
        // segment/fixup walks.
        group.bench_with_input(BenchmarkId::new("signature", slices), &bytes, |b, bytes| {
            b.iter(|| {
                verify_universal_with_checks(black_box(bytes), &opts, &signature)
                    .expect("the container decodes")
            });
        });
    }
    group.finish();
    criterion.final_summary();
}
