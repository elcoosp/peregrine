//! The M71 universal-container face's price: `verify_universal` over
//! 1-, 2- and 4-slice `FAT_MAGIC` containers beside the single-image
//! pass it wraps — the face is one strict pass per declared slice plus
//! the table-row/header agreement check, so the honest expectation is
//! linear in the slices and the container adds nothing per byte.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion};
use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{Options, verify, verify_universal};

/// The CPU type the foreign slices carry (a real fixture image rides
/// the same bytes; the table row names the foreign arch).
const FOREIGN: u32 = 0x0100_0007; // CPU_TYPE_X86_64

/// One small arm64 dylib slice (the export surface the strict pass
/// walks — segments, symtab, chained fixups, the signature recompute).
fn dylib_slice(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libbench.dylib", "m71-bench");
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

/// A container of `slices` real slices (the first arm64, the rest ride
/// foreign rows — the strict pass runs over every window either way).
fn container(slices: usize) -> Vec<u8> {
    let entries: Vec<(Vec<u8>, u32)> = (0..slices)
        .map(|i| {
            let bytes = dylib_slice(0x80 + u64::try_from(i).expect("few slices"));
            let cputype = if i == 0 { CPU_TYPE_ARM64 } else { FOREIGN };
            (bytes, cputype)
        })
        .collect();
    let refs: Vec<(&[u8], u32)> = entries.iter().map(|(b, c)| (b.as_slice(), *c)).collect();
    universal_image(&refs).expect("the container wraps")
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    let opts = Options::default();
    let mut group = criterion.benchmark_group("universal");

    // The single-image pass (the price one slice's window costs).
    let slice = dylib_slice(0x80);
    group.bench_function("single_image", |b| {
        b.iter(|| verify(black_box(&slice), &opts));
    });

    // The container face: one pass per declared slice.
    for slices in [1usize, 2, 4] {
        let bytes = container(slices);
        group.bench_with_input(BenchmarkId::new("verify", slices), &bytes, |b, bytes| {
            b.iter(|| verify_universal(black_box(bytes), &opts).expect("the container decodes"));
        });
    }
    group.finish();
    criterion.final_summary();
}
