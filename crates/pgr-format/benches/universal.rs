//! The universal-container bench (M70): the read seam's own price —
//! the container decode (`parse_universal`: header + slice table +
//! window bounds) and the arm64 selection (`Universal::arm64`) — over
//! containers of 2, 5 and 9 slices built by `pgr-fixtures`. A shape
//! gate: the decode is O(nfat) table rows plus two window checks per
//! row, and the selection is one cputype scan — the honest expectation
//! is near-linearity in the table, nothing rides the slice bytes (the
//! window is a subslice, never a copy). The dispatch that follows (the
//! Mach-O parse, the scan) is priced by the crates that own it.

use criterion::{Criterion, Throughput};
use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_format::universal::parse_universal;

/// One small arm64 dylib slice (an export surface, sized for the bench).
fn dylib_slice(seed: u64, text_kib: usize) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libbench.dylib", "m70-bench");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(seed, text_kib * 1024),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_bench_symbol".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// A container of `slices` arm64 slices (the foreign slices a real
/// container carries are never touched by the seam — the bench prices
/// the arm64-only shape).
fn container(seed: u64, slices: usize, text_kib: usize) -> Vec<u8> {
    let entries: Vec<(Vec<u8>, u32)> = (0..slices)
        .map(|i| {
            (
                dylib_slice(seed + u64::try_from(i).expect("few slices"), text_kib),
                CPU_TYPE_ARM64,
            )
        })
        .collect();
    let refs: Vec<(&[u8], u32)> = entries.iter().map(|(b, c)| (b.as_slice(), *c)).collect();
    universal_image(&refs).expect("the container wraps")
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("pgr-format/universal-decode");
    for (slices, kib) in [(2usize, 4usize), (5, 4), (9, 4)] {
        let bytes = container(0x70, slices, kib);
        group.throughput(Throughput::Bytes(
            u64::try_from(bytes.len()).expect("the length fits u64"),
        ));
        group.bench_with_input(format!("{slices}_slices"), &bytes, |b, bytes| {
            b.iter(|| parse_universal(bytes).expect("the container decodes"));
        });
    }
    group.finish();
}

fn bench_select(c: &mut Criterion) {
    let mut group = c.benchmark_group("pgr-format/universal-select");
    for (slices, kib) in [(2usize, 4usize), (5, 4), (9, 4)] {
        let bytes = container(0x71, slices, kib);
        group.throughput(Throughput::Bytes(
            u64::try_from(bytes.len()).expect("the length fits u64"),
        ));
        group.bench_with_input(format!("{slices}_slices"), &bytes, |b, bytes| {
            b.iter(|| {
                let u = parse_universal(bytes).expect("the container decodes");
                u.arm64(bytes).expect("the arm64 slice selects")
            });
        });
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_decode(&mut criterion);
    bench_select(&mut criterion);
    criterion.final_summary();
}
