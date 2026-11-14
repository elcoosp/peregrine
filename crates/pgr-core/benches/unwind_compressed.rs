//! The compressed-unwind bench (M35): the link cost across the
//! synthesis's shapes — the entry-free corpus (the pre-M34 default
//! bytes) and the carried table (one entry per function, 64 objects ×
//! 4 functions, whose rows all qualify and ride the compressed
//! family) — over the same corpus shape the M21–M34 parity benches
//! share, plus the synthesis seam's own cost across table sizes and
//! both page families (the qualifying table compresses; the
//! beyond-24-bit table plans the pre-M35 bytes). The compressed rows
//! halve the second-level entry width, so the honest expectation is
//! the M34 parity or better — the bench pins "the density rung never
//! regresses the link's hot path" (the same shape gate the M30–M34
//! benches ride), and pins the synthesis at the cost its O(n log n)
//! sort + one pass names.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::unwind::{UnwindEntry, synthesize};
use pgr_format::consts::UNWIND_ARM64_MODE_FRAME;

const OBJECTS: usize = 64;
const FNS_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries it), one compact-unwind entry per function when the shape
/// names them.
fn corpus(entries: bool) -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(FNS_PER_OBJECT),
                vec![],
            ));
            for f in 0..FNS_PER_OBJECT {
                b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
            }
            if entries {
                let table: Vec<pgr_format::CompactUnwindEntry> = (0..FNS_PER_OBJECT)
                    .map(|f| pgr_format::CompactUnwindEntry {
                        range_start: (f * 4) as u64,
                        range_length: 4,
                        encoding: UNWIND_ARM64_MODE_FRAME,
                        personality: 0,
                        lsda: 0,
                    })
                    .collect();
                b.add_section(ObjectSection::compact_unwind(&table));
            }
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// An `n`-row table over one encoding (every row qualifies) or over
/// offsets past the 24-bit field (no row qualifies — the pre-M35
/// bytes).
fn table(n: usize, qualifying: bool) -> Vec<UnwindEntry> {
    (0..n)
        .map(|f| UnwindEntry {
            function_offset: if qualifying {
                (f * 4) as u32
            } else {
                0x0100_0000 + (f * 4) as u32
            },
            range_length: 4,
            encoding: UNWIND_ARM64_MODE_FRAME,
            personality_offset: 0,
            lsda_offset: 0,
        })
        .collect()
}

fn bench_unwind_compressed(c: &mut Criterion) {
    let mut group = c.benchmark_group("compact_unwind_compressed");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, entries) in [("default_0", false), ("carried_256", true)] {
        let inputs = corpus(entries);
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &entries,
            |b, _| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(&result.layout);
                });
            },
        );
    }
    // The synthesis seam's own cost across the page families: the
    // qualifying table (compressed rows) at the sizes a real link
    // carries, and the beyond-24-bit table (the all-regular fallback
    // shape) at the two-page split.
    for (name, n, qualifying) in [
        ("compressible_1024", 1024usize, true),
        ("compressible_4096", 4096, true),
        ("compressible_4097", 4097, true),
        ("beyond_24bit_4097", 4097, false),
    ] {
        let entries = table(n, qualifying);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("synthesize", name), &entries, |b, e| {
            b.iter(|| {
                let info = synthesize(black_box(e)).expect("the honest table synthesizes");
                black_box(info.bytes.len());
            });
        });
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_unwind_compressed(&mut criterion);
    criterion.final_summary();
}
