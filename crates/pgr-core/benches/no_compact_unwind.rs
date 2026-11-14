//! The no-compact-unwind bench (M36): the link cost across the
//! suppression decision — the carried corpus under the default (the
//! M34 carriage rides, the M35 rung compresses) beside the named
//! suppression over the same corpus (the section drops — the pre-M34
//! bytes) — over the same corpus shape the M21–M35 parity benches
//! share. The suppression is one dropped synthetic section (no
//! placement, no rows, no `__unwind_info` slot), so the honest
//! expectation is the suppressed link at or under the carried one —
//! the bench pins "the knob never regresses the link's hot path" (the
//! same shape gate the M30–M35 benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_format::consts::UNWIND_ARM64_MODE_FRAME;

const OBJECTS: usize = 64;
const FNS_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries it), one compact-unwind entry per function.
fn corpus() -> Vec<LinkInput> {
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
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_no_compact_unwind(c: &mut Criterion) {
    let inputs = corpus();
    let mut group = c.benchmark_group("no_compact_unwind");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, suppressed) in [("default_carried", false), ("suppressed", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &suppressed,
            |b, &suppressed| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        compact_unwind: !suppressed,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(&result.layout);
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_no_compact_unwind(&mut criterion);
    criterion.final_summary();
}
