//! M112 — the `-print_statistics` bench: the pipeline's cost with and
//! without the stats collector subscribed over the same corpus (64
//! objects, one `__text` and one `__DATA,__data` section each). The
//! collector rides the M54 observation seam — one match per phase event,
//! seven per segmented link, regardless of the corpus size — so the
//! honest expectation is near-parity: a subscribed collector updates two
//! counts per phase event, and the unobserved link pays nothing.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate on
//! the dev sandbox (bounded `--measurement-time 1`).

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link, link_observed};
use pgr_core::statistics::StatsCollector;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::hint::black_box;

const OBJECTS: usize = 64;

/// `OBJECTS` small objects: the first carries `_main`; every object
/// carries one `__TEXT,__text` and one `__DATA,__data` section (the
/// observer bench's corpus — the shape-parity gate shares it).
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b =
                ObjectBuilder::new(&format!("obj_{i:03}.o")).set_subsections_via_symbols(true);
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            let data = b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".to_string()
                } else {
                    format!("_fn_{i:03}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_data_{i:03}"),
                section_index: data,
                value: 0,
                weak: false,
            });
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_print_statistics(c: &mut Criterion) {
    let mut group = c.benchmark_group("print_statistics");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (face, observed) in [("unobserved", false), ("stats_subscribed", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", face),
            &observed,
            |b, &subscribe| {
                b.iter(|| {
                    if subscribe {
                        let mut stats = StatsCollector::default();
                        let result = link_observed(
                            black_box(&inputs),
                            &[],
                            &LinkConfig::default(),
                            pgr_core::Parallelism::Auto,
                            None,
                            &mut stats,
                        )
                        .expect("the corpus links");
                        let report = stats.finish(
                            result.layout.fixups.slot_count,
                            result.layout.file_size,
                            std::time::Duration::ZERO,
                        );
                        black_box(report.render());
                    } else {
                        let result = link(black_box(&inputs), &[], &LinkConfig::default())
                            .expect("the corpus links");
                        black_box(&result.layout);
                    }
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_print_statistics(&mut criterion);
    criterion.final_summary();
}
