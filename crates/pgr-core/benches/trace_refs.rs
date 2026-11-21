//! M113 — the `-t` reference-trace bench: the pipeline's cost with and
//! without the refs collector subscribed over the same corpus (64
//! objects, one bind each). The collector rides the M54 observation
//! seam's `on_reference` face — one event per reference the resolve
//! visits — so the honest expectation is near-parity: a subscribed
//! collector pushes one event per reference, and the unobserved link
//! pays nothing.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate on
//! the dev sandbox (bounded `--measurement-time 1`).

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link, link_observed};
use pgr_core::observe::RefsCollector;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::hint::black_box;

const OBJECTS: usize = 64;

/// 64 objects: `_main` in the first; every object carries one
/// `__DATA,__data` pointer slot binding `_shared` (the corpus the trace
/// walks — 64 reference visits per link).
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
            let data = b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
            let undef = b.add_symbol(ObjectSymbol::Undefined {
                name: "_shared".into(),
                weak_ref: false,
            });
            let slot = b.sym_index(undef);
            b.section_mut(data)
                .relocs
                .push(ObjectReloc::unsigned(slot).at(0));
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_trace_refs(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace_refs");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (face, observed) in [("unobserved", false), ("refs_subscribed", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", face),
            &observed,
            |b, &subscribe| {
                b.iter(|| {
                    if subscribe {
                        let mut refs = RefsCollector::default();
                        let result = link_observed(
                            black_box(&inputs),
                            &[],
                            &LinkConfig::default(),
                            pgr_core::Parallelism::Auto,
                            None,
                            &mut refs,
                        )
                        .expect("the corpus links");
                        black_box((refs.finish().len(), result.layout.file_size));
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
    bench_trace_refs(&mut criterion);
    criterion.final_summary();
}
