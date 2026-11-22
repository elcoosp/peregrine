//! The weak-reference-mismatches bench (M123): the link cost across the
//! three policy faces over a 32-object corpus whose references mix weak
//! and strong against the same name. The advisory is a measurement,
//! never a layout product (the bytes never move), so the honest
//! expectation is parity — the bench pins the released surface never
//! regresses into the resolve walk's hot path.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::WeakReferenceMismatchesPolicy;

const OBJECTS: usize = 32;

fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let weak = i % 2 == 0;
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".into()
                } else {
                    format!("_fn_{i:03}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Undefined {
                name: "_sym".into(),
                weak_ref: weak,
            });
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .chain(std::iter::once(LinkInput {
            name: "provider.o".to_string(),
            bytes: {
                let mut b = ObjectBuilder::new("provider.o");
                let text = b.add_section(ObjectSection::text(
                    "__text",
                    vec![0xC0, 0x03, 0x5F, 0xD6],
                    vec![],
                ));
                b.add_symbol(ObjectSymbol::Defined {
                    name: "_sym".into(),
                    section_index: text,
                    value: 0,
                    weak: false,
                });
                b.build().expect("the provider builds")
            },
        }))
        .collect()
}

fn bench_weak_reference_mismatches(c: &mut Criterion) {
    let mut group = c.benchmark_group("weak_reference_mismatches");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for policy in [
        WeakReferenceMismatchesPolicy::Error,
        WeakReferenceMismatchesPolicy::Weak,
        WeakReferenceMismatchesPolicy::NonWeak,
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_32_objects", policy.flag_word()),
            &policy,
            |b, &p| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        weak_reference_mismatches: p,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg);
                    black_box(result.map(|r| r.layout.header_bytes.len()).unwrap_or(0));
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_weak_reference_mismatches(&mut criterion);
    criterion.final_summary();
}
