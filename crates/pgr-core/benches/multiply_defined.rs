//! The multiply-defined-policy bench (M108): the link cost across the
//! `-multiply_defined <policy>` faces — the default (the collision
//! refuses, the pre-M108 escalation) beside the three named faces over
//! the same corpus (64 objects, every symbol defined by two of them).
//! The decision is one tie-check at the install site plus one derive
//! walk over the winners, so the honest expectation is parity — the
//! bench pins "the policy never regresses the resolve's hot path" (the
//! same shape gate the M103/M107 policy benches ride, one alphabet
//! over).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::MultiplyDefinedPolicy;

const OBJECTS: usize = 64;

/// `OBJECTS` small objects: `_main` on the first only, and every
/// `_dup_<i>` name defined by exactly two objects (i and i+1) — the
/// collision surface every face walks. One bind slot against each
/// duplicated name keeps the winners live.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            if i == 0 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: "_main".into(),
                    section_index: text,
                    value: 0,
                    weak: false,
                });
            }
            // This object defines the duplicated names it owns.
            let name = format!("_dup_{:03}", i / 2);
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            b.add_symbol(ObjectSymbol::Defined {
                name,
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

fn bench_multiply_defined(c: &mut Criterion) {
    let inputs = corpus();
    let mut group = c.benchmark_group("multiply_defined");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for policy in [
        MultiplyDefinedPolicy::Error,
        MultiplyDefinedPolicy::Warning,
        MultiplyDefinedPolicy::Suppress,
        MultiplyDefinedPolicy::DynamicLookup,
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", policy.flag_word()),
            &policy,
            |b, &policy| {
                b.iter(|| {
                    // The default face refuses the duplicated corpus — the
                    // bench prices the walk to the refusal (the face's own
                    // product), never a fabricated success.
                    let cfg = LinkConfig {
                        multiply_defined: policy,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg);
                    black_box(result.err().map(|e| e.to_string()));
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_multiply_defined(&mut criterion);
    criterion.final_summary();
}
