//! The `force_cpusubtype_all` bench (M125): the link cost across the
//! default cpusubtype word and a named `-force_cpusubtype_ALL` override
//! over a 64-object executable corpus. The cpusubtype word is
//! `CPU_SUBTYPE_ARM64_ALL` either way (the default already carries it —
//! the knob is byte-identity, the M122 `-pie` pattern over the
//! cpusubtype word), so the honest expectation is parity — the bench
//! pins the released surface never regresses into the header-assembly
//! hot path when the decision is named.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;

/// A 64-object executable corpus (each object one defined `_fn_N`, the
/// first carrying `_main`) — the shape the parity gate links over.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
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
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_force_cpusubtype_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("force_cpusubtype_all");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    // The default (the pre-M125 carrying ALL) and the named override:
    // the cpusubtype word is ALL either way, so the parity gate pins
    // byte-identity and the link cost never regresses when the decision
    // is named.
    for (name, forced) in [("default", false), ("forced_ALL", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &forced,
            |b, &f| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        force_cpusubtype_all: f,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg);
                    black_box(result.map_or(0, |r| r.layout.header_bytes.len()));
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_force_cpusubtype_all(&mut criterion);
    criterion.final_summary();
}
