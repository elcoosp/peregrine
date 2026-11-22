//! The `application_extension` bench (M128): the link cost across the
//! default flags word (no `MH_APP_EXTENSION_SAFE` bit) and a named
//! `-application_extension` override over a 64-object executable
//! corpus. The bit is one OR into the flags word the segmented path's
//! `build_header` already writes, so the honest expectation is parity —
//! the bench pins the released surface never regresses into the
//! header-assembly hot path when the decision is named.
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

fn bench_application_extension(c: &mut Criterion) {
    let mut group = c.benchmark_group("application_extension");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    // The default (no `MH_APP_EXTENSION_SAFE` bit) and the named
    // override: the bit is one OR into the flags word, so the parity
    // gate pins byte-identity-except-the-one-bit and the link cost
    // never regresses when the decision is named.
    for (name, on) in [("default", false), ("named_on", true)] {
        group.bench_with_input(BenchmarkId::new("link_64_objects", name), &on, |b, &o| {
            b.iter(|| {
                let cfg = LinkConfig {
                    application_extension: o,
                    ..LinkConfig::default()
                };
                let result = link(black_box(&inputs), &[], &cfg);
                black_box(result.map_or(0, |r| r.layout.header_bytes.len()));
            });
        });
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_application_extension(&mut criterion);
    criterion.final_summary();
}
