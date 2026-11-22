//! The `interposable` bench (M127): the link cost across the default
//! flags word (no `MH_WEAK_DEFINES | MH_BINDS_TO_WEAK` bits) and a
//! named `-interposable` override over a 32-object dylib corpus. The
//! bits are one OR into the flags word the segmented path's
//! `build_header` already writes, so the honest expectation is parity —
//! the bench pins the released surface never regresses into the
//! header-assembly hot path when the decision is named.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 32;

/// A 32-object dylib corpus (each object one defined `_fn_N`, the
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

fn bench_interposable(c: &mut Criterion) {
    let mut group = c.benchmark_group("interposable");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    // The default (no interpose bits) and the named override: the bits
    // are one OR into the flags word, so the parity gate pins
    // byte-identity-except-the-two-bits and the link cost never
    // regresses when the decision is named.
    for (name, on) in [("default", false), ("named_on", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_32_dylib_objects", name),
            &on,
            |b, &o| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Dylib,
                        install_name: Some("@rpath/libbench.dylib".into()),
                        interposable: o,
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
    bench_interposable(&mut criterion);
    criterion.final_summary();
}
