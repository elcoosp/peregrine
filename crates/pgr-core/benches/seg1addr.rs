//! The seg1addr bench (M124): the link cost across the default
//! constant-delta floor and a named `-seg1addr` override over a
//! 64-object executable corpus. The base is one resolver read at the
//! head of the segment planner (the constant-delta contract
//! `vmaddr = fileoff + base` holds either way), so the honest
//! expectation is parity — the bench pins the released surface never
//! regresses into the layout's hot path when the floor shifts.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::seg1addr::Seg1Addr;

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

fn bench_seg1addr(c: &mut Criterion) {
    let mut group = c.benchmark_group("seg1addr");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    // The default floor (0x1_0000_0000 — the pre-M124 constant) and a
    // named 1 GiB floor: the resolver reads either, the segment
    // planner shifts the vmaddrs off either, and the parity gate pins
    // the link cost never regresses when the floor moves.
    for (name, seg1addr) in [("default", None), ("named_0x40000000", Some(0x4000_0000))] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &seg1addr,
            |b, &s| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        seg1addr: s
                            .map(|raw| Seg1Addr::from_override(raw).expect("the base validates")),
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
    bench_seg1addr(&mut criterion);
    criterion.final_summary();
}
