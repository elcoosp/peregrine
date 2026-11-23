//! M110 — the hidden-dylib mark (`-hidden_library`/`-hidden_framework`/
//! `-hidden-l`): the shape-parity gate over the 64-object corpus. The
//! hidden dylib rides the resolve arena with its load command dropped —
//! the bench prices the link beside the visible-dylib face (the command
//! drop and the flat-ride slot the mark plans).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox (bounded `--measurement-time 1`).

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::Dylib;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::hint::black_box;

const OBJECTS: usize = 64;

/// 64 objects; each binds the visible-dylib export `_used` through a
/// `__data` pointer slot (the corpus the dylib benches share). The
/// reference rides the weak bit — the m110 shape the mark plans: a
/// strong reference to a hidden export refuses (dyld cannot bind it
/// without the load command), the weak one rides the flat-lookup slot
/// on the hidden face and the ordinary weak bind on the visible face.
/// `_main` rides the first object (the entry the default config names).
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("o{i:03}.o"));
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
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            let undef = b.add_symbol(ObjectSymbol::Undefined {
                name: "_used".into(),
                weak_ref: true,
            });
            let slot = b.sym_index(undef);
            b.section_mut(data)
                .relocs
                .push(ObjectReloc::unsigned(slot).at(0));
            let bytes = b.build().expect("the fixture object builds");
            LinkInput {
                name: format!("o{i:03}.o"),
                bytes,
            }
        })
        .collect()
}

/// The one decision: the dylib rides visibly (`LC_LOAD_DYLIB`) or
/// hidden (no command; the exports ride the arena all the same).
fn dylibs(hidden: bool) -> Vec<Dylib> {
    let mut provider = Dylib {
        install_name: "@rpath/libprovider.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: (0..OBJECTS)
            .map(|i| format!("_export_{i:03}"))
            .chain(std::iter::once("_used".to_string()))
            .map(String::into_bytes)
            .collect(),
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    };
    provider.hidden = hidden;
    vec![provider]
}

fn bench_hidden_library(c: &mut Criterion) {
    let inputs = corpus();
    let mut group = c.benchmark_group("hidden_library");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (face, hidden) in [("visible_load", false), ("hidden_no_command", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", face),
            &hidden,
            |b, &h| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        dylibs: dylibs(h),
                        ..LinkConfig::default()
                    };
                    black_box(link(black_box(&inputs), &[], &cfg).expect("the corpus links"))
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_hidden_library(&mut criterion);
    criterion.final_summary();
}
