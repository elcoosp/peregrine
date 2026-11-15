//! The dead-strip-dylibs bench (M42): the link cost across the
//! unused-dylib drop — the two-dylib corpus under the default (every
//! input dylib rides its `LC_LOAD_DYLIB` command, ld64's shape) beside
//! the named drop over the same corpus (the unused command leaves the
//! header, the kept list compacts the two-level ordinals) — over the
//! same corpus shape the M21–M41 parity benches share. The drop is one
//! skipped resolve walk and one dropped command, so the honest
//! expectation is parity-or-under — the bench pins "the knob never
//! regresses the link's hot path" (the same shape gate the M30–M41
//! benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::Dylib;

const OBJECTS: usize = 64;
const EXPORTS_PER_DYLIB: usize = 64;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries it), one `__data` bind slot per object against an undefined
/// name the used dylib exports (the two-level bind the ordinals name).
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
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            let undef = b.add_symbol(ObjectSymbol::Undefined {
                name: format!("_used_{i:03}"),
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

/// The two input dylibs: the used one exports every bind target; the
/// unused one exports a parallel set nothing references.
fn dylibs() -> Vec<Dylib> {
    let used = Dylib {
        install_name: "@rpath/libused.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: (0..OBJECTS)
            .map(|i| format!("_used_{i:03}"))
            .chain((0..EXPORTS_PER_DYLIB).map(|i| format!("_export_{i:03}")))
            .map(String::into_bytes)
            .collect(),
        weak: false,
        lazy: false,
        reexport: false,
    };
    let unused = Dylib {
        install_name: "@rpath/libunused.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: (0..EXPORTS_PER_DYLIB)
            .map(|i| format!("_dead_{i:03}"))
            .map(String::into_bytes)
            .collect(),
        weak: false,
        lazy: false,
        reexport: false,
    };
    vec![used, unused]
}

fn bench_dead_strip_dylibs(c: &mut Criterion) {
    let inputs = corpus();
    let dylibs = dylibs();
    let mut group = c.benchmark_group("dead_strip_dylibs");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, dropped) in [("default_carried", false), ("dropped", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &dropped,
            |b, &dropped| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        dylibs: dylibs.clone(),
                        dead_strip_dylibs: dropped,
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
    bench_dead_strip_dylibs(&mut criterion);
    criterion.final_summary();
}
