//! The needed-dylib bench (M106): the link cost across the needed mark
//! under `-dead_strip_dylibs` — the unmarked drop (the unused dylib
//! leaves the header, the kept list compacts the two-level ordinals)
//! beside the needed-marked drop over the same corpus (the needed dylib
//! survives the drop and rides its `LC_LOAD_DYLIB` command). The mark is
//! one bool in the survival check, so the honest expectation is parity —
//! the bench pins "the mark never regresses the drop's hot path" (the
//! same shape gate the M42 dead-strip-dylibs bench rides, one opt-out
//! over).
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
/// unused one exports a parallel set nothing references. The `needed`
/// flag on the unused one is the bench's one decision.
fn dylibs(needed: bool) -> Vec<Dylib> {
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
        upward: false,
        reexport: false,
        needed: false,
    };
    let unused = Dylib {
        install_name: "@rpath/libidle.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: (0..EXPORTS_PER_DYLIB)
            .map(|i| format!("_dead_{i:03}"))
            .map(String::into_bytes)
            .collect(),
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed,
    };
    vec![used, unused]
}

fn bench_needed_dylibs(c: &mut Criterion) {
    let inputs = corpus();
    let unmarked = dylibs(false);
    let marked = dylibs(true);
    let mut group = c.benchmark_group("needed_dylibs");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, dylibs) in [("unmarked_drop", &unmarked), ("needed_survives", &marked)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            dylibs,
            |b, dylibs| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        dylibs: dylibs.clone(),
                        dead_strip_dylibs: true,
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
    bench_needed_dylibs(&mut criterion);
    criterion.final_summary();
}
