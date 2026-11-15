//! The headerpad-max bench (M38): the link cost across the install-name
//! auto-floor — the natural-region link beside the auto-floored link
//! (the same corpus, two stub dylibs of different install-name lengths)
//! over the same corpus shape the M21–M37 parity benches share. The
//! floor is one integer max in the packing loop's `__TEXT` cursor (the
//! growth is computed once from the install names), so parity-or-under
//! is the honest expectation — the bench pins "the knob never regresses
//! the link's hot path" (the same shape gate the M30–M37 benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::Dylib;

const OBJECTS: usize = 64;
const FNS_PER_OBJECT: usize = 4;

/// The two stub dylibs the corpus binds through: install names of
/// different lengths (the growth the auto-floor covers).
fn dylibs() -> Vec<Dylib> {
    let dy = |name: &str, export: &str| Dylib {
        install_name: name.to_string(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![format!("_{export}").into_bytes()],
        weak: false,
        reexport: false,
        lazy: false,
    };
    vec![
        dy("@rpath/lib_with_a_long_install_name.dylib", "fn_a"),
        dy("@rpath/lib_b.dylib", "fn_b"),
    ]
}

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries it) with one undefined reference per dylib export.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(FNS_PER_OBJECT),
                vec![],
            ));
            for f in 0..FNS_PER_OBJECT {
                b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
            }
            b.add_symbol(ObjectSymbol::Undefined {
                name: "_fn_a".into(),
                weak_ref: false,
            });
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_headerpad_max(c: &mut Criterion) {
    let inputs = corpus();
    let dy = dylibs();
    let mut group = c.benchmark_group("headerpad_max");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, floored) in [("natural_region", false), ("auto_floored", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &floored,
            |b, &floored| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        dylibs: dy.clone(),
                        header_pad_max_install_names: floored,
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
    bench_headerpad_max(&mut criterion);
    criterion.final_summary();
}
