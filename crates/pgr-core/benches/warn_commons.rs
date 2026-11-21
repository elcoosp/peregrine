//! The common-symbol advisory bench (M116): the link cost across the
//! `-warn_commons` decision — the advisory face is a measurement, never
//! a layout product (the M109 pattern's face), so the shape-parity gate
//! is the byte-identity lock: the decision on/off plans identical
//! header bytes over the same commons-bearing corpus (32 objects, each
//! carrying one tentative definition — half resolved against a linked
//! dylib export, half landing as the local definition), and the
//! advisory walk's entries derive on the on face only.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::{CommonsPolicy, Dylib};

const OBJECTS: usize = 32;

/// `OBJECTS` objects: `_main` in the first; each carries one tentative
/// definition (`N_UNDF | N_EXT`, non-zero value — the common shape) —
/// even objects' commons ride unshadowed (the local definition the
/// advisory's landing names), odd objects' commons resolve against the
/// linked dylib's export under `-commons use_extern` (the landing the
/// dylib face names).
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = pgr_fixtures::ObjectBuilder::new(&format!("commons_{i:03}.o"));
            let text = b.add_section(pgr_fixtures::ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(if i == 0 { 2 } else { 1 }),
                vec![],
            ));
            b.add_symbol(pgr_fixtures::ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".into()
                } else {
                    format!("_fn_{i}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            b.add_symbol(pgr_fixtures::ObjectSymbol::Common {
                name: format!("_shared_{i}"),
                size: 32,
                align_log2: 3,
            });
            LinkInput {
                name: format!("commons_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// The dylib half of the corpus: one dylib exporting every odd object's
/// common name (the `-commons use_extern` face's landing surface).
fn dylibs() -> Vec<Dylib> {
    let exports: Vec<Vec<u8>> = (0..OBJECTS)
        .filter(|i| i % 2 == 1)
        .map(|i| format!("_shared_{i}").into_bytes())
        .collect();
    vec![Dylib {
        install_name: "@rpath/libcommons.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports,
        weak: false,
        lazy: false,
        upward: false,
        reexport: false,
        needed: false,
        hidden: false,
    }]
}

fn bench_warn_commons(c: &mut Criterion) {
    // The smoke gates first: the decision never moves the bytes (the
    // header parity under the default commons policy and under
    // use_extern alike), and the entries derive on the on face only.
    let inputs = corpus();
    let dylib_list = dylibs();
    let plan_for = |commons: CommonsPolicy, warn: bool| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                dylibs: dylib_list.clone(),
                commons,
                warn_commons: warn,
                ..LinkConfig::default()
            },
        )
        .expect("the corpus links")
    };
    for commons in [CommonsPolicy::UseDylibs, CommonsPolicy::UseExtern] {
        let off = plan_for(commons, false);
        let on = plan_for(commons, true);
        assert_eq!(
            off.layout.header_bytes, on.layout.header_bytes,
            "the advisory face never moves the bytes ({commons:?})"
        );
        assert!(
            on.resolution.warn_commons_open().count() > 0,
            "the on face derives the landing entries ({commons:?})"
        );
        assert!(
            off.resolution.warn_commons_open().count() == 0,
            "the off decision records nothing ({commons:?})"
        );
    }

    let mut group = c.benchmark_group("warn_commons");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions = [("advisory_off", false), ("advisory_on", true)];
    for (name, warn) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_32_objects", name),
            &warn,
            |b, &warn| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        dylibs: dylib_list.clone(),
                        commons: CommonsPolicy::UseDylibs,
                        warn_commons: warn,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.resolution.warn_commons_open().count());
                    black_box(result.layout.linkedit.uuid_at);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_warn_commons(&mut criterion);
    criterion.final_summary();
}
