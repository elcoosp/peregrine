//! The duplicate-symbol advisory bench (M121): the link cost across the
//! `-warn_duplicate` decision — the advisory tallies the duplicate
//! strong-strong collisions the Pass-2 resolve found (the same collision
//! the `multiply_defined` policy prices) without changing the resolution
//! policy itself (the default `error` still applies unless overridden;
//! the bench rides the `warning` policy so the collisions survive). The
//! smoke gates pin the contract: the on face tallies the collisions, the
//! off face records nothing, and the bytes never move under either face.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::MultiplyDefinedPolicy;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

const PAIRS: usize = 16;

/// `2 * PAIRS` objects: the first half defines `_main` (object 0) and
/// `_fn_N` (objects 1..PAIRS); the second half redefines `_fn_N` — the
/// duplicate strong-strong collisions the advisory tallies (one per
/// pair, under the `warning` policy's first-wins resolution).
fn corpus() -> Vec<LinkInput> {
    (0..PAIRS)
        .flat_map(|i| {
            let make = |name: &str, value: u64| {
                let mut b = ObjectBuilder::new(&format!("wd_{name}.o"));
                let text = b.add_section(ObjectSection::text(
                    "__text",
                    [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                    vec![],
                ));
                b.add_symbol(ObjectSymbol::Defined {
                    name: name.into(),
                    section_index: text,
                    value,
                    weak: false,
                });
                LinkInput {
                    name: format!("wd_{name}.o"),
                    bytes: b.build().expect("the bench object builds"),
                }
            };
            if i == 0 {
                [make("_main", 0), make("_fn_0", 0)]
            } else {
                [make(&format!("_fn_{i}"), 0), make(&format!("_fn_{i}"), 16)]
            }
        })
        .collect()
}

fn bench_warn_duplicate(c: &mut Criterion) {
    // The smoke gates first: the on face tallies the duplicate collisions
    // (PAIRS - 1 of them — `_main` has no twin), the off face records
    // nothing, and the bytes never move under either face (the advisory
    // is a measurement, never a layout product).
    let inputs = corpus();
    let plan_for = |inputs: &[LinkInput], warn: bool| {
        link(
            inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                multiply_defined: MultiplyDefinedPolicy::Warning,
                warn_duplicate: warn,
                ..LinkConfig::default()
            },
        )
        .expect("the corpus links")
    };
    let off = plan_for(&inputs, false);
    let on = plan_for(&inputs, true);
    let off_n = off.resolution.warn_duplicate_open().count();
    let on_n = on.resolution.warn_duplicate_open().count();
    assert_eq!(off_n, 0, "the off face records no duplicate advisory");
    assert_eq!(
        on_n,
        PAIRS - 1,
        "the on face tallies the {pairs} duplicate collisions: counted {on_n}",
        pairs = PAIRS - 1
    );
    assert_eq!(
        off.layout.header_bytes, on.layout.header_bytes,
        "the advisory never moves the bytes"
    );

    let mut group = c.benchmark_group("warn_duplicate");
    group.throughput(Throughput::Elements((2 * PAIRS) as u64));
    let decisions = [("off", false), ("on", true)];
    for (name, warn) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_32_objects", name),
            &warn,
            |b, &warn| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        multiply_defined: MultiplyDefinedPolicy::Warning,
                        warn_duplicate: warn,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.header_bytes.len());
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_warn_duplicate(&mut criterion);
    criterion.final_summary();
}
