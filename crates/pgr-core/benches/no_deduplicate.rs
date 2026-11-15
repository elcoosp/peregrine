//! The no-deduplicate bench (M41): the link cost across the dedup
//! decision — the duplicate-literal corpus under the default (the D4
//! merge collapses the duplicates, every reference remaps) beside the
//! named toggle over the same corpus (every literal rides verbatim) —
//! over the same corpus shape the M21–M40 parity benches share. The
//! toggle *removes* work on the plan side (no dedup map, no remap
//! entries) and adds bytes on the copy side, so the honest expectation
//! is parity-or-under — the bench pins "the knob never regresses the
//! link's hot path" (the same shape gate the M30–M40 benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use core::fmt::Write as _;
use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const LITERALS_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries it), one `__cstring` section of four literals — half of
/// them shared across every object (the merge's input shape), half
/// unique to the object.
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
            let mut data = String::new();
            for l in 0..LITERALS_PER_OBJECT {
                if l % 2 == 0 {
                    data.push_str("shared literal across the corpus");
                } else {
                    let _ = write!(data, "unique literal {i:03}_{l}");
                }
                data.push('\0');
            }
            let cstr = b.add_section(ObjectSection::cstring(&data));
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_str_{i:03}"),
                section_index: cstr,
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

fn bench_no_deduplicate(c: &mut Criterion) {
    let inputs = corpus();
    let mut group = c.benchmark_group("no_deduplicate");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, suppressed) in [("default_merged", false), ("suppressed", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &suppressed,
            |b, &suppressed| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        deduplicate: !suppressed,
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
    bench_no_deduplicate(&mut criterion);
    criterion.final_summary();
}
