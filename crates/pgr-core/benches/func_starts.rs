//! The function-starts bench (M31): the link cost across the
//! suppression decision — the default (the `LC_FUNCTION_STARTS`
//! command rides, the ULEB stream encodes every `__text` symbol) and
//! the named suppression (no command, no slot) over the same corpus
//! (64 objects, 256 rebase slots). The default is a shape-parity gate
//! (pre-M31 bytes), the suppression prices the header-assembly
//! simplification — the honest expectation is parity-to-slightly-
//! faster, never a regression into the hot path.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table — the corpus the
/// M21–M30 parity benches share (the `__text` symbol surface is what
/// the function-starts stream encodes).
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let n_fns = if i == 0 { 2 } else { 4 };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
                vec![],
            ));
            let mut first_fn = 0usize;
            for f in 0..n_fns {
                let idx = b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
                if f == 0 {
                    first_fn = idx;
                }
            }
            let data = b.add_section(ObjectSection::data(
                "__data",
                vec![0u8; REBASES_PER_OBJECT * 8],
                vec![],
            ));
            let target = b.sym_index(first_fn);
            for r in 0..REBASES_PER_OBJECT {
                b.section_mut(data)
                    .relocs
                    .push(ObjectReloc::unsigned(target).at((r * 8) as u32));
            }
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_function_starts(c: &mut Criterion) {
    let mut group = c.benchmark_group("func_starts");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, keep) in [("default", true), ("suppressed", false)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &keep,
            |b, &keep| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        function_starts: keep,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.func_starts.len());
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_function_starts(&mut criterion);
    criterion.final_summary();
}
