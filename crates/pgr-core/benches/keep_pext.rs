//! The private-extern bench (M33): the link cost across the keep
//! decision — the conversion default (a private-extern definition
//! lands in the locals range, `N_SECT | N_PEXT`) and the named keep
//! (`-keep_private_externs`: the row stays external with `N_PEXT` set)
//! over the same corpus (64 objects, half their defs private). The
//! pext-free corpus is the shape-parity gate (pre-M33 bytes under
//! either decision), the pext corpus prices the symtab split.
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
/// carries the entry), a private-extern helper def, and a `__data`
/// rebase table — the corpus the M21–M32 parity benches share, plus
/// the `N_PEXT` input bit the decision reads.
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
                let idx = b.add_symbol(if i == 0 && f == 0 {
                    ObjectSymbol::Defined {
                        name: "_main".into(),
                        section_index: text,
                        value: (f * 4) as u64,
                        weak: false,
                    }
                } else {
                    ObjectSymbol::DefinedPrivate {
                        name: format!("_fn_{i:03}_{f}"),
                        section_index: text,
                        value: (f * 4) as u64,
                    }
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

fn bench_keep_pext(c: &mut Criterion) {
    let mut group = c.benchmark_group("keep_pext");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, keep) in [("converted", false), ("kept", true)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &keep,
            |b, &keep| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        keep_private_externs: keep,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.symbols.len());
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_keep_pext(&mut criterion);
    criterion.final_summary();
}
