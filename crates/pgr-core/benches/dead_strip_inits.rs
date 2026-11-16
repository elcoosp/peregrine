//! The dead-strip init/term-roots bench (M52): the link cost across the
//! `-no_dead_strip_inits_and_terms` decisions — the term-strip default
//! (the pre-M52 shape) and the rooted term sections over the same
//! corpus (64 objects, one unreferenced `__mod_term_func` entry each).
//! A root keeps a body the strip would drop, so the honest expectation
//! is a small kept-bytes win for the knob and parity in plan cost — the
//! bench pins "the released surface never regresses into the link's
//! hot path" (the M43 ObjC-pull bench's shape).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;

/// `OBJECTS` small objects: the first carries `_main`; every object
/// carries one unreferenced `_term_fn` and its `__mod_term_func`
/// pointer slot — the atom the decision keeps or strips.
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b =
                ObjectBuilder::new(&format!("obj_{i:03}.o")).set_subsections_via_symbols(true);
            let n_fns = if i == 0 { 3 } else { 2 };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
                vec![],
            ));
            for f in 0..n_fns {
                let name = match (i, f) {
                    (0, 0) => "_main".to_string(),
                    (_, 1) => format!("_term_{i:03}"),
                    (0, _) => format!("_fn_{i:03}_{f}"),
                    _ => format!("_fn_{i:03}"),
                };
                b.add_symbol(ObjectSymbol::Defined {
                    name,
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
            }
            let term_fn = if i == 0 { 2 } else { 1 };
            let modterm = b.add_section(ObjectSection::data(
                "__mod_term_func",
                vec![0u8; 8],
                vec![ObjectReloc::unsigned(term_fn as u32).at(0)],
            ));
            b.section_mut(modterm).flags = pgr_format::consts::S_MOD_TERM_FUNC_POINTERS;
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_dead_strip_inits(c: &mut Criterion) {
    let mut group = c.benchmark_group("dead_strip_inits");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for name in ["term_strip_default", "inits_and_terms_rooted"] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &name,
            |b, name| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        dead_strip: true,
                        no_dead_strip_inits_and_terms: *name == "inits_and_terms_rooted",
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
    bench_dead_strip_inits(&mut criterion);
    criterion.final_summary();
}
