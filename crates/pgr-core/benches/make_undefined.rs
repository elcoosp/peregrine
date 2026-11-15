//! The make-undefined bench (M39): the link cost across the `-U`
//! decisions — the empty table (the pre-M39 default) and two populated
//! tables (8 and 64 marks) over the same corpus (64 objects, 256
//! rebase slots). A mark is one dropped definition at install time (no
//! symtab row, no trie node, no `__common` slot), so the honest
//! expectation is parity-or-under — the bench pins "the released
//! surface never regresses into the link's hot path" (the same shape
//! gate the M24/M21 benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::make_undefined::MakeUndefined;
use pgr_core::resolve::UndefinedPolicy;

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table so the fixup
/// planner, the trie and the symtab all ride the plan the marks land
/// on.
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

/// A mark list with `n` decisions (the flag order the resolve pins),
/// each naming a real definition the way an override sweep does.
fn marks(n: usize) -> MakeUndefined {
    let mut t = MakeUndefined::new();
    for i in 0..n {
        // obj 000 carries the entry — never marked; the corpus's other
        // 63 objects carry four functions each, so 64 distinct marks
        // name obj 1..63's first functions and then obj 1's second.
        let obj = (i % (OBJECTS - 1)) + 1;
        let f = i / (OBJECTS - 1);
        t.push(
            pgr_core::MakeUndefinedName::from_flag(&format!("_fn_{obj:03}_{f}"))
                .expect("the bench mark validates"),
        )
        .expect("the bench list builds");
    }
    t
}

fn bench_make_undefined(c: &mut Criterion) {
    let mut group = c.benchmark_group("make_undefined");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, n) in [("default_0", 0usize), ("marks_8", 8), ("marks_64", 64)] {
        group.bench_with_input(BenchmarkId::new("link_64_objects", name), &n, |b, &n| {
            b.iter(|| {
                let cfg = LinkConfig {
                    filetype: OutputType::Execute,
                    make_undefined: marks(n),
                    // The marked names' references (the rebase slots)
                    // ride the dynamic lookup — the corpus links under
                    // the default `-undefined error` otherwise.
                    undefined_policy: UndefinedPolicy::DynamicLookup,
                    ..LinkConfig::default()
                };
                let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                black_box(result.layout.header_bytes.len());
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_make_undefined(&mut criterion);
    criterion.final_summary();
}
