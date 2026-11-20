//! The symtab-shaping bench (M104): the link cost across the
//! `-keep_local_symbols`/`-x` decisions — the kept default (the
//! pre-M104 shape, ld64's own default: `kLocalSymbolsAll`) and the
//! dropped face (`-x`: the plain local-symbol subrange leaves the
//! output symtab, the string table shrinks with the names) over the
//! same corpus (64 objects, every one carrying section-defined statics
//! plus name-only locals, 256 rebase slots). The drop only moves the
//! symtab builder's subrange and the strtab's tail, so the honest
//! expectation is a narrow win on the shaped face — the bench pins
//! "the released surface never regresses into the link's hot path".
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), two section-defined statics and two name-only
/// locals per object (the plain local-symbol subrange the decision
/// shapes), plus a `__data` rebase table so the fixup planner, the
/// trie and the symtab all ride the plan the subrange rides on.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let n_fns = if i == 0 { 2 } else { 4 };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns + 2),
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
            // The plain locals: two section-defined statics (the
            // `N_SECT & ~N_EXT` shape) and two name-only locals (the
            // absolute-riding shape) per object.
            for l in 0..2 {
                b.add_symbol(ObjectSymbol::LocalDefined {
                    name: format!("_local_{i:03}_{l}"),
                    section_index: text,
                    value: ((n_fns + l) * 4) as u64,
                });
                b.add_symbol(ObjectSymbol::Local(format!("ltmp_{i:03}_{l}")));
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

fn bench_keep_local_symbols(c: &mut Criterion) {
    let mut group = c.benchmark_group("keep_local_symbols");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for name in ["kept_default", "x_dropped"] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &name,
            |b, name| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        keep_local_symbols: *name == "kept_default",
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.file_size);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_keep_local_symbols(&mut criterion);
    criterion.final_summary();
}
