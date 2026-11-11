//! The stack-reserve bench (M18): the link cost across the
//! `-stack_size` decisions — the zero default, a 16 MiB reserve and a
//! 1 GiB reserve over the same corpus (64 objects, 256 rebase slots,
//! one bind-free executable surface). The reserve is one field write in
//! the 24-byte `LC_MAIN` (the command size is unchanged), so the honest
//! expectation is parity — the bench pins "the released surface never
//! regresses into the link's hot path" (the same shape gate the
//! image-base and segment-protection benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::stack_size::StackSize;

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table so the fixup
/// planner, the trie and the symtab all ride the plan the reserve
/// rides.
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

fn bench_stack_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("stack_size");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, reserve) in [
        ("default_zero", None),
        ("reserve_16mib", Some(0x100_0000u64)),
        ("reserve_1gib", Some(0x4000_0000u64)),
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &reserve,
            |b, reserve| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        entry_symbol: "_main".into(),
                        stack_size: reserve
                            .map(StackSize::from_override)
                            .transpose()
                            .expect("the bench reserve validates"),
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.entryoff_at);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_stack_size(&mut criterion);
    criterion.final_summary();
}
