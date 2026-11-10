//! The image-base bench (M15): the link cost across the
//! `-pagezero_size` decisions — the 4 GiB default, a 1 GiB base and a
//! 16 MiB base over the same corpus (64 objects, 256 binds, one rebase
//! table). The base is address arithmetic on the emit plan (every
//! vmaddr is `fileoff + base`), so the honest expectation is parity —
//! the bench pins "the released surface never regresses into the link's
//! hot path" (the same shape gate the dylib-surface bench rides).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::pagezero::PageZero;

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table so the fixup
/// planner, the trie and the symtab all ride the base.
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

fn bench_pagezero(c: &mut Criterion) {
    let mut group = c.benchmark_group("pagezero");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, base) in [
        ("default_4gib", None),
        ("custom_1gib", Some(0x4000_0000u64)),
        ("custom_16mib", Some(0x0100_0000u64)),
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &base,
            |b, base| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        entry_symbol: "_main".into(),
                        pagezero: base
                            .map(PageZero::from_override)
                            .transpose()
                            .expect("the bench base validates")
                            .unwrap_or_default(),
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.image_base);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_pagezero(&mut criterion);
    criterion.final_summary();
}
