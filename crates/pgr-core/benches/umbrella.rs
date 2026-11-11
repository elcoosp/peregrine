//! The umbrella-region bench (M20): the link cost across the
//! `-sub_umbrella`/`-sub_library` decisions — the empty table (the
//! pre-M20 default) and two populated regions (8 and 64 members) over
//! the same corpus (64 objects, 256 rebase slots, one bind-free dylib
//! surface). A member is one 16-32 byte `LC_SUB_UMBRELLA`/`LC_SUB_LIBRARY`
//! command in the identity block, so the honest expectation is parity
//! — the bench pins "the released surface never regresses into the
//! link's hot path" (the same shape gate the image-base bench rides).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::umbrella::{Umbrella, UmbrellaKind, UmbrellaMember};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table so the fixup
/// planner, the trie and the symtab all ride the plan the region lands
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

/// An umbrella region with `n` members alternating the kinds (the flag
/// order the emit pins).
fn region(n: usize) -> Umbrella {
    let mut u = Umbrella::new();
    for i in 0..n {
        let kind = if i % 2 == 0 {
            UmbrellaKind::SubUmbrella
        } else {
            UmbrellaKind::SubLibrary
        };
        u.push(
            UmbrellaMember::from_flag(kind, &format!("libmember_{i:04}.dylib"))
                .expect("the bench member validates"),
        )
        .expect("the bench region builds");
    }
    u
}

fn bench_umbrella(c: &mut Criterion) {
    let mut group = c.benchmark_group("umbrella");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, members) in [("default_0", 0usize), ("region_8", 8), ("region_64", 64)] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &members,
            |b, &members| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Dylib,
                        install_name: Some("@rpath/libbench.dylib".into()),
                        umbrella: region(members),
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
    bench_umbrella(&mut criterion);
    criterion.final_summary();
}
