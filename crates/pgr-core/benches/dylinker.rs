//! The loader-path bench (M26): the link cost across the `-dylinker`
//! decisions — the hard-coded default (the pre-M26 absence) and two
//! named paths (a short one and a 200-byte one) over the same corpus
//! (64 objects, 256 rebase slots). A decision is one string swap in
//! the `LC_LOAD_DYLINKER` command the header already emits, so the
//! honest expectation is parity — the bench pins "the released surface
//! never regresses into the link's hot path" (the same shape gate the
//! M22 dyld-environment bench rides).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::dylinker::Dylinker;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table so the fixup
/// planner, the trie and the symtab all ride the plan the loader
/// command lands on.
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

/// A 200-byte absolute path (the command's long-form parity arm).
fn long_path() -> String {
    let mut p = String::from("/opt/");
    while p.len() < 200 {
        p.push_str("very/long/");
    }
    p.truncate(200);
    p
}

fn bench_dylinker(c: &mut Criterion) {
    let mut group = c.benchmark_group("dylinker");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions: [(&str, Option<Dylinker>); 3] = [
        ("default_none", None),
        (
            "named_short",
            Some(Dylinker::from_flag("/usr/local/bin/mydyld").expect("validates")),
        ),
        (
            "named_200b",
            Some(Dylinker::from_flag(&long_path()).expect("validates")),
        ),
    ];
    for (name, loader) in &decisions {
        group.bench_with_input(BenchmarkId::new("link_64_objects", name), loader, |b, l| {
            b.iter(|| {
                let cfg = LinkConfig {
                    filetype: OutputType::Execute,
                    dylinker: l.clone(),
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
    bench_dylinker(&mut criterion);
    criterion.final_summary();
}
