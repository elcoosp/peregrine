//! The data-in-code bench (M30): the link cost across the carriage's
//! shapes — the entry-free corpus (the pre-M30 default bytes), the
//! carried stream (8 entries per object, 64 objects) and the named
//! suppression — over the same corpus (64 objects, 256 rebase slots).
//! An entry is one Pass-1 decode, one atom-map containment check and
//! 8 `__LINKEDIT` bytes, so the honest expectation is parity — the
//! bench pins "the released surface never regresses into the link's
//! hot path" (the same shape gate the M21–M29 benches ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_format::DataInCodeEntry;

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;
const ENTRIES_PER_OBJECT: usize = 8;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table — the corpus the
/// M21–M29 parity benches share, widened with per-object data-in-code
/// entries when the shape names them (one entry per 8-byte function
/// slot inside `__text`).
fn corpus(entries_per_object: usize) -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let n_fns = if i == 0 { 2 } else { 4 };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns * ENTRIES_PER_OBJECT.max(1)),
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
                    value: (f * 4 * ENTRIES_PER_OBJECT.max(1)) as u64,
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
            if entries_per_object > 0 {
                let b = b.set_data_in_code(
                    (0..entries_per_object)
                        .map(|f| DataInCodeEntry {
                            offset: (f * 4) as u32,
                            length: 4,
                            kind: 1,
                        })
                        .collect(),
                );
                return LinkInput {
                    name: format!("obj_{i:03}.o"),
                    bytes: b.build().expect("the bench object builds"),
                };
            }
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_data_in_code(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_in_code");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, entries) in [("default_0", 0usize), ("dice_8", ENTRIES_PER_OBJECT)] {
        let inputs = corpus(entries);
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &entries,
            |b, _| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.data_in_code.len());
                });
            },
        );
    }
    // The named suppression rides the same corpus with entries — the
    // decision the flag buys (no stream, no slot, no command).
    let inputs = corpus(ENTRIES_PER_OBJECT);
    group.bench_with_input(
        BenchmarkId::new("link_64_objects", "suppressed"),
        &0usize,
        |b, _| {
            b.iter(|| {
                let cfg = LinkConfig {
                    filetype: OutputType::Execute,
                    data_in_code: false,
                    ..LinkConfig::default()
                };
                let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                black_box(result.layout.data_in_code.len());
            });
        },
    );
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_data_in_code(&mut criterion);
    criterion.final_summary();
}
