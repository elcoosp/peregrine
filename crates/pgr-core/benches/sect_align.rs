//! The sect-align bench (M28): the link cost across the `-sectalign`
//! decisions — the empty default table (the pre-M28 shape) beside
//! raised floors over the same corpus (64 objects, 256 rebase slots,
//! one `__data` and one `__more` section per object). The default is a
//! shape-parity gate — an empty table plans the pre-M28 bytes, so the
//! honest expectation is parity — and the raised floors price the
//! packing loop's realignment: every `__data`/`__more` section shifts
//! to its named boundary (the `__more` floor moves it a page), the
//! decision the packing loop pays once per placed section.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::sect_align::{SectAlign, SectAlignTable};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table and a trailing
/// `__more` section — the two `__DATA` sections the floors name.
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
            let more = b.add_section(ObjectSection::data("__more", vec![0u8; 12], vec![]));
            let target = b.sym_index(first_fn);
            for r in 0..REBASES_PER_OBJECT {
                b.section_mut(data)
                    .relocs
                    .push(ObjectReloc::unsigned(target).at((r * 8) as u32));
            }
            let _ = more;
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// The default table (the pre-M28 shape).
fn no_floors() -> SectAlignTable {
    SectAlignTable::default()
}

/// Raised floors over the corpus's two `__DATA` sections: every
/// `__data` to 0x1000, every `__more` to 0x4000 (a page boundary — the
/// packing loop's realignment shows).
fn raised_floors() -> SectAlignTable {
    let mut t = SectAlignTable::default();
    t.push(SectAlign::from_flag("__DATA", "__data", 0x1000).expect("the floor validates"))
        .expect("one decision per pair");
    t.push(SectAlign::from_flag("__DATA", "__more", 0x4000).expect("the floor validates"))
        .expect("one decision per pair");
    t
}

fn bench_sect_align(c: &mut Criterion) {
    let mut group = c.benchmark_group("sect_align");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, table) in [
        ("floors_default", no_floors()),
        ("floors_raised", raised_floors()),
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &table,
            |b, table| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        sect_aligns: table.clone(),
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
    bench_sect_align(&mut criterion);
    criterion.final_summary();
}
