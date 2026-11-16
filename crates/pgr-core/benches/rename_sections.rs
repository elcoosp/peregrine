//! The section-rename bench (M53): the link cost across the
//! `-rename_section` decisions — the empty map (the pre-M53 shape) and
//! a 64-entry rename map over the same corpus (64 objects, one
//! `__DATA,__data` and one `__DATA,__mydata` section each, every
//! `__mydata` renamed onto `__DATA_CONST`). A rename is one map lookup
//! per classified section (the first match wins, the flag-order walk),
//! so the honest expectation is near-parity: the lookup rides the
//! classification the link already pays, and the renamed sections
//! group into buckets the packer plans the same way.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::rename::SectionRenames;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;

/// The rename map: every object's `__DATA,__mydata` renames onto
/// `__DATA_CONST,__mydata` — one shared entry (the sources collide on
/// purpose: one rename per distinct pair, the map the classification
/// consults per section).
fn rename_map() -> SectionRenames {
    SectionRenames::new(vec![("__DATA", "__mydata", "__DATA_CONST", "__mydata")])
        .expect("the rename map validates")
}

/// `OBJECTS` small objects: the first carries `_main`; every object
/// carries one `__TEXT,__text`, one `__DATA,__data` and one
/// `__DATA,__mydata` section — the section the map renames.
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b =
                ObjectBuilder::new(&format!("obj_{i:03}.o")).set_subsections_via_symbols(true);
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            let data = b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
            let mine = b.add_section(ObjectSection::data("__mydata", vec![0x42u8; 8], vec![]));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".to_string()
                } else {
                    format!("_fn_{i:03}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_data_{i:03}"),
                section_index: data,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_mydata_{i:03}"),
                section_index: mine,
                value: 0,
                weak: false,
            });
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_rename_sections(c: &mut Criterion) {
    let mut group = c.benchmark_group("rename_sections");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for name in ["pairs_unnamed", "renamed"] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &name,
            |b, name| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        renames: if *name == "renamed" {
                            rename_map()
                        } else {
                            SectionRenames::default()
                        },
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.sections.len());
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_rename_sections(&mut criterion);
    criterion.final_summary();
}
