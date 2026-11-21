//! The category-merging bench (M115): the link cost across the `ObjC`
//! category-merging decision — the default merge (the registration
//! section folds away) and the `-no_objc_category_merging` disable
//! (categories stay as separate sections) over the same corpus (32
//! objects, each carrying a class family, a category family and a
//! one-entry `__objc_catlist`), plus the unmergeable face (a corpus
//! whose categories' base classes arrive at load time — the
//! conservative verbatim shape both faces plan byte-identically, the
//! pre-knob lock the decision never moves).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 32;

/// `OBJECTS` objects: `_main` in the first; each carries
/// `_OBJC_CLASS_$_Dog<i>` and `_OBJC_CATEGORY_$_Dog<i>` in a data
/// section and a one-entry `__DATA,__objc_catlist` registration whose
/// 8-byte pointer slot relocates against the category symbol. With
/// `with_class`, the base class rides the image (mergeable); without,
/// the base arrives at load time (the classifier keeps the section
/// verbatim under either face).
fn corpus(with_class: bool) -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("cat_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(if i == 0 { 2 } else { 1 }),
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".into()
                } else {
                    format!("_fn_{i}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            let data = b.add_section(ObjectSection::data("__objc_data", vec![0u8; 16], vec![]));
            let cat_sym = b.add_symbol(ObjectSymbol::Defined {
                name: format!("_OBJC_CATEGORY_$_Dog{i}"),
                section_index: data,
                value: 0,
                weak: false,
            });
            if with_class {
                b.add_symbol(ObjectSymbol::Defined {
                    name: format!("_OBJC_CLASS_$_Dog{i}"),
                    section_index: data,
                    value: 8,
                    weak: false,
                });
            }
            let catlist =
                b.add_section(ObjectSection::data("__objc_catlist", vec![0u8; 8], vec![]));
            b.section_mut(catlist)
                .relocs
                .push(ObjectReloc::unsigned(cat_sym as u32).at(0));
            LinkInput {
                name: format!("cat_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_no_objc_category_merging(c: &mut Criterion) {
    // The smoke gates first: the merged plan drops the registration
    // section; the disabled plan keeps it; the unmergeable corpus links
    // byte-identical under either face (the decision never moves a
    // shape it cannot merge).
    let mergeable = corpus(true);
    let plan_for = |inputs: &[LinkInput], merging: bool| {
        link(
            inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                objc_category_merging: merging,
                ..LinkConfig::default()
            },
        )
        .expect("the corpus links")
        .layout
    };
    let merged = plan_for(&mergeable, true);
    let disabled = plan_for(&mergeable, false);
    assert!(
        !merged.sections.iter().any(|s| s.name == "__objc_catlist"),
        "the merged plan drops the registration section"
    );
    assert!(
        disabled.sections.iter().any(|s| s.name == "__objc_catlist"),
        "the disabled plan keeps the registration section"
    );
    let external = corpus(false);
    assert_eq!(
        plan_for(&external, true).header_bytes,
        plan_for(&external, false).header_bytes,
        "the unmergeable corpus links byte-identical under either face"
    );

    let mut group = c.benchmark_group("no_objc_category_merging");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions = [("merged_default", true), ("kept_disabled", false)];
    for (name, merging) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_32_objects", name),
            &merging,
            |b, &m| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        objc_category_merging: m,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&mergeable), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.linkedit.uuid_at);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_no_objc_category_merging(&mut criterion);
    criterion.final_summary();
}
