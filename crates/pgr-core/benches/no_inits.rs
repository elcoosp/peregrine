//! The init/term suppression bench (M117): the link cost across the
//! `-no_inits` decision — the default keeps the init/term pointer
//! sections (every pre-knob link byte-identical), the suppression drops
//! them entirely (no bucket, no placed bytes, no fixup slots), and a
//! corpus without init/term sections links byte-identical under either
//! face (the decision never moves a byte it has nothing to drop). The
//! smoke gates also pin the `LC_ROUTINES_64` drop: the dylib header's
//! command rides only while init machinery remains.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_MOD_INIT_FUNC_POINTERS, S_MOD_TERM_FUNC_POINTERS};

const OBJECTS: usize = 32;

/// `OBJECTS` objects: `_main` in the first; each carries one
/// initializer and one terminator body, each targeted by one 8-byte
/// pointer slot in its `__mod_init_func` / `__mod_term_func` section —
/// the machinery the decision drops.
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("inits_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(if i == 0 { 4 } else { 2 }),
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
            let init_ptr = b.add_symbol(ObjectSymbol::Defined {
                name: format!("_init_ptr_{i}"),
                section_index: text,
                value: 4,
                weak: false,
            });
            let term_ptr = b.add_symbol(ObjectSymbol::Defined {
                name: format!("_term_ptr_{i}"),
                section_index: text,
                value: 8,
                weak: false,
            });
            let modinit = b.add_section(ObjectSection::data(
                "__mod_init_func",
                vec![0u8; 8],
                vec![ObjectReloc::unsigned(init_ptr as u32).at(0)],
            ));
            b.section_mut(modinit).flags = S_MOD_INIT_FUNC_POINTERS;
            let modterm = b.add_section(ObjectSection::data(
                "__mod_term_func",
                vec![0u8; 8],
                vec![ObjectReloc::unsigned(term_ptr as u32).at(0)],
            ));
            b.section_mut(modterm).flags = S_MOD_TERM_FUNC_POINTERS;
            LinkInput {
                name: format!("inits_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// A plain corpus: no init/term machinery at all (the byte-identity
/// lock's subject).
fn plain_corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("plain_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(if i == 0 { 4 } else { 1 }),
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
            LinkInput {
                name: format!("plain_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_no_inits(c: &mut Criterion) {
    // The smoke gates first: the carrying corpus keeps its sections by
    // default and drops them under the suppression; the plain corpus
    // links byte-identical under either face.
    let inputs = corpus();
    let plan_for = |inputs: &[LinkInput], no_inits: bool| {
        link(
            inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                no_inits,
                ..LinkConfig::default()
            },
        )
        .expect("the corpus links")
        .layout
    };
    let carried = plan_for(&inputs, false);
    let suppressed = plan_for(&inputs, true);
    assert!(
        carried
            .sections
            .iter()
            .any(|s| s.name == "__mod_init_func" && s.seg_name == "__DATA"),
        "the default keeps the initializer pointers"
    );
    assert!(
        carried
            .sections
            .iter()
            .any(|s| s.name == "__mod_term_func" && s.seg_name == "__DATA"),
        "the default keeps the terminator pointers"
    );
    assert!(
        !suppressed
            .sections
            .iter()
            .any(|s| s.name == "__mod_init_func")
            && !suppressed
                .sections
                .iter()
                .any(|s| s.name == "__mod_term_func")
            && !suppressed
                .sections
                .iter()
                .any(|s| s.name == "__init_offsets"),
        "the suppression drops the init/term sections entirely"
    );
    let plain = plain_corpus();
    assert_eq!(
        plan_for(&plain, false).header_bytes,
        plan_for(&plain, true).header_bytes,
        "a corpus without init sections links byte-identical under either face"
    );

    let mut group = c.benchmark_group("no_inits");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions = [("carried_default", false), ("suppressed", true)];
    for (name, no_inits) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_32_objects", name),
            &no_inits,
            |b, &no_inits| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        no_inits,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
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
    bench_no_inits(&mut criterion);
    criterion.final_summary();
}
