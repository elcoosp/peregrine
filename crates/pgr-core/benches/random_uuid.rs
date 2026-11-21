//! The random-UUID bench (M114): the link cost across the typed UUID
//! source — the content-derived default (the M32 pattern's derivation),
//! the random draw (`-random_uuid`, the emit's own identity), and the
//! none suppression (`-no_uuid`, one command narrower) over the same
//! corpus (64 objects, 4 rebases each — the corpus the M32/M99 uuid
//! benches share). The source is a plan-level decision (the command
//! rides for `content`/`random`, drops for `none`), so the honest
//! expectation is parity between the two carried faces and one command
//! less for the suppressed one — the smoke gates pin it: the content
//! and random plans' header blocks are byte-identical (the source is
//! the emit's identity write, never the plan's), and the suppressed
//! plan is exactly one 24-byte command narrower.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType, UuidSource};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table — the corpus the
/// M32/M99 uuid benches share (the header shape is what the identity
/// decision sizes).
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

fn bench_random_uuid(c: &mut Criterion) {
    // The smoke gates first: the source never moves the carried plan —
    // the content and random layouts' header blocks are byte-identical
    // (the identity write is the emit's, not the plan's), and the
    // suppressed layout is exactly one command narrower.
    let inputs = corpus();
    let plan_for = |source| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                uuid_source: source,
                ..LinkConfig::default()
            },
        )
        .expect("the corpus links")
        .layout
    };
    let content = plan_for(UuidSource::Content);
    let random = plan_for(UuidSource::Random);
    let suppressed = plan_for(UuidSource::None);
    assert_eq!(
        content.header_bytes, random.header_bytes,
        "the carried faces' plans are byte-identical (the source is the emit's \
         identity write, never the plan's)"
    );
    assert_eq!(
        content.header_bytes.len() - suppressed.header_bytes.len(),
        24,
        "the suppressed face is exactly the LC_UUID command's 24 bytes"
    );

    let mut group = c.benchmark_group("random_uuid");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions = [
        ("content_default", UuidSource::Content),
        ("random_draw", UuidSource::Random),
        ("none_suppressed", UuidSource::None),
    ];
    for (name, source) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &source,
            |b, &source| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        uuid_source: source,
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
    bench_random_uuid(&mut criterion);
    criterion.final_summary();
}
