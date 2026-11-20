//! The named-UUID bench (M99): the link cost across the named-UUID
//! decision — the content-derived default (the uuid field zeroed in the
//! header bytes for the emit's two-pass derivation) and the named value
//! (the config's own 16 bytes riding the same field) over the same
//! corpus (64 objects, 256 rebase slots). The decision is an emit-side
//! identity write — the plan never moves — so the honest expectation is
//! parity, and the smoke gate pins it byte-for-byte (the two layouts'
//! header blocks are identical; only the emit's 16-byte identity write
//! differs, the derivation dropped for the named bytes).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table — the corpus the
/// M32 uuid bench shares (the header shape is what the identity
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

fn bench_named_uuid(c: &mut Criterion) {
    // The smoke gate first: the decision never moves the plan — the
    // named layout's header block is byte-identical to the derived
    // default's (the identity write is the emit's, not the plan's).
    let inputs = corpus();
    let derived = link(
        &inputs,
        &[],
        &LinkConfig {
            filetype: OutputType::Execute,
            ..LinkConfig::default()
        },
    )
    .expect("the corpus links")
    .layout;
    let named = link(
        &inputs,
        &[],
        &LinkConfig {
            filetype: OutputType::Execute,
            named_uuid: Some([
                0x7d, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d, 0x6e,
                0x7f, 0x80,
            ]),
            ..LinkConfig::default()
        },
    )
    .expect("the corpus links")
    .layout;
    assert_eq!(
        derived.header_bytes, named.header_bytes,
        "the decision never moves the plan (the uuid field rides zeroed either way)"
    );
    assert_eq!(
        named.named_uuid,
        Some([
            0x7d, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d, 0x6e,
            0x7f, 0x80,
        ]),
        "the plan echoes the named identity"
    );

    let mut group = c.benchmark_group("named_uuid");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions = [
        ("derived_default", None),
        (
            "named_value",
            Some([
                0x7du8, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d,
                0x6e, 0x7f, 0x80,
            ]),
        ),
    ];
    for (name, value) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &value,
            |b, value| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        named_uuid: *value,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.named_uuid);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_named_uuid(&mut criterion);
    criterion.final_summary();
}
