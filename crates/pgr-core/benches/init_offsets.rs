//! The initializer-offsets bench (M16): the link cost across the
//! initializer-form decisions — the classic pointer sections (the
//! default) and the `__init_offsets` transform — over the same corpus
//! (32 objects, one `__mod_init_func` section each, 4 initializers per
//! object, chained *and* classic fixup paths). The transform is
//! bucketing-time removal plus one synthetic u32 piece, so the honest
//! expectation is parity-to-slightly-faster on the offsets side (two
//! fewer rebases per object leave the fixup payload); the bench pins
//! "the released surface never regresses into the link's hot path" (the
//! same shape gate the pagezero bench rides).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::init_offsets::InitOffsets;
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 32;
const INITS_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry) plus a `__mod_init_func` section of
/// `INITS_PER_OBJECT` pointers, so the collector, the bucketing skip and
/// the Pass-3 fill all ride the decision.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let n_fns = if i == 0 {
                1 + INITS_PER_OBJECT
            } else {
                INITS_PER_OBJECT
            };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
                vec![],
            ));
            for f in 0..n_fns {
                b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_init_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
            }
            let mut relocs = Vec::new();
            for r in 0..INITS_PER_OBJECT {
                relocs.push(ObjectReloc::unsigned(r as u32).at((r * 8) as u32));
            }
            let modinit = b.add_section(ObjectSection::data(
                "__mod_init_func",
                vec![0u8; INITS_PER_OBJECT * 8],
                relocs,
            ));
            b.section_mut(modinit).flags = pgr_format::consts::S_MOD_INIT_FUNC_POINTERS;
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_init_offsets(c: &mut Criterion) {
    let mut group = c.benchmark_group("init_offsets");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    // macOS 12.0 — at the chained-fixups floor, where the named form is
    // consumable on both fixup paths.
    let offsets =
        InitOffsets::from_flag(Some(true), pgr_format::consts::PLATFORM_MACOS, 0x000C_0000)
            .expect("macos 12.0 validates");
    for (name, form) in [
        ("classic_pointers", InitOffsets::Classic),
        ("init_offsets", offsets),
    ] {
        for path in ["chained", "classic_streams"] {
            group.bench_with_input(
                BenchmarkId::new(format!("link_{path}_32_objects"), name),
                &form,
                |b, form| {
                    b.iter(|| {
                        let cfg = LinkConfig {
                            entry_symbol: "_main".into(),
                            fixup_chains: path == "chained",
                            init_offsets: *form,
                            ..LinkConfig::default()
                        };
                        let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                        black_box(
                            result
                                .layout
                                .sections
                                .iter()
                                .filter(|s| s.name == "__init_offsets")
                                .count(),
                        );
                    });
                },
            );
        }
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_init_offsets(&mut criterion);
    criterion.final_summary();
}
