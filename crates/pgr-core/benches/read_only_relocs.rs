//! M111 — the read-only-relocations policy (`-read_only_relocs
//! <policy>`): the three-face shape gate over the 64-object corpus (a
//! `__TEXT` pointer slot per object — the target the policy prices).
//! The `error` face refuses (the bench prices the refusal walk), the
//! `warning`/`suppress` faces link (identical images, the advisory the
//! only delta).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox (bounded `--measurement-time 1`).

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::ReadOnlyRelocsPolicy;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::hint::black_box;

const OBJECTS: usize = 64;

fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("o{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                vec![0xC0u8, 0x03, 0x5F, 0xD6],
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_fn_{i:03}"),
                section_index: text,
                value: 0,
                weak: false,
            });
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            let def = b.add_symbol(ObjectSymbol::Defined {
                name: format!("_table_{i:03}"),
                section_index: data,
                value: 0,
                weak: false,
            });
            let slot = b.sym_index(def);
            let c = b.add_section(ObjectSection::data("__const", vec![0u8; 8], vec![]));
            b.section_mut(c)
                .relocs
                .push(ObjectReloc::unsigned(slot).at(0));
            let bytes = b.build().expect("the fixture object builds");
            LinkInput {
                name: format!("o{i:03}.o"),
                bytes,
            }
        })
        .collect()
}

fn bench_read_only_relocs(c: &mut Criterion) {
    let inputs = corpus();
    let mut group = c.benchmark_group("read_only_relocs");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for policy in [
        ReadOnlyRelocsPolicy::Error,
        ReadOnlyRelocsPolicy::Warning,
        ReadOnlyRelocsPolicy::Suppress,
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", policy.flag_word()),
            &policy,
            |b, &p| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        read_only_relocs: p,
                        ..LinkConfig::default()
                    };
                    black_box(link(black_box(&inputs), &[], &cfg).is_ok())
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_read_only_relocs(&mut criterion);
    criterion.final_summary();
}
