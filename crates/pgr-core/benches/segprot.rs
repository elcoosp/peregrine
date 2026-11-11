//! The segment-protection bench (M17): the link cost across the
//! `-segprot` decisions — the house table (the empty decision set), a
//! read-only-after-rebase `__DATA_CONST` (`rw`/`r`) and a writable
//! `__TEXT` ceiling (`rwx`/`rx`) over the same corpus (64 objects, 256
//! rebase slots, one bind-free executable surface). The protections are
//! two field writes per planned segment, so the honest expectation is
//! parity — the bench pins "the released surface never regresses into
//! the link's hot path" (the same shape gate the image-base bench
//! rides).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::segprot::{SegName, SegProt, SegProts};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table so the fixup
/// planner, the trie and the symtab all ride the plan the protections
/// land on.
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

/// The decision variants: the house table (empty) and the two named
/// shapes (`__DATA_CONST` read-only after rebase; a `__TEXT` writable
/// ceiling under an RX init).
fn decisions() -> Vec<(&'static str, SegProts)> {
    let mut dataconst_ro = SegProts::default();
    dataconst_ro
        .insert(
            SegName::DataConst,
            SegProt::parse("rw", "r").expect("the decision validates"),
        )
        .expect("one decision per segment");
    let mut text_writable_ceiling = SegProts::default();
    text_writable_ceiling
        .insert(
            SegName::Text,
            SegProt::parse("rwx", "rx").expect("the decision validates"),
        )
        .expect("one decision per segment");
    vec![
        ("house_table", SegProts::default()),
        ("dataconst_ro_after_rebase", dataconst_ro),
        ("text_writable_ceiling", text_writable_ceiling),
    ]
}

fn bench_segprot(c: &mut Criterion) {
    let mut group = c.benchmark_group("segprot");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, prots) in decisions() {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &prots,
            |b, prots| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        entry_symbol: "_main".into(),
                        seg_prots: prots.clone(),
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    let prot_sum: u32 = result
                        .layout
                        .segments
                        .iter()
                        .map(|s| s.maxprot + s.initprot)
                        .sum();
                    black_box(prot_sum);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_segprot(&mut criterion);
    criterion.final_summary();
}
