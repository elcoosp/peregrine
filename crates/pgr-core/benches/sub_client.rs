//! The sub-client bench (M21): the link cost across the `-sub_client`
//! decisions — the empty list (the pre-M21 default) and two populated
//! lists (8 and 64 clients) over the same corpus (64 objects, 256
//! rebase slots, one bind-free dylib surface). A client is one 16-24
//! byte `LC_SUB_CLIENT` command in the identity block, so the honest
//! expectation is parity — the bench pins "the released surface never
//! regresses into the link's hot path" (the same shape gate the M20
//! umbrella bench rides).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::sub_client::{SubClient, SubClientEntry};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table so the fixup
/// planner, the trie and the symtab all ride the plan the clients land
/// on.
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

/// A client list with `n` entries (the flag order the emit pins).
fn clients(n: usize) -> SubClient {
    let mut t = SubClient::new();
    for i in 0..n {
        t.push(
            SubClientEntry::from_flag(&format!("com.example.client_{i:04}"))
                .expect("the bench client validates"),
        )
        .expect("the bench list builds");
    }
    t
}

fn bench_sub_client(c: &mut Criterion) {
    let mut group = c.benchmark_group("sub_client");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, n) in [("default_0", 0usize), ("clients_8", 8), ("clients_64", 64)] {
        group.bench_with_input(BenchmarkId::new("link_64_objects", name), &n, |b, &n| {
            b.iter(|| {
                let cfg = LinkConfig {
                    filetype: OutputType::Dylib,
                    install_name: Some("@rpath/libbench.dylib".into()),
                    sub_clients: clients(n),
                    ..LinkConfig::default()
                };
                let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                black_box(result.layout.header_bytes.len());
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_sub_client(&mut criterion);
    criterion.final_summary();
}
