//! The bundle-loader bench (M25): the link cost across the
//! `-bundle_loader` decisions — no loader (the pre-M25 default; the
//! bundle's externals ride `-undefined dynamic_lookup`) beside a loader
//! surface resolving the same 64 externals — over the same corpus (64
//! bundle objects, 256 rebase slots). A loader decision is a Pass-2
//! set insert and one ordinal arm per bind, so the honest expectation
//! is parity — the bench pins "the released surface never regresses
//! into the link's hot path" (the same shape gate the M21–M24 benches
//! ride).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::bundle_loader::BundleLoader;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const EXTERNS_PER_OBJECT: usize = 1;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` bundle objects: one `_main`-candidate each (only the first
/// carries the entry), `EXTERNS_PER_OBJECT` unresolved externals the
/// loader resolves, plus a `__data` rebase table so the fixup planner,
/// the trie and the symtab all ride the plan the loader binds land on.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            for f in 0..2 {
                b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".into()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
            }
            for e in 0..EXTERNS_PER_OBJECT {
                b.add_symbol(ObjectSymbol::Undefined {
                    name: format!("_host_{e:03}"),
                    weak_ref: false,
                });
            }
            let data = b.add_section(ObjectSection::data(
                "__data",
                vec![0u8; REBASES_PER_OBJECT * 8],
                vec![],
            ));
            let target = b.sym_index(0);
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

/// A loader surface with `n` exports (the scan order the wire pins).
fn loader(n: usize) -> BundleLoader {
    BundleLoader::new(
        "/usr/lib/host",
        (0..n)
            .map(|i| format!("_host_{i:03}").into_bytes())
            .collect(),
    )
    .expect("the bench loader validates")
}

fn bench_bundle_loader(c: &mut Criterion) {
    let mut group = c.benchmark_group("bundle_loader");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, resolved) in [("dynamic_lookup", 0usize), ("loader_64", 64)] {
        group.bench_with_input(
            BenchmarkId::new("bundle_64_objects", name),
            &resolved,
            |b, &n| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Bundle,
                        undefined_policy: if n == 0 {
                            pgr_core::resolve::UndefinedPolicy::DynamicLookup
                        } else {
                            pgr_core::resolve::UndefinedPolicy::Error
                        },
                        bundle_loader: (n > 0).then(|| loader(n)),
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
    bench_bundle_loader(&mut criterion);
    criterion.final_summary();
}
