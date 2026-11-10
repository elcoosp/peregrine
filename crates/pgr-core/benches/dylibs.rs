//! The dylib-surface bench (M14 rung 2): the link cost across the load
//! command kinds — plain `LC_LOAD_DYLIB` vs `LC_LOAD_WEAK_DYLIB` vs
//! `LC_LAZY_LOAD_DYLIB` over the same corpus (16 dylibs × 16 exports,
//! 256 binds). The kind is one header opcode per dylib; binds, the
//! import table and the trie do not read it, so the honest expectation
//! is parity — the bench pins "the released surface never regresses
//! into the link's hot path".
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the map/report benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::Dylib;

const DYLIBS: usize = 16;
const EXPORTS_PER_DYLIB: usize = 16;
const BINDS: usize = DYLIBS * EXPORTS_PER_DYLIB;

/// One object whose `__data` is a table of `BINDS` pointers, one bind
/// per dylib export (`_sym_%03d`, dylib `d` owns syms `d*16..d*16+16`).
fn binder_object() -> Vec<u8> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    let mut b = ObjectBuilder::new("binder.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; BINDS * 8], vec![]));
    let mut syms = Vec::new();
    for i in 0..BINDS {
        let s = b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_sym_{i:03}"),
            weak_ref: false,
        });
        syms.push(s);
    }
    for (i, s) in syms.iter().enumerate() {
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(u32::try_from(*s).unwrap()).at((i * 8) as u32));
    }
    b.build().expect("the bench object builds")
}

/// `DYLIBS` dylib inputs, each exporting its slice of the bind surface.
fn dylibs(kind: &str) -> Vec<Dylib> {
    (0..DYLIBS)
        .map(|d| Dylib {
            install_name: format!("@rpath/lib{d:02}.dylib"),
            current_version: 0x1_0000,
            compatibility_version: 0x1_0000,
            exports: (0..EXPORTS_PER_DYLIB)
                .map(|e| format!("_sym_{:03}", d * EXPORTS_PER_DYLIB + e).into_bytes())
                .collect(),
            weak: kind == "weak",
            reexport: false,
            lazy: kind == "lazy",
        })
        .collect()
}

fn bench_dylib_surface(c: &mut Criterion) {
    let mut group = c.benchmark_group("dylib_surface");
    let bytes = binder_object();
    let inputs = vec![LinkInput {
        name: "binder.o".into(),
        bytes,
    }];
    group.throughput(Throughput::Elements(BINDS as u64));
    for kind in ["load", "weak", "lazy"] {
        group.bench_with_input(BenchmarkId::new("link_256_binds", kind), kind, |b, kind| {
            b.iter(|| {
                let cfg = LinkConfig {
                    entry_symbol: "_main".into(),
                    dylibs: dylibs(kind),
                    ..LinkConfig::default()
                };
                let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                black_box(result.layout.trie.len());
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_dylib_surface(&mut criterion);
    criterion.final_summary();
}
