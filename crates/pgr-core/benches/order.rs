//! The order-file rank bench (M11 rung 1): the same corpus laid out
//! without a rank table (the M1–M10 byte shape) and with one — the rank
//! lookup is a per-piece hash probe over `(file, atom start)` and the
//! sort is a stable pass over each bucket, so the cost should ride the
//! piece count, not the entry count. The corpus mirrors a
//! `-dead_strip`-free, subsection-split link (the shape an order file
//! forces into atom granularity).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded honestly as a
//! *shape-parity* gate on the dev sandbox — the ranked layout pays the
//! atom split (pieces per symbol instead of per section) plus one
//! stable sort per bucket; the bench exists so the next perf pass
//! measures both shapes against the same corpus.

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::link::link;
use pgr_core::link::{LinkArchive, LinkInput};
use pgr_core::order::{OrderFile, SymbolOrder};
use std::hint::black_box;

/// One subsection-split object: `n` functions of one ret each, one
/// symbol per atom (the shape an order file ranks).
fn object(name: &str, n: usize) -> Vec<u8> {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    let stem = name.trim_end_matches(".o");
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    for i in 0..n {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_{stem}_f{i:03}"),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the bench object builds")
}

fn corpus(objects: usize, fns_per_object: usize) -> Vec<LinkInput> {
    (0..objects)
        .map(|o| LinkInput {
            name: format!("obj{o:02}.o"),
            bytes: object(&format!("obj{o:02}.o"), fns_per_object),
        })
        .collect()
}

/// Ranks every function of the even-indexed objects (half the corpus).
fn order_for(objects: usize, fns_per_object: usize) -> SymbolOrder {
    use std::fmt::Write as _;
    let mut text = String::new();
    for o in (0..objects).step_by(2) {
        for f in 0..fns_per_object {
            let _ = writeln!(text, "_obj{o:02}_f{f:03}");
        }
    }
    SymbolOrder::build(&OrderFile::parse(&text).expect("the bench order file parses"))
}

const OBJECTS: usize = 12;
const FNS: usize = 256;

fn bench_layout(c: &mut Criterion) {
    let mut group = c.benchmark_group("order_file");
    let inputs = corpus(OBJECTS, FNS);
    let pieces = OBJECTS * FNS;
    group.throughput(Throughput::Elements(pieces as u64));

    let plain_cfg = LinkConfig {
        entry_symbol: "_obj00_f000".into(),
        ..LinkConfig::default()
    };
    let ranked_cfg = LinkConfig {
        entry_symbol: "_obj00_f000".into(),
        symbol_order: Some(order_for(OBJECTS, FNS)),
        ..LinkConfig::default()
    };

    group.bench_with_input(
        BenchmarkId::new("layout", "no_order"),
        &plain_cfg,
        |b, cfg| {
            b.iter(|| {
                let archives: [LinkArchive; 0] = [];
                let result =
                    link(black_box(&inputs), &archives, cfg).expect("the plain link plans");
                black_box(result.layout.order_unmatched.len());
            });
        },
    );
    group.bench_with_input(
        BenchmarkId::new("layout", "ranked"),
        &ranked_cfg,
        |b, cfg| {
            b.iter(|| {
                let archives: [LinkArchive; 0] = [];
                let result =
                    link(black_box(&inputs), &archives, cfg).expect("the ranked link plans");
                black_box(result.layout.order_unmatched.len());
            });
        },
    );
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_layout(&mut criterion);
    criterion.final_summary();
}
