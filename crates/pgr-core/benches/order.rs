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
use pgr_core::order::{CstringOrder, OrderFile, OrderSource, SymbolOrder};
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

/// The M90 `-sectorder` composition groups: the seam's own price —
/// building the one rank table from N parsed sources (the cross-source
/// duplicate walk plus the merged maps) over 2- and 8-source
/// compositions at the per-subsystem order-file scale (128 entries per
/// source) — and the composed table's link, whose ranked shape is the
/// `order_file/ranked` group's again (the compose is paid once per
/// link, before Pass 3; the sort is the same stable pass).
fn bench_sectorder(c: &mut Criterion) {
    let mut group = c.benchmark_group("sectorder_compose");
    for sources_n in [2usize, 8] {
        let files: Vec<OrderFile> = (0..sources_n)
            .map(|s| {
                let mut text = String::new();
                for f in 0..128usize {
                    let _ =
                        std::fmt::Write::write_fmt(&mut text, format_args!("_obj{s:02}_f{f:03}\n"));
                }
                OrderFile::parse(&text).expect("the bench order file parses")
            })
            .collect();
        let sources: Vec<OrderSource<'_>> = files
            .iter()
            .map(|file| OrderSource {
                name: "sectorder __TEXT __text",
                file,
            })
            .collect();
        group.throughput(Throughput::Elements((sources_n * 128) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(sources_n),
            &sources,
            |b, src| {
                b.iter(|| {
                    let table = SymbolOrder::compose(black_box(src)).expect("the sources compose");
                    black_box(table.entries().len());
                });
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("sectorder_link");
    let inputs = corpus(OBJECTS, FNS);
    let pieces = OBJECTS * FNS;
    group.throughput(Throughput::Elements(pieces as u64));
    let mut text = String::new();
    for o in (0..OBJECTS).step_by(2) {
        for f in 0..FNS {
            let _ = std::fmt::Write::write_fmt(&mut text, format_args!("_obj{o:02}_f{f:03}\n"));
        }
    }
    let file = OrderFile::parse(&text).expect("the bench order file parses");
    let composed_cfg = LinkConfig {
        entry_symbol: "_obj00_f000".into(),
        symbol_order: Some(
            SymbolOrder::compose(&[OrderSource {
                name: "sectorder __TEXT __text",
                file: &file,
            }])
            .expect("the single source composes"),
        ),
        ..LinkConfig::default()
    };
    group.bench_with_input(
        BenchmarkId::new("layout", "composed"),
        &composed_cfg,
        |b, cfg| {
            b.iter(|| {
                let archives: [LinkArchive; 0] = [];
                let result =
                    link(black_box(&inputs), &archives, cfg).expect("the composed link plans");
                black_box(result.layout.order_unmatched.len());
            });
        },
    );
    group.finish();
}

/// The M91 cstring-rank groups: the rank pass's own price over the D4
/// corpus — the plain `__cstring` merge beside the content-ranked sort
/// (32 objects, 16 literals each; the lookup is one linear probe per
/// piece over the small rank vector, the sort the same stable pass the
/// symbol ranks ride).
fn bench_cstring(c: &mut Criterion) {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    let objects_n = 32usize;
    let literals_n = 16usize;
    let inputs: Vec<LinkInput> = (0..objects_n)
        .map(|o| {
            let name = format!("obj{o:02}.o");
            let mut b = ObjectBuilder::new(&name).set_subsections_via_symbols(true);
            let text = b.add_section(ObjectSection::text(
                "__text",
                vec![0xC0u8, 0x03, 0x5F, 0xD6],
                Vec::new(),
            ));
            let mut data = Vec::new();
            for f in 0..literals_n {
                data.extend_from_slice(format!("str{o:02}_{f:02}").as_bytes());
                data.push(0);
            }
            b.add_section(ObjectSection {
                name: "__cstring".into(),
                segment: "__TEXT".into(),
                align_log2: 0,
                flags: pgr_format::consts::S_CSTRING_LITERALS,
                data,
                relocs: Vec::new(),
            });
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_main{o:02}"),
                section_index: text,
                value: 0,
                weak: false,
            });
            LinkInput {
                name: format!("obj{o:02}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect();
    // The ranks reverse the literal order (every piece ranked — the
    // sort's real work, not the identity pass).
    let mut text = String::new();
    for o in (0..objects_n).rev() {
        for f in (0..literals_n).rev() {
            let _ = std::fmt::Write::write_fmt(&mut text, format_args!("str{o:02}_{f:02}\n"));
        }
    }
    let ranks = CstringOrder::parse(&text).expect("the bench cstring ranks parse");
    let ranked_cfg = LinkConfig {
        entry_symbol: "_main00".into(),
        cstring_order: Some(ranks),
        ..LinkConfig::default()
    };
    let plain_cfg = LinkConfig {
        entry_symbol: "_main00".into(),
        ..LinkConfig::default()
    };
    let mut group = c.benchmark_group("sectorder_cstring");
    group.throughput(Throughput::Elements((objects_n * literals_n) as u64));
    group.bench_with_input(
        BenchmarkId::new("layout", "no_order"),
        &plain_cfg,
        |b, cfg| {
            b.iter(|| {
                let archives: [LinkArchive; 0] = [];
                let result =
                    link(black_box(&inputs), &archives, cfg).expect("the plain link plans");
                black_box(result.layout.cstring_order_unmatched.len());
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
                black_box(result.layout.cstring_order_unmatched.len());
            });
        },
    );
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_layout(&mut criterion);
    bench_sectorder(&mut criterion);
    bench_cstring(&mut criterion);
    criterion.final_summary();
}
