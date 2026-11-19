//! The wire-config bench (M81): the order-file rank table's encode/
//! decode price over the request body — the table rides the config tail
//! (a present byte, count-prefixed entries with their scopes and
//! lines), so the honest expectation is noise beside the inputs the
//! same body carries; the gate pins the codec's own price at the
//! build-system scales (8 and 64 entries) beside the table-free shape.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::order::{OrderEntry, SymbolOrder};
use pgr_daemon::protocol::{InputEntry, LinkRequest, content_hash};

/// A request body over `entries` rank entries (the table rides, or the
/// pre-M81 absence when `entries` is empty).
fn request(entries: usize) -> LinkRequest {
    let config = if entries == 0 {
        LinkConfig::default()
    } else {
        LinkConfig {
            symbol_order: Some(
                SymbolOrder::from_entries(
                    (0..entries)
                        .map(|i| {
                            if i % 4 == 3 {
                                // Every fourth entry scoped (the
                                // `object.o:symbol` shape).
                                OrderEntry {
                                    symbol: format!("_fn_{i}"),
                                    object: Some(format!("obj_{}.o", i % 8)),
                                    line: i + 1,
                                }
                            } else {
                                OrderEntry {
                                    symbol: format!("_fn_{i}"),
                                    object: None,
                                    line: i + 1,
                                }
                            }
                        })
                        .collect(),
                )
                .expect("the table builds"),
            ),
            ..LinkConfig::default()
        }
    };
    LinkRequest {
        config,
        force_load: Vec::new(),
        inputs: vec![InputEntry {
            name: "hello.o".into(),
            hash: content_hash(b"hello"),
        }],
        archives: Vec::new(),
        record: None,
        record_resolution: false,
        prev_output: None,
        audit: false,
        tiles: false,
        time: false,
        trace: false,
        verify: false,
        verify_checks: None,
        why_export: Vec::new(),
        why_load: false,
        map: false,
        why_live: Vec::new(),
    }
}

fn bench_wire_order(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_order");
    for entries in [0usize, 8, 64] {
        let req = request(entries);
        let label = if entries == 0 {
            "no_table".to_string()
        } else {
            format!("{entries}_entries")
        };
        group.throughput(Throughput::Elements(entries.max(1) as u64));
        group.bench_function(BenchmarkId::new("encode", &label), |b| {
            b.iter(|| {
                let body = black_box(&req).encode();
                black_box(body.len());
            });
        });
        let body = req.encode();
        group.bench_function(BenchmarkId::new("decode", &label), |b| {
            b.iter(|| {
                let back = LinkRequest::decode(black_box(&body)).expect("the body decodes");
                black_box(back.config.symbol_order.is_some());
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_wire_order(&mut criterion);
    criterion.final_summary();
}
