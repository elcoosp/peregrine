//! The wire-tail bench (M79): the provenance tail's encode/decode price
//! over served-shape answers — one export answer (the definition and
//! every reference site the index recorded) beside the load report, and
//! a multi-query shape. The tail rides an IMAGE reply that carries pages
//! of image bytes, so the honest expectation is noise beside the
//! transfer; the gate pins the codec's own price (one present byte,
//! length-prefixed rendered strings — the wire never re-shapes the face
//! the client prints).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_daemon::protocol::{
    ServedExport, ServedProvenance, decode_provenance_bytes, encode_provenance,
};

/// A served-shape answer set: one `-why_export` query (the render is the
/// definition line plus a reference-site row, the shape the cold lane
/// prints) beside the `-why_load` report (one pulled member).
fn one_query() -> ServedProvenance {
    ServedProvenance {
        exports: vec![ServedExport {
            name: "_greet".to_string(),
            render: "_greet: greet.o(__TEXT,__text), defined at 0x0 (rank 2)\n  \
                     read by main.o(__TEXT,__text) at 0x8\n"
                .to_string(),
        }],
        loads: Some(
            "libgreet.a(greet.o):\n  pulled for _greet (the lazy fixpoint)\n  \
             defines: _greet\n  opens: \n"
                .to_string(),
        ),
        lives: Vec::new(),
    }
}

/// A served-shape answer set at the build-system scale: eight queries
/// (the repeatable flag's real shape on a big link) beside the report.
fn eight_queries() -> ServedProvenance {
    ServedProvenance {
        exports: (0..8)
            .map(|i| ServedExport {
                name: format!("_fn_{i}"),
                render: format!(
                    "_fn_{i}: obj_{i}.o(__TEXT,__text), defined at 0x{i:x}0 (rank 2)\n  \
                     read by main.o(__TEXT,__text) at 0x{i:x}8\n"
                ),
            })
            .collect(),
        loads: Some(one_query().loads.expect("the report rides")),
        lives: Vec::new(),
    }
}

fn bench_wire_provenance(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_provenance");
    for (name, served) in [
        ("one_query", one_query()),
        ("eight_queries", eight_queries()),
    ] {
        group.throughput(Throughput::Elements(served.exports.len() as u64 + 1));
        group.bench_function(BenchmarkId::new("encode", name), |b| {
            b.iter(|| {
                let mut body = Vec::with_capacity(256);
                encode_provenance(&mut body, Some(black_box(&served)));
                black_box(body.len());
            });
        });
        group.bench_function(BenchmarkId::new("decode", name), |b| {
            let mut body = Vec::with_capacity(256);
            encode_provenance(&mut body, Some(&served));
            b.iter(|| {
                let back = decode_provenance_bytes(black_box(&body)).expect("the tail decodes");
                black_box(back.expect("the answers ride"));
            });
        });
        group.bench_function(BenchmarkId::new("encode_absent", name), |b| {
            b.iter(|| {
                let mut body = Vec::with_capacity(4);
                encode_provenance(&mut body, None);
                black_box(body.len());
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_wire_provenance(&mut criterion);
    criterion.final_summary();
}
