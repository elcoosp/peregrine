//! The wire-tail bench (M93): the liveness ask's encode/decode price —
//! the request's `why_live` names and the reply's served chains (one
//! chain: the verdict line, the keeper rows, the root decision; a dead
//! answer is one line). The answers ride the provenance tail beside an
//! IMAGE reply that carries pages of image bytes, so the honest
//! expectation is noise beside the transfer; the gate pins the codec's
//! own price (count-prefixed length-prefixed rendered strings — the
//! wire never re-shapes the face the client prints).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_daemon::protocol::{
    LinkRequest, ServedLive, ServedProvenance, decode_provenance_bytes, encode_provenance,
};

/// A served-shape answer set: one `-why_live` query (the render is the
/// verdict line plus a keeper row and the root decision, the shape the
/// cold lane prints) beside a dead answer (the verdict is the answer).
fn one_query() -> ServedProvenance {
    ServedProvenance {
        exports: Vec::new(),
        loads: None,
        lives: vec![
            ServedLive {
                name: "_greet".to_string(),
                render: "_greet: kept by the strip\n  kept by _main (main.o,__TEXT,__text) \
                         at 0x8 (via _greet)\n  rooted at the entry point (-e)\n"
                    .to_string(),
            },
            ServedLive {
                name: "_orphan".to_string(),
                render: "_orphan: dropped by the strip\n".to_string(),
            },
        ],
    }
}

/// A served-shape answer set at the build-system scale: eight queries
/// (the repeatable flag's real shape on a big link) — one keeper row per
/// chain, the walk's own shape.
fn eight_queries() -> ServedProvenance {
    ServedProvenance {
        exports: Vec::new(),
        loads: None,
        lives: (0..8)
            .map(|i| ServedLive {
                name: format!("_fn_{i}"),
                render: format!(
                    "_fn_{i}: kept by the strip\n  kept by _caller_{i} \
                     (obj_{i}.o,__TEXT,__text) at 0x{i:x}8 (via _fn_{i})\n  \
                     rooted at the export surface (dylib/bundle)\n"
                ),
            })
            .collect(),
    }
}

fn bench_wire_liveness(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_liveness");
    for (name, served) in [
        ("one_query", one_query()),
        ("eight_queries", eight_queries()),
    ] {
        group.throughput(Throughput::Elements(served.lives.len() as u64));
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
    }
    group.finish();
}

/// The request side: the liveness names' encode/decode price (the
/// tail is the count plus the C-symbol names the driver parsed).
fn bench_request_liveness(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_liveness");
    let mut req = request_shape();
    group.throughput(Throughput::Elements(req.why_live.len() as u64));
    group.bench_function(BenchmarkId::new("request_encode", "eight_queries"), |b| {
        b.iter(|| black_box(req.encode().len()));
    });
    group.bench_function(BenchmarkId::new("request_decode", "eight_queries"), |b| {
        let body = req.encode();
        b.iter(|| {
            let back = LinkRequest::decode(black_box(&body)).expect("the request decodes");
            black_box(back.why_live.len());
        });
    });
    req.why_live.clear();
    group.finish();
}

/// A request-shaped skeleton (the config is the codec's own price, the
/// liveness tail is the variable under measure).
fn request_shape() -> LinkRequest {
    LinkRequest {
        config: {
            let mut cfg = pgr_core::layout::LinkConfig {
                ident: "wire-liveness".into(),
                ..pgr_core::layout::LinkConfig::default()
            };
            cfg.platform = 0x1;
            cfg.minos = 0x000c_0100;
            cfg.sdk = 0x000e_0400;
            cfg
        },
        force_load: Vec::new(),
        inputs: Vec::new(),
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
        why_live: (0..8).map(|i| format!("_fn_{i}")).collect::<Vec<String>>(),
    }
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_wire_liveness(&mut criterion);
    bench_request_liveness(&mut criterion);
    criterion.final_summary();
}
