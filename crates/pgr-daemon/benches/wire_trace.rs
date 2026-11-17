//! The wire-tail bench (M62): the Chrome-trace timeline's encode/decode
//! price over a served-shape document — the warm pipeline's six phase
//! rows, the ladder's note instant. The tail rides an IMAGE reply that
//! carries pages of image bytes, so the honest expectation is noise
//! beside the transfer; the gate pins the codec's own price (one length
//! prefix, one string push — the JSON rides verbatim, the strict reader
//! is the document's own face).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::observe::{LinkObserver, Phase, PhaseDetail, PhaseEvent};
use pgr_daemon::protocol::{decode_trace_bytes, encode_trace};

/// A served-shape timeline: the warm pipeline's phases (no `Parse` row —
/// the POIs are resident) plus the ladder's note instant.
fn served_trace() -> String {
    let mut c = pgr_core::trace::TraceCollector::new();
    let span = |phase: Phase, detail: PhaseDetail, us: u64| PhaseEvent {
        phase,
        detail,
        elapsed: std::time::Duration::from_micros(us),
    };
    c.on_phase(span(
        Phase::ArchivePull,
        PhaseDetail::Members { pulled: 3 },
        42,
    ));
    c.on_phase(span(
        Phase::Intern,
        PhaseDetail::Names { interned: 128 },
        90,
    ));
    c.on_phase(span(
        Phase::Resolve,
        PhaseDetail::Winners { reused: false },
        120,
    ));
    c.on_phase(span(
        Phase::Liveness,
        PhaseDetail::Live { active: false },
        30,
    ));
    c.on_phase(span(Phase::Fold, PhaseDetail::Folded { folded: 0 }, 10));
    c.on_phase(span(
        Phase::Layout,
        PhaseDetail::Planned {
            segments: 4,
            sections: 9,
        },
        210,
    ));
    c.on_note(pgr_core::observe::LinkNote::ResolveReuseFallback {
        reason: "the resolve-reuse replay fell back to the full resolve (the file list moved)"
            .to_string(),
    });
    c.finish().render()
}

fn bench_wire_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_trace");
    let json = served_trace();
    group.throughput(Throughput::Bytes(json.len() as u64));
    group.bench_function(BenchmarkId::new("encode_trace", "6_rows"), |b| {
        b.iter(|| {
            let mut body = Vec::with_capacity(json.len() + 8);
            encode_trace(&mut body, Some(black_box(&json)));
            black_box(body.len());
        });
    });
    group.bench_function(BenchmarkId::new("decode_trace", "6_rows"), |b| {
        let mut body = Vec::with_capacity(json.len() + 8);
        encode_trace(&mut body, Some(&json));
        b.iter(|| {
            let back = decode_trace_bytes(black_box(&body)).expect("the tail decodes");
            black_box(back.expect("the timeline rides"));
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_wire_trace(&mut criterion);
    criterion.final_summary();
}
