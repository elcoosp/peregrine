//! The wire-tail bench (M59): the time report's encode/decode price over
//! a served-shape report — the warm pipeline's six phase rows, the
//! ladder's note, the measured total band. The tail rides an IMAGE reply
//! that carries pages of image bytes, so the honest expectation is noise
//! beside the transfer; the gate pins the codec's own price (a handful of
//! scalars per row, one push per field).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::time::Duration;

use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
use pgr_daemon::protocol::{decode_time_report_bytes, encode_time_report};

/// A served-shape report: the warm pipeline's phases (no `Parse` row —
/// the POIs are resident), a note, no emit band (the relink's Pass-4
/// half is the patch), a measured total.
fn served_report() -> pgr_core::time_report::TimeReport {
    let row = |phase: Phase, detail: PhaseDetail, us: u64| PhaseEvent {
        phase,
        detail,
        elapsed: Duration::from_micros(us),
    };
    pgr_core::time_report::TimeReport {
        phases: vec![
            row(Phase::ArchivePull, PhaseDetail::Members { pulled: 3 }, 42),
            row(Phase::Intern, PhaseDetail::Names { interned: 128 }, 90),
            row(Phase::Resolve, PhaseDetail::Winners { reused: false }, 120),
            row(Phase::Liveness, PhaseDetail::Live { active: false }, 30),
            row(Phase::Fold, PhaseDetail::Folded { folded: 0 }, 10),
            row(
                Phase::Layout,
                PhaseDetail::Planned {
                    segments: 4,
                    sections: 9,
                },
                210,
            ),
        ],
        emit: None,
        total: Some(Duration::from_micros(502)),
        notes: vec![
            "the resolve-reuse replay fell back to the full resolve (the file list moved)"
                .to_string(),
        ],
    }
}

fn bench_wire_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_time");
    let report = served_report();
    group.throughput(Throughput::Elements(report.phases.len() as u64));
    group.bench_function(BenchmarkId::new("encode_report", "6_rows"), |b| {
        b.iter(|| {
            let mut body = Vec::with_capacity(128);
            encode_time_report(&mut body, Some(black_box(&report)));
            black_box(body.len());
        });
    });
    group.bench_function(BenchmarkId::new("decode_report", "6_rows"), |b| {
        let mut body = Vec::with_capacity(128);
        encode_time_report(&mut body, Some(&report));
        b.iter(|| {
            let back = decode_time_report_bytes(black_box(&body)).expect("the tail decodes");
            black_box(back.expect("the report rides"));
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_wire_time(&mut criterion);
    criterion.final_summary();
}
