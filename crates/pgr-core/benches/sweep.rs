//! The shape-sweep bench: the harness's own price beside the pipeline it
//! measures. The §9.3 nightly contract ("full corpus, 10 runs, median and
//! p95") rides the seam — the groups pin the reduction's O(n log n) over
//! the recorded run sets, the stored ledger's render and parse faces
//! (the round-trip convention's two halves), and one full sweep run
//! beside the plain link (the harness's per-link overhead: the collector
//! subscription plus the reduction — a handful of pushes and one sort).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox; the hardware gates own the comparable numbers.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::time::Duration;

use pgr_core::link::{LinkInput, link};
use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
use pgr_core::sweep::{
    SweepDelta, SweepLedger, SweepPlan, SweepSample, SweepSummary, ledger_json, parse_ledger,
    reduce, run_sweep,
};
use pgr_core::time_report::TimeReport;
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

/// The samples the reduction benches read: `runs` synthetic runs, each
/// with the segmented pipeline's seven phase rows (the M58 shape — the
/// rows a real sweep records).
fn samples(runs: usize) -> Vec<SweepSample> {
    let row = |us: u64| PhaseEvent {
        phase: Phase::Parse,
        detail: PhaseDetail::Objects { inputs: 64 },
        elapsed: Duration::from_micros(us),
    };
    (0..runs)
        .map(|r| SweepSample {
            wall: Duration::from_micros(1_000 + u64::try_from(r).unwrap_or(0)),
            report: TimeReport {
                phases: vec![
                    row(900 + u64::try_from(r).unwrap_or(0)),
                    row(4),
                    row(90),
                    row(120),
                    row(30),
                    row(10),
                    row(210),
                ],
                emit: None,
                total: None,
                notes: Vec::new(),
            },
        })
        .collect()
}

/// The sweep bench: reduction, faces, and one swept link beside the
/// plain one.
fn bench_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("sweep");

    // The reduction over the run sets the nightly records (§9.3's ten
    // runs, and a hundred for the slope).
    for runs in [10usize, 100] {
        let set = samples(runs);
        group.throughput(Throughput::Elements(runs as u64));
        group.bench_with_input(BenchmarkId::new("reduce", runs), &set, |b, set| {
            b.iter(|| black_box(reduce("bench-shape", black_box(set))));
        });
    }

    // The stored ledger's two faces over the ten-run summary (the
    // round-trip convention's halves).
    let set = samples(10);
    let summary: SweepSummary = reduce("bench-shape", &set);
    group.throughput(Throughput::Elements(10));
    group.bench_function("render_ledger_10_runs", |b| {
        b.iter(|| black_box(ledger_json("bench-shape", 10, black_box(&summary))));
    });
    let json = ledger_json("bench-shape", 10, &summary);
    group.bench_function("parse_ledger_10_runs", |b| {
        b.iter(|| {
            let parsed = parse_ledger(black_box(&json)).expect("the bench ledger parses");
            black_box(parsed.summary.runs);
        });
    });
    // The §9.3 "vs baselines" face: the two stored ledgers' comparison
    // price (the chart's input — bands plus seven phase rows).
    let previous = SweepLedger {
        label: "bench-shape".to_string(),
        runs: 10,
        summary: summary.clone(),
    };
    group.bench_function("delta_7_phases", |b| {
        b.iter(|| {
            let delta = SweepDelta::between(black_box(&previous), black_box(&previous))
                .expect("one shape's own history compares");
            black_box(delta.phases.len());
        });
    });

    // The harness's per-link overhead: one swept run beside the plain
    // link over the same generated corpus (the collector subscription
    // plus the reduction — the honest expectation is near-parity).
    let contents = build_corpus(&CorpusSpec {
        objects: Some(64),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    })
    .expect("the bench corpus builds");
    let inputs: Vec<LinkInput> = contents
        .files
        .iter()
        .map(|(name, bytes)| LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect();
    group.throughput(Throughput::Elements(64));
    group.bench_function("link_64_objects/plain", |b| {
        b.iter(|| {
            let result = link(
                black_box(&inputs),
                &[],
                &pgr_core::layout::LinkConfig::default(),
            )
            .expect("the corpus links");
            black_box(result.layout.sections.len());
        });
    });
    group.bench_function("link_64_objects/one_run_sweep", |b| {
        b.iter(|| {
            let outcome = run_sweep(
                black_box(&inputs),
                &[],
                &pgr_core::layout::LinkConfig::default(),
                pgr_core::link::Parallelism::Auto,
                &SweepPlan {
                    label: "bench-shape".to_string(),
                    runs: 1,
                },
            )
            .expect("the sweep sweeps");
            black_box(outcome.summary.runs);
        });
    });

    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_sweep(&mut criterion);
    criterion.final_summary();
}
