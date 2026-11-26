//! The §9.3 budget gate's bench: the enforcement half's own price beside
//! the rows it reads. The gate is integer permille over the recorded
//! rows — the groups pin the two checkers' cost over the nightly's row
//! sets (the sweep face with and without the 1-thread reference, the
//! `--time` report face), and the two rendered faces a build system
//! diffs (the text table and the one-line interchange).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox; the hardware gates own the comparable numbers.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::time::Duration;

use pgr_core::budget::{check_report, check_sweep};
use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
use pgr_core::sweep::{SweepPhaseRow, SweepSummary};
use pgr_core::time_report::TimeReport;

/// The nightly's reduced shape: `phases` rows at plausible shares of the
/// run wall (the M58 segmented pipeline's shape).
fn summary(wall_us: u64, phases: &[(&str, u64)]) -> SweepSummary {
    let token = |name: &str| match name {
        "parse" => Phase::Parse,
        "archive_pull" => Phase::ArchivePull,
        "intern" => Phase::Intern,
        "resolve" => Phase::Resolve,
        "liveness" => Phase::Liveness,
        "fold" => Phase::Fold,
        "layout" => Phase::Layout,
        "flush" => Phase::Flush,
        other => panic!("unknown phase token {other}"),
    };
    SweepSummary {
        runs: 10,
        median_wall_us: wall_us,
        p95_wall_us: wall_us,
        min_wall_us: wall_us,
        max_wall_us: wall_us,
        phases: phases
            .iter()
            .map(|(name, us)| SweepPhaseRow {
                phase: token(name),
                median_us: *us,
            })
            .collect(),
    }
}

/// One run's `--time` rows at the same shape (the report face's input).
fn report() -> TimeReport {
    let row = |phase: Phase, us: u64| PhaseEvent {
        phase,
        detail: PhaseDetail::Objects { inputs: 64 },
        elapsed: Duration::from_micros(us),
    };
    TimeReport {
        phases: vec![
            row(Phase::Parse, 900),
            row(Phase::ArchivePull, 4),
            row(Phase::Intern, 90),
            row(Phase::Resolve, 120),
            row(Phase::Liveness, 30),
            row(Phase::Fold, 10),
            row(Phase::Layout, 210),
        ],
        emit: None,
        total: Some(Duration::from_micros(1_364)),
        notes: Vec::new(),
    }
}

/// The budget gate's bench: both checkers and both faces.
fn bench_budgets(c: &mut Criterion) {
    let mut group = c.benchmark_group("budgets");

    // The nightly's row set: the seven-phase segmented pipeline at ten
    // runs (§9.3's nightly contract), and a hundred-run slope.
    let parallel = summary(
        1_364,
        &[
            ("parse", 900),
            ("archive_pull", 4),
            ("intern", 90),
            ("resolve", 120),
            ("liveness", 30),
            ("fold", 10),
            ("layout", 210),
        ],
    );
    let reference = summary(
        2_400,
        &[
            ("parse", 1_700),
            ("archive_pull", 6),
            ("intern", 160),
            ("resolve", 260),
            ("liveness", 60),
            ("fold", 20),
            ("layout", 380),
        ],
    );
    for runs in [10usize, 100] {
        let mut lane = parallel.clone();
        lane.runs = runs;
        group.throughput(Throughput::Elements(u64::try_from(runs).unwrap_or(0)));
        group.bench_with_input(
            BenchmarkId::new("check_sweep_7_phases", runs),
            &lane,
            |b, lane| {
                b.iter(|| {
                    let verdict = check_sweep("bench-shape", black_box(lane), None, 8);
                    black_box(verdict.is_clean());
                });
            },
        );
    }
    group.throughput(Throughput::Elements(7));
    group.bench_function("check_sweep_7_phases_paired", |b| {
        b.iter(|| {
            let verdict = check_sweep(
                "bench-shape",
                black_box(&parallel),
                Some(black_box(&reference)),
                8,
            );
            black_box(verdict.efficiency_rows.len());
        });
    });
    group.bench_function("check_report_7_rows", |b| {
        b.iter(|| {
            let verdict = check_report("bench-shape", black_box(&report()));
            black_box(verdict.is_clean());
        });
    });

    // The two faces over a dirty verdict (the breach lines ride).
    let dirty = check_sweep("bench-shape", &parallel, Some(&reference), 8);
    group.bench_function("render_verdict_7_phases", |b| {
        b.iter(|| black_box(dirty.render().len()));
    });
    group.bench_function("render_json_7_phases", |b| {
        b.iter(|| black_box(dirty.render_json().len()));
    });

    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_budgets(&mut criterion);
    criterion.final_summary();
}
