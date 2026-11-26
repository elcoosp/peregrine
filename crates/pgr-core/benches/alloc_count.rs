//! The allocation-count seam's bench (the `alloc_count` groups): the
//! §9.3 per-PR allocation-count job's own price. The groups pin the
//! collector's per-event price (one sample plus one push — the §9.3
//! "per pass" face's per-phase cost), the report's O(rows) render faces
//! (the text table and the one-line JSON interchange), the DHAT seat's
//! own sample price, and the counted lane's allocation price beside the
//! pass-through's (the profiler's recording is the lane's honest
//! overhead — the walls it rides are the counted lane's own, never the
//! plain sweep's).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox; the hardware gates own the comparable numbers.

use criterion::{BenchmarkId, Criterion};
use std::hint::black_box;
use std::time::Duration;

use pgr_core::alloc_count::{
    AllocCollector, AllocReport, AllocRow, AllocSnapshot, AllocSource, SharedCounters,
};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::observe::{LinkObserver, Phase, PhaseDetail, PhaseEvent};
use pgr_core::sweep::{SweepPlan, run_alloc_sweep, run_sweep};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

/// The test binary's global allocator: the DHAT seat. Without a running
/// profiler it is a pass-through — the first group prices that — and
/// the counted group's profiler is the recording window.
#[global_allocator]
static DHAT: dhat::Alloc = dhat::Alloc;

/// The DHAT seat's bridge — the seat consumer's own glue (the library
/// never links DHAT: the driver's dependency surface stays lean, perf
/// doc §8). This file's bridge is the copy the counted group owns.
struct DhatSource;

impl AllocSource for DhatSource {
    fn sample(&self) -> AllocSnapshot {
        let stats = dhat::HeapStats::get();
        AllocSnapshot {
            blocks: stats.total_blocks,
            bytes: stats.total_bytes,
        }
    }
}

/// One pass completion (the M54 vocabulary's shape — the collector
/// reads only the phase).
fn event(phase: Phase) -> PhaseEvent {
    PhaseEvent {
        phase,
        detail: PhaseDetail::Objects { inputs: 64 },
        elapsed: Duration::from_micros(1),
    }
}

/// The segmented pipeline's phase sequence — the seven rows a real
/// sweep records.
const PHASES: [Phase; 7] = [
    Phase::Parse,
    Phase::ArchivePull,
    Phase::Intern,
    Phase::Resolve,
    Phase::Liveness,
    Phase::Fold,
    Phase::Layout,
];

/// A fourteen-row report (two link runs' worth — the render faces'
/// O(rows) price at the nightly's own row counts).
fn report_14_rows() -> AllocReport {
    let mut rows = Vec::new();
    for _ in 0..2 {
        for phase in PHASES {
            rows.push(AllocRow {
                phase,
                blocks: 1_024,
                bytes: 65_536,
            });
        }
    }
    AllocReport {
        rows,
        total_blocks: 14_336,
        total_bytes: 917_504,
    }
}

/// The pass-through groups: the collector's per-event price over the
/// shared-counters seat (the DHAT pass-through costs nothing — no
/// profiler rides) and the faces' render price.
fn bench_pass_through(c: &mut Criterion) {
    let seat = SharedCounters::new();

    let mut group = c.benchmark_group("alloc_count");
    group.bench_with_input(
        BenchmarkId::new("collector", "events_14"),
        &PHASES,
        |b, phases| {
            b.iter(|| {
                let mut collector = AllocCollector::new(&seat);
                for phase in phases.iter().chain(phases.iter()) {
                    collector.on_phase(event(*phase));
                }
                black_box(collector.finish())
            });
        },
    );

    let report = report_14_rows();
    group.bench_function("report/render_14_rows", |b| {
        b.iter(|| black_box(report.render()));
    });
    group.bench_function("report/render_json_14_rows", |b| {
        b.iter(|| black_box(report.render_json()));
    });
    group.finish();
}

/// The counted lane's groups: the DHAT seat's sample price (the
/// profiler is the caller's — running), the seat's allocation price
/// beside the pass-through's (one 4 KiB alloc/free cycle per iteration,
/// the recording included — the counted lane's honest overhead), the
/// collector's per-event price under the recording seat, and one
/// allocation-lane sweep run beside the wall lane's (the §9.3 per-PR
/// job's lane prices: the plumbing beside the recording seat's).
fn bench_counted(c: &mut Criterion, _profiler: &dhat::Profiler) {
    let source = DhatSource;
    let seat = SharedCounters::new();

    let mut group = c.benchmark_group("alloc_count");
    group.bench_function("seat/dhat_sample", |b| {
        b.iter(|| black_box(source.sample()));
    });
    group.bench_function("seat/counted_alloc_4kib", |b| {
        b.iter(|| {
            let v = Vec::<u8>::with_capacity(4_096);
            black_box(&v);
            drop(v);
        });
    });
    group.bench_with_input(
        BenchmarkId::new("counted_collector", "events_14"),
        &PHASES,
        |b, phases| {
            b.iter(|| {
                let mut collector = AllocCollector::new(&source);
                for phase in phases.iter().chain(phases.iter()) {
                    collector.on_phase(event(*phase));
                }
                black_box(collector.finish())
            });
        },
    );

    // The lane prices: one sweep run over the quartered many-tiny
    // preset — the wall lane's beside the allocation lane's (the silent
    // seat's plumbing beside the recording seat's; the recording ride
    // is the lane's honest overhead, the walls its own).
    let spec = CorpusSpec {
        objects: Some(8),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&spec).expect("the corpus builds");
    let inputs: Vec<LinkInput> = contents
        .files
        .iter()
        .map(|(name, bytes)| LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect();
    let cfg = LinkConfig::default();
    let plan = SweepPlan {
        label: "bench-lane".to_string(),
        runs: 1,
    };
    group.bench_function("sweep/wall_lane_1_run", |b| {
        b.iter(|| black_box(run_sweep(&inputs, &[], &cfg, Parallelism::Serial, &plan)));
    });
    group.bench_function("sweep/alloc_lane_silent_seat_1_run", |b| {
        b.iter(|| {
            black_box(run_alloc_sweep(
                &inputs,
                &[],
                &cfg,
                Parallelism::Serial,
                &plan,
                &mut (),
                &seat,
            ))
        });
    });
    group.bench_function("sweep/alloc_lane_counted_seat_1_run", |b| {
        b.iter(|| {
            black_box(run_alloc_sweep(
                &inputs,
                &[],
                &cfg,
                Parallelism::Serial,
                &plan,
                &mut (),
                &source,
            ))
        });
    });
    group.finish();
}

fn main() {
    let mut c = Criterion::default();

    // The pass-through price first (no profiler runs — the DHAT seat is
    // a pass-through and the numbers are the seam's own).
    bench_pass_through(&mut c);

    // The counted lane's price second (the profiler rides the group —
    // every allocation the group makes is recorded, the backtrace
    // capture included; the walls are the counted lane's own).
    let profiler = dhat::Profiler::builder().testing().build();
    bench_counted(&mut c, &profiler);
    drop(profiler);

    c.final_summary();
}
