//! The trace bench (M61, the M63 task rows): the observation seam's cost
//! with the [`TraceCollector`] subscribed (beside the unobserved link —
//! the parity shape the m54/m58 benches pin), the timeline's render price
//! and the strict reader's parse price over fixed reports. The seam emits
//! one event per phase — seven per segmented link — plus the M63 parse
//! tasks (one per input when the pool path runs), so the collector's
//! honest expectation is near-parity: a recording observer pushes a
//! handful of structs and one task record per input per link; the render
//! and the parse are O(rows), the rows are the pipeline's own count.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link, link_observed};
use pgr_core::observe::{Phase, PhaseDetail};
use pgr_core::trace::{TraceCollector, TraceLane, TraceTask, parse_trace_json};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;

/// `OBJECTS` small objects: the first carries `_main`; every object
/// carries one `__TEXT,__text` and one `__DATA,__data` section.
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b =
                ObjectBuilder::new(&format!("obj_{i:03}.o")).set_subsections_via_symbols(true);
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            let data = b.add_section(ObjectSection::data("__data", vec![0x41u8; 8], vec![]));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".to_string()
                } else {
                    format!("_fn_{i:03}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_data_{i:03}"),
                section_index: data,
                value: 0,
                weak: false,
            });
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// A fixed eight-row timeline (the segmented pipeline's seven phases in
/// link order plus the note instant) — the render and parse gates'
/// input. The starts ride the runs' own sequence (each phase opens where
/// the previous closed).
fn fixed_report() -> pgr_core::trace::TraceReport {
    let span =
        |phase: Phase, detail: PhaseDetail, start: u64, dur: u64| pgr_core::trace::TraceSpan {
            phase,
            detail,
            lane: 1,
            start_us: start,
            dur_us: dur,
        };
    pgr_core::trace::TraceReport {
        spans: vec![
            span(Phase::Parse, PhaseDetail::Objects { inputs: 64 }, 0, 900),
            span(
                Phase::ArchivePull,
                PhaseDetail::Members { pulled: 0 },
                900,
                4,
            ),
            span(Phase::Intern, PhaseDetail::Names { interned: 128 }, 904, 90),
            span(
                Phase::Resolve,
                PhaseDetail::Winners { reused: false },
                994,
                120,
            ),
            span(
                Phase::Liveness,
                PhaseDetail::Live { active: false },
                1114,
                30,
            ),
            span(Phase::Fold, PhaseDetail::Folded { folded: 0 }, 1144, 10),
            span(
                Phase::Layout,
                PhaseDetail::Planned {
                    segments: 4,
                    sections: 9,
                },
                1154,
                210,
            ),
        ],
        tasks: Vec::new(),
        notes: vec![pgr_core::trace::TraceNote {
            kind: "resolve_reuse_fallback",
            reason: "the seed's file list moved (the bench's fixed shape)".to_string(),
            lane: 1,
            at_us: 1_364,
        }],
        lanes: vec![TraceLane {
            id: 1,
            name: "pgr link".to_string(),
        }],
    }
}

/// The fixed eight-row timeline's task rows (the M63 shape): the parse
/// pool's per-input spans riding the three worker lanes the task report
/// declares (`fixed_task_report` — the pipeline's lane 1 stays the
/// phase spans').
fn fixed_task_rows() -> Vec<TraceTask> {
    (0..OBJECTS)
        .map(|i| TraceTask {
            phase: Phase::Parse,
            label: format!("obj_{i:03}.o"),
            lane: u64::try_from(i % WORKER_LANES + 2).unwrap_or(2),
            start_us: u64::try_from(i * 14).unwrap_or(u64::MAX),
            dur_us: 12,
        })
        .collect()
}

/// The worker lanes a 64-task report declares beside the pipeline's own
/// (the M64 names — the reader refuses a lane no `thread_name` names).
const WORKER_LANES: usize = 3;

/// The fixed report with the M63 task rows riding (the 64-object link's
/// report shape): the eight-row base plus the worker lanes and their 64
/// task spans.
fn fixed_task_report() -> pgr_core::trace::TraceReport {
    let mut report = fixed_report();
    report.tasks = fixed_task_rows();
    for w in 0..WORKER_LANES {
        let id = u64::try_from(w + 2).unwrap_or(u64::MAX);
        report.lanes.push(TraceLane {
            id,
            name: format!("pgr parse pool {}", w + 1),
        });
    }
    report
}

fn bench_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for name in ["unobserved", "collector"] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &name,
            |b, name| {
                b.iter(|| {
                    if *name == "unobserved" {
                        let result = link(black_box(&inputs), &[], &LinkConfig::default())
                            .expect("the corpus links");
                        black_box(result.layout.sections.len());
                    } else {
                        let mut collector = TraceCollector::new();
                        let result = link_observed(
                            black_box(&inputs),
                            &[],
                            &LinkConfig::default(),
                            pgr_core::Parallelism::Auto,
                            None,
                            &mut collector,
                        )
                        .expect("the corpus links");
                        black_box(collector.finish().spans.len());
                        black_box(result.layout.sections.len());
                    }
                });
            },
        );
    }
    group.bench_function("render_8_rows", |b| {
        let report = fixed_report();
        b.iter(|| black_box(black_box(&report).render()));
    });
    group.bench_function("parse_8_rows", |b| {
        let json = fixed_report().render();
        b.iter(|| {
            let parsed = parse_trace_json(black_box(&json)).expect("the fixed trace parses");
            black_box(parsed.spans.len());
        });
    });
    // The M63 task rows' price: the pool's per-input spans ride the
    // render's `ts` sort and the reader's arg union beside the 8-row
    // report (one 64-task report is the 64-object link's shape).
    group.bench_function("render_8_rows_64_tasks", |b| {
        let report = fixed_task_report();
        b.iter(|| black_box(black_box(&report).render()));
    });
    group.bench_function("parse_8_rows_64_tasks", |b| {
        let json = fixed_task_report().render();
        b.iter(|| {
            let parsed = parse_trace_json(black_box(&json)).expect("the fixed trace parses");
            black_box(parsed.tasks.len());
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_trace(&mut criterion);
    criterion.final_summary();
}
