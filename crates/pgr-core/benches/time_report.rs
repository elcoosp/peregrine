//! The time-report bench (M58): the observation seam's cost with the
//! [`TimeCollector`] subscribed, beside the two faces' render price over
//! a fixed report. The seam emits one event per phase — seven per
//! segmented link, regardless of the corpus size — so the collector's
//! honest expectation is near-parity with the unobserved link (a handful
//! of pushes per link); the renders are O(rows), the rows are the
//! pipeline's own count.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::time::Duration;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link, link_observed};
use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
use pgr_core::time_report::TimeCollector;
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

/// A fixed eight-row report (the segmented pipeline's seven phases plus
/// the emit band and the total) — the render gates' input.
fn fixed_report() -> pgr_core::time_report::TimeReport {
    let row = |phase: Phase, detail: PhaseDetail, us: u64| PhaseEvent {
        phase,
        detail,
        elapsed: Duration::from_micros(us),
    };
    pgr_core::time_report::TimeReport {
        phases: vec![
            row(Phase::Parse, PhaseDetail::Objects { inputs: 64 }, 900),
            row(Phase::ArchivePull, PhaseDetail::Members { pulled: 0 }, 4),
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
        emit: Some(Duration::from_micros(1_100)),
        total: Some(Duration::from_micros(2_464)),
        notes: Vec::new(),
    }
}

fn bench_time_report(c: &mut Criterion) {
    let mut group = c.benchmark_group("time_report");
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
                        let mut collector = TimeCollector::default();
                        let result = link_observed(
                            black_box(&inputs),
                            &[],
                            &LinkConfig::default(),
                            pgr_core::Parallelism::Auto,
                            None,
                            &mut collector,
                        )
                        .expect("the corpus links");
                        black_box(collector.report().phases.len());
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
    group.bench_function("render_json_8_rows", |b| {
        let report = fixed_report();
        b.iter(|| black_box(black_box(&report).render_json()));
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_time_report(&mut criterion);
    criterion.final_summary();
}
