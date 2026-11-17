//! The link-observer bench (M54): the pipeline's cost with and without a
//! subscribed observer over the same corpus (64 objects, one `__text` and
//! one `__DATA,__data` section each). The seam emits one event per phase —
//! seven per segmented link, regardless of the corpus size — so the honest
//! expectation is near-parity: a recording observer pushes a handful of
//! structs per link, the tracing bridge formats only when a subscriber is
//! installed, and the unobserved link pays nothing.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link, link_observed};
use pgr_core::observe::{LinkNote, LinkObserver, PhaseEvent};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;

/// The recording observer a build-system consumer ships: every event rides
/// a `Vec` (the progress-bar/report face of the seam).
#[derive(Default)]
struct Recorder {
    phases: Vec<PhaseEvent>,
    notes: Vec<LinkNote>,
}

impl LinkObserver for Recorder {
    fn on_phase(&mut self, event: PhaseEvent) {
        self.phases.push(event);
    }

    fn on_note(&mut self, note: LinkNote) {
        self.notes.push(note);
    }
}

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

fn bench_observer(c: &mut Criterion) {
    let mut group = c.benchmark_group("observer");
    let inputs = corpus();
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for name in ["unobserved", "tracing_bridge", "recording"] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &name,
            |b, name| {
                b.iter(|| match *name {
                    "unobserved" => {
                        let result = link(black_box(&inputs), &[], &LinkConfig::default())
                            .expect("the corpus links");
                        black_box(result.layout.sections.len());
                    }
                    "tracing_bridge" => {
                        let result = link_observed(
                            black_box(&inputs),
                            &[],
                            &LinkConfig::default(),
                            pgr_core::Parallelism::Auto,
                            None,
                            &mut pgr_core::observe::TracingObserver,
                        )
                        .expect("the corpus links");
                        black_box(result.layout.sections.len());
                    }
                    _ => {
                        let mut observer = Recorder::default();
                        let result = link_observed(
                            black_box(&inputs),
                            &[],
                            &LinkConfig::default(),
                            pgr_core::Parallelism::Auto,
                            None,
                            &mut observer,
                        )
                        .expect("the corpus links");
                        black_box(observer.phases.len());
                        black_box(observer.notes.len());
                        black_box(result.layout.sections.len());
                    }
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_observer(&mut criterion);
    criterion.final_summary();
}
