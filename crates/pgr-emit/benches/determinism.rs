//! The sweep's determinism-gate bench: §9.3's determinism half priced
//! beside the emit it compares. The groups pin the gate's per-image
//! cost — the fused emit alone beside the emit-plus-byte-compare over
//! the same corpus (the gate's overhead is the compare over the image
//! the emit already built), and one deterministic sweep run beside the
//! plain sweep (the nightly's per-run gate cost).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox; the hardware gates own the comparable numbers.

use criterion::{Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::sweep::{SweepPlan, run_sweep};
use pgr_emit::build_image_fused;
use pgr_emit::sweep::{DeterminismGate, run_deterministic_sweep};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

/// The bench corpus: the many-tiny preset at the 64-object gate scale.
fn corpus_inputs() -> Vec<LinkInput> {
    let spec = CorpusSpec {
        objects: Some(64),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&spec).expect("the bench corpus builds");
    contents
        .files
        .iter()
        .map(|(name, bytes)| LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect()
}

/// The config the sweep rides.
fn exec_cfg() -> LinkConfig {
    LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    }
}

/// The determinism-gate bench: the gate's price beside the emit it
/// compares.
fn bench_determinism_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("determinism");
    let inputs = corpus_inputs();

    group.throughput(Throughput::Elements(64));
    group.bench_function("link_emit_64_objects", |b| {
        b.iter(|| {
            let result = pgr_core::link::link(black_box(&inputs), &[], &exec_cfg())
                .expect("the corpus links");
            let image =
                build_image_fused(&result.layout, &result.objects).expect("the image emits");
            black_box(image.len());
        });
    });
    group.bench_function("link_emit_compare_64_objects", |b| {
        b.iter(|| {
            let result = pgr_core::link::link(black_box(&inputs), &[], &exec_cfg())
                .expect("the corpus links");
            let image =
                build_image_fused(&result.layout, &result.objects).expect("the image emits");
            // The compare's own price: the baseline rides in, the image
            // matches it (the honest run's shape — a divergence refuses,
            // and a refused run is not a measured one).
            let mut gate = DeterminismGate::new();
            gate.compare_image(0, &image).expect("the baseline rides");
            black_box(gate.compare_image(1, &image).is_ok());
        });
    });

    // One deterministic sweep run beside the plain sweep (the nightly's
    // per-run gate cost — the fused emit + compare after the measured
    // wall).
    let plan_one = SweepPlan {
        label: "bench-shape".to_string(),
        runs: 1,
    };
    group.bench_function("sweep_1_run/plain", |b| {
        b.iter(|| {
            let outcome = run_sweep(
                black_box(&inputs),
                &[],
                &exec_cfg(),
                Parallelism::Serial,
                &plan_one,
            )
            .expect("the sweep sweeps");
            black_box(outcome.summary.runs);
        });
    });
    group.bench_function("sweep_1_run/deterministic", |b| {
        b.iter(|| {
            let swept = run_deterministic_sweep(
                black_box(&inputs),
                &[],
                &exec_cfg(),
                Parallelism::Serial,
                &plan_one,
            )
            .expect("the deterministic sweep sweeps");
            black_box(swept.gate.stats().len());
        });
    });

    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_determinism_sweep(&mut criterion);
    criterion.final_summary();
}
