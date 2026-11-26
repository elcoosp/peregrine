//! The sweep's verify-gate bench: §9.3's correctness half priced beside
//! the emit it gates. The groups pin the gate's per-image cost — the
//! fused emit alone beside the emit-plus-strict-verify over the same
//! corpus (the gate's overhead is the verifier's whole-image pass), and
//! one verified sweep run beside the plain sweep (the nightly's
//! per-run gate cost).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox; the hardware gates own the comparable numbers.

use criterion::{Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::sweep::{SweepPlan, run_sweep};
use pgr_emit::build_image_fused;
use pgr_emit::sweep::run_verified_sweep;
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};
use pgr_verify::Options;

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

/// The verify-gate bench: the gate's price beside the emit it gates.
fn bench_verified_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("verified_sweep");
    let inputs = corpus_inputs();
    let opts = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

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
    group.bench_function("link_emit_verify_64_objects", |b| {
        b.iter(|| {
            let result = pgr_core::link::link(black_box(&inputs), &[], &exec_cfg())
                .expect("the corpus links");
            let image =
                build_image_fused(&result.layout, &result.objects).expect("the image emits");
            let report = pgr_verify::verify(black_box(&image), &opts);
            black_box(report.is_ok(&opts));
        });
    });

    // One verified sweep run beside the plain sweep (the nightly's
    // per-run gate cost — the strict pass after the measured wall).
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
    group.bench_function("sweep_1_run/verified", |b| {
        b.iter(|| {
            let verified = run_verified_sweep(
                black_box(&inputs),
                &[],
                &exec_cfg(),
                Parallelism::Serial,
                &plan_one,
                &opts,
            )
            .expect("the verified sweep sweeps");
            black_box(verified.gate.stats().len());
        });
    });

    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_verified_sweep(&mut criterion);
    criterion.final_summary();
}
