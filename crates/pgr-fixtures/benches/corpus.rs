//! The corpus generation bench (the `pgr_fixtures::corpus` seam's own
//! price): the four §9.2 presets built in memory — no I/O, no clocks, the
//! BENCHMARKS corpora contract — with `Throughput::Bytes` over the
//! manifest's total, so the rate reads as corpus bytes per second.
//!
//! The presets' default shapes are the recorded numbers' shapes (the
//! many-tiny links, the parse-heavy large-debug set, the archive-heavy
//! set, the single giant object); a shape sweep parameterizes them the
//! same way the `xtask` corpus command does.

use std::hint::black_box;

use criterion::{Criterion, Throughput};
use pgr_fixtures::{CorpusPreset, CorpusSpec, build_corpus};

/// Prices one preset's generation: the pure `build_corpus` face — the
/// bytes every shape sweep consumes, built deterministic.
fn bench_preset(c: &mut Criterion, preset: CorpusPreset) {
    let spec = CorpusSpec::new(preset);
    // The manifest rides the bench both as the throughput denominator and
    // as the shape the rate prices.
    let contents = build_corpus(&spec).expect("the corpus builds");
    let total = contents.manifest.file_bytes;
    let label = preset.name();

    let mut group = c.benchmark_group("pgr-fixtures/corpus");
    group.throughput(Throughput::Bytes(total));
    group.bench_function(label, |b| {
        b.iter(|| {
            let contents = build_corpus(black_box(&spec)).expect("the corpus builds");
            black_box((
                contents.manifest.file_bytes,
                contents.manifest.symbols,
                contents.files.len(),
            ));
        });
    });
    group.finish();
}

fn bench_many_tiny(c: &mut Criterion) {
    bench_preset(c, CorpusPreset::ManyTiny);
}

fn bench_large_debug(c: &mut Criterion) {
    bench_preset(c, CorpusPreset::LargeDebug);
}

fn bench_archive_heavy(c: &mut Criterion) {
    bench_preset(c, CorpusPreset::ArchiveHeavy);
}

fn bench_single_giant(c: &mut Criterion) {
    bench_preset(c, CorpusPreset::SingleGiant);
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint
/// holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_many_tiny(&mut criterion);
    bench_large_debug(&mut criterion);
    bench_archive_heavy(&mut criterion);
    bench_single_giant(&mut criterion);
    criterion.final_summary();
}
