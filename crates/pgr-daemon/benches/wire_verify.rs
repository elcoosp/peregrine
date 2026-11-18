//! The wire-tail bench (M72): the verify verdict's encode/decode price
//! over a served-shape report — a clean verdict on a linked image (the
//! stats ride, the issue list is empty) and a refused one (a handful of
//! issues). The tail rides an IMAGE reply that carries pages of image
//! bytes, so the honest expectation is noise beside the transfer; the
//! gate pins the codec's own price (one present byte, one length-
//! prefixed interchange document — the M13 writer and the strict reader,
//! not a re-shape).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_daemon::protocol::{decode_verify_report_bytes, encode_verify_report};
use pgr_verify::{Code, Issue, Report};

/// A served-shape clean verdict: the stats of a linked image, no issues.
fn clean_verdict() -> Report {
    let mut report = Report::default();
    report.stats.segments = 4;
    report.stats.sections = 9;
    report.stats.symbols = 12;
    report.stats.fixup_slots = 17;
    report.stats.hash_pages = 3;
    report
}

/// A served-shape refused verdict: a handful of issues on the same stats.
fn refused_verdict() -> Report {
    let mut report = clean_verdict();
    report.issues.push(Issue::error(
        Code::SegmentContract,
        "the `__DATA` vmaddr breaks the 16 KiB congruence",
        Some(98_304),
    ));
    report.issues.push(Issue::error(
        Code::FixupsChain,
        "the chain walk hit a stride the page does not carry",
        Some(163_840),
    ));
    report.issues.push(Issue::warning(
        Code::Suspicious,
        "an odd n_desc rode the symtab",
        None,
    ));
    report
}

fn bench_wire_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_verify");
    let clean = clean_verdict();
    let refused = refused_verdict();
    for (name, report) in [("clean", &clean), ("refused", &refused)] {
        group.throughput(Throughput::Elements(report.issues.len() as u64 + 1));
        group.bench_function(BenchmarkId::new("encode_report", name), |b| {
            b.iter(|| {
                let mut body = Vec::with_capacity(256);
                encode_verify_report(&mut body, Some(black_box(report)));
                black_box(body.len());
            });
        });
        group.bench_function(BenchmarkId::new("decode_report", name), |b| {
            let mut body = Vec::with_capacity(256);
            encode_verify_report(&mut body, Some(report));
            b.iter(|| {
                let back = decode_verify_report_bytes(black_box(&body)).expect("the tail decodes");
                black_box(back.expect("the verdict rides"));
            });
        });
        group.bench_function(BenchmarkId::new("encode_absent", name), |b| {
            b.iter(|| {
                let mut body = Vec::with_capacity(4);
                encode_verify_report(&mut body, None);
                black_box(body.len());
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_wire_verify(&mut criterion);
    criterion.final_summary();
}
